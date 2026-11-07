"""Fixed M6B authorization ledger. Reservations are permanent, including uncertainty."""
import hashlib
from pathlib import Path
import sqlite3
from .live_contracts import LiveResearchError
from .services import utc

MODEL = 'gpt-5.4-mini-2026-03-17'
CVE = 'CVE-2022-3602'
LEDGER = Path(__file__).resolve().parents[1]/'artifacts/m6b-campaign-20261104/campaign.sqlite3'
RESERVATION_MICRO_USD = 75432


def initialize():
    """Explicit first creation only; never recreate or clear an existing ledger."""
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open('xb'):
        pass
    with sqlite3.connect(LEDGER) as db:
        db.executescript('''
        CREATE TABLE authorization (id INTEGER PRIMARY KEY CHECK(id=1),
          campaign TEXT NOT NULL CHECK(campaign='m6b-20261104'),
          max_attempts INTEGER NOT NULL CHECK(max_attempts=5),
          allowance_micro_usd INTEGER NOT NULL CHECK(allowance_micro_usd=500000));
        INSERT INTO authorization VALUES(1,'m6b-20261104',5,500000);
        CREATE TABLE reservations (id INTEGER PRIMARY KEY, session TEXT NOT NULL UNIQUE,
          prompt_sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL,
          model TEXT NOT NULL CHECK(model='gpt-5.4-mini-2026-03-17'),
          micro_usd INTEGER NOT NULL CHECK(micro_usd=75432));
        CREATE TRIGGER bounded BEFORE INSERT ON reservations BEGIN
          SELECT CASE WHEN (SELECT count(*) FROM reservations)>=5
            OR (SELECT coalesce(sum(micro_usd),0) FROM reservations)+NEW.micro_usd>500000
            THEN RAISE(ABORT,'Campaign authorization exhausted') END;
        END;
        CREATE TRIGGER reservation_no_update BEFORE UPDATE ON reservations BEGIN SELECT RAISE(ABORT,'Immutable reservation'); END;
        CREATE TRIGGER reservation_no_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'Immutable reservation'); END;
        CREATE TRIGGER authorization_no_update BEFORE UPDATE ON authorization BEGIN SELECT RAISE(ABORT,'Immutable authorization'); END;
        CREATE TRIGGER authorization_no_delete BEFORE DELETE ON authorization BEGIN SELECT RAISE(ABORT,'Immutable authorization'); END;
        ''')


def reserve(config, prompt):
    """Atomic global debit immediately before transport; no refunds or retries."""
    if (config.model != MODEL or config.max_input_bytes > 60000 or config.max_output_tokens > 4096
            or config.timeout_seconds > 60 or config.input_rate != .75 or config.output_rate != 4.5
            or config.budget_usd > .10 or config.max_session_requests != 1
            or config.session_output_tokens > 4096 or not config.session_id.startswith('m6b-')):
        raise LiveResearchError('M6B campaign model/session/request limits rejected.')
    import json
    if json.loads(prompt).get('cve_id') != CVE:
        raise LiveResearchError('M6B campaign CVE rejected.')
    debit_ledger(LEDGER, (1, 'm6b-20261104', 5, 500000), config,
                 hashlib.sha256(prompt.encode()).hexdigest(), RESERVATION_MICRO_USD)


def debit_ledger(path, authorization, config, prompt_hash, micro_usd):
    """Shared atomic accounting; callers supply separate fixed campaign policies.

    Never creates a ledger, initializes authority, refunds or changes policy rows.
    Agent 2 retains its original schema and immutable historical reservations.
    """
    try:
        with sqlite3.connect(path.as_uri()+'?mode=rw', uri=True, timeout=10) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT * FROM authorization').fetchall() != [authorization]:
                raise LiveResearchError('Campaign authorization integrity failed.')
            if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise LiveResearchError('Campaign ledger integrity failed.')
            count, used = db.execute('SELECT count(*),coalesce(sum(micro_usd),0) FROM reservations').fetchone()
            if count >= authorization[2] or used+micro_usd > authorization[3]:
                raise LiveResearchError('Campaign authorization exhausted; no provider request made.')
            db.execute('INSERT INTO reservations(session,prompt_sha256,recorded_at,model,micro_usd) VALUES(?,?,?,?,?)',
                       (config.session_id, prompt_hash, utc(), config.model, micro_usd))
    except sqlite3.Error:
        raise LiveResearchError('Campaign ledger unavailable or reservation rejected; no provider request made.') from None
