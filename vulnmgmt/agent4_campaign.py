"""One proposed Agent 4 evaluation. Pending by default; no credential/readiness probe.

Separate ledger, CVE, workspace identity, session and plan binding from M6B.
Only an explicitly confirmed future operator command may activate this proposal.
"""
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
from . import agent4, threat_evidence, live_research
from .live_contracts import LiveConfig, LiveResearchError, redact
from .live_campaign import debit_ledger, RESERVATION_MICRO_USD
from .enrichment_evidence import timestamp
from .services import canonical, digest, stable, utc

ROOT=Path(__file__).resolve().parents[1]
EVALUATION_ROOT=ROOT/'artifacts/m6c-agent4-live-evaluation-01-20261104'
MODEL='gpt-5.4-mini-2026-03-17'
CVE='CVE-2021-44228'
SESSION='m6c-agent4-evaluation-01-20261104'
AUTHORIZATION=(1,SESSION,1,100000)


def configuration(*, enabled=False):
    return LiveConfig(enabled=enabled,authorized=enabled,model=MODEL,session_id=SESSION,
        max_session_requests=1,max_output_tokens=4096,session_output_tokens=4096,max_input_bytes=60000,
        budget_usd=.10,input_rate=.75,output_rate=4.5,timeout_seconds=60)


def implementation_hashes():
    names=['vulnmgmt/agent4.py','vulnmgmt/agent4_campaign.py','vulnmgmt/agent2_sdk.py',
        'vulnmgmt/live_research.py','vulnmgmt/live_campaign.py','vulnmgmt/live_contracts.py',
        'vulnmgmt/credentials.py','vulnmgmt/threat_contracts.py','vulnmgmt/threat_evidence.py',
        'audit_tools/agent4_live_evaluation.py']
    return {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names}


def ledger():
    return EVALUATION_ROOT/'campaign.sqlite3'


def connect():
    return sqlite3.connect(ledger().resolve().as_uri()+'?mode=rw',uri=True,timeout=10)


def initialize_pending(plan_hash):
    """Explicit new isolated preparation only; no authority row is inserted."""
    with ledger().open('xb'):
        pass
    with connect() as c:
        c.executescript('''
        CREATE TABLE proposal(id INTEGER PRIMARY KEY CHECK(id=1),plan_hash TEXT NOT NULL);
        CREATE TABLE authorization(id INTEGER PRIMARY KEY CHECK(id=1),
          campaign TEXT NOT NULL CHECK(campaign='m6c-agent4-evaluation-01-20261104'),
          max_attempts INTEGER NOT NULL CHECK(max_attempts=1),
          allowance_micro_usd INTEGER NOT NULL CHECK(allowance_micro_usd=100000));
        CREATE TABLE activation(id INTEGER PRIMARY KEY CHECK(id=1),plan_hash TEXT NOT NULL,
          actor TEXT NOT NULL,recorded_at TEXT NOT NULL);
        CREATE TABLE reservations(id INTEGER PRIMARY KEY,session TEXT NOT NULL UNIQUE,
          prompt_sha256 TEXT NOT NULL,recorded_at TEXT NOT NULL,
          model TEXT NOT NULL CHECK(model='gpt-5.4-mini-2026-03-17'),
          micro_usd INTEGER NOT NULL CHECK(micro_usd=75432));
        CREATE TRIGGER bounded BEFORE INSERT ON reservations BEGIN
          SELECT CASE WHEN (SELECT count(*) FROM authorization)!=1
            OR (SELECT count(*) FROM reservations)>=1
            OR (SELECT coalesce(sum(micro_usd),0) FROM reservations)+NEW.micro_usd>100000
            THEN RAISE(ABORT,'Agent 4 authorization unavailable/exhausted') END;
        END;
        ''')
        c.execute('INSERT INTO proposal VALUES(1,?)',(plan_hash,))
        for table in ('proposal','authorization','activation','reservations'):
            for action in ('UPDATE','DELETE'):
                c.execute(f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Immutable Agent 4 campaign'); END;")


def plan():
    try:
        raw=(EVALUATION_ROOT/'attempt-plan.json').read_bytes()
        value=json.loads(raw)
        with connect() as c:
            if c.execute('SELECT * FROM proposal').fetchall()!=[(1,hashlib.sha256(raw).hexdigest())]:
                raise LiveResearchError('Agent 4 evaluation plan integrity failed.')
        if value['implementation_sha256']!=implementation_hashes():
            raise LiveResearchError('Agent 4 prepared implementation changed; stop for review, never rewrite plan hashes.')
        if value['configuration']!=configuration().model_dump() or value['cve_id']!=CVE:
            raise LiveResearchError('Agent 4 proposed settings changed.')
        return value
    except (OSError,sqlite3.Error,ValueError,KeyError) as exc:
        if isinstance(exc,LiveResearchError):
            raise
        raise LiveResearchError('Agent 4 prepared plan/ledger unavailable; no live permission inferred.') from None


def require_configuration(config):
    proposed=configuration(enabled=config.enabled and config.authorized)
    if config.model_dump()!=proposed.model_dump():
        raise LiveResearchError('Agent 4 evaluation model/session/budget/request settings rejected.')
    config.require_authorization()


def activate(*, actor, confirmed):
    """Future explicit execution approval, not human acceptance of research."""
    if not confirmed or not actor.strip():
        raise LiveResearchError('Separate explicit Agent 4 execution authorization and analyst required.')
    p=plan()
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT count(*) FROM authorization').fetchone()[0] or c.execute('SELECT count(*) FROM reservations').fetchone()[0]:
            raise LiveResearchError('Agent 4 campaign already activated/used; no automatic retry or new authorization.')
        c.execute('INSERT INTO authorization VALUES(?,?,?,?)',AUTHORIZATION)
        c.execute('INSERT INTO activation VALUES(1,?,?,?)',
            (hashlib.sha256((EVALUATION_ROOT/'attempt-plan.json').read_bytes()).hexdigest(),redact(actor),utc()))


def require_authorized(config):
    require_configuration(config)
    plan()
    with connect() as c:
        if c.execute('SELECT * FROM authorization').fetchall()!=[AUTHORIZATION]:
            raise LiveResearchError('Agent 4 live execution disabled: separate campaign authorization pending.')
        expected_hash=hashlib.sha256((EVALUATION_ROOT/'attempt-plan.json').read_bytes()).hexdigest()
        if c.execute('SELECT plan_hash FROM activation').fetchall()!=[(expected_hash,)]:
            raise LiveResearchError('Agent 4 execution approval is not bound to the exact prepared plan.')
        if c.execute('SELECT count(*) FROM reservations').fetchone()[0]:
            raise LiveResearchError('Agent 4 single attempt exhausted; reservation retained, no retry.')


def context(data,cve,secret=''):
    p=plan()
    if cve!=CVE or data['workspace_id']!=p['workspace_id']:
        raise LiveResearchError('Foreign Agent 4 workspace/CVE rejected.')
    captures=[]
    for item in p['sources']:
        raw=(EVALUATION_ROOT/item['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=item['sha256']:
            raise LiveResearchError('Agent 4 pinned source file changed.')
        capture=json.loads(raw)
        row=next((s for s in data['sources'] if s['id']==item['source_id']),None)
        if row is None or row['snapshot_json']!=canonical(capture) or row['content_hash']!=capture.get('content_sha256'):
            raise LiveResearchError('Agent 4 workspace source binding failed.')
        captures.append(dict(capture,id=row['id']))
    now=utc()
    # Refuse old prepared feed captures; observation-date Stale remains explicit.
    if any(timestamp(now)>timestamp(s['retrieved_at'])+timedelta(days=1)
           for s in captures if s['kind'] in ('KEV','EPSS') and s['fetch_status']=='Success'):
        raise LiveResearchError('Agent 4 prepared feed captures exceed 24 hours; stop for new source preparation/authorization.')
    result=threat_evidence.build(CVE,data['workspace_id'],now,captures,p['report_facts'])
    if result['kev']['state'] not in ('Confirmed','Not listed') or result['epss']['state']!='Confirmed':
        raise LiveResearchError('Agent 4 evaluation requires usable KEV and EPSS; missing/conflicting feeds block the call.')
    if result['kev']['freshness']!='Fresh' or result['epss']['freshness']!='Fresh':
        raise LiveResearchError('Agent 4 evaluation feed freshness expired; stop for fresh preparation and review.')
    result['source_limitations'].append('Saved CISA aa22-174a is a historical 2022 advisory, not proof of ongoing exploitation now; current report access failures and government-targeting Unknown must be retained.')
    return redact(result,secret)


def reserve_provider(config,prompt):
    require_authorized(config)
    supplied=json.loads(prompt)
    if supplied['cve_id']!=CVE or supplied['workspace_id']!=plan()['workspace_id']:
        raise LiveResearchError('Agent 4 provider request is not bound to this evaluation.')
    debit_ledger(ledger(),AUTHORIZATION,config,hashlib.sha256(prompt.encode()).hexdigest(),RESERVATION_MICRO_USD)


class ControlledSDKAgent4(agent4.SDKAgent4):
    reserve_mock_requests=True

    def reserve_provider(self,config,prompt):
        reserve_provider(config,prompt)


@dataclass(frozen=True)
class LiveSpec(agent4.Spec):
    mode: str='live'
    version: str='m6c-agent4-live-evaluation-v1'
    runtime_credential: bool=True
    context=staticmethod(context)


def run(manager,generation,*,config=None,gateway=None,**request):
    cfg=config or LiveConfig.environment()
    require_authorized(cfg)  # always before production credential access
    p=plan()
    state=manager.state()
    if (manager.root.resolve()!=EVALUATION_ROOT.resolve() or generation!=p['generation']
            or state['active']!=p['active_database'] or state['generation']!=p['generation']):
        raise LiveResearchError('Agent 4 evaluation workspace generation/pointer changed.')
    with sqlite3.connect((EVALUATION_ROOT/state['active']).resolve().as_uri()+'?mode=ro',uri=True) as c:
        if c.execute('SELECT database_identity FROM demo_workspaces').fetchone()[0]!=p['database_identity']:
            raise LiveResearchError('Foreign Agent 4 evaluation database identity rejected.')
    if gateway is not None and not isinstance(gateway,ControlledSDKAgent4):
        raise LiveResearchError('Agent 4 controlled evaluation requires the bounded shared SDK adapter.')
    return live_research.run(manager,generation,config=cfg,gateway=gateway or ControlledSDKAgent4(),
        spec=LiveSpec(),**request)
