"""Fixed pending Agent 3 evaluation policy; separate durable one-attempt ledger."""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from sqlalchemy import create_engine
from . import agent3, batching_evidence, live_research
from .dashboard_queries import dashboard
from .live_campaign import debit_ledger, RESERVATION_MICRO_USD
from .live_contracts import LiveConfig, LiveResearchError
from .services import canonical, digest, utc
from .enrichment_evidence import timestamp

ROOT=Path(__file__).resolve().parents[1]
EVALUATION_ROOT=ROOT/'artifacts/m6d-agent3-live-evaluation-01-20261104'
MODEL='gpt-5.4-mini-2026-03-17'
SESSION='m6d-agent3-evaluation-01-20261104'
AUTHORIZATION=(1,SESSION,1,100000)


def configuration(enabled=False):
    return LiveConfig(enabled=enabled,authorized=enabled,model=MODEL,session_id=SESSION,
        max_session_requests=1,max_output_tokens=4096,session_output_tokens=4096,max_input_bytes=60000,
        budget_usd=.10,input_rate=.75,output_rate=4.5,timeout_seconds=60)


def implementation_hashes():
    names=['agent3.py','agent3_campaign.py','batching_contracts.py','batching_evidence.py','agent2_sdk.py',
        'live_research.py','live_contracts.py','live_campaign.py','credentials.py','enrichment_evidence.py',
        'research_contracts.py','dashboard_queries.py','lifecycle.py']
    paths=['vulnmgmt/'+n for n in names]+['audit_tools/agent3_live_evaluation.py']
    return {p:sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}


def connect(readonly=False):
    return sqlite3.connect((EVALUATION_ROOT/'campaign.sqlite3').resolve().as_uri()+
                          ('?mode=ro' if readonly else '?mode=rw'),uri=True,timeout=10)


def initialize_pending(plan_hash):
    with (EVALUATION_ROOT/'campaign.sqlite3').open('xb'):
        pass
    with connect() as c:
        c.executescript('''CREATE TABLE proposal(id INTEGER PRIMARY KEY CHECK(id=1),plan_hash TEXT NOT NULL);
        CREATE TABLE authorization(id INTEGER PRIMARY KEY CHECK(id=1),campaign TEXT NOT NULL,
          max_attempts INTEGER NOT NULL CHECK(max_attempts=1),allowance_micro_usd INTEGER NOT NULL CHECK(allowance_micro_usd=100000));
        CREATE TABLE activation(id INTEGER PRIMARY KEY CHECK(id=1),plan_hash TEXT NOT NULL,actor TEXT NOT NULL,recorded_at TEXT NOT NULL);
        CREATE TABLE reservations(id INTEGER PRIMARY KEY,session TEXT NOT NULL UNIQUE,prompt_sha256 TEXT NOT NULL,
          recorded_at TEXT NOT NULL,model TEXT NOT NULL CHECK(model='gpt-5.4-mini-2026-03-17'),micro_usd INTEGER NOT NULL CHECK(micro_usd=75432));
        CREATE TRIGGER bounded BEFORE INSERT ON reservations BEGIN
          SELECT CASE WHEN (SELECT count(*) FROM authorization)!=1 OR (SELECT count(*) FROM activation)!=1
            OR (SELECT count(*) FROM reservations)>=1 OR (SELECT coalesce(sum(micro_usd),0) FROM reservations)+NEW.micro_usd>100000
            THEN RAISE(ABORT,'Agent 3 authorization unavailable/exhausted') END; END;''')
        c.execute('INSERT INTO proposal VALUES(1,?)',(plan_hash,))
        for t in ('proposal','authorization','activation','reservations'):
            for operation in ('UPDATE','DELETE'):
                c.execute(f"CREATE TRIGGER {t}_no_{operation.lower()} BEFORE {operation} ON {t} BEGIN SELECT RAISE(ABORT,'Immutable Agent 3 campaign'); END")


def plan():
    try:
        raw=(EVALUATION_ROOT/'attempt-plan.json').read_bytes();p=json.loads(raw)
        with connect(True) as c:
            if c.execute('SELECT * FROM proposal').fetchall()!=[(1,sha256(raw).hexdigest())]:
                raise LiveResearchError('Agent 3 plan hash changed; preserve and stop.')
        if p['implementation_sha256']!=implementation_hashes() or p['configuration']!=configuration().model_dump():
            raise LiveResearchError('Agent 3 prepared implementation/settings changed; do not repin a used plan.')
        return p
    except (OSError,ValueError,KeyError,sqlite3.Error) as exc:
        if isinstance(exc,LiveResearchError):raise
        raise LiveResearchError('Agent 3 prepared plan/ledger unavailable; no authorization inferred.') from None


def read_workspace():
    """Readiness must not initialize DemoManager or touch SQLite header metadata."""
    with sqlite3.connect((EVALUATION_ROOT/'control.sqlite3').resolve().as_uri()+'?mode=ro',uri=True) as c:
        c.row_factory=sqlite3.Row
        state=dict(c.execute('SELECT * FROM registry').fetchone())
        events=[dict(r) for r in c.execute('SELECT * FROM events')]
    path=(EVALUATION_ROOT/state['active']).resolve()
    if path.parent!=EVALUATION_ROOT.resolve():
        raise LiveResearchError('Foreign evaluation database path.')
    engine=create_engine('sqlite://',creator=lambda:sqlite3.connect(path.as_uri()+'?mode=ro',uri=True))
    try:
        with engine.connect() as c:
            w=c.exec_driver_sql('SELECT id FROM demo_workspaces').scalar_one()
            data=dashboard(c,w,state['clock']);data['manager']=state
    finally:engine.dispose()
    return data,events


def input_hash(supplied):
    return digest({k:v for k,v in supplied.items() if k!='as_of'})


def context(data,component_id,secret=''):
    p=plan()
    if (component_id!=p['component_id'] or data['workspace_id']!=p['workspace_id'] or
        data['workspace_identity']!=p['database_identity'] or data['generation']!=p['generation']):
        raise LiveResearchError('Foreign Agent 3 evaluation workspace/component.')
    for item in p['sources']:
        raw=(EVALUATION_ROOT/item['path']).read_bytes()
        row=next((r for r in data['sources'] if r['id']==item['id']),None)
        if sha256(raw).hexdigest()!=item['sha256'] or not row or row['snapshot_json']!=canonical(json.loads(raw)):
            raise LiveResearchError('Agent 3 pinned source changed.')
    supplied=batching_evidence.context(dict(data,as_of=utc()),component_id,secret,p['finding_ids'])
    if input_hash(supplied)!=p['input_sha256'] or not supplied['options']:
        raise LiveResearchError('Agent 3 evidence/applicability changed or expired; stop for new preparation/review.')
    return supplied


def activate(actor,confirmed):
    if not confirmed or not actor.strip():raise LiveResearchError('Separate explicit Agent 3 request authorization required.')
    plan()
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if any(c.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ('authorization','activation','reservations')):
            raise LiveResearchError('Agent 3 evaluation already activated/used; no retry.')
        c.execute('INSERT INTO authorization VALUES(?,?,?,?)',AUTHORIZATION)
        c.execute('INSERT INTO activation VALUES(1,?,?,?)',
            (sha256((EVALUATION_ROOT/'attempt-plan.json').read_bytes()).hexdigest(),actor,utc()))


def require_authorized(config):
    if config.model_dump()!=configuration(enabled=True).model_dump():
        raise LiveResearchError('Agent 3 model/session/budget settings rejected.')
    config.require_authorization();plan()
    with connect(True) as c:
        if c.execute('SELECT * FROM authorization').fetchall()!=[AUTHORIZATION] or c.execute('SELECT plan_hash FROM activation').fetchall()!=[(sha256((EVALUATION_ROOT/'attempt-plan.json').read_bytes()).hexdigest(),)]:
            raise LiveResearchError('Separate Agent 3 campaign authorization pending.')
        if c.execute('SELECT count(*) FROM reservations').fetchone()[0]:
            raise LiveResearchError('Agent 3 single attempt exhausted; no refund/retry.')


def reserve_provider(config,prompt):
    require_authorized(config)
    supplied=json.loads(prompt);data,_=read_workspace();expected=context(data,plan()['component_id'])
    age=(timestamp(utc())-timestamp(supplied['as_of'])).total_seconds()
    if input_hash(supplied)!=input_hash(expected) or not 0<=age<=60:
        raise LiveResearchError('Agent 3 provider input binding/freshness rejected.')
    debit_ledger(EVALUATION_ROOT/'campaign.sqlite3',AUTHORIZATION,config,sha256(prompt.encode()).hexdigest(),RESERVATION_MICRO_USD)


class ControlledSDKAgent3(agent3.SDKAgent3):
    reserve_mock_requests=True
    def reserve_provider(self,config,prompt):reserve_provider(config,prompt)


@dataclass(frozen=True)
class LiveSpec(agent3.Spec):
    mode: str='live'
    processing_mode: str='live'
    version: str='m6d-agent3-live-evaluation-v1'
    runtime_credential: bool=True
    context=staticmethod(context)


def run(manager,generation,*,config=None,gateway=None,**request):
    cfg=config or LiveConfig.environment();require_authorized(cfg)
    p=plan();state=manager.state()
    if (manager.root.resolve()!=EVALUATION_ROOT.resolve() or generation!=p['generation'] or
        state['active']!=p['active_database'] or state['generation']!=p['generation']):
        raise LiveResearchError('Agent 3 workspace generation/pointer changed.')
    if gateway is not None and not isinstance(gateway,ControlledSDKAgent3):
        raise LiveResearchError('Agent 3 requires the bounded shared SDK gateway.')
    return live_research.run(manager,generation,config=cfg,gateway=gateway or ControlledSDKAgent3(),spec=LiveSpec(),**request)
