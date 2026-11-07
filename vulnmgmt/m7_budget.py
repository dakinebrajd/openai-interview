"""Additive M7 budget policy. Explicit migration/amendment, never a reset/refund.

The original40 authorization/rows/triggers remain intact. After those40 slots are
used, audited addenda share the SAME campaign/run/project dollar ceilings.
Historical fingerprints are a readiness boundary, not cross-database atomicity.
"""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import json,re,sqlite3
from .live_contracts import LiveResearchError,redact
from .services import canonical,digest,utc

MODEL='gpt-5.4-mini-2026-03-17'
RESERVATION=75432
CAMPAIGN_USD=10000000
PROJECT_USD=50000000
ORIGINAL=(1,'m7',40,CAMPAIGN_USD)
LEGACY_SHA='e4549db23ca1b3c116b8a8ab117c156af13d6eace950836c65971f3a2b971243'
LEGACY_NAMES=('authorization','events','reservations','run_limits','authorization_no_delete','authorization_no_update',
 'events_no_delete','events_no_update','limits_no_delete','limits_no_update','m7_bounded','m7_exact_debit',
 'm7_run_bounded','reservations_no_delete','reservations_no_update')
VERSION='m7-additive-budget-v1'

def _authority_sql(alias):
    return "json_object('actor',"+alias+".actor,'reason',"+alias+".reason,'authority_reference',"+alias+".authority_reference,'confirmed',json('true'),'user_budget_unit','USD','project_limit_micro_usd',50000000,'campaign_allowance_micro_usd',10000000)"

def _material_sql(alias):
    return "json_object('id',"+alias+".id,'previous_id',"+alias+".previous_id,'previous_limit',"+alias+".previous_limit,'new_limit',"+alias+".new_limit,'operation_key',"+alias+".operation_key,'actor',"+alias+".actor,'reason',"+alias+".reason,'authority_reference',"+alias+".authority_reference,'recorded_at',"+alias+".recorded_at,'authority_payload',json("+alias+".authority_json),'authority_sha256',"+alias+".authority_sha,'previous_amendment_sha256',"+alias+".previous_hash)"

def _event_sql(alias):
    return "json_set("+_material_sql(alias)+",'$.amendment_sha256',"+alias+".amendment_sha)"

DDL=[
"""CREATE TABLE m7_schema_extensions (
 id INTEGER PRIMARY KEY CHECK(id=1),version TEXT NOT NULL CHECK(version='m7-additive-budget-v1'),
 migration_sha TEXT NOT NULL,original_schema_sha TEXT NOT NULL CHECK(original_schema_sha='e4549db23ca1b3c116b8a8ab117c156af13d6eace950836c65971f3a2b971243'),
 project_root TEXT NOT NULL,source_manifest_json TEXT NOT NULL CHECK(json_valid(source_manifest_json) AND json_type(source_manifest_json)='array'),
 project_limit_micro_usd NOT NULL CHECK(typeof(project_limit_micro_usd)='integer' AND project_limit_micro_usd=50000000),
 actor TEXT NOT NULL CHECK(length(trim(actor))>0),reason TEXT NOT NULL CHECK(length(trim(reason))>0),
 authority_reference TEXT NOT NULL CHECK(length(trim(authority_reference))>0),recorded_at TEXT NOT NULL)""",
"""CREATE TABLE project_commitments (
 id INTEGER PRIMARY KEY,source_identity TEXT NOT NULL UNIQUE,source_sha TEXT NOT NULL,
 micro_usd NOT NULL CHECK(typeof(micro_usd)='integer' AND micro_usd>0),recorded_at TEXT NOT NULL)""",
"""CREATE TABLE attempt_amendments (
 id INTEGER PRIMARY KEY,previous_id INTEGER,previous_limit NOT NULL CHECK(typeof(previous_limit)='integer' AND previous_limit>=40),
 new_limit NOT NULL CHECK(typeof(new_limit)='integer' AND new_limit>previous_limit AND new_limit<=132),
 operation_key TEXT NOT NULL UNIQUE,actor TEXT NOT NULL CHECK(length(trim(actor))>0),reason TEXT NOT NULL CHECK(length(trim(reason))>0),
 authority_reference TEXT NOT NULL CHECK(length(trim(authority_reference))>0),recorded_at TEXT NOT NULL,
 authority_json TEXT NOT NULL CHECK(json_valid(authority_json) AND json_type(authority_json)='object'),
 authority_sha TEXT NOT NULL CHECK(length(authority_sha)=64),previous_hash TEXT CHECK(previous_hash IS NULL OR length(previous_hash)=64),
 amendment_sha TEXT NOT NULL UNIQUE CHECK(length(amendment_sha)=64))""",
"""CREATE TABLE extension_reservations (
 id INTEGER PRIMARY KEY,session TEXT NOT NULL UNIQUE,prompt_sha256 TEXT NOT NULL,recorded_at TEXT NOT NULL,
 model TEXT NOT NULL,micro_usd NOT NULL CHECK(typeof(micro_usd)='integer' AND micro_usd>0),amendment_id INTEGER NOT NULL)""",
"""CREATE VIEW m7_all_reservations AS
 SELECT id,session,prompt_sha256,recorded_at,model,micro_usd,'original' AS reservation_source FROM reservations
 UNION ALL SELECT id,session,prompt_sha256,recorded_at,model,micro_usd,'extension' AS reservation_source FROM extension_reservations""",
"""CREATE TRIGGER project_commitment_bound BEFORE INSERT ON project_commitments BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM m7_schema_extensions p,json_each(p.source_manifest_json) s
  WHERE json_extract(s.value,'$.source_identity')=NEW.source_identity AND json_extract(s.value,'$.sha256')=NEW.source_sha
  AND json_extract(s.value,'$.reserved_micro_usd')=NEW.micro_usd)
  OR (SELECT coalesce(sum(micro_usd),0) FROM project_commitments)+(SELECT coalesce(sum(micro_usd),0) FROM m7_all_reservations)+NEW.micro_usd>50000000
 THEN RAISE(ABORT,'Invalid historical project commitment') END; END""",
f"""CREATE TRIGGER attempt_amendment_chain BEFORE INSERT ON attempt_amendments BEGIN
 SELECT CASE WHEN (SELECT count(*) FROM m7_schema_extensions)!=1
 OR NEW.id!=(SELECT coalesce(max(id),0)+1 FROM attempt_amendments)
 OR NEW.previous_limit!=(SELECT coalesce(max(new_limit),40) FROM attempt_amendments)
 OR (NEW.id=1 AND NEW.previous_id IS NOT NULL)
 OR (NEW.id>1 AND (NEW.previous_id IS NULL OR NEW.previous_id!=(SELECT max(id) FROM attempt_amendments)))
 OR (SELECT count(*) FROM events WHERE kind='M7AttemptLimitAmended')!=(SELECT count(*)+1 FROM attempt_amendments)
 OR NEW.previous_hash IS NOT (SELECT amendment_sha FROM attempt_amendments ORDER BY id DESC LIMIT 1)
 OR m7_budget_digest(NEW.authority_json) IS NOT NEW.authority_sha
 OR m7_budget_digest(NEW.authority_json) IS NOT m7_budget_digest({_authority_sql('NEW')})
 OR m7_budget_digest({_material_sql('NEW')}) IS NOT NEW.amendment_sha
 OR (SELECT count(*) FROM events e WHERE e.kind='M7AttemptLimitAmended' AND m7_budget_digest(e.payload)=m7_budget_digest({_event_sql('NEW')}))!=1
 THEN RAISE(ABORT,'Invalid contiguous attempt amendment') END; END""",
]

def _guard(table):
    extra="""OR (SELECT count(*) FROM reservations)!=40
 OR NOT EXISTS(SELECT 1 FROM attempt_amendments WHERE id=NEW.amendment_id)
 OR NEW.amendment_id!=(SELECT max(id) FROM attempt_amendments)""" if table=='extension_reservations' else ''
    return f"""CREATE TRIGGER m7_aggregate_guard_{table} BEFORE INSERT ON {table} BEGIN
 SELECT CASE WHEN (SELECT count(*) FROM m7_schema_extensions)!=1
 OR (SELECT count(*) FROM events WHERE kind='M7AttemptLimitAmended')!=(SELECT count(*) FROM attempt_amendments)
 OR (SELECT count(*) FROM authorization)!=1
 OR NOT EXISTS(SELECT 1 FROM authorization WHERE id=1 AND campaign='m7' AND max_attempts=40 AND allowance_micro_usd=10000000)
 OR (SELECT count(*) FROM project_commitments)!=(SELECT count(*) FROM m7_schema_extensions p,json_each(p.source_manifest_json) s WHERE json_extract(s.value,'$.reserved_micro_usd')>0)
 OR NEW.model!='gpt-5.4-mini-2026-03-17' OR NEW.micro_usd!=75432 OR typeof(NEW.micro_usd)!='integer' OR substr(NEW.session,1,3)!='m7-'
 OR EXISTS(SELECT 1 FROM m7_all_reservations WHERE session=NEW.session)
 OR (SELECT count(*) FROM m7_all_reservations)>=(SELECT coalesce(max(new_limit),40) FROM attempt_amendments)
 OR EXISTS(SELECT 1 FROM attempt_amendments a WHERE
  m7_budget_digest(a.authority_json) IS NOT a.authority_sha
  OR m7_budget_digest(a.authority_json) IS NOT m7_budget_digest({_authority_sql('a')})
  OR m7_budget_digest({_material_sql('a')}) IS NOT a.amendment_sha
  OR (SELECT count(*) FROM events e WHERE e.kind='M7AttemptLimitAmended' AND m7_budget_digest(e.payload)=m7_budget_digest({_event_sql('a')}))!=1)
 OR (SELECT coalesce(sum(micro_usd),0) FROM m7_all_reservations)+NEW.micro_usd>10000000
 OR (SELECT coalesce(sum(micro_usd),0) FROM project_commitments)+(SELECT coalesce(sum(micro_usd),0) FROM m7_all_reservations)+NEW.micro_usd>50000000
 OR NOT EXISTS(SELECT 1 FROM run_limits WHERE substr(NEW.session,1,length(prefix))=prefix)
 OR EXISTS(SELECT 1 FROM run_limits l WHERE substr(NEW.session,1,length(l.prefix))=l.prefix AND
  (typeof(l.max_attempts)!='integer' OR l.max_attempts<=0 OR typeof(l.allowance_micro_usd)!='integer' OR l.allowance_micro_usd<=0
  OR (SELECT count(*) FROM m7_all_reservations r WHERE substr(r.session,1,length(l.prefix))=l.prefix)>=l.max_attempts
  OR (SELECT coalesce(sum(micro_usd),0) FROM m7_all_reservations r WHERE substr(r.session,1,length(l.prefix))=l.prefix)+NEW.micro_usd>l.allowance_micro_usd))
 {extra}
 THEN RAISE(ABORT,'M7 aggregate campaign/run/project policy exhausted or invalid') END; END"""

DDL.extend(_guard(t) for t in ('reservations','extension_reservations'))
for _table in ('m7_schema_extensions','project_commitments','attempt_amendments','extension_reservations'):
    for _action in ('UPDATE','DELETE'):
        DDL.append(f"CREATE TRIGGER {_table}_no_{_action.lower()} BEFORE {_action} ON {_table} BEGIN SELECT RAISE(ABORT,'Immutable budget policy/history'); END")
MIGRATION_SHA=digest(DDL)
NEW_NAMES=tuple(re.match(r'CREATE (?:TABLE|VIEW|TRIGGER) (\w+)',s).group(1) for s in DDL)

def _dict_rows(c,sql,args=()):
    cur=c.execute(sql,args);names=[d[0] for d in cur.description]
    return [dict(zip(names,r)) for r in cur]

def _legacy_schema(c):
    marks=','.join('?' for _ in LEGACY_NAMES)
    rows=c.execute(f"SELECT type,name,sql FROM sqlite_master WHERE name IN ({marks}) ORDER BY type,name",LEGACY_NAMES).fetchall()
    return sha256(json.dumps([list(r) for r in rows],separators=(',',':')).encode()).hexdigest()

def _original(c):
    if [tuple(r) for r in c.execute('SELECT * FROM authorization')]!=[ORIGINAL] or _legacy_schema(c)!=LEGACY_SHA:
        raise LiveResearchError('Original M7 authorization/schema integrity failed.')

def _new_schema(c):
    actual={name:' '.join(sql.split()).rstrip(';') for name,sql in c.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL") if name in NEW_NAMES}
    expected={name:' '.join(sql.split()).rstrip(';') for name,sql in zip(NEW_NAMES,DDL)}
    if actual!=expected:raise LiveResearchError('M7 additive policy schema missing or altered.')

def historical_inventory(project_root):
    """Recognized retired production sources; no scan of copied pytest/snapshot DBs.

    Newly discovered pre-campaign evaluation roots or changed fixed legacy ledger
    files block readiness. Other new paid paths require explicit registration and
    a canonical commitment BEFORE spending; external writers are not atomic here.
    """
    root=Path(project_root).resolve();art=root/'artifacts'
    paths=[(art/name/'campaign.sqlite3','campaign') for name in ('m6b-campaign-20261104','m6c-agent4-live-evaluation-01-20261104','m6d-agent3-live-evaluation-01-20261104')]
    known={path.resolve() for path,kind in paths}
    # Discover additional retired-production campaign roots; never silently give
    # an unregistered m6 campaign a fresh project allowance.
    paths.extend((path,'campaign') for path in sorted(art.glob('m6*/campaign.sqlite3')) if path.resolve() not in known)
    paths.extend((p,'pre_campaign') for folder in sorted(art.glob('m6a-live-evaluation*')) if folder.is_dir() for p in sorted(folder.glob('generation-*.sqlite3')))
    if len(paths)>100:raise LiveResearchError('Historical source census exceeds bounded review scope.')
    result=[]
    for path,kind in paths:
        path=path.resolve();identity=digest(dict(path=str(path).casefold(),kind=kind))
        if not path.exists():
            result.append(dict(source_identity=identity,path=str(path),kind=kind,sha256=None,reserved_micro_usd=0));continue
        before=sha256(path.read_bytes()).hexdigest()
        if Path(str(path)+'-wal').exists() and Path(str(path)+'-wal').stat().st_size:
            raise LiveResearchError('Historical source has active WAL; freeze/reconcile before spending.')
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
            db.execute('PRAGMA query_only=ON')
            if kind=='campaign':
                amounts=[r[0] for r in db.execute('SELECT micro_usd FROM reservations')]
                if any(type(n) is not int or n<=0 for n in amounts):raise LiveResearchError('Historical reservation amount invalid.')
                amount=sum(amounts)
            else:
                amount=0;seen=set()
                for row in db.execute('SELECT output_json FROM agent_steps WHERE role_number=2'):
                    try:p=json.loads(row[0])
                    except (ValueError,TypeError):continue
                    execution=p.get('execution',{}) if isinstance(p,dict) else {}
                    if execution.get('origin')!='live_model':continue
                    attempts=execution.get('provider_attempts');key=p.get('run_id')
                    if type(attempts) is not int or not 0<=attempts<=1 or not key:raise LiveResearchError('Historical provider accounting is unbounded/unknown.')
                    if key not in seen:amount+=attempts*RESERVATION;seen.add(key)
        if sha256(path.read_bytes()).hexdigest()!=before:raise LiveResearchError('Historical source changed while fingerprinting.')
        result.append(dict(source_identity=identity,path=str(path),kind=kind,sha256=before,reserved_micro_usd=amount))
    if len({r['source_identity'] for r in result})!=len(result):raise LiveResearchError('Duplicate historical source identity.')
    return sorted(result,key=lambda r:r['source_identity'])

def verify_historical(c,policy):
    expected=json.loads(policy['source_manifest_json'])
    if historical_inventory(policy['project_root'])!=expected:
        raise LiveResearchError('Historical project sources changed or unregistered spending found; reconcile before any provider request.')

def state(c,*,verify_sources=False):
    names={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view','trigger')")}
    marked=c.execute("SELECT count(*) FROM events WHERE kind='M7SchemaExtensionInstalled'").fetchone()[0]
    installed='m7_schema_extensions' in names
    if not installed:
        if marked or any(name in names for name in NEW_NAMES):raise LiveResearchError('Incomplete M7 policy installation.')
        rows=_dict_rows(c,'SELECT *,\'original\' AS reservation_source FROM reservations')
        return dict(migrated=False,rows=rows,effective_limit=40,original_limit=40,historical_micro_usd=None,project_limit_micro_usd=PROJECT_USD)
    _original(c);_new_schema(c)
    policies=_dict_rows(c,'SELECT * FROM m7_schema_extensions')
    if len(policies)!=1 or policies[0]['migration_sha']!=MIGRATION_SHA:raise LiveResearchError('M7 additive policy checksum invalid.')
    policy=policies[0];manifest=json.loads(policy['source_manifest_json'])
    expected={p['source_identity']:(p['sha256'],p['reserved_micro_usd']) for p in manifest if p['reserved_micro_usd']>0}
    commits={p['source_identity']:(p['source_sha'],p['micro_usd']) for p in _dict_rows(c,'SELECT * FROM project_commitments')}
    if expected!=commits:raise LiveResearchError('Historical project commitments incomplete or altered.')
    prior=40;previous=None;previous_hash=None
    audit=[json.loads(r[0]) for r in c.execute("SELECT payload FROM events WHERE kind='M7AttemptLimitAmended'")]
    amendments=_dict_rows(c,'SELECT * FROM attempt_amendments ORDER BY id')
    if len(audit)!=len(amendments):raise LiveResearchError('Missing or orphaned attempt amendment audit.')
    for amendment in amendments:
        if amendment['id']!=(previous or 0)+1 or amendment['previous_id']!=previous or amendment['previous_limit']!=prior or not prior<amendment['new_limit']<=132:
            raise LiveResearchError('Attempt amendment chain invalid.')
        material=_material(amendment)
        expected_authority=_authority_payload(amendment['actor'],amendment['reason'],amendment['authority_reference'])
        expected_event=dict(material,amendment_sha256=amendment['amendment_sha'])
        if (material['authority_payload']!=expected_authority or digest(expected_authority)!=amendment['authority_sha']
                or amendment['previous_hash']!=previous_hash or digest(material)!=amendment['amendment_sha']
                or sum(event==expected_event for event in audit)!=1):
            raise LiveResearchError('Attempt amendment authority/hash/audit chain invalid.')
        prior=amendment['new_limit'];previous=amendment['id'];previous_hash=amendment['amendment_sha']
    if verify_sources:verify_historical(c,policy)
    rows=_dict_rows(c,'SELECT * FROM m7_all_reservations')
    return dict(migrated=True,rows=rows,effective_limit=prior,original_limit=40,historical_micro_usd=sum(p[1] for p in commits.values()),project_limit_micro_usd=PROJECT_USD,amendment_id=previous,amendment_hash=previous_hash)

def register_sql_functions(c):
    def bounded_digest(value):
        if not isinstance(value,str) or len(value.encode('utf-8'))>20000:return None
        try:return digest(json.loads(value,parse_constant=lambda _:(_ for _ in ()).throw(ValueError())))
        except (ValueError,TypeError,RecursionError,OverflowError):return None
    c.create_function('m7_budget_digest',1,bounded_digest,deterministic=True)

def _authority_payload(actor,reason,reference):
    return dict(actor=actor,reason=reason,authority_reference=reference,confirmed=True,
        user_budget_unit='USD',project_limit_micro_usd=PROJECT_USD,campaign_allowance_micro_usd=CAMPAIGN_USD)

def _material(row):
    keys=('id','previous_id','previous_limit','new_limit','operation_key','actor','reason','authority_reference','recorded_at')
    return dict({k:row[k] for k in keys},authority_payload=json.loads(row['authority_json']),
        authority_sha256=row['authority_sha'],previous_amendment_sha256=row['previous_hash'])

@contextmanager
def _rw(path):
    try:
        c=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=rw',uri=True,timeout=10)
        try:
            register_sql_functions(c)
            c.execute('PRAGMA foreign_keys=ON');c.execute('BEGIN IMMEDIATE')
            try:yield c;c.commit()
            except BaseException:c.rollback();raise
        finally:c.close()
    except sqlite3.Error:
        raise LiveResearchError('M7 ledger unavailable or policy/reservation rejected; no provider request made.') from None

def _audit(c,kind,payload):
    c.execute('INSERT INTO events(kind,payload,recorded_at) VALUES(?,?,?)',(kind,canonical(redact(payload)),utc()))

def _authority(confirmed,actor,reason,reference):
    if not confirmed or any(not isinstance(s,str) or not s.strip() or len(s)>2000 or redact(s)!=s for s in (actor,reason,reference)):
        raise LiveResearchError('Confirmed named bounded authorization evidence required.')

def install(path,*,project_root,expected_historical_micro_usd,confirmed,actor,reason,authority_reference):
    """Explicit additive migration; call only after reviewed offline acceptance."""
    _authority(confirmed,actor,reason,authority_reference)
    if type(expected_historical_micro_usd) is not int or expected_historical_micro_usd<0:raise LiveResearchError('Integer historical commitment required.')
    root=Path(project_root).resolve();Path(path).resolve().relative_to(root)
    manifest=historical_inventory(root);amount=sum(s['reserved_micro_usd'] for s in manifest)
    if amount!=expected_historical_micro_usd:raise LiveResearchError('Historical reconciliation differs from approved carry-forward.')
    with _rw(path) as c:
        _original(c)
        current=state(c)
        if current['migrated']:
            verify_historical(c,_dict_rows(c,'SELECT * FROM m7_schema_extensions')[0]);return current
        # execute individual statements: executescript would break atomic DDL.
        for statement in DDL:c.execute(statement)
        c.execute('INSERT INTO m7_schema_extensions VALUES(1,?,?,?,?,?,?,?,?,?,?)',(VERSION,MIGRATION_SHA,LEGACY_SHA,str(root),canonical(manifest),PROJECT_USD,actor,reason,authority_reference,utc()))
        for source in manifest:
            if source['reserved_micro_usd']>0:
                c.execute('INSERT INTO project_commitments(source_identity,source_sha,micro_usd,recorded_at) VALUES(?,?,?,?)',(source['source_identity'],source['sha256'],source['reserved_micro_usd'],utc()))
        _audit(c,'M7SchemaExtensionInstalled',dict(version=VERSION,migration_sha=MIGRATION_SHA,original_schema_sha=LEGACY_SHA,actor=actor,reason=reason,authority_reference=authority_reference,authority_reference_sha256=digest(authority_reference),historical_micro_usd=amount,project_cap_micro_usd=PROJECT_USD,campaign_allowance_micro_usd=CAMPAIGN_USD))
        return state(c,verify_sources=True)

def amend(path,*,new_limit,operation_key,confirmed,actor,reason,authority_reference):
    _authority(confirmed,actor,reason,authority_reference)
    if type(new_limit) is not int or not 40<new_limit<=CAMPAIGN_USD//RESERVATION or not isinstance(operation_key,str) or not 1<=len(operation_key)<=100 or redact(operation_key)!=operation_key:
        raise LiveResearchError('Finite integer internal attempt amendment required.')
    with _rw(path) as c:
        s=state(c,verify_sources=True)
        if not s['migrated']:raise LiveResearchError('Reviewed additive policy must be installed before an amendment.')
        old=_dict_rows(c,'SELECT * FROM attempt_amendments WHERE operation_key=?',(operation_key,))
        if old:
            if any(old[0][k]!=v for k,v in dict(new_limit=new_limit,actor=actor,reason=reason,authority_reference=authority_reference).items()):raise LiveResearchError('Amendment identity reused with different authority/limits.')
            return old[0]
        if new_limit<=s['effective_limit']:raise LiveResearchError('Attempt amendment must strictly increase the finite internal ceiling.')
        id=(s['amendment_id'] or 0)+1
        authority=_authority_payload(actor,reason,authority_reference)
        row=dict(id=id,previous_id=s['amendment_id'],previous_limit=s['effective_limit'],new_limit=new_limit,
            operation_key=operation_key,actor=actor,reason=reason,authority_reference=authority_reference,recorded_at=utc(),
            authority_json=canonical(authority),authority_sha=digest(authority),previous_hash=s['amendment_hash'])
        row['amendment_sha']=digest(_material(row))
        # Both append-only evidence and row commit in one transaction. The row
        # trigger requires this exact prior audit payload and cryptographic chain.
        _audit(c,'M7AttemptLimitAmended',dict(_material(row),amendment_sha256=row['amendment_sha']))
        c.execute('INSERT INTO attempt_amendments VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',tuple(row[k] for k in (
            'id','previous_id','previous_limit','new_limit','operation_key','actor','reason','authority_reference','recorded_at',
            'authority_json','authority_sha','previous_hash','amendment_sha')))
        result=_dict_rows(c,'SELECT * FROM attempt_amendments WHERE id=?',(id,))[0]
        return result

def debit(path,config,prompt_hash,micro_usd=RESERVATION):
    if type(micro_usd) is not int or micro_usd!=RESERVATION or config.model!=MODEL or not config.session_id.startswith('m7-') or not isinstance(prompt_hash,str) or not re.fullmatch('[0-9a-f]{64}',prompt_hash):
        raise LiveResearchError('Exact M7 debit/configuration policy rejected.')
    with _rw(path) as c:
        _original(c)
        if c.execute('PRAGMA quick_check').fetchone()!=('ok',):raise LiveResearchError('Campaign ledger integrity failed.')
        s=state(c,verify_sources=True);rows=s['rows'];total=sum(r['micro_usd'] for r in rows)
        if len(rows)>=s['effective_limit'] or total+micro_usd>CAMPAIGN_USD or (s['historical_micro_usd'] is not None and s['historical_micro_usd']+total+micro_usd>PROJECT_USD):
            raise LiveResearchError('M7 aggregate campaign/project budget exhausted; no provider request made.')
        values=(config.session_id,prompt_hash,utc(),config.model,micro_usd)
        original_count=c.execute('SELECT count(*) FROM reservations').fetchone()[0]
        if original_count<40:c.execute('INSERT INTO reservations(session,prompt_sha256,recorded_at,model,micro_usd) VALUES(?,?,?,?,?)',values)
        else:
            if not s['migrated'] or not s['amendment_id']:raise LiveResearchError('No audited extension authorization exists.')
            c.execute('INSERT INTO extension_reservations(session,prompt_sha256,recorded_at,model,micro_usd,amendment_id) VALUES(?,?,?,?,?,?)',values+(s['amendment_id'],))

def snapshot(path,*,verify_sources=True):
    with sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True) as c:
        c.execute('PRAGMA query_only=ON');s=state(c,verify_sources=verify_sources)
        usage=[json.loads(r[0]) for r in c.execute("SELECT payload FROM events WHERE kind='ModelUsageRecorded'")]
    return s,usage
