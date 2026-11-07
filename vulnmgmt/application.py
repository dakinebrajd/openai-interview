"""Local assessment catalogue/settings; operational state stays in DemoManager.

The catalogue never stores a key. Managed paths come only from generated IDs.
M7's immutable, cross-assessment campaign survives reset, restore and archive.
"""
from pathlib import Path
from contextlib import contextmanager
import sqlite3,json,re
from uuid import uuid4,UUID
from .services import canonical,utc,digest
from .live_contracts import redact,LiveResearchError
from .demo_manager import DemoManager
from .runtime_binding import runtime_configuration,validate_campaign,_absolute

MODEL='gpt-5.4-mini-2026-03-17'
DEFAULTS=dict(model=MODEL,mode='Replay',max_attempts=8,allowance_micro_usd=1000000)
CAMPAIGN=Path(runtime_configuration()['canonical_ledger'])

class Application:
    def __init__(self,root,*,_test_campaign_path=None):
        self._runtime=runtime_configuration()
        if self._runtime['mode']=='existing-only':
            if _test_campaign_path is not None:raise LiveResearchError('Test campaign override is not production preview routing.')
            self.root=_absolute(str(root))
            if self.root!=Path(self._runtime['application_root']):raise LiveResearchError('Bound application root mismatch.')
            self.path=self.root/'application.sqlite3';self.campaign_path=CAMPAIGN
            self._validate_existing_application()
            validate_campaign(self.campaign_path)
            return
        self.root=Path(root).resolve();self.root.mkdir(parents=True,exist_ok=True)
        if self.root.is_symlink():raise ValueError('Application root must not be a symlink')
        self.path=self.root/'application.sqlite3'
        self.campaign_path=Path(_test_campaign_path).resolve() if _test_campaign_path else CAMPAIGN
        self.campaign_path.parent.mkdir(parents=True,exist_ok=True)
        self._initialize_application()
        self._initialize_campaign()

    def _validate_existing_application(self):
        database=_absolute(str(self.path))
        if database.parent!=self.root or not self.root.is_dir() or not database.is_file():raise LiveResearchError('Existing preview application state required; provision explicitly before startup.')
        with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as c:
            c.execute('PRAGMA query_only=ON')
            names={row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            triggers={row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
            settings=c.execute('SELECT payload FROM settings WHERE id=1').fetchone() if names=={'assessments','settings','events'} else None
            if names!={'assessments','settings','events'} or not {'events_no_update','events_no_delete'}<=triggers or not settings or c.execute('PRAGMA quick_check').fetchone()!=('ok',):
                raise LiveResearchError('Existing preview application schema/state unavailable; no automatic initialization or repair.')
            values=json.loads(settings[0])
            if set(values)!=set(DEFAULTS) or values['model']!=MODEL:raise LiveResearchError('Existing preview settings incompatible.')

    @classmethod
    def provision_state(cls,root,*,confirmed,actor,reason):
        config=runtime_configuration()
        if config['mode']!='existing-only' or not confirmed or not actor.strip() or not reason.strip() or redact(actor)!=actor or redact(reason)!=reason:
            raise LiveResearchError('Explicit named bound-preview state provisioning required.')
        target=_absolute(str(root))
        if target!=Path(config['application_root']) or target.exists():raise LiveResearchError('Provision only the exact new unused preview catalogue root.')
        validate_campaign(CAMPAIGN)
        obj=cls.__new__(cls);obj._runtime=config;obj.root=target;obj.path=target/'application.sqlite3';obj.campaign_path=CAMPAIGN
        obj._provisioning=True;target.mkdir(parents=True,exist_ok=False)
        try:
            obj._initialize_application()
            with obj.db() as c:obj.event(c,'PreviewStateProvisioned',dict(actor=actor,reason=reason,configuration_sha256=digest(config),campaign_initialized=False))
        finally:obj._provisioning=False
        return dict(root=str(target),campaign_initialized=False,configuration_sha256=digest(config))

    def _initialize_application(self):
        with self.db() as c:
            c.executescript('''CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,name TEXT NOT NULL,operation_key TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,archived INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,recorded_at TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'Immutable application audit'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'Immutable application audit'); END;''')
            c.execute('INSERT OR IGNORE INTO settings VALUES(1,?)',(canonical(DEFAULTS),))
    def _initialize_campaign(self):
        with self.campaign_db() as c:
            c.executescript('''CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,recorded_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authorization(id INTEGER PRIMARY KEY CHECK(id=1),campaign TEXT NOT NULL CHECK(campaign='m7'),max_attempts INTEGER NOT NULL CHECK(max_attempts=40),allowance_micro_usd INTEGER NOT NULL CHECK(allowance_micro_usd=10000000));
            CREATE TABLE IF NOT EXISTS reservations(id INTEGER PRIMARY KEY,session TEXT NOT NULL UNIQUE,prompt_sha256 TEXT NOT NULL,recorded_at TEXT NOT NULL,model TEXT NOT NULL,micro_usd INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS run_limits(prefix TEXT PRIMARY KEY,max_attempts INTEGER NOT NULL,allowance_micro_usd INTEGER NOT NULL);
            CREATE TRIGGER IF NOT EXISTS m7_exact_debit BEFORE INSERT ON reservations BEGIN
            SELECT CASE WHEN NEW.model!='gpt-5.4-mini-2026-03-17' OR NEW.micro_usd!=75432 OR substr(NEW.session,1,3)!='m7-'
            THEN RAISE(ABORT,'M7 exact reservation policy') END; END;
            CREATE TRIGGER IF NOT EXISTS m7_bounded BEFORE INSERT ON reservations BEGIN
            SELECT CASE WHEN (SELECT count(*) FROM reservations)>=40 OR (SELECT coalesce(sum(micro_usd),0) FROM reservations)+NEW.micro_usd>10000000 THEN RAISE(ABORT,'M7 campaign exhausted') END; END;
            CREATE TRIGGER IF NOT EXISTS m7_run_bounded BEFORE INSERT ON reservations BEGIN
            SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM run_limits WHERE substr(NEW.session,1,length(prefix))=prefix)
              OR EXISTS(SELECT 1 FROM run_limits l WHERE substr(NEW.session,1,length(l.prefix))=l.prefix AND
               ((SELECT count(*) FROM reservations r WHERE substr(r.session,1,length(l.prefix))=l.prefix)>=l.max_attempts OR
               (SELECT coalesce(sum(micro_usd),0) FROM reservations r WHERE substr(r.session,1,length(l.prefix))=l.prefix)+NEW.micro_usd>l.allowance_micro_usd))
            THEN RAISE(ABORT,'M7 run exhausted') END; END;
            CREATE TRIGGER IF NOT EXISTS limits_no_update BEFORE UPDATE ON run_limits BEGIN SELECT RAISE(ABORT,'Immutable run limits'); END;
            CREATE TRIGGER IF NOT EXISTS limits_no_delete BEFORE DELETE ON run_limits BEGIN SELECT RAISE(ABORT,'Immutable run limits'); END;
            CREATE TRIGGER IF NOT EXISTS reservations_no_update BEFORE UPDATE ON reservations BEGIN SELECT RAISE(ABORT,'Immutable reservation'); END;
            CREATE TRIGGER IF NOT EXISTS reservations_no_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'Immutable reservation'); END;
            CREATE TRIGGER IF NOT EXISTS authorization_no_update BEFORE UPDATE ON authorization BEGIN SELECT RAISE(ABORT,'Immutable authorization'); END;
            CREATE TRIGGER IF NOT EXISTS authorization_no_delete BEFORE DELETE ON authorization BEGIN SELECT RAISE(ABORT,'Immutable authorization'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'Immutable application audit'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'Immutable application audit'); END;''')
            c.execute('INSERT OR IGNORE INTO authorization VALUES(1,?,?,?)',('m7',40,10000000))
    def db(self):
        return self._connection(self.path)
    def campaign_db(self):
        return self._connection(self.campaign_path)
    @contextmanager
    def _connection(self,path):
        config=runtime_configuration()
        existing=config['mode']=='existing-only'
        if existing:path=_absolute(str(path))
        readonly_campaign=existing and config['live_enabled'] is False and Path(path)==self.campaign_path
        creating_catalogue=existing and getattr(self,'_provisioning',False) and Path(path)==self.path
        if existing and not creating_catalogue:
            if not Path(path).is_file():raise LiveResearchError('Existing-only database unavailable; creation refused.')
            if Path(path)==self.campaign_path:validate_campaign(path)
            c=sqlite3.connect(Path(path).resolve().as_uri()+('?mode=ro' if readonly_campaign else '?mode=rw'),uri=True,timeout=10)
        else:c=sqlite3.connect(path,timeout=10)
        c.row_factory=sqlite3.Row
        from .m7_budget import register_sql_functions
        register_sql_functions(c)
        try:
            if readonly_campaign:
                c.execute('PRAGMA query_only=ON')
                yield c
            else:
                c.execute('BEGIN IMMEDIATE');yield c;c.commit()
        except BaseException:c.rollback();raise
        finally:c.close()
    def event(self,c,kind,payload):
        c.execute('INSERT INTO events(kind,payload,recorded_at) VALUES(?,?,?)',(kind,canonical(redact(payload)),utc()))
    def assessments(self):
        with self.db() as c:return [dict(x) for x in c.execute('SELECT * FROM assessments ORDER BY created_at')]
    def outcomes(self):
        values=[]
        for item in self.assessments():
            root=self.root/'assessments'/item['id'];value=dict(item,status='Not started',ticket_outcomes={},prior_completed=[])
            try:
                with sqlite3.connect((root/'control.sqlite3').as_uri()+'?mode=ro',uri=True) as control:
                    active,token,generation=control.execute('SELECT active,token,generation FROM registry').fetchone()
                with sqlite3.connect((root/active).as_uri()+'?mode=ro',uri=True) as db:
                    row=db.execute("SELECT output_json FROM agent_steps WHERE role_number=0 AND step_key='orchestration-state' ORDER BY rowid DESC LIMIT 1").fetchone()
                    if row:
                        state=json.loads(row[0]);value['status']=state['status'] if state['identity']==token and state['generation']==generation else 'Restored history; new run required'
                        if state['identity']==token and state['generation']==generation:
                            from .agent0 import STAGES
                            value['pending_stage']=STAGES[state['cursor']] if state['status']!='Completed' and state['cursor']<len(STAGES) else 'Completed'
                            value['pending_reason']=state.get('reason','')
                            history=[h for h in state.get('history',[]) if h.get('stage') and h.get('recorded_at')]
                            value['last_action']=history[-1]['stage'] if history else 'Not recorded'
                            value['last_action_at']=history[-1]['recorded_at'] if history else 'Not recorded'
                    value['ticket_outcomes']={status:count for status,count in db.execute('SELECT status,count(*) FROM tickets GROUP BY status')}
                for old in root.glob('generation-*.sqlite3'):
                    if old.name==active or old.is_symlink():continue
                    with sqlite3.connect(old.as_uri()+'?mode=ro',uri=True) as db:
                        row=db.execute("SELECT output_json FROM agent_steps WHERE role_number=0 AND step_key='orchestration-state' ORDER BY rowid DESC LIMIT 1").fetchone()
                        identity,gen=db.execute('SELECT database_identity,generation FROM demo_workspaces').fetchone()
                        if row:
                            prior=json.loads(row[0])
                            if prior['status']=='Completed' and prior['identity']==identity and prior['generation']==gen:
                                value['prior_completed'].append(dict(generation=gen,run_id=prior['run_id'],file=old.name,
                                    ticket_outcomes={status:n for status,n in db.execute('SELECT status,count(*) FROM tickets GROUP BY status')}))
            except (sqlite3.Error,OSError,ValueError):value['status']='Needs review; no automatic repair'
            values.append(value)
        return values
    def manager(self,id):
        UUID(id)
        if id not in {r['id'] for r in self.assessments()}:raise ValueError('Unknown assessment')
        path=self.root/'assessments'/id
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):raise ValueError('Unsafe assessment path')
        return DemoManager.open_existing(path) if runtime_configuration()['mode']=='existing-only' else DemoManager(path)
    def create(self,name,operation_key,*,confirmed):
        if not confirmed or not name.strip() or len(name)>100 or redact(name)!=name:raise ValueError('Confirmed non-secret assessment name required')
        with self.db() as c:
            old=c.execute('SELECT * FROM assessments WHERE operation_key=?',(operation_key,)).fetchone()
            if old:
                if old['name']!=name:raise ValueError('Assessment operation reused with changed name')
                return old['id']
            id=str(uuid4());path=self.root/'assessments'/id
            DemoManager(path)
            c.execute('INSERT INTO assessments VALUES(?,?,?,?,0)',(id,name,operation_key,utc()));self.event(c,'AssessmentCreated',dict(id=id,name=name));return id
    def archive(self,id,*,confirmed):
        if not confirmed:raise ValueError('Explicit archive confirmation required; archive never deletes files')
        with self.db() as c:
            if c.execute('UPDATE assessments SET archived=1 WHERE id=?',(id,)).rowcount!=1:raise ValueError('Unknown assessment')
            self.event(c,'AssessmentArchived',dict(id=id,deleted=False))
    def settings(self):
        with self.db() as c:return json.loads(c.execute('SELECT payload FROM settings WHERE id=1').fetchone()[0])
    def configure(self,values,*,confirmed):
        if (not confirmed or set(values)!=set(DEFAULTS) or values['model']!=MODEL or values['mode'] not in ('Replay','Live AI') or
            type(values['max_attempts']) is not int or not 1<=values['max_attempts']<=40 or
            type(values['allowance_micro_usd']) is not int or not 1<=values['allowance_micro_usd']<=10000000):raise ValueError('Invalid approved model/mode/bounded settings')
        with self.db() as c:
            c.execute('UPDATE settings SET payload=? WHERE id=1',(canonical(values),));self.event(c,'ConfigurationSaved',dict(values=values,spending_authorized=False))
    def usage(self):
        with self.campaign_db() as c:
            from .m7_budget import state
            budget=state(c,verify_sources=True);rows=budget['rows']
            usage=[json.loads(x[0]) for x in c.execute("SELECT payload FROM events WHERE kind='ModelUsageRecorded'")]
        return dict(attempts=len(rows),remaining_attempts=budget['effective_limit']-len(rows),effective_attempt_limit=budget['effective_limit'],original_attempt_limit=40,
            historical_reserved_usd=None if budget['historical_micro_usd'] is None else budget['historical_micro_usd']/1e6,
            project_reserved_usd=None if budget['historical_micro_usd'] is None else (budget['historical_micro_usd']+sum(r['micro_usd'] for r in rows))/1e6,reserved_usd=sum(r['micro_usd'] for r in rows)/1e6,
            remaining_estimated_allowance_usd=(10000000-sum(r['micro_usd'] for r in rows))/1e6,
            measured_usage=usage,estimated_actual_cost_usd=sum((u.get('estimated_cost_usd') or 0) for u in usage),
            billing_unknown_attempts=len([r for r in rows if not any(u.get('session_id')==r['session'] and u.get('usage') is not None for u in usage)]))
