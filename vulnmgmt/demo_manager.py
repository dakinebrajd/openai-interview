"""Agent 9: isolated, append-only demo generations; never reset an arbitrary database.

The control SQLite database owns the active pointer and immutable event/snapshot
metadata. Each generation is a complete operational SQLite database. Old files
are retained, not overwritten. No model, network, shell or deletion interfaces.
"""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from sqlalchemy import select
from .database import make_engine, migrate, tables
from .scenario import load_scenario, seed_scenario
from .services import audit, canonical

CLOCK = '2026-11-03T23:54:00Z'


def actual_time():
    return datetime.now(timezone.utc).isoformat()


class DemoManager:
    """Trusted-local control plane, with compare-and-swap generation guards."""

    @classmethod
    def open_existing(cls,root):
        """Validated noninitializing open; creation remains a separate explicit action."""
        from .runtime_binding import _absolute
        location=_absolute(str(root));control=_absolute(str(location/'control.sqlite3'))
        if not location.is_dir() or not control.is_file():raise ValueError('Existing demo state required; no startup initialization.')
        with sqlite3.connect(control.as_uri()+'?mode=ro',uri=True) as c:
            c.row_factory=sqlite3.Row;c.execute('PRAGMA query_only=ON')
            names={row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if names!={'registry','events','snapshots','leases'} or c.execute('PRAGMA user_version').fetchone()[0]!=1:raise ValueError('Existing demo control schema incompatible.')
            state=c.execute('SELECT * FROM registry WHERE id=1').fetchone()
            if state is None or Path(state['root']).resolve()!=location:raise ValueError('Existing demo root binding mismatch.')
            state=dict(state)
        obj=cls.__new__(cls);obj.root=location;obj.control=control
        name=state['active']
        if not isinstance(name,str) or Path(name).name!=name or Path(name).is_absolute():raise ValueError('Unsafe existing operational database name.')
        checked=_absolute(str(location/name))
        path=obj._path(name)
        if checked!=path or checked.parent!=location:raise ValueError('Existing operational path binding mismatch.')
        if not path.is_file():raise ValueError('Existing operational database unavailable.')
        with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True) as c:
            c.row_factory=sqlite3.Row;c.execute('PRAGMA query_only=ON')
            rows=c.execute('SELECT * FROM demo_workspaces').fetchall()
            if len(rows)!=1 or rows[0]['generation']!=state['generation'] or rows[0]['database_identity']!=state['token'] or rows[0]['state']!='Ready' or c.execute('PRAGMA quick_check').fetchone()[0]!='ok':
                raise ValueError('Existing operational identity/state incompatible.')
        return obj

    def __init__(self, root):
        self._initializing=True
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.control = self.root / 'control.sqlite3'
        with self._control() as c:
            existing = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if existing and existing != {'registry', 'events', 'snapshots', 'leases'}:
                raise ValueError('Refusing to adopt an unrelated control database')
            control_version=c.execute('PRAGMA user_version').fetchone()[0]
            if control_version not in (0, 1):
                raise ValueError('Unsupported demo control schema version')
            c.executescript('''
            CREATE TABLE IF NOT EXISTS registry(
              id INTEGER PRIMARY KEY CHECK(id=1), root TEXT NOT NULL,
              token TEXT NOT NULL, active TEXT, generation INTEGER NOT NULL,
              clock TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY, generation INTEGER NOT NULL, kind TEXT NOT NULL,
              payload TEXT NOT NULL CHECK(json_valid(payload)), recorded_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS snapshots(
              id TEXT PRIMARY KEY, name TEXT NOT NULL, file TEXT NOT NULL UNIQUE,
              sha256 TEXT NOT NULL, clock TEXT NOT NULL, generation INTEGER NOT NULL,
              created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS leases(
              id TEXT PRIMARY KEY, generation INTEGER NOT NULL, stage TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('Running','Succeeded','Failed')),
              started_at TEXT NOT NULL, ended_at TEXT, result TEXT, error TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_lease ON leases(status) WHERE status='Running';
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
              BEGIN SELECT RAISE(ABORT,'immutable manager audit'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
              BEGIN SELECT RAISE(ABORT,'immutable manager audit'); END;
            CREATE TRIGGER IF NOT EXISTS snapshots_no_update BEFORE UPDATE ON snapshots
              BEGIN SELECT RAISE(ABORT,'immutable snapshot'); END;
            CREATE TRIGGER IF NOT EXISTS snapshots_no_delete BEFORE DELETE ON snapshots
              BEGIN SELECT RAISE(ABORT,'immutable snapshot'); END;
            ''')
            # Reassigning the same version still changes SQLite's file-header
            # counters. Opening an initialized manager must preserve its bytes.
            if control_version==0:
                c.execute('PRAGMA user_version=1')
            row = c.execute('SELECT * FROM registry').fetchone()
            if row is None:
                # Never adopt unknown operational files as a managed sandbox.
                if any(self.root.glob('generation-*.sqlite3')):
                    raise ValueError('Unregistered generation files; choose a new demo directory')
                c.execute('INSERT INTO registry VALUES(1,?,?,NULL,0,?)',
                          (str(self.root), str(uuid4()), CLOCK))
            elif row['root'] != str(self.root):
                raise ValueError('Demo registry belongs to a different directory')
        if self.state()['active'] is None:
            self.reset(0, 'RESET DEMO')

        self._initializing=False

    @contextmanager
    def _control(self):
        from .runtime_binding import runtime_configuration,_absolute
        existing=runtime_configuration()['mode']=='existing-only' and not getattr(self,'_initializing',False)
        control=_absolute(str(self.control)) if existing else self.control
        if existing and not control.is_file():raise ValueError('Existing-only demo control unavailable; creation refused.')
        c = (sqlite3.connect(control.as_uri()+'?mode=rw',uri=True,timeout=10) if existing else sqlite3.connect(control,timeout=10))
        c.row_factory = sqlite3.Row
        try:
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('BEGIN IMMEDIATE')
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def _path(self, name):
        from .runtime_binding import runtime_configuration,_absolute
        p = (_absolute(str(self.root/name)) if runtime_configuration()['mode']=='existing-only' else (self.root/name).resolve())
        if p.parent != self.root or p.suffix != '.sqlite3' or p.is_symlink():
            raise ValueError('Unsafe managed database path')
        return p

    def state(self):
        with self._control() as c:
            return dict(c.execute('SELECT * FROM registry WHERE id=1').fetchone())

    def history(self):
        with self._control() as c:
            return {name: [dict(r) for r in c.execute(f'SELECT * FROM {name} ORDER BY rowid')]
                    for name in ('events', 'snapshots', 'leases')}

    def _event(self, c, generation, kind, payload):
        c.execute('INSERT INTO events(generation,kind,payload,recorded_at) VALUES(?,?,?,?)',
                  (generation, kind, canonical(payload), actual_time()))

    def _guard(self, c, expected, *, idle=True):
        state = dict(c.execute('SELECT * FROM registry WHERE id=1').fetchone())
        if state['generation'] != expected:
            raise ValueError('Stale demo generation; refresh before changing state')
        if idle and c.execute("SELECT 1 FROM leases WHERE status='Running'").fetchone():
            raise ValueError('Workflow execution is active; reset/snapshot/action blocked')
        return state

    def _workspace(self, path):
        # Validate before invoking the migration verifier: never upgrade a saved
        # snapshot/archive in place. A future schema needs an explicit new-copy upgrade.
        with closing(sqlite3.connect(path)) as db:
            version = db.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]
            if version != 3:
                raise ValueError('Unsupported snapshot/operational schema version; no in-place upgrade')
        engine = make_engine(path)
        try:
            migrate(engine)
            with engine.begin() as c:
                rows = list(c.execute(select(tables['demo_workspaces'])).mappings())
                if len(rows) != 1 or not rows[0]['synthetic_only'] or rows[0]['state'] != 'Ready':
                    raise ValueError('Reset requires exactly one Ready synthetic demo workspace')
                if c.scalar(select(tables['runs'].c.id).where(tables['runs'].c.status.in_(['Running', 'Queued']))):
                    raise ValueError('Operational workflow is active')
                return dict(rows[0])
        finally:
            engine.dispose()

    @staticmethod
    def _backup(source, target):
        if target.exists():
            raise ValueError('Refusing to overwrite a database generation or snapshot')
        with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(target)) as dst:
            src.backup(dst)

    def snapshot(self, expected, name, operation_key=None):
        if not name.strip():
            raise ValueError('Snapshot name required')
        with self._control() as c:
            s = self._guard(c, expected)
            if operation_key:
                for event in c.execute("SELECT payload FROM events WHERE generation=? AND kind='SnapshotSaved'", (expected,)):
                    payload = json.loads(event['payload'])
                    if payload.get('operation_key') == operation_key:
                        if payload.get('name') != name:
                            raise ValueError('Snapshot operation key reused with different name')
                        return payload['snapshot_id']
            source = self._path(s['active'])
            self._workspace(source)
            id = str(uuid4())
            target = self._path('snapshot-' + id + '.sqlite3')
            self._backup(source, target)
            checksum = sha256(target.read_bytes()).hexdigest()
            c.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?,?)',
                      (id, name, target.name, checksum, s['clock'], expected, actual_time()))
            self._event(c, expected, 'SnapshotSaved', {'snapshot_id': id, 'sha256': checksum,
                         'operation_key': operation_key, 'name': name})
            return id

    def reset(self, expected, confirmation, snapshot_id=None):
        if confirmation != 'RESET DEMO':
            raise ValueError('Type RESET DEMO to confirm the isolated reset')
        with self._control() as c:
            s = self._guard(c, expected)
            if s['active']:
                self._workspace(self._path(s['active']))
            new_generation = expected + 1
            target = self._path('generation-' + str(new_generation) + '-' + str(uuid4()) + '.sqlite3')
            clock = CLOCK
            expected_summary = None
            if snapshot_id:
                snap = c.execute('SELECT * FROM snapshots WHERE id=?', (snapshot_id,)).fetchone()
                if snap is None:
                    raise ValueError('Snapshot does not belong to this demo registry')
                source = self._path(snap['file'])
                if sha256(source.read_bytes()).hexdigest() != snap['sha256']:
                    raise ValueError('Snapshot integrity check failed')
                self._workspace(source)
                from .register import build_register
                check_engine = make_engine(source)
                try:
                    with check_engine.begin() as check:
                        sw = check.execute(select(tables['demo_workspaces'])).mappings().one()
                        expected_summary = build_register(check, sw['id'])['summary']
                finally:
                    check_engine.dispose()
                self._backup(source, target)
                clock = snap['clock']
            else:
                engine = make_engine(target)
                try:
                    migrate(engine)
                    manifest, files = load_scenario()
                    with engine.begin() as db:
                        seed_scenario(db, manifest, files)
                finally:
                    engine.dispose()
            engine = make_engine(target)
            try:
                with engine.begin() as db:
                    w = db.execute(select(tables['demo_workspaces'])).mappings().one()
                    db.execute(tables['demo_workspaces'].update().where(
                        tables['demo_workspaces'].c.id == w['id']).values(
                            generation=new_generation, database_identity=s['token']))
                    # Historical approvals remain immutable, but cannot authorize restored actions.
                    for name in ('proposals', 'lifecycle_reviews'):
                        t = tables[name]
                        db.execute(t.update().where(t.c.status.in_(['Draft', 'Awaiting Approval', 'Approved'])).values(
                            **({'status': 'Invalidated', 'revision': t.c.revision + 1}
                               if name == 'lifecycle_reviews' else {'status': 'Invalidated'})))
                    audit(db, w['id'], 'DemoGenerationCreated', 'demo_workspaces', w['id'],
                          new_generation, {'previous_file': s['active'], 'snapshot_id': snapshot_id,
                                           'restored_history': bool(snapshot_id)})
                    from .register import build_register
                    verified_summary = build_register(db, w['id'])['summary']
                    if expected_summary is not None and verified_summary != expected_summary:
                        raise ValueError('Restored snapshot record counts do not match the source')
                    if expected_summary is None and (verified_summary['assets'] != manifest['expected']['assets']
                            or verified_summary['raw_findings'] or verified_summary['normalized_records']):
                        raise ValueError('Fresh inventory baseline verification failed')
            finally:
                engine.dispose()
            c.execute('UPDATE registry SET active=?,generation=?,clock=? WHERE id=1',
                      (target.name, new_generation, clock))
            self._event(c, new_generation, 'SnapshotRestored' if snapshot_id else 'DemoReset',
                        {'old_file': s['active'], 'new_file': target.name, 'snapshot_id': snapshot_id,
                         'verified_summary': verified_summary,
                         'active_scenario': 'Snapshot: '+snap['name'] if snapshot_id else 'Fresh inventory'})
            return target

    @contextmanager
    def execution(self, expected, stage):
        id = str(uuid4())
        with self._control() as c:
            s = self._guard(c, expected)
            path = self._path(s['active'])
            workspace = self._workspace(path)
            if workspace['database_identity'] != s['token'] or workspace['generation'] != expected:
                raise ValueError('Workspace identity/generation does not match the demo registry')
            c.execute("INSERT INTO leases VALUES(?,?,?,'Running',?,NULL,NULL,NULL)",
                      (id, expected, stage, actual_time()))
        output = {}
        try:
            yield path, workspace, s['clock'], output
        except BaseException as exc:
            with self._control() as c:
                c.execute("UPDATE leases SET status='Failed',ended_at=?,error=? WHERE id=?",
                          (actual_time(), str(exc), id))
                self._event(c, expected, 'WorkflowFailed', {'stage': stage, 'error': str(exc)})
            raise
        else:
            with self._control() as c:
                c.execute("UPDATE leases SET status='Succeeded',ended_at=?,result=? WHERE id=?",
                          (actual_time(), canonical(output), id))
                self._event(c, expected, 'WorkflowSucceeded', {'stage': stage, 'result': output})

    def set_clock(self, expected, clock):
        from .enrichment_evidence import timestamp
        with self._control() as c:
            s = self._guard(c, expected)
            if timestamp(clock) < timestamp(s['clock']):
                raise ValueError('Demo clock cannot move backward within a generation')
            c.execute('UPDATE registry SET clock=? WHERE id=1', (clock,))
            self._event(c, expected, 'SyntheticClockAdvanced', {'from': s['clock'], 'to': clock})

    def advance(self, expected, seconds=60):
        from datetime import timedelta
        from .enrichment_evidence import timestamp
        self.set_clock(expected, (timestamp(self.state()['clock']) + timedelta(seconds=seconds)).isoformat())
