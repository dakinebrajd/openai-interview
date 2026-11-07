"""Read-only local interview preflight. Never contacts a model or public endpoint."""
import importlib.metadata
import importlib
import struct
import sys
from pathlib import Path
from .database import make_engine
from .scenario import load_scenario
from .enrichment_evidence import load_bundle
from .dashboard_service import view


def readiness(manager):
    checks = []
    def check(name, fn):
        try:
            detail = fn()
            checks.append({'Check': name, 'Status': 'Ready', 'Detail': str(detail)})
        except Exception as exc:
            checks.append({'Check': name, 'Status': 'Blocked', 'Detail': str(exc)})
    def runtime():
        if sys.version_info[:2] != (3, 13) or struct.calcsize('P') != 8:
            raise ValueError('Use approved standard Python 3.13 x64 virtual environment')
        return sys.version.split()[0]+' x64'
    def fixtures():
        manifest, files = load_scenario()
        load_bundle()
        return f"Scanner manifest v{manifest['version']}, {len(files)} checked inputs; evidence bundle hashes verified"
    def database():
        state = manager.state()
        workspace = manager._workspace(manager._path(state['active']))
        if workspace['database_identity'] != state['token'] or workspace['generation'] != state['generation']:
            raise ValueError('Registry and workspace identity/generation mismatch')
        engine = make_engine(manager._path(state['active']))
        try:
            with engine.begin() as c:
                if list(c.exec_driver_sql('PRAGMA foreign_key_check')):
                    raise ValueError('Foreign-key integrity check failed')
            return 'Operational schema, synthetic identity, integrity and access verified'
        finally:
            engine.dispose()
    def workflow():
        if any(l['status'] == 'Running' for l in manager.history()['leases']):
            raise ValueError('Workflow active; wait before starting or resetting')
        d = view(manager)
        return f"Generation {d['manager']['generation']}; {len(d['findings'])} findings; no live AI enabled"
    check('Python runtime', runtime)
    def dependencies():
        for module in ('streamlit', 'altair', 'pandas', 'sqlalchemy', 'pydantic', 'agents'):
            importlib.import_module(module)
        rows = (Path(__file__).resolve().parent.parent/'requirements.lock').read_text(encoding='utf-8').splitlines()
        pins = [r.split(' --hash=')[0] for r in rows if r and not r.startswith('#')]
        for pin in pins:
            name, expected = pin.split('==')
            if importlib.metadata.version(name) != expected:
                raise ValueError('Installed dependency differs from lock: '+name)
        return f'{len(pins)} pinned distributions match; required UI/domain/SDK modules import successfully'
    check('Local dependencies', dependencies)
    check('Seed and evidence fixtures', fixtures)
    check('Database access and integrity', database)
    check('Workflow readiness', workflow)
    return checks
