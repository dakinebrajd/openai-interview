from datetime import datetime, timezone
from uuid import uuid4

import pytest
import socket

_SOCKET_CONNECT = socket.socket.connect

from vulnmgmt.database import make_engine, migrate, tables
from vulnmgmt.services import canonical, digest


@pytest.fixture(autouse=True)
def prohibit_network(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        raise AssertionError('Network access is forbidden in foundation tests')

    monkeypatch.setattr(socket, 'create_connection', denied)
    monkeypatch.setattr(socket.socket, 'connect', denied)


@pytest.fixture
def streamlit_loopback(monkeypatch):
    """Windows asyncio uses a loopback socketpair for local inter-thread wakeups.

    Only UI tests opt in. External destinations and create_connection stay blocked.
    """
    def local_connect(sock, address):
        if not isinstance(address, tuple) or address[0] not in ('127.0.0.1', '::1'):
            raise AssertionError('External network access is forbidden in UI tests')
        return _SOCKET_CONNECT(sock, address)
    monkeypatch.setattr(socket.socket, 'connect', local_connect)


@pytest.fixture
def engine(tmp_path):
    value = make_engine(tmp_path / 'test.sqlite3')
    migrate(value)
    yield value
    value.dispose()


@pytest.fixture
def seeded(engine):
    ids = {name: str(uuid4()) for name in ('scenario', 'version', 'workspace', 'owner', 'asset', 'component')}
    with engine.begin() as c:
        c.execute(tables['demo_scenarios'].insert().values(id=ids['scenario'], name='Synthetic test only'))
        c.execute(tables['scenario_versions'].insert().values(
            id=ids['version'], scenario_id=ids['scenario'], version=1, manifest_json='{}',
            manifest_hash=digest({}), fixed_clock='2099-01-01T00:00:00.000000Z', seed=1))
        c.execute(tables['demo_workspaces'].insert().values(
            id=ids['workspace'], scenario_version_id=ids['version'], database_identity=str(uuid4()),
            generation=0, synthetic_only=1, state='Ready'))
        c.execute(tables['owners'].insert().values(
            id=ids['owner'], workspace_id=ids['workspace'], display_name='Test owner',
            synthetic_email='test@example.invalid'))
        c.execute(tables['assets'].insert().values(
            id=ids['asset'], workspace_id=ids['workspace'], asset_key='test-asset',
            hostname='host.invalid', criticality='High'))
        c.execute(tables['asset_components'].insert().values(
            id=ids['component'], workspace_id=ids['workspace'], asset_id=ids['asset'],
            component_key='app-instance-1', product='Synthetic product', installed_version='1', location='/app'))
        for scanner in ('Tenable', 'Defender'):
            c.execute(tables['asset_aliases'].insert().values(
                id=str(uuid4()), workspace_id=ids['workspace'], asset_id=ids['asset'],
                scanner=scanner, scanner_tenant='synthetic', native_asset_id='scanner-asset'))
    return ids


@pytest.fixture
def finding_data(seeded):
    # Deliberately fictional future ID: tests assert no real CVE facts.
    return dict(workspace_id=seeded['workspace'], scenario_version_id=seeded['version'],
                correlation_id=str(uuid4()), mode='replay', scanner='Tenable', scanner_tenant='synthetic',
                native_scan_id='scan-1', native_asset_id='scanner-asset', native_finding_id='plugin-1',
                asset_id=seeded['asset'], component_id=seeded['component'],
                observed_at='2099-01-01T00:00:00Z', raw_severity='High', mapped_severity_rank=3,
                mapping_version='test-1', cve_ids=['CVE-2099-99999'], payload={'synthetic': True})
