from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from vulnmgmt.database import tables
from vulnmgmt.demo import run_demo
from vulnmgmt.fixture_builder import FIXTURE_DIR, build
from vulnmgmt.register import build_register, export_register
from vulnmgmt.scanners import ingest_export
from vulnmgmt.scenario import load_scenario, seed_scenario
from vulnmgmt.services import canonical


@pytest.fixture
def scenario(engine):
    manifest, files = load_scenario()
    with engine.begin() as c:
        workspace, version = seed_scenario(c, manifest, files)
    return {'manifest': manifest, 'files': files, 'workspace': workspace, 'version': version}


def count(c, name):
    return c.scalar(select(func.count()).select_from(tables[name]))


def import_file(engine, scenario, filename='tenable.json', data=None):
    format_name = 'synthetic-defender' if filename == 'defender.json' else 'synthetic-tenable'
    data = data if data is not None else scenario['files'][filename]
    with engine.begin() as c:
        return ingest_export(c, scenario['workspace'], scenario['version'], data, format_name)


def register(engine, scenario):
    with engine.begin() as c:
        return build_register(c, scenario['workspace'])


def changed_export(scenario, row_changes=None, rows=None, scanner='tenable'):
    value = json.loads(scenario['files'][scanner+'.json'])
    key = 'findings' if scanner == 'tenable' else 'value'
    original = deepcopy(value[key][0])
    value[key] = rows if rows is not None else [original | (row_changes or {})]
    return canonical(value).encode('utf-8')


def test_full_dataset_counts_and_repeated_exports(engine, scenario):
    assert not import_file(engine, scenario)['repeated']
    assert not import_file(engine, scenario, 'defender.json')['repeated']
    before = register(engine, scenario)
    with engine.begin() as c:
        audit_before = count(c, 'audit_events')
    assert import_file(engine, scenario, 'tenable_repeat.json') == {
        'batch_id': import_file(engine, scenario)['batch_id'], 'repeated': True, 'new_rows': 0}
    assert import_file(engine, scenario, 'defender.json')['repeated']
    assert register(engine, scenario) == before
    with engine.begin() as c:
        assert count(c, 'audit_events') == audit_before
    for name, expected in scenario['manifest']['expected'].items():
        assert before['summary'][name] == expected


def test_raw_rows_and_export_bytes_preserved(engine, scenario):
    for filename in ('tenable.json', 'defender.json'):
        result = import_file(engine, scenario, filename)
        source = json.loads(scenario['files'][filename])
        expected = source['findings'] if filename == 'tenable.json' else source['value']
        with engine.begin() as c:
            raw = c.execute(select(tables['raw_findings']).where(
                tables['raw_findings'].c.ingestion_batch_id == result['batch_id'])
                .order_by(tables['raw_findings'].c.row_key)).mappings().all()
            assert [json.loads(row['payload_json']) for row in raw] == expected
            batch = c.execute(select(tables['ingestion_batches']).where(
                tables['ingestion_batches'].c.id == result['batch_id'])).mappings().one()
            expected_hash = sha256(scenario['files'][filename]).hexdigest()
            assert batch['export_hash'] == expected_hash
            archive = c.execute(select(tables['evidence_sources']).where(
                tables['evidence_sources'].c.content_hash == expected_hash)).mappings().one()
            assert json.loads(archive['snapshot_json'])['original_text'].encode('utf-8') == scenario['files'][filename]


def test_cross_scanner_conflict_highest_and_timestamps(engine, scenario):
    import_file(engine, scenario)
    import_file(engine, scenario, 'defender.json')
    values = register(engine, scenario)['vulnerabilities']
    row = next(v for v in values if v['asset_key'] == 'WIN-SRV-003' and v['cve_id'] == 'CVE-2021-34527')
    assert row['severity'] == 'Critical'
    assert {o['scanner'] for o in row['observations']} == {'Tenable', 'Defender'}
    assert {o['raw_severity'] for o in row['observations']} == {'4', 'Low'}
    assert row['first_seen'] == '2026-10-18T09:00:00.000000Z'
    assert row['last_seen'] == '2026-10-20T10:00:00.000000Z'
    assert len({v['asset_id'] for v in values if v['cve_id'] == row['cve_id']}) > 1


def test_component_instances_not_merged(engine, scenario):
    import_file(engine, scenario)
    values = [v for v in register(engine, scenario)['vulnerabilities']
              if v['asset_key'] == 'WEB-001' and v['cve_id'] == 'CVE-2021-44228']
    assert len(values) == 2
    assert len({v['component_id'] for v in values}) == 2
    assert len({v['product'] for v in values}) == 1


@pytest.mark.parametrize('scanner,changes', [
    ('tenable', {'cve': ['garbage']}), ('tenable', {'cve': []}),
    ('tenable', {'last_seen': 'wrong'}), ('tenable', {'last_seen': '2026-10-18T09:00:00'}),
    ('tenable', {'plugin_id': None}), ('tenable', {'severity': None}),
    ('defender', {'cveId': 'CVE-not-valid'}), ('defender', {'findingId': 42}),
    ('defender', {'detectedAt': False}),
])
def test_malformed_row_quarantined_not_whole_import(engine, scenario, scanner, changes):
    source = json.loads(scenario['files'][scanner+'.json'])
    key = 'findings' if scanner == 'tenable' else 'value'
    valid = deepcopy(source[key][0])
    data = changed_export(scenario, rows=[valid, valid | changes], scanner=scanner)
    import_file(engine, scenario, scanner+'.json', data)
    value = register(engine, scenario)
    assert value['summary']['raw_findings'] == 2
    assert value['summary']['valid_rows'] == 1
    assert value['summary']['quarantined_rows'] == 1
    assert value['quarantine'][0]['errors']
    assert value['quarantine'][0]['payload'] == valid | changes


@pytest.mark.parametrize('bad_row', [None, 'invalid', ['not', 'object'], 13])
def test_nonobject_rows_quarantined(engine, scenario, bad_row):
    valid = json.loads(scenario['files']['tenable.json'])['findings'][0]
    import_file(engine, scenario, data=changed_export(scenario, rows=[bad_row, valid]))
    value = register(engine, scenario)
    assert value['summary']['quarantined_rows'] == 1
    assert value['summary']['normalized_records'] == 1


@pytest.mark.parametrize('changes,code', [
    ({'host_uuid': None}, 'AssetIdentityAmbiguous'),
    ({'host_uuid': 'unmapped-id'}, 'AssetIdentityAmbiguous'),
    ({'component_key': 'missing-instance'}, 'ComponentIdentityUnresolved'),
    ({'host_uuid': None, 'hostname': 'not-found.invalid'}, 'AssetIdentityUnresolved'),
])
def test_identity_quarantine_never_fuzzy_merges(engine, scenario, changes, code):
    import_file(engine, scenario, data=changed_export(scenario, changes))
    value = register(engine, scenario)
    assert value['summary']['normalized_records'] == 0
    assert value['summary']['unresolved_identity_conflicts'] == 1
    assert value['quarantine'][0]['errors'][0]['code'] == code


def test_unique_hostname_still_requires_alias(engine, scenario):
    value = json.loads(scenario['files']['tenable.json'])
    row = value['findings'][2] | {'host_uuid': None}
    import_file(engine, scenario, data=changed_export(scenario, rows=[row]))
    result = register(engine, scenario)
    error = result['quarantine'][0]['errors'][0]
    assert error['code'] == 'AssetIdentityUnresolved'
    assert len(error['candidate_asset_ids']) == 1
    assert result['summary']['normalized_records'] == 0


def test_quarantine_only_idempotency(engine, scenario):
    data = changed_export(scenario, {'cve': ['invalid']})
    first = import_file(engine, scenario, data=data)
    assert not first['repeated']
    assert import_file(engine, scenario, data=data)['repeated']
    with engine.begin() as c:
        assert c.scalar(select(tables['ingestion_batches'].c.status)) == 'Quarantined'
        assert count(c, 'raw_findings') == 1


@pytest.mark.parametrize('change', [
    {'format_version': '2'}, {'synthetic': False}, {'tenant': None},
    {'exported_at': 'invalid'}, {'findings': 'not-an-array'}, {'unexpected': True},
])
def test_invalid_envelope_atomic_rejection(engine, scenario, change):
    value = json.loads(scenario['files']['tenable.json']) | change
    with pytest.raises((ValidationError, ValueError)):
        import_file(engine, scenario, data=canonical(value).encode('utf-8'))
    with engine.begin() as c:
        assert count(c, 'ingestion_batches') == count(c, 'raw_findings') == 0


@pytest.mark.parametrize('data', [b'{', b'{"format":"synthetic-tenable","format":"other"}', b'{"x":NaN}'])
def test_invalid_json_atomic_rejection(engine, scenario, data):
    with pytest.raises(ValueError):
        import_file(engine, scenario, data=data)
    with engine.begin() as c:
        assert count(c, 'ingestion_batches') == 0


def test_exact_duplicate_occurrences_preserved(engine, scenario):
    row = json.loads(scenario['files']['tenable.json'])['findings'][0]
    import_file(engine, scenario, data=changed_export(scenario, rows=[row, row, row]))
    value = register(engine, scenario)
    assert value['summary']['raw_findings'] == value['summary']['source_to_normalized_links'] == 3
    assert value['summary']['normalized_records'] == 1
    assert value['summary']['exact_duplicate_rows'] == value['summary']['duplicates_consolidated'] == 2


def test_multicve_row_and_separate_metric_denominators(engine, scenario):
    import_file(engine, scenario, data=changed_export(scenario,
        {'cve': ['cve-2021-44228', ' CVE-2021-45046 ']}))
    value = register(engine, scenario)
    assert value['summary']['raw_findings'] == 1
    assert value['summary']['source_to_normalized_links'] == value['summary']['normalized_records'] == 2
    assert value['summary']['duplicates_consolidated'] == 0


@pytest.mark.parametrize('scanner,severity', [('tenable', 999), ('defender', 'Unrated')])
def test_unknown_rating_not_invented(engine, scenario, scanner, severity):
    import_file(engine, scenario, scanner+'.json', changed_export(scenario, {'severity': severity}, scanner=scanner))
    row = register(engine, scenario)['vulnerabilities'][0]
    assert row['max_severity_rank'] is None
    assert row['has_unknown_severity']
    assert row['observations'][0]['raw_severity'] == str(severity)


def test_changed_export_same_scan_retained(engine, scenario):
    original = changed_export(scenario)
    import_file(engine, scenario, data=original)
    import_file(engine, scenario, data=changed_export(scenario, {'scanner_text': 'Changed synthetic diagnostic'}))
    value = register(engine, scenario)
    assert value['summary']['scanner_imports'] == 2
    assert value['summary']['normalized_records'] == 1
    assert value['summary']['raw_findings'] == 2


def test_sqlite_is_authoritative_for_exports(engine, scenario, tmp_path):
    import_file(engine, scenario)
    value = register(engine, scenario)
    export_register(value, tmp_path)
    output = json.loads((tmp_path/'vulnerability_register.json').read_text(encoding='utf-8'))
    assert output == value
    markdown = (tmp_path/'vulnerability_register.md').read_text(encoding='utf-8')
    assert 'SQLite is authoritative' in markdown
    assert 'Quarantine' in markdown and 'CVE-2021-44228' in markdown
    assert 'no remediation evidence' in markdown


def test_cve_sources_and_no_remediation_claims(engine, scenario):
    import_file(engine, scenario)
    import_file(engine, scenario, 'defender.json')
    value = register(engine, scenario)
    assert value['summary']['cve_identifiers'] == 12
    assert value['summary']['unverified_cve_identifiers'] == 0
    for row in value['vulnerabilities']:
        assert row['cve_source']['identifier_status'] == 'verified_identifier'
        assert row['cve_source']['retrieved_at']
        assert row['cve_source']['url'].endswith(row['cve_id'])
        assert not row['cve_source']['remediation_claim_eligible']
        assert row['installed_version'] is None
    with engine.begin() as c:
        for name in ('remediation_actions', 'threat_intel', 'remediation_batches', 'tickets', 'communications'):
            assert count(c, name) == 0


def test_unverified_identifier_excluded_from_evidence_claims(engine, tmp_path):
    directory = tmp_path/'fixtures'
    directory.mkdir()
    sources = json.loads((FIXTURE_DIR/'cve_sources.json').read_text(encoding='utf-8'))
    source = sources['records'][0]
    source.update(verification_status='unverified', retrieved_at=None, error='Synthetic retrieval failure')
    (directory/'cve_sources.json').write_text(canonical(sources), encoding='utf-8')
    build(directory)
    manifest, files = load_scenario(directory)
    with engine.begin() as c:
        workspace, version = seed_scenario(c, manifest, files)
        ingest_export(c, workspace, version, files['tenable.json'], 'synthetic-tenable')
        value = build_register(c, workspace)
    assert value['summary']['unverified_cve_identifiers'] == 1
    affected = [r for r in value['vulnerabilities'] if r['cve_id'] == source['cve_id']]
    assert affected and all(r['cve_source']['identifier_status'] == 'unverified' for r in affected)
    assert all(not r['cve_source']['remediation_claim_eligible'] for r in affected)


def test_fixture_generation_reproducible_and_hash_guard(tmp_path):
    shutil.copy(FIXTURE_DIR/'cve_sources.json', tmp_path/'cve_sources.json')
    build(tmp_path)
    for path in FIXTURE_DIR.glob('*.json'):
        assert (tmp_path/path.name).read_bytes() == path.read_bytes()
    (tmp_path/'tenable.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='checksum'):
        load_scenario(tmp_path)


def test_demo_two_runs_and_fresh_databases_equivalent(tmp_path):
    first = run_demo(tmp_path/'a.sqlite3', tmp_path/'out-a')
    snapshot = (tmp_path/'out-a/vulnerability_register.json').read_bytes()
    repeated = run_demo(tmp_path/'a.sqlite3', tmp_path/'out-a')
    fresh = run_demo(tmp_path/'b.sqlite3', tmp_path/'out-b')
    assert first['summary'] == repeated['summary'] == fresh['summary']
    assert all(i['repeated'] for i in repeated['imports'])
    assert snapshot == (tmp_path/'out-a/vulnerability_register.json').read_bytes()
    assert snapshot == (tmp_path/'out-b/vulnerability_register.json').read_bytes()


def test_cross_workspace_alias_not_resolved(engine, scenario):
    w = str(uuid4())
    with engine.begin() as c:
        c.execute(tables['demo_workspaces'].insert().values(id=w, scenario_version_id=scenario['version'],
            database_identity=w, generation=0, synthetic_only=1, state='Ready'))
        ingest_export(c, w, scenario['version'], changed_export(scenario), 'synthetic-tenable')
        value = build_register(c, w)
    assert value['summary']['valid_rows'] == 0
    assert value['summary']['unresolved_identity_conflicts'] == 1


def test_cannot_modify_or_delete_ingestion_evidence(engine, scenario):
    import_file(engine, scenario)
    for name in ('raw_findings', 'ingestion_batches', 'evidence_sources'):
        with pytest.raises(IntegrityError), engine.begin() as c:
            c.execute(tables[name].delete())


def test_uncatalogued_cve_visible_as_unverified(engine, scenario):
    import_file(engine, scenario, data=changed_export(scenario, {'cve': ['CVE-2099-99999']}))
    value = register(engine, scenario)
    assert value['summary']['cve_identifiers'] == 13
    assert value['summary']['unverified_cve_identifiers'] == 1
    assert value['vulnerabilities'][0]['cve_source']['identifier_status'] == 'unverified'
    assert not value['vulnerabilities'][0]['cve_source']['remediation_claim_eligible']


def test_empty_valid_export_supported(engine, scenario):
    first = import_file(engine, scenario, data=changed_export(scenario, rows=[]))
    assert first['new_rows'] == 0 and not first['repeated']
    assert import_file(engine, scenario, data=changed_export(scenario, rows=[]))['repeated']
    assert register(engine, scenario)['summary']['raw_findings'] == 0


def test_exception_rolls_back_whole_export(engine, scenario, monkeypatch):
    import vulnmgmt.scanners as module
    original = module.link_observation
    counter = 0

    def fail_second(*args, **kwargs):
        nonlocal counter
        counter += 1
        if counter == 2:
            raise RuntimeError('Synthetic unexpected storage failure')
        return original(*args, **kwargs)

    monkeypatch.setattr(module, 'link_observation', fail_second)
    with pytest.raises(RuntimeError):
        import_file(engine, scenario)
    with engine.begin() as c:
        assert count(c, 'ingestion_batches') == count(c, 'raw_findings') == count(c, 'asset_cves') == 0


def test_reversed_scanner_import_order_same_domain_results(engine, scenario, tmp_path):
    import_file(engine, scenario, 'defender.json')
    import_file(engine, scenario)
    result = register(engine, scenario)
    normal = run_demo(tmp_path/'normal.sqlite3', tmp_path/'normal-out')
    expected = json.loads((tmp_path/'normal-out/vulnerability_register.json').read_text(encoding='utf-8'))
    assert result['summary'] == expected['summary']
    # Revision count is observation-count-based and independent of import order.
    assert result['vulnerabilities'] == expected['vulnerabilities']
