import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError

from vulnmgmt.contracts import (NormalizedVulnerability, RemediationBatch, RemediationEvidence,
                                ScannerFinding, StatusTransition, Ticket)
from vulnmgmt.database import make_engine, migrate, tables
from vulnmgmt.services import (RevisionConflict, canonical, digest, ingest_findings,
                               transition_finding)


def finding(data, **changes):
    return ScannerFinding.model_validate_json(json.dumps(data | changes))


def count(c, name):
    return c.scalar(select(func.count()).select_from(tables[name]))


def import_one(engine, data, **changes):
    with engine.begin() as c:
        batch = ingest_findings(c, [finding(data, **changes)])
        normalized = c.execute(select(tables['asset_cves'])).mappings().first()
    return batch, dict(normalized)


def transition(data, normalized, to_status, **changes):
    return StatusTransition.model_validate_json(json.dumps({
        'workspace_id': data['workspace_id'], 'scenario_version_id': data['scenario_version_id'],
        'correlation_id': str(uuid4()), 'mode': 'replay', 'asset_cve_id': normalized['id'],
        'expected_revision': normalized['revision'], 'from_status': normalized['status'],
        'to_status': to_status, 'actor_id': 'synthetic-analyst', 'reason': 'Synthetic test',
        'occurred_at': '2099-01-02T00:00:00Z', **changes}))


def test_migration_creation_repeat_and_foreign_keys(engine):
    migrate(engine)
    migrate(engine)
    with engine.begin() as c:
        assert c.exec_driver_sql('PRAGMA foreign_keys').scalar() == 1
        assert not c.exec_driver_sql('PRAGMA foreign_key_check').all()
        assert c.exec_driver_sql('SELECT count(*) FROM schema_migrations').scalar() == 3
    assert set(inspect(engine).get_table_names()) == set(tables) | {'schema_migrations'}


def test_migration_unknown_checksum_rejected(engine):
    with engine.begin() as c:
        c.exec_driver_sql("UPDATE schema_migrations SET checksum='modified'")
    with pytest.raises(RuntimeError, match='checksum'):
        migrate(engine)


def test_migration_nonempty_database_refused(tmp_path):
    e = make_engine(tmp_path / 'unknown.db')
    try:
        with e.begin() as c:
            c.exec_driver_sql('CREATE TABLE unrelated (id INTEGER)')
        with pytest.raises(RuntimeError, match='nonempty'):
            migrate(e)
        assert inspect(e).get_table_names() == ['unrelated']
    finally:
        e.dispose()


def test_migration_rollback_on_ddl_failure(tmp_path, monkeypatch):
    from vulnmgmt.migrations import v0001
    e = make_engine(tmp_path / 'failed.db')
    original = v0001.apply

    def fail(c):
        original(c)
        raise RuntimeError('deliberate test failure')

    monkeypatch.setattr(v0001, 'apply', fail)
    try:
        with pytest.raises(RuntimeError, match='deliberate'):
            migrate(e)
        assert inspect(e).get_table_names() == []
        monkeypatch.setattr(v0001, 'apply', original)
        migrate(e)
        assert 'assets' in inspect(e).get_table_names()
    finally:
        e.dispose()


def test_rerun_refuses_missing_table(engine):
    with engine.begin() as c:
        c.exec_driver_sql('DROP TABLE reset_events')
    with pytest.raises(RuntimeError, match='incomplete'):
        migrate(engine)


def test_duplicate_import_no_changes(engine, finding_data):
    batch, _ = import_one(engine, finding_data)
    with engine.begin() as c:
        before = count(c, 'audit_events')
        assert ingest_findings(c, [finding(finding_data, correlation_id=str(uuid4()))]) == batch
        assert count(c, 'audit_events') == before
        assert count(c, 'ingestion_batches') == count(c, 'raw_findings') == count(c, 'asset_cves') == 1


def test_duplicate_rows_counted(engine, finding_data):
    f = finding(finding_data)
    with engine.begin() as c:
        ingest_findings(c, [f, f])
        assert count(c, 'raw_findings') == 1
        assert c.scalar(select(tables['ingestion_batches'].c.duplicate_rows)) == 1


def test_import_row_order_does_not_change_identity(engine, finding_data):
    a = finding(finding_data)
    b = finding(finding_data, native_finding_id='plugin-2')
    with engine.begin() as c:
        assert ingest_findings(c, [a, b]) == ingest_findings(c, [b, a])
        assert count(c, 'ingestion_batches') == 1


def test_changed_export_retained(engine, finding_data):
    import_one(engine, finding_data)
    import_one(engine, finding_data, payload={'synthetic': True, 'changed': True})
    with engine.begin() as c:
        assert count(c, 'ingestion_batches') == 2
        assert count(c, 'raw_findings') == 2
        assert count(c, 'asset_cves') == 1


def test_same_asset_cve_multiple_scanners_preserves_highest(engine, finding_data):
    import_one(engine, finding_data, raw_severity='Critical', mapped_severity_rank=4)
    import_one(engine, finding_data, scanner='Defender', raw_severity='Medium', mapped_severity_rank=2)
    with engine.begin() as c:
        assert count(c, 'asset_cves') == 1
        assert count(c, 'finding_links') == 2
        assert c.scalar(select(tables['asset_cves'].c.max_severity_rank)) == 4
        assert set(c.scalars(select(tables['raw_findings'].c.raw_severity))) == {'Critical', 'Medium'}
        assert set(c.scalars(select(tables['ingestion_batches'].c.scanner))) == {'Tenable', 'Defender'}


def test_unknown_severity_not_zero(engine, finding_data):
    import_one(engine, finding_data, mapped_severity_rank=None, raw_severity='Unclassified')
    with engine.begin() as c:
        row = c.execute(select(tables['asset_cves'])).mappings().one()
        assert row['max_severity_rank'] is None and row['has_unknown_severity'] == 1
    import_one(engine, finding_data)
    with engine.begin() as c:
        row = c.execute(select(tables['asset_cves'])).mappings().one()
        assert row['max_severity_rank'] == 3 and row['has_unknown_severity'] == 1


def test_multi_cve_observation(engine, finding_data):
    import_one(engine, finding_data, cve_ids=['CVE-2099-99999', 'CVE-2099-99998'])
    with engine.begin() as c:
        assert count(c, 'raw_findings') == 1
        assert count(c, 'asset_cves') == count(c, 'finding_cves') == count(c, 'finding_links') == 2


def second_asset(c, ids):
    asset, component = str(uuid4()), str(uuid4())
    c.execute(tables['assets'].insert().values(id=asset, workspace_id=ids['workspace'],
        asset_key=asset, hostname='host.invalid', criticality='Low'))
    c.execute(tables['asset_components'].insert().values(id=component, workspace_id=ids['workspace'],
        asset_id=asset, component_key='app-instance-1', product='Synthetic product', location='/app'))
    c.execute(tables['asset_aliases'].insert().values(id=str(uuid4()), workspace_id=ids['workspace'],
        asset_id=asset, scanner='Tenable', scanner_tenant='synthetic', native_asset_id=asset))
    return asset, component


def test_same_cve_multiple_assets_not_merged(engine, seeded, finding_data):
    import_one(engine, finding_data)
    with engine.begin() as c:
        asset, component = second_asset(c, seeded)
    import_one(engine, finding_data, asset_id=asset, component_id=component, native_asset_id=asset)
    with engine.begin() as c:
        assert count(c, 'asset_cves') == 2
        assert count(c, 'cves') == 1


def test_component_identity_separates_instances(engine, seeded, finding_data):
    import_one(engine, finding_data)
    component = str(uuid4())
    with engine.begin() as c:
        c.execute(tables['asset_components'].insert().values(
            id=component, workspace_id=seeded['workspace'], asset_id=seeded['asset'],
            component_key='second-install', product='Synthetic product', location='/other'))
    import_one(engine, finding_data, component_id=component)
    with engine.begin() as c:
        assert count(c, 'asset_cves') == 2


def test_duplicate_component_identity_rejected(engine, seeded):
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(tables['asset_components'].insert().values(
            id=str(uuid4()), workspace_id=seeded['workspace'], asset_id=seeded['asset'],
            component_key='app-instance-1', product='Other name', location='/different'))


def test_component_asset_mismatch_atomic(engine, seeded, finding_data):
    with engine.begin() as c:
        asset, component = second_asset(c, seeded)
    with pytest.raises(ValueError, match='another asset'), engine.begin() as c:
        ingest_findings(c, [finding(finding_data, component_id=component)])
    with engine.begin() as c:
        assert count(c, 'ingestion_batches') == 0


def test_unconfirmed_alias_rejected(engine, finding_data):
    with pytest.raises(ValueError, match='identity'), engine.begin() as c:
        ingest_findings(c, [finding(finding_data, native_asset_id='unknown')])


def other_workspace(c, ids):
    w = str(uuid4())
    c.execute(tables['demo_workspaces'].insert().values(id=w, scenario_version_id=ids['version'],
        database_identity=w, generation=0, synthetic_only=1, state='Ready'))
    return w


@pytest.mark.parametrize('target', ['asset_components', 'asset_owners', 'asset_aliases'])
def test_cross_workspace_reference_rejected(engine, seeded, target):
    with engine.begin() as c:
        w = other_workspace(c, seeded)
    values = {'asset_components': dict(component_key='x', product='x', location='x'),
              'asset_owners': dict(owner_id=seeded['owner'], role='primary', valid_from='2099-01-01Z'),
              'asset_aliases': dict(scanner='Tenable', scanner_tenant='x', native_asset_id='x')}[target]
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(tables[target].insert().values(id=str(uuid4()), workspace_id=w,
                                               asset_id=seeded['asset'], **values))


def test_contract_workspace_scenario_mismatch(engine, finding_data):
    with pytest.raises(ValueError, match='scenario'), engine.begin() as c:
        ingest_findings(c, [finding(finding_data, scenario_version_id=str(uuid4()))])


def test_db_component_belongs_to_asset(engine, seeded, finding_data):
    _, n = import_one(engine, finding_data)
    with engine.begin() as c:
        asset, component = second_asset(c, seeded)
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(tables['asset_cves'].insert().values(**(n | {'id': str(uuid4()), 'component_id': component})))


def test_pending_claim_then_revision_conflict(engine, finding_data):
    _, n = import_one(engine, finding_data)
    request = transition(finding_data, n, 'Pending Verification')
    with engine.begin() as c:
        assert transition_finding(c, request) == 1
    with pytest.raises(RevisionConflict), engine.begin() as c:
        transition_finding(c, request)
    with engine.begin() as c:
        assert count(c, 'status_history') == 1
        assert c.scalar(select(tables['asset_cves'].c.status)) == 'Pending Verification'


def test_observation_update_invalidates_stale_revision(engine, finding_data):
    _, n = import_one(engine, finding_data)
    import_one(engine, finding_data, scanner='Defender')
    with pytest.raises(RevisionConflict), engine.begin() as c:
        transition_finding(c, transition(finding_data, n, 'Pending Verification'))


@pytest.mark.parametrize('before,after', [
    ('Open', 'Verified Remediated'), ('In Remediation', 'Open'),
    ('Verified Remediated', 'Pending Verification'), ('Pending Verification', 'In Remediation'),
    ('Open', 'Open'),
])
def test_invalid_transition_contract(finding_data, before, after):
    with pytest.raises(ValidationError):
        transition(finding_data, {'id': str(uuid4()), 'revision': 0, 'status': before}, after,
                   verification_event_id=str(uuid4()))


def test_claim_cannot_close_without_evidence(finding_data):
    with pytest.raises(ValidationError, match='verification'):
        transition(finding_data, {'id': str(uuid4()), 'revision': 1, 'status': 'Pending Verification'},
                   'Verified Remediated')


def add_verification(c, data, n, batch, *, scan_status='Success', result='Pass',
                     when='2099-01-03T00:00:00.000000Z', covered=True):
    assessment, verification = str(uuid4()), str(uuid4())
    c.execute(tables['scan_assessments'].insert().values(
        id=assessment, workspace_id=data['workspace_id'], asset_id=data['asset_id'],
        component_id=data['component_id'], ingestion_batch_id=batch, assessed_at=when,
        scan_status=scan_status, coverage_json=canonical({
            'cve_ids': [n['cve_id']] if covered else [], 'explicit_results': {n['cve_id']: result}})))
    c.execute(tables['verification_events'].insert().values(
        id=verification, workspace_id=data['workspace_id'], asset_cve_id=n['id'],
        assessment_id=assessment, result=result, decided_at=when, reason='Synthetic scanner result'))
    return verification


@pytest.mark.parametrize('scan_status,result,when,covered', [
    ('Failed', 'Pass', '2099-01-03T00:00:00.000000Z', True),
    ('Partial', 'Pass', '2099-01-03T00:00:00.000000Z', True),
    ('Success', 'Inconclusive', '2099-01-03T00:00:00.000000Z', True),
    ('Success', 'Pass', '2099-01-01T00:00:00.000000Z', True),
    ('Success', 'Pass', '2099-01-03T00:00:00.000000Z', False),
])
def test_insufficient_verification_blocks_closure(engine, finding_data, scan_status, result, when, covered):
    batch, n = import_one(engine, finding_data)
    with engine.begin() as c:
        transition_finding(c, transition(finding_data, n, 'Pending Verification'))
        n = dict(c.execute(select(tables['asset_cves'])).mappings().one())
        verification = add_verification(c, finding_data, n, batch, scan_status=scan_status,
                                        result=result, when=when, covered=covered)
    with pytest.raises(ValueError), engine.begin() as c:
        transition_finding(c, transition(finding_data, n, 'Verified Remediated',
            verification_event_id=verification, occurred_at='2099-01-04T00:00:00Z'))
    with engine.begin() as c:
        assert c.scalar(select(tables['asset_cves'].c.status)) == 'Pending Verification'


def test_verified_closure_and_recurrence_preserve_history(engine, finding_data):
    batch, n = import_one(engine, finding_data)
    with engine.begin() as c:
        transition_finding(c, transition(finding_data, n, 'Pending Verification'))
        n = dict(c.execute(select(tables['asset_cves'])).mappings().one())
        verification = add_verification(c, finding_data, n, batch)
        transition_finding(c, transition(finding_data, n, 'Verified Remediated',
            verification_event_id=verification, occurred_at='2099-01-04T00:00:00Z'))
        n = dict(c.execute(select(tables['asset_cves'])).mappings().one())
        failure = add_verification(c, finding_data, n, batch, result='Fail', when='2099-01-05T00:00:00.000000Z')
        transition_finding(c, transition(finding_data, n, 'Open', verification_event_id=failure,
                                        occurred_at='2099-01-06T00:00:00Z'))
        assert count(c, 'status_history') == 3
        assert count(c, 'raw_findings') == 1
        assert c.scalar(select(tables['asset_cves'].c.revision)) == 3


@pytest.mark.parametrize('table_name', ['raw_findings', 'finding_links', 'audit_events', 'status_history'])
@pytest.mark.parametrize('operation', ['update', 'delete'])
def test_immutable_history(engine, finding_data, table_name, operation):
    _, n = import_one(engine, finding_data)
    with engine.begin() as c:
        transition_finding(c, transition(finding_data, n, 'Pending Verification'))
    t = tables[table_name]
    statement = t.delete() if operation == 'delete' else t.update().values(id='tampered')
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(statement)
    with engine.begin() as c:
        assert count(c, table_name) >= 1


def test_transaction_rollback_preserves_no_partial_audit(engine, finding_data):
    with pytest.raises(RuntimeError), engine.begin() as c:
        ingest_findings(c, [finding(finding_data)])
        raise RuntimeError('abort')
    with engine.begin() as c:
        assert count(c, 'raw_findings') == count(c, 'audit_events') == count(c, 'asset_cves') == 0


@pytest.mark.parametrize('change', [dict(cve_ids=['wrong']), dict(mapped_severity_rank=5),
    dict(mapped_severity_rank='3'), dict(observed_at='2099-01-01T00:00:00'),
    dict(unexpected=True), dict(cve_ids=['CVE-2099-99999', 'CVE-2099-99999'])])
def test_scanner_contract_rejects_invalid(finding_data, change):
    with pytest.raises(ValidationError):
        finding(finding_data, **change)


def test_contract_schema_generation():
    for cls in (ScannerFinding, NormalizedVulnerability, RemediationEvidence,
                RemediationBatch, Ticket, StatusTransition):
        schema = cls.model_json_schema()
        assert schema['additionalProperties'] is False


def test_canonical_hash_order_and_nonfinite():
    assert digest({'a': 1, 'b': 2}) == digest({'b': 2, 'a': 1})
    with pytest.raises(ValueError):
        digest({'bad': float('nan')})


def test_database_rejects_severity_decrease_and_revision_skip(engine, finding_data):
    _, n = import_one(engine, finding_data)
    for changes in ({'max_severity_rank': 1, 'revision': 1}, {'revision': 8}):
        with pytest.raises(IntegrityError), engine.begin() as c:
            c.execute(tables['asset_cves'].update().values(**changes))


def test_every_scoped_table_has_workspace_foreign_keys():
    for name, t in tables.items():
        if 'workspace_id' not in t.c:
            continue
        assert any(tuple(fk.column_keys) == ('workspace_id',) for fk in t.foreign_key_constraints)
        for fk in t.foreign_key_constraints:
            parent = next(iter(fk.elements)).column.table
            if 'workspace_id' in parent.c and parent.name != 'demo_workspaces':
                assert 'workspace_id' in fk.column_keys, (name, fk)


def test_schema_drift_detected(engine):
    with engine.begin() as c:
        c.exec_driver_sql('DROP TRIGGER monotonic_severity')
    with pytest.raises(RuntimeError, match='drift'):
        migrate(engine)


def test_optimistic_identity_edit_audited(engine, seeded):
    from vulnmgmt.services import revise_identity
    with engine.begin() as c:
        assert revise_identity(c, seeded['workspace'], 'assets', seeded['asset'], 0,
                               {'hostname': 'renamed.invalid'}, 'test-analyst') == 1
    with pytest.raises(RevisionConflict), engine.begin() as c:
        revise_identity(c, seeded['workspace'], 'assets', seeded['asset'], 0,
                        {'hostname': 'stale.invalid'}, 'test-analyst')
    with engine.begin() as c:
        assert count(c, 'audit_events') == 1
        assert c.scalar(select(tables['assets'].c.asset_key)) == 'test-asset'
        assert c.scalar(select(tables['assets'].c.hostname)) == 'renamed.invalid'


def test_natural_identity_edit_not_supported(engine, seeded):
    from vulnmgmt.services import revise_identity
    with pytest.raises(ValueError), engine.begin() as c:
        revise_identity(c, seeded['workspace'], 'assets', seeded['asset'], 0,
                        {'asset_key': 'changed'}, 'test-analyst')


def evidence_source(c, seeded, success=True):
    id = str(uuid4())
    c.execute(tables['evidence_sources'].insert().values(
        id=id, workspace_id=seeded['workspace'], url='https://example.invalid/synthetic',
        publisher='Synthetic test', retrieved_at='2099-01-01T00:00:00.000000Z',
        fetch_status='Success' if success else 'Failed',
        content_hash=digest({}) if success else None, snapshot_json='{}' if success else None,
        error=None if success else 'Synthetic retrieval failure'))
    return id


def test_failed_source_cannot_confirm_claim(engine, seeded):
    with engine.begin() as c:
        source = evidence_source(c, seeded, success=False)
    with pytest.raises(IntegrityError, match='failed source'), engine.begin() as c:
        c.execute(tables['evidence_claims'].insert().values(
            id=str(uuid4()), workspace_id=seeded['workspace'], source_id=source,
            claim_type='test', statement='Synthetic only', supporting_excerpt='test',
            validation_status='Confirmed', validator='test', validated_at='2099-01-01T00:00:00Z'))


@pytest.mark.parametrize('kind,extra', [
    ('EPSS', {'epss_score': 1.2, 'epss_percentile': .9}),
    ('KEV', {'kev_member': 1, 'epss_score': .5}),
    ('Sector', {'sector': 'government', 'assessment': 'invented'}),
])
def test_intelligence_kind_constraints(engine, seeded, kind, extra):
    with engine.begin() as c:
        source = evidence_source(c, seeded)
        c.execute(tables['cves'].insert().values(cve_id='CVE-2099-99999'))
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(tables['threat_intel'].insert().values(
            id=str(uuid4()), workspace_id=seeded['workspace'], source_id=source,
            cve_id='CVE-2099-99999', kind=kind, as_of='2099-01-01Z', expires_at='2099-01-02Z',
            validation_status='Proposed', **extra))


def proposal_fixture(c, seeded, *, kind='Ticket'):
    action, batch, proposal = [str(uuid4()) for _ in range(3)]
    c.execute(tables['remediation_actions'].insert().values(
        id=action, workspace_id=seeded['workspace'], action_key='synthetic-action', revision=0,
        product='Synthetic product', applicability_json='{}', instructions='Synthetic test only', status='Proposed'))
    c.execute(tables['remediation_batches'].insert().values(
        id=batch, workspace_id=seeded['workspace'], asset_id=seeded['asset'], action_id=action,
        cycle=1, status='Proposed', revision=0))
    c.execute(tables['proposals'].insert().values(
        id=proposal, workspace_id=seeded['workspace'], batch_id=batch, kind=kind,
        revision=0, payload_json='{}', payload_hash=digest({}), status='Awaiting Approval',
        expected_batch_revision=0, workspace_generation=0))
    return batch, proposal


@pytest.mark.parametrize('wrong', ['hash', 'generation', 'batch_revision'])
def test_approval_binds_exact_revision(engine, seeded, wrong):
    with engine.begin() as c:
        batch, proposal = proposal_fixture(c, seeded)
        if wrong == 'generation':
            c.execute(tables['demo_workspaces'].update().values(generation=1))
        elif wrong == 'batch_revision':
            c.execute(tables['remediation_batches'].update().values(revision=1))
    with pytest.raises(IntegrityError, match='approval revision'), engine.begin() as c:
        c.execute(tables['approvals'].insert().values(
            id=str(uuid4()), workspace_id=seeded['workspace'], proposal_id=proposal,
            proposal_hash='0'*64 if wrong == 'hash' else digest({}), decision='Approved',
            analyst_id='synthetic-analyst', decided_at='2099-01-01Z', reason='Test only'))


def test_approved_payload_immutable(engine, seeded):
    with engine.begin() as c:
        _, proposal = proposal_fixture(c, seeded)
    with pytest.raises(IntegrityError, match='immutable'), engine.begin() as c:
        c.execute(tables['proposals'].update().values(payload_json='{"changed":true}'))


def test_unapproved_generated_ticket_rejected(engine, seeded):
    with engine.begin() as c:
        batch, proposal = proposal_fixture(c, seeded)
    with pytest.raises(IntegrityError, match='approved proposal'), engine.begin() as c:
        c.execute(tables['tickets'].insert().values(
            id=str(uuid4()), workspace_id=seeded['workspace'], batch_id=batch,
            proposal_id=proposal, action_key='test-ticket', origin='generated',
            status='Simulated Open', created_at='2099-01-01Z'))


def test_batch_membership_requires_confirmed_evidence(engine, seeded, finding_data):
    _, n = import_one(engine, finding_data)
    with engine.begin() as c:
        batch, _ = proposal_fixture(c, seeded)
        source = evidence_source(c, seeded)
        claim = str(uuid4())
        c.execute(tables['evidence_claims'].insert().values(
            id=claim, workspace_id=seeded['workspace'], source_id=source, cve_id=n['cve_id'],
            claim_type='test', statement='Synthetic only', supporting_excerpt='test', validation_status='Proposed'))
    with pytest.raises(IntegrityError, match='membership'), engine.begin() as c:
        c.execute(tables['batch_memberships'].insert().values(
            id=str(uuid4()), workspace_id=seeded['workspace'], batch_id=batch,
            asset_cve_id=n['id'], evidence_claim_id=claim, joined_at='2099-01-01Z'))


def test_one_primary_owner_at_a_time(engine, seeded):
    values = dict(workspace_id=seeded['workspace'], asset_id=seeded['asset'],
                  owner_id=seeded['owner'], role='primary', valid_from='2099-01-01Z')
    with engine.begin() as c:
        c.execute(tables['asset_owners'].insert().values(id=str(uuid4()), **values))
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(tables['asset_owners'].insert().values(id=str(uuid4()), **values))


def test_migration_preserves_import_and_audit(engine, finding_data):
    import_one(engine, finding_data)
    with engine.begin() as c:
        before = {name: c.execute(select(tables[name])).all()
                  for name in ('raw_findings', 'asset_cves', 'audit_events')}
    migrate(engine)
    with engine.begin() as c:
        after = {name: c.execute(select(tables[name])).all() for name in before}
    assert before == after


def test_chronological_first_last_seen(engine, finding_data):
    import_one(engine, finding_data)
    import_one(engine, finding_data, native_scan_id='earlier', observed_at='2098-12-01T00:00:00Z')
    import_one(engine, finding_data, native_scan_id='later', observed_at='2099-02-01T00:00:00Z')
    with engine.begin() as c:
        n = c.execute(select(tables['asset_cves'])).mappings().one()
        assert n['first_seen'] == '2098-12-01T00:00:00.000000Z'
        assert n['last_seen'] == '2099-02-01T00:00:00.000000Z'


def envelope(data):
    return {key: data[key] for key in ('workspace_id', 'scenario_version_id', 'correlation_id', 'mode')}


def test_normalized_contract_roundtrip_and_invalid_dates(engine, finding_data):
    _, n = import_one(engine, finding_data)
    with engine.begin() as c:
        raw = c.scalar(select(tables['raw_findings'].c.id))
    payload = envelope(finding_data) | {key: n[key] for key in (
        'id', 'asset_id', 'component_id', 'cve_id', 'first_seen', 'last_seen', 'status', 'revision', 'max_severity_rank')}
    payload |= {'source_raw_ids': [raw], 'has_unknown_severity': False}
    contract = NormalizedVulnerability.model_validate_json(json.dumps(payload))
    assert NormalizedVulnerability.model_validate_json(contract.model_dump_json()) == contract
    with pytest.raises(ValidationError):
        NormalizedVulnerability.model_validate_json(json.dumps(payload | {'last_seen': '2098-01-01T00:00:00Z'}))


@pytest.mark.parametrize('bad', [False, True])
def test_evidence_contract_grounding(finding_data, bad):
    data = envelope(finding_data) | dict(source_id=str(uuid4()), url='https://example.invalid/synthetic',
        publisher='Synthetic test', retrieved_at='2099-01-01T00:00:00Z', fetch_status='Success',
        content_hash=digest({}), snapshot={}, statement='Synthetic only', supporting_excerpt='test excerpt',
        validation_status='Confirmed', validator='test', validated_at='2099-01-01T00:00:00Z')
    if bad:
        with pytest.raises(ValidationError):
            RemediationEvidence.model_validate_json(json.dumps(data | {'fetch_status': 'Failed', 'error': 'Test failure'}))
    else:
        assert RemediationEvidence.model_validate_json(json.dumps(data)).validation_status == 'Confirmed'


@pytest.mark.parametrize('origin,proposal,valid', [('seeded', None, True), ('generated', str(uuid4()), True),
                                                ('generated', None, False), ('seeded', str(uuid4()), False)])
def test_ticket_contract_proposal_link(finding_data, origin, proposal, valid):
    data = envelope(finding_data) | dict(id=str(uuid4()), batch_id=str(uuid4()), action_key=digest({}),
        origin=origin, proposal_id=proposal, status='Open', created_at='2099-01-01T00:00:00Z', revision=0)
    if valid:
        assert Ticket.model_validate_json(json.dumps(data)).origin == origin
    else:
        with pytest.raises(ValidationError):
            Ticket.model_validate_json(json.dumps(data))


def test_batch_contract_duplicate_members(finding_data):
    member = str(uuid4())
    data = envelope(finding_data) | dict(id=str(uuid4()), asset_id=finding_data['asset_id'],
        action_id=str(uuid4()), action_revision=0, cycle=1, member_ids=[member],
        applicability_claim_ids=[str(uuid4())], status='Proposed', revision=0)
    assert RemediationBatch.model_validate_json(json.dumps(data)).cycle == 1
    with pytest.raises(ValidationError):
        RemediationBatch.model_validate_json(json.dumps(data | {'member_ids': [member, member]}))
