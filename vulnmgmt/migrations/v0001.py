"""Migration 0001: authoritative domain schema. Freeze after first release."""

from sqlalchemy import (
    CheckConstraint, Column, Float, ForeignKey, ForeignKeyConstraint, Index,
    Integer, MetaData, Table, Text, UniqueConstraint, text,
)

metadata = MetaData()


def col(name, type_=Text, *, nullable=False, default=None):
    return Column(name, type_, nullable=nullable, server_default=default)


def choice(name, values):
    return CheckConstraint(f"{name} IN ({','.join(repr(v) for v in values)})")


def unique(*names):
    return UniqueConstraint('workspace_id', *names)


def ref(column, target, *, nullable=False):
    return (
        col(column, nullable=nullable),
        ForeignKeyConstraint(['workspace_id', column],
                             [f'{target}.workspace_id', f'{target}.id']),
    )


def table(name, *items, scoped=True):
    base = [Column('id', Text, primary_key=True)]
    if scoped:
        base += [Column('workspace_id', Text, ForeignKey('demo_workspaces.id'), nullable=False),
                 UniqueConstraint('workspace_id', 'id')]
    expanded = []
    for item in items:
        expanded.extend(item if isinstance(item, tuple) else [item])
    return Table(name, metadata, *base, *expanded)


def revision():
    return (col('revision', Integer, default='0'), CheckConstraint('revision >= 0'))


def jsoncol(name, *, nullable=False, default=None):
    return (col(name, nullable=nullable, default=default),
            CheckConstraint(f'{name} IS NULL OR json_valid({name})'))


def cve_ref(*, nullable=False):
    return Column('cve_id', Text, ForeignKey('cves.cve_id'), nullable=nullable)


FINDING_STATES = ('Open', 'In Remediation', 'Pending Verification', 'Verified Remediated')
PROPOSAL_STATES = ('Draft', 'Awaiting Approval', 'Approved', 'Rejected', 'Superseded',
                   'Expired', 'Invalidated', 'Simulated Executed', 'Failed')

table('demo_scenarios', col('name'), scoped=False)
table('scenario_versions', Column('scenario_id', Text, ForeignKey('demo_scenarios.id'), nullable=False),
      col('version', Integer), jsoncol('manifest_json'), col('manifest_hash'), col('fixed_clock'),
      col('seed', Integer), UniqueConstraint('scenario_id', 'version'),
      CheckConstraint('version >= 1'), scoped=False)
table('demo_workspaces', Column('scenario_version_id', Text, ForeignKey('scenario_versions.id'), nullable=False),
      col('database_identity'), col('generation', Integer, default='0'),
      col('synthetic_only', Integer), col('state', default='Ready'),
      CheckConstraint('generation >= 0'), CheckConstraint('synthetic_only IN (0,1)'),
      choice('state', ('Ready', 'Resetting', 'Archived')),
      UniqueConstraint('id', 'scenario_version_id'), scoped=False)

table('owners', col('display_name'), col('synthetic_email'), col('active', Integer, default='1'),
      CheckConstraint('active IN (0,1)'), unique('synthetic_email'), revision())
table('assets', col('asset_key'), col('hostname'), col('criticality'), unique('asset_key'), revision())
table('asset_owners', ref('asset_id', 'assets'), ref('owner_id', 'owners'), col('role'),
      col('valid_from'), col('valid_to', nullable=True), choice('role', ('primary', 'secondary')))
Index('uq_current_primary_owner', metadata.tables['asset_owners'].c.workspace_id,
      metadata.tables['asset_owners'].c.asset_id, unique=True,
      sqlite_where=text("valid_to IS NULL AND role = 'primary'"))
table('asset_aliases', ref('asset_id', 'assets'), col('scanner'), col('scanner_tenant'),
      col('native_asset_id'), unique('scanner', 'scanner_tenant', 'native_asset_id'),
      choice('scanner', ('Tenable', 'Defender')))
table('asset_components', ref('asset_id', 'assets'), col('component_key'), col('product'),
      col('installed_version', nullable=True), col('location'), revision(),
      unique('asset_id', 'component_key'), unique('asset_id', 'id'))

table('ingestion_batches', col('scanner'), col('scanner_tenant'), col('native_scan_id'),
      col('export_hash'), col('observed_at'), col('ingested_at'), col('status'),
      col('duplicate_rows', Integer, default='0'), CheckConstraint('duplicate_rows >= 0'),
      choice('scanner', ('Tenable', 'Defender')), choice('status', ('Imported', 'Quarantined')),
      unique('scanner', 'scanner_tenant', 'native_scan_id', 'export_hash'))
table('raw_findings', ref('ingestion_batch_id', 'ingestion_batches'), col('native_finding_id'),
      col('row_key'), jsoncol('payload_json'), col('payload_hash'), col('raw_severity'),
      col('observed_at'), col('validation_status'), jsoncol('validation_errors_json'),
      choice('validation_status', ('Valid', 'Quarantined')), unique('ingestion_batch_id', 'row_key'))
Table('cves', metadata, Column('cve_id', Text, primary_key=True),
      CheckConstraint("cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' "
                      "AND substr(cve_id,10) NOT GLOB '*[^0-9]*'"))
table('asset_cves', ref('asset_id', 'assets'), ref('component_id', 'asset_components'), cve_ref(),
      col('first_seen'), col('last_seen'), col('max_severity_rank', Integer, nullable=True),
      col('has_unknown_severity', Integer, default='0'), col('status', default='Open'), revision(),
      CheckConstraint('max_severity_rank IS NULL OR max_severity_rank BETWEEN 0 AND 4'),
      CheckConstraint('has_unknown_severity IN (0,1)'), CheckConstraint('first_seen <= last_seen'),
      CheckConstraint('max_severity_rank IS NOT NULL OR has_unknown_severity=1'),
      choice('status', FINDING_STATES), unique('asset_id', 'component_id', 'cve_id'),
      ForeignKeyConstraint(['workspace_id', 'asset_id', 'component_id'],
                           ['asset_components.workspace_id', 'asset_components.asset_id', 'asset_components.id']))
table('finding_cves', ref('raw_finding_id', 'raw_findings'), cve_ref(), unique('raw_finding_id', 'cve_id'))
table('finding_links', ref('raw_finding_id', 'raw_findings'), ref('asset_cve_id', 'asset_cves'),
      col('mapped_severity_rank', Integer, nullable=True), col('mapping_version'),
      CheckConstraint('mapped_severity_rank IS NULL OR mapped_severity_rank BETWEEN 0 AND 4'),
      unique('raw_finding_id', 'asset_cve_id'))

table('evidence_sources', col('url'), col('publisher'), col('retrieved_at'),
      col('published_at', nullable=True), col('content_hash', nullable=True),
      jsoncol('snapshot_json', nullable=True), col('fetch_status'), col('error', nullable=True),
      choice('fetch_status', ('Success', 'Failed')),
      CheckConstraint("(fetch_status = 'Success' AND content_hash IS NOT NULL AND snapshot_json IS NOT NULL "
                      "AND error IS NULL) OR (fetch_status = 'Failed' AND error IS NOT NULL)"))
table('evidence_claims', ref('source_id', 'evidence_sources'), cve_ref(nullable=True), col('claim_type'),
      col('statement'), col('supporting_excerpt'), col('validation_status'), col('validator', nullable=True),
      col('validated_at', nullable=True), choice('validation_status', ('Proposed', 'Confirmed', 'Rejected')),
      CheckConstraint("validation_status != 'Confirmed' OR (validator IS NOT NULL AND validated_at IS NOT NULL)"))
table('remediation_actions', col('action_key'), revision(), col('product'), jsoncol('applicability_json'),
      col('instructions'), col('status'), choice('status', ('Proposed', 'Confirmed', 'Rejected')),
      unique('action_key', 'revision'))
table('action_evidence', ref('action_id', 'remediation_actions'), ref('claim_id', 'evidence_claims'),
      unique('action_id', 'claim_id'))
table('threat_intel', cve_ref(), col('kind'), ref('source_id', 'evidence_sources'), col('as_of'),
      col('expires_at'), col('kev_member', Integer, nullable=True), col('kev_added_date', nullable=True),
      col('epss_score', Float, nullable=True), col('epss_percentile', Float, nullable=True),
      col('sector', nullable=True), col('assessment', nullable=True), col('validation_status'),
      choice('validation_status', ('Proposed', 'Confirmed', 'Rejected')),
      CheckConstraint('as_of <= expires_at'), CheckConstraint('kev_member IS NULL OR kev_member IN (0,1)'),
      CheckConstraint('epss_score IS NULL OR epss_score BETWEEN 0 AND 1'),
      CheckConstraint('epss_percentile IS NULL OR epss_percentile BETWEEN 0 AND 1'),
      CheckConstraint("(kind='KEV' AND epss_score IS NULL AND epss_percentile IS NULL AND sector IS NULL AND assessment IS NULL) "
                      "OR (kind='EPSS' AND kev_member IS NULL AND kev_added_date IS NULL AND sector IS NULL AND assessment IS NULL "
                      "AND epss_score IS NOT NULL AND epss_percentile IS NOT NULL) "
                      "OR (kind='Sector' AND kev_member IS NULL AND kev_added_date IS NULL AND epss_score IS NULL "
                      "AND epss_percentile IS NULL AND sector IS NOT NULL AND assessment IN ('Supported','Unknown','Conflicting'))"),
      unique('cve_id', 'kind', 'source_id', 'as_of'))

table('remediation_batches', ref('asset_id', 'assets'), ref('action_id', 'remediation_actions'),
      col('cycle', Integer), col('status'), revision(), col('confirmed_by', nullable=True),
      col('confirmed_at', nullable=True), CheckConstraint('cycle >= 1'),
      choice('status', ('Proposed', 'Confirmed', 'Active', 'Pending Verification', 'Verified Remediated', 'Cancelled')),
      unique('asset_id', 'action_id', 'cycle'))
table('batch_memberships', ref('batch_id', 'remediation_batches'), ref('asset_cve_id', 'asset_cves'),
      col('joined_at'), col('left_at', nullable=True), ref('evidence_claim_id', 'evidence_claims'))
table('policy_versions', col('policy_key'), col('version', Integer), jsoncol('config_json'),
      CheckConstraint('version >= 1'), unique('policy_key', 'version'))
table('finding_deadlines', ref('asset_cve_id', 'asset_cves'), ref('policy_id', 'policy_versions'),
      col('anchor_at'), col('due_at'), col('rationale'), col('superseded_at', nullable=True))
for name, key, predicate in [('batch_memberships', 'asset_cve_id', 'left_at IS NULL'),
                             ('finding_deadlines', 'asset_cve_id', 'superseded_at IS NULL')]:
    t = metadata.tables[name]
    Index(f'uq_active_{name}', t.c.workspace_id, t.c[key], unique=True, sqlite_where=text(predicate))

table('proposals', ref('batch_id', 'remediation_batches'), col('kind'), revision(),
      jsoncol('payload_json'), col('payload_hash'), col('status'), col('expected_batch_revision', Integer),
      col('workspace_generation', Integer), CheckConstraint('expected_batch_revision >= 0'),
      CheckConstraint('workspace_generation >= 0'), choice('kind', ('Ticket', 'Escalation', 'Communication')),
      choice('status', PROPOSAL_STATES), unique('batch_id', 'kind', 'revision'))
table('approvals', ref('proposal_id', 'proposals'), col('proposal_hash'), col('decision'),
      col('analyst_id'), col('decided_at'), col('expires_at', nullable=True), col('reason'),
      choice('decision', ('Approved', 'Rejected')), unique('proposal_id'))
table('tickets', ref('batch_id', 'remediation_batches'), col('external_synthetic_key', nullable=True),
      col('action_key'), col('origin'), col('status'), ref('proposal_id', 'proposals', nullable=True),
      col('created_at'), revision(), unique('action_key'), unique('external_synthetic_key'),
      choice('origin', ('seeded', 'generated')),
      choice('status', ('Open', 'Simulated Open', 'In Progress', 'Pending Verification', 'Closed')),
      CheckConstraint("(origin='seeded' AND proposal_id IS NULL) OR (origin='generated' AND proposal_id IS NOT NULL)"))
table('ticket_findings', ref('ticket_id', 'tickets'), ref('asset_cve_id', 'asset_cves'),
      unique('ticket_id', 'asset_cve_id'))
table('escalations', ref('batch_id', 'remediation_batches'), col('level', Integer),
      ref('policy_id', 'policy_versions'), col('action_key'), ref('proposal_id', 'proposals'),
      col('status'), revision(), CheckConstraint('level >= 1'), unique('action_key'),
      choice('status', ('Simulated Open', 'In Progress', 'Pending Verification', 'Closed')))
table('communications', ref('batch_id', 'remediation_batches'), ref('proposal_id', 'proposals'),
      col('channel'), ref('recipient_owner_id', 'owners'), col('body_hash'), col('delivery_key'),
      col('status'), revision(), unique('delivery_key'), choice('channel', ('Email',)),
      choice('status', ('Draft', 'Awaiting Approval', 'Approved', 'Rejected', 'Expired', 'Invalidated',
                        'Simulated Delivered', 'Failed')))
table('simulated_deliveries', ref('communication_id', 'communications'), col('receipt_key'),
      col('persisted_at'), col('outcome'), choice('outcome', ('Simulated Delivered',)),
      unique('communication_id'), unique('receipt_key'))
table('owner_replies', ref('communication_id', 'communications', nullable=True), ref('owner_id', 'owners'),
      col('native_reply_key'), col('received_at'), col('raw_body'), col('body_hash'), unique('native_reply_key'))
table('reply_claims', ref('reply_id', 'owner_replies'), ref('asset_cve_id', 'asset_cves'),
      col('claimed_action'), col('claimed_at', nullable=True), col('extraction_status'),
      choice('extraction_status', ('Matched', 'Ambiguous', 'Rejected')))
table('scan_assessments', ref('asset_id', 'assets'), ref('component_id', 'asset_components'),
      ref('ingestion_batch_id', 'ingestion_batches'), col('assessed_at'), col('scan_status'),
      jsoncol('coverage_json'), choice('scan_status', ('Success', 'Failed', 'Partial')),
      ForeignKeyConstraint(['workspace_id', 'asset_id', 'component_id'],
                           ['asset_components.workspace_id', 'asset_components.asset_id', 'asset_components.id']))
table('verification_events', ref('asset_cve_id', 'asset_cves'), ref('assessment_id', 'scan_assessments'),
      col('result'), ref('evidence_claim_id', 'evidence_claims', nullable=True), col('decided_at'),
      col('reason'), choice('result', ('Pass', 'Fail', 'Inconclusive')), unique('asset_cve_id', 'assessment_id'))
table('status_history', ref('asset_cve_id', 'asset_cves'), col('from_status'), col('to_status'),
      col('reason'), col('actor_id'), col('occurred_at'),
      ref('verification_event_id', 'verification_events', nullable=True),
      ref('reply_claim_id', 'reply_claims', nullable=True), col('expected_revision', Integer),
      CheckConstraint('expected_revision >= 0'), choice('from_status', FINDING_STATES),
      choice('to_status', FINDING_STATES), unique('asset_cve_id', 'expected_revision'))
table('exceptions', ref('asset_cve_id', 'asset_cves'), col('analyst_id'), col('reason'),
      col('expires_at'), col('status'), choice('status', ('Active', 'Expired', 'Revoked')))
table('runs', Column('scenario_version_id', Text, ForeignKey('scenario_versions.id'), nullable=False),
      col('mode'), col('effective_clock'), col('started_at'), col('ended_at', nullable=True),
      col('status'), col('input_hash'), col('contract_version'),
      choice('mode', ('live', 'replay')),
      choice('status', ('Queued', 'Running', 'Succeeded', 'Failed', 'Cancelled', 'Awaiting Approval')),
      ForeignKeyConstraint(['workspace_id', 'scenario_version_id'],
                           ['demo_workspaces.id', 'demo_workspaces.scenario_version_id']))
table('agent_steps', ref('run_id', 'runs'), col('role_number', Integer), col('step_key'),
      col('attempt', Integer), col('status'), col('model', nullable=True), col('prompt_version'),
      col('input_hash'), jsoncol('output_json', nullable=True), jsoncol('error_json', nullable=True),
      jsoncol('token_usage_json', nullable=True), CheckConstraint('role_number BETWEEN 0 AND 9'),
      CheckConstraint('attempt >= 1'), unique('run_id', 'role_number', 'step_key', 'attempt'),
      choice('status', ('Queued', 'Running', 'Succeeded', 'Failed', 'Cancelled', 'Awaiting Approval')))
table('audit_events', ref('run_id', 'runs', nullable=True), col('actor_type'), col('actor_id'),
      col('event_type'), col('entity_type'), col('entity_id'), revision(),
      jsoncol('payload_json'), col('recorded_at'))
table('reset_snapshots', Column('scenario_version_id', Text, ForeignKey('scenario_versions.id'), nullable=False),
      col('schema_version', Integer), col('manifest_hash'), col('snapshot_hash'),
      jsoncol('snapshot_payload_json'), col('created_at'),
      UniqueConstraint('scenario_version_id', 'snapshot_hash'), scoped=False)
table('reset_events', Column('snapshot_id', Text, ForeignKey('reset_snapshots.id'), nullable=False),
      col('old_generation', Integer), col('new_generation', Integer), col('requested_at'),
      col('outcome'), col('error', nullable=True), choice('outcome', ('Applied', 'Failed')),
      CheckConstraint('new_generation = old_generation + 1'))

# Index every child FK, including composite workspace relationships.
for t in metadata.tables.values():
    for number, fk in enumerate(t.foreign_key_constraints):
        columns = [t.c[element.parent.name] for element in fk.elements]
        Index(f'ix_{t.name}_fk_{number}', *columns)
for name, fields in [('asset_cves', ('status', 'max_severity_rank')),
                     ('finding_deadlines', ('due_at',)), ('evidence_claims', ('cve_id',)),
                     ('threat_intel', ('cve_id', 'kind', 'as_of')), ('tickets', ('batch_id', 'status')),
                     ('proposals', ('status',)), ('audit_events', ('entity_type', 'entity_id', 'recorded_at'))]:
    t = metadata.tables[name]
    Index(f'ix_{name}_lookup', t.c.workspace_id, *(t.c[f] for f in fields))

IMMUTABLE = ('scenario_versions', 'ingestion_batches', 'raw_findings', 'finding_cves', 'finding_links', 'evidence_sources',
             'evidence_claims', 'approvals', 'owner_replies', 'verification_events', 'status_history',
             'audit_events', 'reset_snapshots', 'reset_events', 'simulated_deliveries', 'policy_versions',
             'scan_assessments')


def apply(connection):
    metadata.create_all(connection, checkfirst=False)
    for t in metadata.tables.values():
        if 'workspace_id' not in t.c:
            continue
        connection.exec_driver_sql(f"""
            CREATE TRIGGER stable_identity_{t.name} BEFORE UPDATE ON {t.name}
            WHEN NEW.id != OLD.id OR NEW.workspace_id != OLD.workspace_id
            BEGIN SELECT RAISE(ABORT, 'identity cannot change'); END
        """)
    for name in IMMUTABLE:
        for operation in ('UPDATE', 'DELETE'):
            connection.exec_driver_sql(
                f"CREATE TRIGGER immutable_{name}_{operation.lower()} BEFORE {operation} ON {name} "
                f"BEGIN SELECT RAISE(ABORT, '{name} is append-only'); END")
    connection.exec_driver_sql("""
        CREATE TRIGGER immutable_proposal_payload BEFORE UPDATE ON proposals
        WHEN NEW.payload_json != OLD.payload_json OR NEW.payload_hash != OLD.payload_hash
          OR NEW.batch_id != OLD.batch_id OR NEW.revision != OLD.revision
          OR NEW.kind != OLD.kind OR NEW.workspace_id != OLD.workspace_id
          OR NEW.workspace_generation != OLD.workspace_generation
          OR NEW.expected_batch_revision != OLD.expected_batch_revision
        BEGIN SELECT RAISE(ABORT, 'proposal revision is immutable'); END
    """)
    connection.exec_driver_sql("""
        CREATE TRIGGER monotonic_severity BEFORE UPDATE ON asset_cves
        WHEN OLD.max_severity_rank IS NOT NULL AND
          (NEW.max_severity_rank IS NULL OR NEW.max_severity_rank < OLD.max_severity_rank)
        BEGIN SELECT RAISE(ABORT, 'severity cannot decrease'); END
    """)
    connection.exec_driver_sql("""
        CREATE TRIGGER valid_finding_transition BEFORE UPDATE OF status ON asset_cves
        WHEN NEW.status != OLD.status AND NOT (
          (OLD.status='Open' AND NEW.status IN ('In Remediation','Pending Verification')) OR
          (OLD.status='In Remediation' AND NEW.status='Pending Verification') OR
          (OLD.status='Pending Verification' AND NEW.status IN ('Open','Verified Remediated')) OR
          (OLD.status='Verified Remediated' AND NEW.status='Open'))
        BEGIN SELECT RAISE(ABORT, 'invalid finding transition'); END
    """)
    connection.exec_driver_sql("""
        CREATE TRIGGER finding_revision BEFORE UPDATE ON asset_cves
        WHEN NEW.revision != OLD.revision + 1
        BEGIN SELECT RAISE(ABORT, 'finding revision must increment'); END
    """)
    for name in ('assets', 'owners', 'asset_components', 'remediation_batches', 'tickets',
                 'communications', 'escalations'):
        connection.exec_driver_sql(f"""
            CREATE TRIGGER revision_{name} BEFORE UPDATE ON {name}
            WHEN NEW.revision != OLD.revision + 1
            BEGIN SELECT RAISE(ABORT, 'revision must increment'); END
        """)
    connection.exec_driver_sql("""
        CREATE TRIGGER confirmed_evidence BEFORE INSERT ON evidence_claims
        WHEN NEW.validation_status='Confirmed' AND NOT EXISTS (
          SELECT 1 FROM evidence_sources s WHERE s.workspace_id=NEW.workspace_id
            AND s.id=NEW.source_id AND s.fetch_status='Success')
        BEGIN SELECT RAISE(ABORT, 'failed source cannot confirm evidence'); END
    """)
    connection.exec_driver_sql("""
        CREATE TRIGGER valid_batch_member BEFORE INSERT ON batch_memberships
        WHEN NOT EXISTS (
          SELECT 1 FROM remediation_batches b
          JOIN asset_cves f ON f.workspace_id=b.workspace_id AND f.asset_id=b.asset_id
          JOIN remediation_actions a ON a.workspace_id=b.workspace_id AND a.id=b.action_id
          JOIN action_evidence ae ON ae.workspace_id=a.workspace_id AND ae.action_id=a.id
          JOIN evidence_claims e ON e.workspace_id=ae.workspace_id AND e.id=ae.claim_id
          WHERE b.workspace_id=NEW.workspace_id AND b.id=NEW.batch_id AND f.id=NEW.asset_cve_id
            AND e.id=NEW.evidence_claim_id AND e.cve_id=f.cve_id AND e.validation_status='Confirmed'
            AND a.status='Confirmed' AND b.status='Confirmed')
        BEGIN SELECT RAISE(ABORT, 'membership requires same asset and confirmed action evidence'); END
    """)
    connection.exec_driver_sql("""
        CREATE TRIGGER approval_binding BEFORE INSERT ON approvals
        WHEN NOT EXISTS (
          SELECT 1 FROM proposals p
          JOIN remediation_batches b ON b.workspace_id=p.workspace_id AND b.id=p.batch_id
          JOIN demo_workspaces w ON w.id=p.workspace_id
          WHERE p.workspace_id=NEW.workspace_id AND p.id=NEW.proposal_id
            AND p.payload_hash=NEW.proposal_hash AND p.status='Awaiting Approval'
            AND p.expected_batch_revision=b.revision AND p.workspace_generation=w.generation
            AND w.state='Ready')
        BEGIN SELECT RAISE(ABORT, 'approval revision or generation mismatch'); END
    """)
    for name, kind, condition in [('tickets', 'Ticket', "NEW.origin='generated'"),
                                   ('escalations', 'Escalation', '1'),
                                   ('communications', 'Communication', "NEW.status IN ('Approved','Simulated Delivered')")]:
        connection.exec_driver_sql(f"""
            CREATE TRIGGER approved_{name}_insert BEFORE INSERT ON {name}
            WHEN {condition} AND NOT EXISTS (
              SELECT 1 FROM proposals p
              JOIN approvals a ON a.workspace_id=p.workspace_id AND a.proposal_id=p.id
              JOIN remediation_batches b ON b.workspace_id=p.workspace_id AND b.id=p.batch_id
              JOIN demo_workspaces w ON w.id=p.workspace_id
              WHERE p.workspace_id=NEW.workspace_id AND p.id=NEW.proposal_id
                AND p.batch_id=NEW.batch_id AND p.kind='{kind}' AND p.status='Approved'
                AND a.decision='Approved' AND a.proposal_hash=p.payload_hash
                AND p.expected_batch_revision=b.revision AND p.workspace_generation=w.generation)
            BEGIN SELECT RAISE(ABORT, 'approved proposal required'); END
        """)
