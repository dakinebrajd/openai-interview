"""0002: isolate synthetic applicability and proposed batch membership from approval."""
from sqlalchemy import (CheckConstraint, Column, ForeignKeyConstraint, Index, Integer,
                        MetaData, Table, Text, UniqueConstraint)
from . import v0001

metadata = MetaData()
# Copy reference definitions only; apply() creates just the two new tables.
for t in v0001.metadata.sorted_tables:
    t.to_metadata(metadata)


def scoped(name, *items):
    return Table(name, metadata, Column('id', Text, primary_key=True),
        Column('workspace_id', Text, nullable=False), UniqueConstraint('workspace_id', 'id'),
        ForeignKeyConstraint(['workspace_id'], ['demo_workspaces.id']), *items)


scoped('synthetic_applicability',
    Column('component_id', Text, nullable=False), Column('expected_component_revision', Integer, nullable=False),
    Column('overlay_version', Text, nullable=False), Column('product', Text, nullable=False),
    Column('installed_version', Text, nullable=False), Column('label', Text, nullable=False),
    Column('assumption_hash', Text, nullable=False), Column('created_at', Text, nullable=False),
    CheckConstraint('expected_component_revision >= 0'),
    CheckConstraint("label = 'SYNTHETIC ASSUMPTION - NOT SCANNER EVIDENCE'"),
    UniqueConstraint('workspace_id', 'component_id', 'overlay_version'),
    ForeignKeyConstraint(['workspace_id', 'component_id'], ['asset_components.workspace_id', 'asset_components.id']))
scoped('batch_proposal_members',
    Column('batch_id', Text, nullable=False), Column('asset_cve_id', Text, nullable=False),
    Column('assumption_id', Text, nullable=False), Column('evidence_claim_id', Text, nullable=False),
    Column('source_hash', Text, nullable=False), Column('created_at', Text, nullable=False),
    UniqueConstraint('workspace_id', 'batch_id', 'asset_cve_id'),
    ForeignKeyConstraint(['workspace_id', 'batch_id'], ['remediation_batches.workspace_id', 'remediation_batches.id']),
    ForeignKeyConstraint(['workspace_id', 'asset_cve_id'], ['asset_cves.workspace_id', 'asset_cves.id']),
    ForeignKeyConstraint(['workspace_id', 'assumption_id'], ['synthetic_applicability.workspace_id', 'synthetic_applicability.id']),
    ForeignKeyConstraint(['workspace_id', 'evidence_claim_id'], ['evidence_claims.workspace_id', 'evidence_claims.id']))

NAMES = ('synthetic_applicability', 'batch_proposal_members')
for name in NAMES:
    t = metadata.tables[name]
    for i, fk in enumerate(t.foreign_key_constraints):
        Index(f'ix_{name}_fk_{i}', *(t.c[c] for c in fk.column_keys))


def apply(connection):
    for name in NAMES:
        metadata.tables[name].create(connection, checkfirst=False)
        for operation in ('UPDATE', 'DELETE'):
            connection.exec_driver_sql(f"CREATE TRIGGER immutable_{name}_{operation.lower()} "
                f"BEFORE {operation} ON {name} BEGIN SELECT RAISE(ABORT, '{name} is append-only'); END")
    connection.exec_driver_sql("""
        CREATE TRIGGER validate_proposal_member BEFORE INSERT ON batch_proposal_members
        WHEN NOT EXISTS (
          SELECT 1 FROM remediation_batches b
          JOIN asset_cves f ON f.workspace_id=b.workspace_id AND f.asset_id=b.asset_id
          JOIN synthetic_applicability a ON a.workspace_id=f.workspace_id AND a.component_id=f.component_id
          JOIN evidence_claims e ON e.workspace_id=f.workspace_id AND e.cve_id=f.cve_id
          JOIN action_evidence ae ON ae.workspace_id=e.workspace_id AND ae.claim_id=e.id AND ae.action_id=b.action_id
          WHERE b.workspace_id=NEW.workspace_id AND b.id=NEW.batch_id AND b.status='Proposed'
            AND f.id=NEW.asset_cve_id AND a.id=NEW.assumption_id AND e.id=NEW.evidence_claim_id
            AND e.validation_status='Confirmed' AND e.claim_type='VendorRemediation')
        BEGIN SELECT RAISE(ABORT, 'invalid proposed membership or cross-asset batch'); END
    """)
