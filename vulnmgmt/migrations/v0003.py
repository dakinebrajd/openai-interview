"""0003: local synthetic lifecycle, immutable versions and analyst decisions."""
from sqlalchemy import (CheckConstraint, Column, ForeignKeyConstraint, Index, Integer,
                        MetaData, Table, Text, UniqueConstraint)
from . import v0002

metadata = MetaData()
for original in v0002.metadata.sorted_tables:
    original.to_metadata(metadata)


def fk(name, target, nullable=False):
    return (Column(name, Text, nullable=nullable), ForeignKeyConstraint(
        ['workspace_id', name], [target+'.workspace_id', target+'.id']))


def table(name, *items):
    expanded = []
    for item in items:
        expanded.extend(item if isinstance(item, tuple) else [item])
    return Table(name, metadata, Column('id', Text, primary_key=True),
        Column('workspace_id', Text, nullable=False), UniqueConstraint('workspace_id', 'id'),
        ForeignKeyConstraint(['workspace_id'], ['demo_workspaces.id']), *expanded)


def textcol(name, nullable=False):
    return Column(name, Text, nullable=nullable)


def jsoncol(name):
    return (textcol(name), CheckConstraint(f'json_valid({name})'))


table('lifecycle_scopes', fk('asset_id', 'assets'), fk('resolver_group_id', 'owners'),
      fk('batch_id', 'remediation_batches'), fk('individual_finding_id', 'asset_cves', True),
      textcol('remediation_identity'), textcol('created_at'),
      UniqueConstraint('workspace_id', 'asset_id', 'resolver_group_id', 'remediation_identity'))
table('ticket_bindings', fk('ticket_id', 'tickets'), fk('scope_id', 'lifecycle_scopes'),
      UniqueConstraint('workspace_id', 'ticket_id'), UniqueConstraint('workspace_id', 'scope_id'))
table('ticket_versions', fk('ticket_id', 'tickets'), fk('proposal_id', 'proposals', True),
      Column('ticket_revision', Integer, nullable=False), jsoncol('snapshot_json'),
      textcol('material_hash'), textcol('event_type'), textcol('reason'), textcol('actor_id'), textcol('created_at'),
      CheckConstraint('ticket_revision >= 0'), UniqueConstraint('workspace_id', 'ticket_id', 'ticket_revision'))
table('communication_links', fk('communication_id', 'communications'), fk('ticket_id', 'tickets'),
      UniqueConstraint('workspace_id', 'communication_id'))
table('reply_interpretations', fk('reply_id', 'owner_replies'), fk('ticket_id', 'tickets'),
      textcol('intent'), jsoncol('interpretation_json'), textcol('created_at'),
      UniqueConstraint('workspace_id', 'reply_id'))
table('lifecycle_reviews', textcol('kind'), textcol('target_id'), jsoncol('payload_json'),
      textcol('payload_hash'), Column('workspace_generation', Integer, nullable=False),
      textcol('status'), Column('revision', Integer, nullable=False), textcol('created_at'), textcol('expires_at'),
      CheckConstraint("kind IN ('Batch','Risk')"),
      CheckConstraint("status IN ('Awaiting Approval','Approved','Rejected','Invalidated')"),
      CheckConstraint('revision >= 0 AND workspace_generation >= 0'))
table('lifecycle_decisions', fk('review_id', 'lifecycle_reviews'), textcol('payload_hash'),
      textcol('decision'), textcol('analyst_id'), textcol('reason'), textcol('decided_at'),
      CheckConstraint("decision IN ('Approved','Rejected')"), UniqueConstraint('workspace_id', 'review_id'))
table('exception_review_links', fk('exception_id', 'exceptions'), fk('review_id', 'lifecycle_reviews'),
      UniqueConstraint('workspace_id', 'exception_id'))
table('lifecycle_operations', textcol('operation_key'), textcol('payload_hash'), jsoncol('result_json'),
      textcol('created_at'), UniqueConstraint('workspace_id', 'operation_key'))

NAMES = ('lifecycle_scopes', 'ticket_bindings', 'ticket_versions', 'communication_links',
         'reply_interpretations', 'lifecycle_reviews', 'lifecycle_decisions', 'exception_review_links',
         'lifecycle_operations')
for name in NAMES:
    t = metadata.tables[name]
    for i, constraint in enumerate(t.foreign_key_constraints):
        Index(f'ix_{name}_fk_{i}', *(t.c[key] for key in constraint.column_keys))


def apply(connection):
    for name in NAMES:
        metadata.tables[name].create(connection, checkfirst=False)
        if name != 'lifecycle_reviews':
            for operation in ('UPDATE', 'DELETE'):
                connection.exec_driver_sql(f"CREATE TRIGGER immutable_{name}_{operation.lower()} BEFORE {operation} "
                    f"ON {name} BEGIN SELECT RAISE(ABORT, '{name} is append-only'); END")
    connection.exec_driver_sql("""CREATE TRIGGER immutable_review_payload BEFORE UPDATE ON lifecycle_reviews
        WHEN NEW.id!=OLD.id OR NEW.workspace_id!=OLD.workspace_id OR NEW.payload_json!=OLD.payload_json
          OR NEW.payload_hash!=OLD.payload_hash OR NEW.kind!=OLD.kind OR NEW.target_id!=OLD.target_id
          OR NEW.workspace_generation!=OLD.workspace_generation OR NEW.expires_at!=OLD.expires_at
          OR NEW.revision!=OLD.revision+1
        BEGIN SELECT RAISE(ABORT, 'review payload is immutable; revision must increment'); END""")
    connection.exec_driver_sql("""CREATE TRIGGER protect_review_delete BEFORE DELETE ON lifecycle_reviews
        BEGIN SELECT RAISE(ABORT, 'review history is retained'); END""")
    connection.exec_driver_sql("""CREATE TRIGGER scope_asset_integrity BEFORE INSERT ON lifecycle_scopes
        WHEN NOT EXISTS (SELECT 1 FROM remediation_batches b WHERE b.workspace_id=NEW.workspace_id
          AND b.id=NEW.batch_id AND b.asset_id=NEW.asset_id)
        OR (NEW.individual_finding_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM asset_cves f
          WHERE f.workspace_id=NEW.workspace_id AND f.id=NEW.individual_finding_id AND f.asset_id=NEW.asset_id))
        BEGIN SELECT RAISE(ABORT, 'scope must belong to one asset'); END""")
    connection.exec_driver_sql("""CREATE TRIGGER sent_communication_immutable BEFORE UPDATE ON communications
        WHEN OLD.status='Simulated Delivered'
        BEGIN SELECT RAISE(ABORT, 'simulated sent communication is immutable'); END""")
