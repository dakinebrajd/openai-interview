"""Deterministic foundation operations. Call within engine.begin() for atomic audit."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from uuid import UUID, uuid4, uuid5

from sqlalchemy import select, update
from sqlalchemy.dialects.sqlite import insert

from .contracts import ScannerFinding, StatusTransition
from .database import tables


class RevisionConflict(ValueError):
    pass


def utc(value=None):
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError('Naive timestamp')
    return value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode('utf-8')).hexdigest()


def stable(workspace_id, kind, *parts):
    return str(uuid5(UUID(str(workspace_id)), canonical(['1', kind, *parts])))


def row(connection, name, workspace_id, id):
    t = tables[name]
    value = connection.execute(select(t).where(
        t.c.workspace_id == str(workspace_id), t.c.id == str(id))).mappings().first()
    if value is None:
        raise ValueError(f'{name} not found in workspace')
    return value


def context(connection, contract):
    w = tables['demo_workspaces']
    workspace = connection.execute(select(w).where(w.c.id == str(contract.workspace_id))).mappings().one()
    if workspace['scenario_version_id'] != str(contract.scenario_version_id):
        raise ValueError('Contract scenario does not match workspace')
    if workspace['state'] != 'Ready':
        raise ValueError('Workspace is not ready')
    return workspace


def revise_identity(connection, workspace_id, entity, entity_id, expected_revision, changes, actor_id):
    """Optimistic identity attribute edits; natural identities and ownership links stay fixed."""
    permitted = {'assets': {'hostname', 'criticality'}, 'owners': {'display_name', 'synthetic_email', 'active'},
                 'asset_components': {'product', 'installed_version', 'location'}}
    if entity not in permitted or not changes or not set(changes) <= permitted[entity]:
        raise ValueError('Unsupported identity edit')
    old = row(connection, entity, workspace_id, entity_id)
    if old['revision'] != expected_revision:
        raise RevisionConflict('Stale identity revision')
    t = tables[entity]
    result = connection.execute(update(t).where(t.c.workspace_id == str(workspace_id),
        t.c.id == str(entity_id), t.c.revision == expected_revision).values(
            **changes, revision=expected_revision + 1))
    if result.rowcount != 1:
        raise RevisionConflict('Identity changed during update')
    audit(connection, workspace_id, 'IdentityUpdated', entity, entity_id, expected_revision + 1,
          {'before': {key: old[key] for key in changes}, 'after': changes}, actor_id=actor_id,
          actor_type='analyst')
    return expected_revision + 1


def audit(connection, workspace_id, event_type, entity_type, entity_id, revision, payload,
          actor_id='foundation', actor_type='service', recorded_at=None):
    connection.execute(tables['audit_events'].insert().values(
        id=str(uuid4()), workspace_id=str(workspace_id), actor_type=actor_type, actor_id=actor_id,
        event_type=event_type, entity_type=entity_type, entity_id=str(entity_id), revision=revision,
        payload_json=canonical(payload), recorded_at=utc(recorded_at)))


def ingest_findings(connection, findings: list[ScannerFinding]):
    """Legacy foundation import for already-mapped observations (M1 tests/compatibility).

    Export identity is order-independent over the supplied rows, including duplicates.
    Use scanners.ingest_export for M2 exports, quarantine and per-occurrence preservation.
    """
    if not findings:
        raise ValueError('An import needs at least one finding')
    if any(not isinstance(f, ScannerFinding) for f in findings):
        raise TypeError('Validated ScannerFinding contracts required')
    first = findings[0]
    context(connection, first)
    same = ('workspace_id', 'scenario_version_id', 'mode', 'scanner', 'scanner_tenant', 'native_scan_id')
    if any(any(getattr(f, key) != getattr(first, key) for key in same) for f in findings):
        raise ValueError('One import must share workspace, scenario, mode and scanner scan')
    serialized = [f.model_dump(mode='json', exclude={'correlation_id'}) for f in findings]
    export_hash = digest(sorted(serialized, key=canonical))
    workspace_id = str(first.workspace_id)
    batch_id = stable(workspace_id, 'import', first.scanner, first.scanner_tenant,
                      first.native_scan_id, export_hash)
    batches = tables['ingestion_batches']
    existing = connection.execute(select(batches.c.id).where(batches.c.id == batch_id)).scalar_one_or_none()
    if existing:
        return batch_id
    # Resolve all references before mutation. Alias mappings are explicit, never inferred.
    aliases = tables['asset_aliases']
    for f in findings:
        component = row(connection, 'asset_components', workspace_id, f.component_id)
        if component['asset_id'] != str(f.asset_id):
            raise ValueError('Component belongs to another asset')
        alias_asset = connection.execute(select(aliases.c.asset_id).where(
            aliases.c.workspace_id == workspace_id, aliases.c.scanner == f.scanner,
            aliases.c.scanner_tenant == f.scanner_tenant,
            aliases.c.native_asset_id == f.native_asset_id)).scalar_one_or_none()
        if alias_asset != str(f.asset_id):
            raise ValueError('Unconfirmed scanner asset identity')
    unique_rows = {digest(v): (f, v) for f, v in zip(findings, serialized)}
    connection.execute(batches.insert().values(
        id=batch_id, workspace_id=workspace_id, scanner=first.scanner,
        scanner_tenant=first.scanner_tenant, native_scan_id=first.native_scan_id,
        export_hash=export_hash, observed_at=min(utc(f.observed_at) for f in findings),
        ingested_at=utc(), status='Imported', duplicate_rows=len(findings)-len(unique_rows)))
    for row_key, (f, _) in unique_rows.items():
        raw_id = stable(workspace_id, 'raw', batch_id, row_key)
        connection.execute(tables['raw_findings'].insert().values(
            id=raw_id, workspace_id=workspace_id, ingestion_batch_id=batch_id,
            native_finding_id=f.native_finding_id, row_key=row_key, payload_json=canonical(f.payload),
            payload_hash=digest(f.payload), raw_severity=f.raw_severity, observed_at=utc(f.observed_at),
            validation_status='Valid', validation_errors_json='[]'))
        link_observation(connection, f, raw_id, batch_id)
    audit(connection, workspace_id, 'ScannerImport', 'ingestion_batches', batch_id, 0,
          {'unique_rows': len(unique_rows), 'duplicate_rows': len(findings)-len(unique_rows)})
    return batch_id


def link_observation(connection, f: ScannerFinding, raw_id, batch_id, *, discovered_at=None):
    """Link one persisted raw observation; caller owns transaction and identity validation."""
    workspace_id = str(f.workspace_id)
    for cve in f.cve_ids:
        connection.execute(insert(tables['cves']).values(cve_id=cve).on_conflict_do_nothing())
        connection.execute(tables['finding_cves'].insert().values(
            id=stable(workspace_id, 'raw-cve', raw_id, cve), workspace_id=workspace_id,
            raw_finding_id=raw_id, cve_id=cve))
        finding_id = stable(workspace_id, 'asset-cve', str(f.asset_id), str(f.component_id), cve)
        t = tables['asset_cves']
        old = connection.execute(select(t).where(t.c.id == finding_id)).mappings().first()
        observed = utc(f.observed_at)
        discovered = utc(datetime.fromisoformat(discovered_at.replace('Z','+00:00'))) if discovered_at is not None else observed
        if discovered>observed:raise ValueError('Discovery cannot follow observation')
        if old is None:
            connection.execute(t.insert().values(
                id=finding_id, workspace_id=workspace_id, asset_id=str(f.asset_id),
                component_id=str(f.component_id), cve_id=cve, first_seen=discovered, last_seen=observed,
                max_severity_rank=f.mapped_severity_rank,
                has_unknown_severity=int(f.mapped_severity_rank is None), status='Open', revision=0))
            revision = 0
        else:
            ranks = [v for v in (old['max_severity_rank'], f.mapped_severity_rank) if v is not None]
            revision = old['revision'] + 1
            result = connection.execute(update(t).where(t.c.id == finding_id,
                t.c.workspace_id == workspace_id, t.c.revision == old['revision']).values(
                    first_seen=min(old['first_seen'], discovered), last_seen=max(old['last_seen'], observed),
                    max_severity_rank=max(ranks) if ranks else None,
                    has_unknown_severity=int(old['has_unknown_severity'] or f.mapped_severity_rank is None),
                    revision=revision))
            if result.rowcount != 1:
                raise RevisionConflict('Finding changed during import')
        connection.execute(tables['finding_links'].insert().values(
            id=stable(workspace_id, 'link', raw_id, finding_id), workspace_id=workspace_id,
            raw_finding_id=raw_id, asset_cve_id=finding_id,
            mapped_severity_rank=f.mapped_severity_rank, mapping_version=f.mapping_version))
        audit(connection, workspace_id, 'ObservationLinked', 'asset_cves', finding_id, revision,
              {'raw_id': raw_id, 'batch_id': batch_id})


def transition_finding(connection, request: StatusTransition):
    """Enforce scanner verification, optimistic revision and append-only history together."""
    if not isinstance(request, StatusTransition):
        raise TypeError('Validated StatusTransition required')
    context(connection, request)
    w = str(request.workspace_id)
    finding = row(connection, 'asset_cves', w, request.asset_cve_id)
    if finding['revision'] != request.expected_revision or finding['status'] != request.from_status:
        raise RevisionConflict('Stale finding revision or status')
    occurred_at = utc(request.occurred_at)
    history = tables['status_history']
    last = connection.execute(select(history.c.occurred_at).where(
        history.c.workspace_id == w, history.c.asset_cve_id == str(request.asset_cve_id))
        .order_by(history.c.expected_revision.desc())).scalar()
    if last and occurred_at < last:
        raise ValueError('Transition predates current state')
    if request.reply_claim_id:
        claim = row(connection, 'reply_claims', w, request.reply_claim_id)
        if claim['asset_cve_id'] != finding['id'] or claim['extraction_status'] != 'Matched':
            raise ValueError('Reply does not support this finding')
        if request.to_status != 'Pending Verification':
            raise ValueError('Owner claim can only request Pending Verification')
    if request.to_status in ('Verified Remediated', 'Open'):
        verification = row(connection, 'verification_events', w, request.verification_event_id)
        assessment = row(connection, 'scan_assessments', w, verification['assessment_id'])
        expected_result = 'Pass' if request.to_status == 'Verified Remediated' else 'Fail'
        coverage = json.loads(assessment['coverage_json'])
        covered = coverage.get('cve_ids', [])
        if (verification['asset_cve_id'] != finding['id'] or verification['result'] != expected_result
                or assessment['asset_id'] != finding['asset_id']
                or assessment['component_id'] != finding['component_id']
                or assessment['scan_status'] != 'Success' or finding['cve_id'] not in covered
                or coverage.get('explicit_results', {}).get(finding['cve_id']) != expected_result
                or assessment['assessed_at'] > occurred_at or verification['decided_at'] > occurred_at):
            raise ValueError('Insufficient or mismatched scanner verification')
        if request.to_status == 'Verified Remediated' and (
                assessment['assessed_at'] <= max(finding['last_seen'], last or finding['last_seen'])):
            raise ValueError('Passing scan must follow observations and fix claim')
        if request.to_status == 'Open' and last and assessment['assessed_at'] <= last:
            raise ValueError('Reopening needs subsequent positive scanner evidence')
    t = tables['asset_cves']
    result = connection.execute(update(t).where(
        t.c.workspace_id == w, t.c.id == finding['id'], t.c.revision == request.expected_revision
    ).values(status=request.to_status, revision=request.expected_revision + 1))
    if result.rowcount != 1:
        raise RevisionConflict('Finding changed during transition')
    connection.execute(history.insert().values(
        id=str(uuid4()), workspace_id=w, asset_cve_id=finding['id'], from_status=request.from_status,
        to_status=request.to_status, reason=request.reason, actor_id=request.actor_id,
        occurred_at=occurred_at, verification_event_id=str(request.verification_event_id) if request.verification_event_id else None,
        reply_claim_id=str(request.reply_claim_id) if request.reply_claim_id else None,
        expected_revision=request.expected_revision))
    audit(connection, w, 'StatusTransition', 'asset_cves', finding['id'], request.expected_revision + 1,
          request.model_dump(mode='json'), actor_id=request.actor_id,
          actor_type='scanner' if request.actor_id=='synthetic-scanner' else 'analyst')
    return request.expected_revision + 1
