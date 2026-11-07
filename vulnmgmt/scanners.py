"""Separate version-1 synthetic-format adapters. NOT production scanner integrations."""

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, JsonValue, ValidationError, TypeAdapter
from sqlalchemy import select

from .contracts import Contract, Nonempty, ScannerFinding, UtcTime
from .database import tables
from .services import audit, canonical, context, digest, link_observation, stable, utc


class Envelope(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    format_version: Literal['1']
    synthetic: Literal[True]


class TenableEnvelope(Envelope):
    format: Literal['synthetic-tenable']
    tenant: Nonempty
    scan_id: Nonempty
    exported_at: UtcTime
    findings: list[JsonValue]


class DefenderEnvelope(Envelope):
    format: Literal['synthetic-defender']
    tenantId: Nonempty
    scanId: Nonempty
    exportedAt: UtcTime
    value: list[JsonValue]


class RowError(ValueError):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.details = dict(code=code, message=message, **details)


def required(row, name, type_=str):
    value = row.get(name)
    if type(value) is not type_ or (type_ is str and not value.strip()):
        raise RowError('MissingOrInvalidField', f'{name} must be a nonempty {type_.__name__}', field=name)
    return value


def resolve_identity(connection, w, scanner, tenant, native, hostname, component_key):
    aliases, assets, components = (tables[n] for n in ('asset_aliases', 'assets', 'asset_components'))
    asset_id = None
    if isinstance(native, str) and native.strip():
        asset_id = connection.scalar(select(aliases.c.asset_id).where(
            aliases.c.workspace_id == w, aliases.c.scanner == scanner,
            aliases.c.scanner_tenant == tenant, aliases.c.native_asset_id == native))
    if asset_id is None:
        candidates = []
        if isinstance(hostname, str):
            candidates = list(connection.scalars(select(assets.c.id).where(
                assets.c.workspace_id == w, assets.c.hostname == hostname)))
        code = 'AssetIdentityAmbiguous' if len(candidates) > 1 else 'AssetIdentityUnresolved'
        raise RowError(code, 'Explicit scanner alias required; hostname candidates are review-only',
                       candidate_asset_ids=sorted(candidates))
    if not isinstance(component_key, str) or not component_key:
        raise RowError('ComponentIdentityUnresolved', 'Explicit software instance key is required')
    component_id = connection.scalar(select(components.c.id).where(
        components.c.workspace_id == w, components.c.asset_id == asset_id,
        components.c.component_key == component_key))
    if component_id is None:
        raise RowError('ComponentIdentityUnresolved', 'Unknown software instance for resolved asset')
    return asset_id, component_id


@dataclass(frozen=True)
class SyntheticTenableAdapter:
    scanner: str = 'Tenable'
    envelope_type = TenableEnvelope

    def unpack(self, envelope):
        return envelope.tenant, envelope.scan_id, envelope.exported_at, envelope.findings

    def fields(self, row):
        cves = required(row, 'cve', list)
        if not cves or any(not isinstance(c, str) for c in cves):
            raise RowError('InvalidCVE', 'cve must contain CVE identifiers')
        severity = row.get('severity')
        # Explicit synthetic mapping; unknown vendor ratings are never treated as zero.
        rank = severity if type(severity) is int and 0 <= severity <= 4 else None
        return dict(native_asset=row.get('host_uuid'), hostname=row.get('hostname'),
                    component=row.get('component_key'), native_finding_id=required(row, 'plugin_id'),
                    cves=cves, observed_at=required(row, 'last_seen'),
                    raw_severity=canonical(severity) if not isinstance(severity, str) else severity,
                    rank=rank)


@dataclass(frozen=True)
class SyntheticDefenderAdapter:
    scanner: str = 'Defender'
    envelope_type = DefenderEnvelope

    def unpack(self, envelope):
        return envelope.tenantId, envelope.scanId, envelope.exportedAt, envelope.value

    def fields(self, row):
        severity = row.get('severity')
        ranks = {'Informational': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        return dict(native_asset=row.get('deviceId'), hostname=row.get('deviceName'),
                    component=row.get('softwareKey'), native_finding_id=required(row, 'findingId'),
                    cves=[required(row, 'cveId')], observed_at=required(row, 'detectedAt'),
                    raw_severity=severity if isinstance(severity, str) else canonical(severity),
                    rank=ranks.get(severity) if isinstance(severity, str) else None)


ADAPTERS = {'synthetic-tenable': SyntheticTenableAdapter(), 'synthetic-defender': SyntheticDefenderAdapter()}
IDENTITY_ERRORS = {'AssetIdentityAmbiguous', 'AssetIdentityUnresolved', 'ComponentIdentityUnresolved'}


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON object key: {key}')
        result[key] = value
    return result


def ingest_export(connection, workspace_id, scenario_version_id, content: bytes, format_name):
    """Atomic per-export import; preserve *every* row occurrence, including invalid rows.

    Invalid envelopes fail before mutation. Row validation failures are quarantined;
    unexpected program/DB errors abort the transaction rather than hide data loss.
    """
    if format_name not in ADAPTERS:
        raise ValueError('Unsupported synthetic format')
    raw_text = content.decode('utf-8-sig')
    parsed = json.loads(raw_text, object_pairs_hook=_unique_keys,
                        parse_constant=lambda s: (_ for _ in ()).throw(ValueError(f'Invalid JSON number {s}')))
    adapter = ADAPTERS[format_name]
    envelope = adapter.envelope_type.model_validate_json(canonical(parsed))
    tenant, scan_id, exported_at, rows = adapter.unpack(envelope)
    request = Contract.model_validate_json(canonical(dict(workspace_id=str(workspace_id),
        scenario_version_id=str(scenario_version_id), correlation_id=str(uuid4()), mode='replay')))
    workspace = context(connection, request)
    if not workspace['synthetic_only']:
        raise ValueError('Synthetic adapter requires a synthetic workspace')
    w = str(request.workspace_id)
    export_hash = sha256(content).hexdigest()
    batch_id = stable(w, 'scanner-export', adapter.scanner, tenant, scan_id, export_hash)
    batch_table = tables['ingestion_batches']
    if connection.scalar(select(batch_table.c.id).where(
            batch_table.c.workspace_id == w, batch_table.c.id == batch_id)):
        return {'batch_id': batch_id, 'repeated': True, 'new_rows': 0}
    prepared = []
    for index, raw in enumerate(rows):
        normalized, errors, values = None, [], {}
        try:
            if not isinstance(raw, dict):
                raise RowError('InvalidRow', 'Scanner finding must be a JSON object')
            if 'severity' not in raw or raw['severity'] is None:
                raise RowError('MissingOrInvalidField', 'severity is required', field='severity')
            values = adapter.fields(raw)
            # Validate before identity lookup so malformed timestamps/CVEs are not silently accepted.
            candidate = dict(workspace_id=w, scenario_version_id=str(scenario_version_id),
                correlation_id=str(uuid4()), mode='replay', scanner=adapter.scanner,
                scanner_tenant=tenant, native_scan_id=scan_id,
                native_asset_id=values['native_asset'] if isinstance(values['native_asset'], str) else '<missing>',
                native_finding_id=values['native_finding_id'], asset_id=w, component_id=w,
                observed_at=values['observed_at'], raw_severity=values['raw_severity'] or '<empty>',
                mapped_severity_rank=values['rank'], mapping_version=f'{format_name}:1',
                cve_ids=sorted({c.strip().upper() for c in values['cves']}), payload=raw)
            checked = ScannerFinding.model_validate_json(canonical(candidate))
            if 'discovered_at' in raw:
                try:discovery=TypeAdapter(UtcTime).validate_json(canonical(raw['discovered_at']))
                except ValidationError:raise RowError('InvalidDiscoveryTimestamp','discovered_at must be a timezone-aware timestamp',field='discovered_at') from None
                if discovery>checked.observed_at:raise RowError('DiscoveryAfterObservation','discovered_at cannot follow the scanner observation',field='discovered_at')
                values['discovered_at']=utc(discovery)
            asset_id, component_id = resolve_identity(connection, w, adapter.scanner, tenant,
                values['native_asset'], values['hostname'], values['component'])
            normalized = ScannerFinding.model_validate_json(canonical(
                checked.model_dump(mode='json') | {'asset_id': asset_id, 'component_id': component_id}))
        except RowError as error:
            errors = [error.details]
        except ValidationError as error:
            errors = [dict(code='ContractValidation', field='.'.join(map(str, item['loc'])),
                           message=item['msg']) for item in error.errors(include_url=False, include_input=False)]
        raw_id = stable(w, 'scanner-row', batch_id, index)
        prepared.append((raw_id, raw, normalized, errors, values))
    quarantined = sum(normalized is None for _, _, normalized, _, _ in prepared)
    connection.execute(batch_table.insert().values(
        id=batch_id, workspace_id=w, scanner=adapter.scanner, scanner_tenant=tenant,
        native_scan_id=scan_id, export_hash=export_hash, observed_at=utc(exported_at), ingested_at=utc(),
        status='Quarantined' if quarantined == len(rows) and rows else 'Imported',
        duplicate_rows=len(rows)-len({digest(raw) for raw in rows})))
    archive_id = stable(w, 'scanner-archive', batch_id)
    connection.execute(tables['evidence_sources'].insert().values(
        id=archive_id, workspace_id=w, url=f'synthetic://{format_name}/{export_hash}',
        publisher='Synthetic scanner export archive (not remediation evidence)', retrieved_at=utc(),
        content_hash=export_hash, snapshot_json=canonical({'format': format_name, 'original_text': content.decode('utf-8')}),
        fetch_status='Success'))
    for index, (raw_id, raw, normalized, errors, values) in enumerate(prepared):
        connection.execute(tables['raw_findings'].insert().values(
            id=raw_id, workspace_id=w, ingestion_batch_id=batch_id,
            native_finding_id=values.get('native_finding_id',
                str(raw.get('plugin_id', raw.get('findingId', f'<missing:row-{index}>')))
                if isinstance(raw, dict) else f'<missing:row-{index}>'),
            row_key=f'{index:06}:{digest(raw)}', payload_json=canonical(raw), payload_hash=digest(raw),
            raw_severity=values.get('raw_severity', canonical(raw.get('severity')) if isinstance(raw, dict) else '<missing>'),
            observed_at=utc(normalized.observed_at) if normalized else utc(exported_at),
            validation_status='Valid' if normalized else 'Quarantined', validation_errors_json=canonical(errors)))
        if normalized:
            link_observation(connection, normalized, raw_id, batch_id, discovered_at=values.get('discovered_at'))
            if values.get('discovered_at'):
                for cve in normalized.cve_ids:
                    finding_id=stable(w,'asset-cve',str(normalized.asset_id),str(normalized.component_id),cve)
                    audit(connection,w,'ScannerDiscoveryRecorded','asset_cves',finding_id,0,dict(discovered_at=values['discovered_at'],observed_at=utc(normalized.observed_at),raw_id=raw_id,batch_id=batch_id,clock_basis='synthetic-effective'))
        else:
            audit(connection, w, 'ScannerRowQuarantined', 'raw_findings', raw_id, 0,
                  {'batch_id': batch_id, 'errors': errors})
    audit(connection, w, 'SyntheticScannerImport', 'ingestion_batches', batch_id, 0,
          {'format_version': '1', 'archive_id': archive_id, 'raw_rows': len(rows),
           'valid_rows': len(rows)-quarantined, 'quarantined_rows': quarantined})
    return {'batch_id': batch_id, 'repeated': False, 'new_rows': len(rows)}
