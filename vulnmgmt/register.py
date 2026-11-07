"""SQLite-derived vulnerability register and analyst exports; never a Markdown database."""

import json
from pathlib import Path

from sqlalchemy import select

from .database import tables
from .scanners import IDENTITY_ERRORS


SEVERITIES = {0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical', None: 'Unknown'}


def build_register(connection, workspace_id):
    w = str(workspace_id)
    def rows(name):
        t = tables[name]
        return [dict(r) for r in connection.execute(select(t).where(t.c.workspace_id == w)).mappings()]

    workspace = connection.execute(select(tables['demo_workspaces']).where(
        tables['demo_workspaces'].c.id == w)).mappings().one()
    version = connection.execute(select(tables['scenario_versions']).where(
        tables['scenario_versions'].c.id == workspace['scenario_version_id'])).mappings().one()
    assets, components, owners = ({r['id']: r for r in rows(name)}
                                   for name in ('assets', 'asset_components', 'owners'))
    ownership = rows('asset_owners')
    raw = {r['id']: r for r in rows('raw_findings')}
    batches = {r['id']: r for r in rows('ingestion_batches')}
    links = rows('finding_links')
    sources = {r['id']: r for r in rows('evidence_sources')}
    claims = {r['cve_id']: r for r in rows('evidence_claims') if r['claim_type'] == 'CVEIdentifier'}
    inventory_types = {r['entity_id']: json.loads(r['payload_json'])['asset_type']
                       for r in rows('audit_events') if r['event_type'] == 'SyntheticInventoryAsset'}
    register = []
    for finding in rows('asset_cves'):
        asset = assets[finding['asset_id']]
        observations = []
        for link in links:
            if link['asset_cve_id'] != finding['id']:
                continue
            source_row = raw[link['raw_finding_id']]
            batch = batches[source_row['ingestion_batch_id']]
            observations.append(dict(raw_id=source_row['id'], scanner=batch['scanner'],
                scanner_tenant=batch['scanner_tenant'], native_scan_id=batch['native_scan_id'],
                native_finding_id=source_row['native_finding_id'], export_sha256=batch['export_hash'],
                raw_severity=source_row['raw_severity'], mapped_severity_rank=link['mapped_severity_rank'],
                mapping_version=link['mapping_version'], observed_at=source_row['observed_at'],
                payload_hash=source_row['payload_hash'], payload=json.loads(source_row['payload_json'])))
        claim = claims.get(finding['cve_id'])
        source = sources[claim['source_id']] if claim else None
        record = dict(finding)
        record.update(asset_key=asset['asset_key'], hostname=asset['hostname'],
            asset_type=inventory_types.get(asset['id'], 'Unknown'),
            component_key=components[finding['component_id']]['component_key'],
            product=components[finding['component_id']]['product'],
            installed_version=components[finding['component_id']]['installed_version'],
            severity=SEVERITIES[finding['max_severity_rank']],
            has_unknown_severity=bool(finding['has_unknown_severity']),
            owners=sorted(owners[o['owner_id']]['display_name'] for o in ownership
                          if o['asset_id'] == asset['id'] and o['role'] == 'primary' and o['valid_to'] is None),
            resolver_groups=sorted(owners[o['owner_id']]['display_name'] for o in ownership
                          if o['asset_id'] == asset['id'] and o['role'] == 'secondary' and o['valid_to'] is None),
            cve_source={'url': source['url'] if source else None,
                        'retrieved_at': source['retrieved_at'] if source else None,
                        'identifier_status': 'verified_identifier' if claim and claim['validation_status'] == 'Confirmed' else 'unverified',
                        'scope': 'Identifier only; asset applicability and remediation unknown',
                        'remediation_claim_eligible': False},
            observations=sorted(observations, key=lambda r: (r['scanner'], r['raw_id'])))
        register.append(record)
    quarantine = []
    for raw_row in raw.values():
        if raw_row['validation_status'] == 'Quarantined':
            batch = batches[raw_row['ingestion_batch_id']]
            quarantine.append(dict(raw_id=raw_row['id'], scanner=batch['scanner'],
                batch_id=batch['id'], native_finding_id=raw_row['native_finding_id'],
                errors=json.loads(raw_row['validation_errors_json']), payload=json.loads(raw_row['payload_json'])))
    identifier_ids = set(claims) | {r['cve_id'] for r in register}
    summary = dict(assets=len(assets), raw_findings=len(raw), valid_rows=len(raw)-len(quarantine),
        normalized_records=len(register), source_to_normalized_links=len(links),
        duplicates_consolidated=len(links)-len(register), quarantined_rows=len(quarantine),
        unresolved_identity_conflicts=sum(any(e['code'] in IDENTITY_ERRORS for e in r['errors']) for r in quarantine),
        exact_duplicate_rows=sum(b['duplicate_rows'] for b in batches.values()),
        scanner_imports=len(batches), cve_identifiers=len(identifier_ids),
        unverified_cve_identifiers=sum(cve not in claims or claims[cve]['validation_status'] != 'Confirmed'
                                        for cve in identifier_ids))
    return dict(schema_version='1', label='SYNTHETIC scanner observations / offline replay',
        workspace_id=w, scenario_version_id=version['id'], manifest_hash=version['manifest_hash'],
        as_of=version['fixed_clock'], summary=summary,
        metric_definitions={'duplicates_consolidated': 'Valid source-to-CVE links minus unique asset/component/CVE records',
            'exact_duplicate_rows': 'Repeated identical row occurrences within exports, all preserved',
            'repeated_imports': 'Identical export bytes are no-ops and not included again in cumulative counts'},
        vulnerabilities=sorted(register, key=lambda r: (r['asset_key'], r['component_key'], r['cve_id'])),
        quarantine=sorted(quarantine, key=lambda r: r['raw_id']))


def export_register(register, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir/'vulnerability_register.json').write_text(
        json.dumps(register, indent=2, sort_keys=True, ensure_ascii=False)+'\n', encoding='utf-8')
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')

    lines = ['# Synthetic vulnerability register', '', register['label'], '',
        f'As of scenario time: {register["as_of"]}; source retrieval dates are listed separately.', '',
        'SQLite is authoritative. All installations and observations are synthetic. '
        'No vendor patches, exploitation or shared remediation actions are asserted.', '', '## Ingestion summary', '']
    lines += [f'- {key}: {value}' for key, value in register['summary'].items()]
    lines += ['', 'Duplicates consolidated = valid source-to-CVE links minus unique asset/component/CVE records.', '',
        '## Normalized register', '',
        '| Asset | Type | Component | CVE | Highest severity | Status | Owner / resolver | First / last seen | Sources |',
        '|---|---|---|---|---|---|---|---|---|']
    for r in register['vulnerabilities']:
        lines.append('| '+' | '.join(cell(v) for v in (
            r['asset_key'], r['asset_type'], r['component_key'], r['cve_id'], r['severity'], r['status'],
            ', '.join(r['owners']+r['resolver_groups']), f'{r["first_seen"]} / {r["last_seen"]}',
            ', '.join(f'{o["scanner"]}:{o["native_finding_id"]} ({o["raw_severity"]})' for o in r['observations'])))+' |')
    lines += ['', '## CVE identifier sources (no remediation evidence)', '']
    seen = set()
    for r in register['vulnerabilities']:
        if r['cve_id'] in seen:
            continue
        seen.add(r['cve_id'])
        s = r['cve_source']
        citation = f'[{r["cve_id"]}]({s["url"]})' if s['url'] else r['cve_id']
        lines.append(f'- {citation}: {s["identifier_status"]}; retrieved {s["retrieved_at"]}. Applicability unknown.')
    lines += ['', '## Quarantine — analyst review required', '']
    for r in register['quarantine']:
        lines.append(f'- {r["scanner"]} / {cell(r["native_finding_id"])} / raw ID {r["raw_id"]}: '+
                     '; '.join(cell(e['code']+': '+e['message']) for e in r['errors']))
    (output_dir/'vulnerability_register.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    (output_dir/'ingestion_summary.json').write_text(json.dumps(register['summary'], indent=2)+'\n', encoding='utf-8')
