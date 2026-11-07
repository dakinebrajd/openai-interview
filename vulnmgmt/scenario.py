"""Seed the versioned M2 synthetic inventory without deleting or resetting any data."""

from hashlib import sha256
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from .database import tables
from .fixture_builder import FIXTURE_DIR
from .services import audit, canonical, digest, stable, utc


def load_scenario(directory=FIXTURE_DIR):
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    expected_files = {'inventory.json', 'cve_sources.json', 'tenable.json', 'defender.json', 'tenable_repeat.json'}
    if (manifest.get('schema_version') != '1' or manifest.get('version') != 1
            or set(manifest.get('files', {})) != expected_files):
        raise ValueError('Unsupported or incomplete scenario manifest')
    files = {}
    for name, expected in manifest['files'].items():
        data = (directory/name).read_bytes()
        if sha256(data).hexdigest() != expected:
            raise ValueError(f'Fixture checksum mismatch: {name}')
        files[name] = data
    return manifest, files


def seed_scenario(connection, manifest, files):
    """Seed once; require a new version for modified fixture content."""
    scenario_id = str(uuid5(NAMESPACE_URL, 'synthetic://'+manifest['scenario']))
    version_id = str(uuid5(NAMESPACE_URL, f'synthetic://{manifest["scenario"]}/v{manifest["version"]}'))
    w = stable(version_id, 'workspace', 'default')
    versions, workspaces = tables['scenario_versions'], tables['demo_workspaces']
    existing = connection.execute(select(versions).where(versions.c.id == version_id)).mappings().first()
    if existing:
        if existing['manifest_hash'] != digest(manifest):
            raise ValueError('Scenario changed without a version increment')
        workspace = connection.execute(select(workspaces).where(workspaces.c.id == w)).mappings().one()
        if not workspace['synthetic_only'] or workspace['state'] != 'Ready':
            raise ValueError('Existing synthetic workspace is unavailable')
        return w, version_id
    inventory = json.loads(files['inventory.json'])
    connection.execute(tables['demo_scenarios'].insert().values(id=scenario_id, name=manifest['scenario']))
    connection.execute(versions.insert().values(id=version_id, scenario_id=scenario_id,
        version=manifest['version'], manifest_json=canonical(manifest), manifest_hash=digest(manifest),
        fixed_clock=manifest['fixed_clock'], seed=manifest['seed']))
    connection.execute(workspaces.insert().values(id=w, scenario_version_id=version_id,
        database_identity=stable(w, 'database-identity'), generation=0, synthetic_only=1, state='Ready'))
    for owner in inventory['owners'] + inventory['resolver_groups']:
        connection.execute(tables['owners'].insert().values(id=stable(w, 'owner', owner['key']),
            workspace_id=w, display_name=owner['name'], synthetic_email=owner['email']))
    for asset in inventory['assets']:
        asset_id = stable(w, 'asset', asset['key'])
        connection.execute(tables['assets'].insert().values(id=asset_id, workspace_id=w,
            asset_key=asset['key'], hostname=asset['hostname'], criticality=asset['criticality']))
        for role, owner_key in [('primary', asset['owner_key']), ('secondary', asset['resolver_group'])]:
            connection.execute(tables['asset_owners'].insert().values(
                id=stable(w, 'ownership', asset['key'], role), workspace_id=w, asset_id=asset_id,
                owner_id=stable(w, 'owner', owner_key), role=role, valid_from=manifest['fixed_clock']))
        for scanner, native in asset['aliases'].items():
            connection.execute(tables['asset_aliases'].insert().values(
                id=stable(w, 'alias', scanner, native), workspace_id=w, asset_id=asset_id,
                scanner=scanner, scanner_tenant='agency-demo', native_asset_id=native))
        for component in asset['components']:
            connection.execute(tables['asset_components'].insert().values(
                id=stable(w, 'component', asset['key'], component['key']), workspace_id=w,
                asset_id=asset_id, component_key=component['key'], product=component['product'],
                installed_version=component['installed_version'], location=component['location']))
        audit(connection, w, 'SyntheticInventoryAsset', 'assets', asset_id, 0,
              {'asset_type': asset['type'], 'resolver_group_key': asset['resolver_group']})
    sources = json.loads(files['cve_sources.json'])
    for record in sources['records']:
        cve = record['cve_id']
        connection.execute(tables['cves'].insert().values(cve_id=cve))
        verified = (record['verification_status'] == 'verified_identifier'
                    and record.get('metadata_snapshot', {}).get('cveId') == cve
                    and record.get('metadata_snapshot', {}).get('state') == 'PUBLISHED'
                    and bool(record.get('retrieved_at')))
        source_id = stable(w, 'cve-source', cve)
        connection.execute(tables['evidence_sources'].insert().values(
            id=source_id, workspace_id=w, url=record['source_url'], publisher='CVE Program Services',
            retrieved_at=record['retrieved_at'] or record['retrieval_attempted_at'],
            published_at=record.get('published_at'), content_hash=digest(record) if verified else None,
            snapshot_json=canonical(record) if verified else None,
            fetch_status='Success' if verified else 'Failed',
            error=None if verified else record.get('error') or 'Published identifier was not verified'))
        connection.execute(tables['evidence_claims'].insert().values(
            id=stable(w, 'cve-identifier', cve), workspace_id=w, source_id=source_id, cve_id=cve,
            claim_type='CVEIdentifier', statement=f'{cve}: published identifier only; synthetic applicability unknown',
            supporting_excerpt=canonical(record.get('metadata_snapshot', {})),
            validation_status='Confirmed' if verified else 'Proposed',
            validator='Cached CVE metadata ID/state check' if verified else None,
            validated_at=utc() if verified else None))
    audit(connection, w, 'SyntheticScenarioSeeded', 'demo_workspaces', w, 0,
          {'scenario_version_id': version_id, 'manifest_hash': digest(manifest)})
    return w, version_id
