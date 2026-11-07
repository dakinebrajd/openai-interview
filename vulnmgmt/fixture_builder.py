"""Offline generator for version 1 synthetic-format fixtures, not scanner integrations."""

import argparse
from copy import deepcopy
import json
from hashlib import sha256
from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent.parent / 'fixtures' / 'scanner_demo' / 'v1'
SCENARIO_CLOCK = '2026-10-20T12:00:00Z'


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8')


def build(directory=FIXTURE_DIR):
    directory = Path(directory)
    sources = json.loads((directory / 'cve_sources.json').read_text(encoding='utf-8'))
    cves = {record['cve_id'] for record in sources['records']}
    owners = [dict(key=f'owner-{i}', name=f'Synthetic Agency Owner {i}',
                   email=f'owner-{i}@agency.example.invalid') for i in range(1, 7)]
    groups = [dict(key=f'group-{i}', name=name, email=f'group-{i}@agency.example.invalid')
              for i, name in enumerate(('Windows Operations', 'Linux Operations',
                                       'Endpoint Services', 'Digital Services'), 1)]
    definitions = [
        ('Windows server', 'WIN-SRV', 8, ['CVE-2021-34527', 'CVE-2023-23397'], 'windows-assessment'),
        ('Linux server', 'LNX-SRV', 8,
         ['CVE-2021-4034', 'CVE-2023-38408', 'CVE-2024-6387', 'CVE-2022-3602', 'CVE-2022-3786'], 'linux-assessment'),
        ('Workstation', 'WS', 8, ['CVE-2023-38545', 'CVE-2023-23397', 'CVE-2021-34527'], 'desktop-assessment'),
        ('Web application', 'WEB', 6,
         ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105', 'CVE-2021-44832'], 'java-assessment'),
    ]
    assets, tenable, defender = [], [], []
    first_observations = []
    for group, (kind, prefix, size, ids, component) in enumerate(definitions, 1):
        for i in range(size):
            key = f'{prefix}-{i+1:03}'
            hostname = f'{key.lower()}.agency.example.invalid'
            if key in ('WIN-SRV-001', 'WIN-SRV-002'):
                hostname = 'shared-name.agency.example.invalid'
            asset = dict(key=key, type=kind, hostname=hostname, owner_key=f'owner-{len(assets)%6+1}',
                         resolver_group=f'group-{group}', criticality='High' if group in (1, 4) else 'Medium',
                         aliases={'Tenable': f'tenable-{key}', 'Defender': f'defender-{key}'},
                         components=[dict(key=component, product=f'Synthetic {kind} assessment target',
                                          installed_version=None, location=f'synthetic://{key}/primary')])
            if key == 'WEB-001':
                asset['components'].append(dict(key=component+'-second-instance',
                    product=f'Synthetic {kind} assessment target', installed_version=None,
                    location=f'synthetic://{key}/secondary'))
            assets.append(asset)
            a = dict(plugin_id=f'plugin-{len(assets):03}', host_uuid=asset['aliases']['Tenable'],
                     hostname=hostname, component_key=component, cve=[ids[(2*i) % len(ids)]],
                     severity=4 if len(assets)%3 == 0 else 3, last_seen='2026-10-18T09:00:00Z',
                     scanner_text='SYNTHETIC observation; version/applicability unverified')
            b = dict(findingId=f'finding-{len(assets):03}', deviceId=asset['aliases']['Defender'],
                     deviceName=hostname, softwareKey=component, cveId=ids[(2*i+1) % len(ids)],
                     severity='Medium' if len(assets)%2 else 'High', detectedAt='2026-10-19T10:00:00Z',
                     scannerText='SYNTHETIC observation; no patch or targeting assertion')
            tenable.append(a)
            defender.append(b)
            first_observations.append((asset, a))
    # Same CVE/asset/component from both scanners; dates and severity differ.
    for i, (asset, a) in enumerate(first_observations[:10]):
        defender.append(dict(findingId=f'cross-scanner-{i}', deviceId=asset['aliases']['Defender'],
            deviceName=asset['hostname'], softwareKey=a['component_key'], cveId=a['cve'][0],
            severity='Low', detectedAt='2026-10-20T10:00:00Z', scannerText='SYNTHETIC overlapping observation'))
    # Same asset and CVE, separate explicitly mapped software instance: must not merge.
    web = next(a for a in assets if a['key'] == 'WEB-001')
    web_row = next(r for r in tenable if r['host_uuid'] == web['aliases']['Tenable'])
    tenable.append(deepcopy(web_row) | {'component_key': 'java-assessment-second-instance', 'plugin_id': 'second-instance'})
    tenable.extend([deepcopy(tenable[0]), deepcopy(tenable[0])])
    # Six independently quarantined cases; every original row will remain in SQLite.
    tenable.append(deepcopy(tenable[0]) | {'plugin_id': 'bad-cve', 'cve': ['not-a-cve']})
    missing = deepcopy(tenable[0]) | {'plugin_id': 'missing-cve'}
    del missing['cve']
    tenable.append(missing)
    tenable.append(deepcopy(tenable[0]) | {'plugin_id': 'ambiguous-host', 'host_uuid': None})
    defender.append(deepcopy(defender[0]) | {'findingId': 'unknown-device', 'deviceId': 'unmapped-device'})
    defender.append(deepcopy(defender[0]) | {'findingId': 'missing-component', 'softwareKey': 'unmapped-instance'})
    defender.append(deepcopy(defender[0]) | {'findingId': 'bad-time', 'detectedAt': 'not-a-timestamp'})
    observed_cves = {c for row in tenable for c in row.get('cve', []) if c.startswith('CVE-')}
    observed_cves |= {row['cveId'] for row in defender}
    assert observed_cves == cves, (observed_cves, cves)
    inventory = dict(schema_version='1', label='SYNTHETIC hypothetical state agency',
        owners=owners, resolver_groups=groups, assets=assets,
        applicability='Unknown for all synthetic installations; no confirmed remediation equivalence',
        review_hints=['Multiple CVEs on the same Java/OpenSSL assessment target are review candidates only'])
    write_json(directory / 'inventory.json', inventory)
    write_json(directory / 'tenable.json', dict(format='synthetic-tenable', format_version='1',
        synthetic=True, tenant='agency-demo', scan_id='tenable-scan-v1', exported_at=SCENARIO_CLOCK, findings=tenable))
    write_json(directory / 'defender.json', dict(format='synthetic-defender', format_version='1',
        synthetic=True, tenantId='agency-demo', scanId='defender-scan-v1', exportedAt=SCENARIO_CLOCK, value=defender))
    # Identical repeat file: importing a differently named copy must not change state.
    (directory / 'tenable_repeat.json').write_bytes((directory / 'tenable.json').read_bytes())
    files = ('inventory.json', 'cve_sources.json', 'tenable.json', 'defender.json', 'tenable_repeat.json')
    write_json(directory / 'manifest.json', dict(schema_version='1', scenario='state-agency-scanner-demo',
        version=1, fixed_clock=SCENARIO_CLOCK, seed=1, label='SYNTHETIC / offline deterministic ingestion',
        files={name: sha256((directory/name).read_bytes()).hexdigest() for name in files},
        expected=dict(assets=30, raw_findings=79, valid_rows=73, normalized_records=61,
                      duplicates_consolidated=12, quarantined_rows=6, unresolved_identity_conflicts=3,
                      exact_duplicate_rows=2, cve_identifiers=12),
        exclusions=['No verified asset applicability', 'No patches, remediation equivalence or exploitation claims']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=FIXTURE_DIR)
    build(parser.parse_args().output_dir)
