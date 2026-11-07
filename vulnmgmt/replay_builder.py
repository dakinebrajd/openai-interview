"""Offline human-curated M3 replay preparation; this is NOT model-recorded output."""
import json
import re
from hashlib import sha256
from pathlib import Path

from .enrichment_evidence import source_text, validate_guidance, validate_rule
from .research_contracts import Guidance, RemediationRule
from .research_sources import RESEARCH_DIR
from .services import canonical


def build_replay(directory=RESEARCH_DIR):
    directory = Path(directory)
    source_paths = sorted(p for p in directory.glob('*.json') if p.stem not in ('manifest', 'replay'))
    sources = {json.loads(p.read_text(encoding='utf-8'))['id']: json.loads(p.read_text(encoding='utf-8'))
               for p in source_paths}
    guidance = []
    mappings = {'CVE-2022-3602': ('openssl', '3.0.7', 'OpenSSL 3.0 users should upgrade to OpenSSL 3.0.7.'),
                'CVE-2022-3786': ('openssl', '3.0.7', 'OpenSSL 3.0 users should upgrade to OpenSSL 3.0.7.'),
                'CVE-2023-38545': ('curl', '8.4.0', 'Upgrade curl to version 8.4.0'),
                'CVE-2023-38408': ('openssh-93p2', '9.3p2', 'OpenSSH 9.3p2 was released on 2023-07-19.'),
                'CVE-2024-6387': ('openssh-98', '9.8', 'OpenSSH 9.8 was released on 2024-07-01.')}
    apache = source_text(sources['apache'])
    for cve in ('CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'):
        start = apache.index(cve+' Summary')
        section = apache[start:]
        match = re.search(r'Upgrade to (?:Log4j )?2\.3\.1[^.]+?later\)\.', section)
        # Version dots need a less restrictive sentence boundary.
        if match is None:
            match = re.search(r'Upgrade to (?:Log4j )?2\.3\.1.*?later\)\.', section)
        if not match:
            raise ValueError('Reviewed Apache recommendation not found')
        fixed = {'CVE-2021-44228': '2.15.0', 'CVE-2021-45046': '2.16.0', 'CVE-2021-45105': '2.17.0'}[cve]
        mappings[cve] = ('apache', fixed, match.group(0))
    for cve in sorted(key for key in sources if key.startswith('CVE-')):
        cna = json.loads(sources[cve]['body'])['containers']['cna']
        record = dict(cve_id=cve, affected_source_id=cve, affected_json=canonical(cna.get('affected', [])),
                      vendor_source_id=None, instructions=None, fixed_version=None,
                      status='Missing', citations=[], gaps=[], confidence='review_required')
        if cve in mappings:
            vendor, version, instruction = mappings[cve]
            record.update(vendor_source_id=vendor, fixed_version=version, instructions=instruction,
                status='Supported', confidence='primary_source',
                citations=[dict(source_id=vendor, excerpt=instruction)],
                gaps=['Historical CVE-specific fix only; not a claim that this release is currently secure or supported',
                      'Synthetic asset product/version applicability requires explicit assumptions and analyst review'])
        else:
            record['gaps'] = ['Vendor package/patch applicability requires analyst review; no patch identifier selected']
        if cve == 'CVE-2021-44832':
            record.update(status='Conflicting', vendor_source_id='apache',
                gaps=['Captured Apache table lists 2.17.0 for Java 8+, while published CNA affected range extends below 2.17.1; do not select a fix until resolved'],
                citations=[dict(source_id='apache', excerpt='Versions fixed 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later)')])
        if cve == 'CVE-2023-38545':
            record.update(status='Conflicting', instructions=None, fixed_version=None, confidence='review_required',
                gaps=['Captured CNA affected interval is internally inconsistent; curl vendor page identifies 7.69.0 through 8.3.0, fixed in 8.4.0. Retain both sources for analyst reconciliation'])
        if cve in ('CVE-2023-23397', 'CVE-2021-34527'):
            record['vendor_source_id'] = 'msrc-outlook' if cve.endswith('23397') else 'msrc-print'
            record['gaps'].append('MSRC HTTP response is a JavaScript shell, not retrieved patch guidance')
        if cve == 'CVE-2021-4034':
            record['vendor_source_id'] = 'redhat-pkexec'
            record['gaps'].append('Distribution/package-specific fixed build is not established for generic synthetic assets')
        value = Guidance.model_validate_json(canonical(record))
        validate_guidance(value, sources)
        guidance.append(value.model_dump(mode='json'))
    rule = dict(action_key='openssl-upstream-3.0.7-historical', product='OpenSSL (upstream)',
        affected_min='3.0.0', affected_max_inclusive='3.0.6', target_version='3.0.7',
        cve_ids=['CVE-2022-3602', 'CVE-2022-3786'], source_id='openssl',
        instruction='OpenSSL 3.0 users should upgrade to OpenSSL 3.0.7.',
        affected_excerpt='OpenSSL versions 3.0.0 to 3.0.6 are vulnerable to this issue.',
        warning='Historical advisory-specific common fix; revalidate current supported vendor release before any real action')
    validate_rule(RemediationRule.model_validate_json(canonical(rule)),
                  {g['cve_id']: Guidance.model_validate_json(canonical(g)) for g in guidance}, sources)
    replay = dict(schema_version='1', origin='human_curated_source_backed_replay',
        model_calls_recorded=0, guidance=guidance, rules=[rule], overlay_version='openssl-demo-v1',
        assumptions=[dict(asset_key='LNX-SRV-005', component_key='linux-assessment', product='OpenSSL (upstream)',
            installed_version='3.0.6', expected_component_revision=0,
            label='SYNTHETIC ASSUMPTION - NOT SCANNER EVIDENCE')])
    (directory/'replay.json').write_text(json.dumps(replay, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    files = source_paths + [directory/'replay.json']
    manifest = dict(schema_version='1', bundle_version='m3-v1', origin=replay['origin'],
        replay_reference_time=max(s['retrieved_at'] for s in sources.values()),
        source_files=[p.name for p in source_paths],
        files={p.name: sha256(p.read_bytes()).hexdigest() for p in files},
        freshness_policy={'KEV_days': 1, 'EPSS_days': 1, 'Vendor_days': 30},
        live_model_calls_authorized=False)
    (directory/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    build_replay()
