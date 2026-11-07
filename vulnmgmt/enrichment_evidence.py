"""Deterministic evidence validation and replay parsing; no model or network calls."""
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from pathlib import Path

from packaging.version import Version, InvalidVersion

from .research_contracts import Guidance, RemediationRule, ThreatAssessment, Citation, BatchCandidate
from .research_sources import RESEARCH_DIR, source_text, validate_url
from .services import canonical


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Evidence time must have a timezone')
    return parsed.astimezone(timezone.utc)


def validate_source(source):
    validate_url(source['url'])
    validate_url(source['final_url'])
    timestamp(source['retrieved_at'])
    timestamp(source['expires_at'])
    if source['fetch_status'] != 'Success':
        return False
    if sha256(source['body'].encode('utf-8')).hexdigest() != source['content_sha256']:
        raise ValueError('Evidence body hash mismatch')
    if not source['body'].strip():
        return False
    kind = source['kind']
    if kind == 'CVE':
        payload = json.loads(source['body'])
        return (payload['cveMetadata']['cveId'] == source['id']
                and payload['cveMetadata']['state'] == 'PUBLISHED')
    if kind == 'KEV':
        payload = json.loads(source['body'])
        entries = payload['vulnerabilities']
        return (payload['count'] == len(entries) and len({v['cveID'] for v in entries}) == len(entries)
                and timestamp(payload['dateReleased']) <= timestamp(source['retrieved_at']))
    if kind == 'EPSS':
        payload = json.loads(source['body'])
        if payload.get('status') != 'OK' or payload.get('total') != len(payload.get('data', [])):
            return False
        return all(0 <= float(r['epss']) <= 1 and 0 <= float(r['percentile']) <= 1
                   and date.fromisoformat(r['date']) <= timestamp(source['retrieved_at']).date()
                   for r in payload['data'])
    return 'enable JavaScript to run this app' not in source_text(source)


def freshness(source, as_of):
    time = timestamp(as_of)
    if time < timestamp(source['retrieved_at']):
        return 'FutureEvidence'
    if time > timestamp(source['expires_at']):
        return 'Stale'
    if source['fetch_status'] == 'Success' and source['kind'] == 'EPSS':
        data = json.loads(source['body'])['data']
        if any(time.date() > date.fromisoformat(r['date']) for r in data):
            return 'Stale'
    if source['fetch_status'] == 'Success' and source['kind'] == 'KEV':
        published = timestamp(json.loads(source['body'])['dateReleased'])
        if time > published + timedelta(days=1):
            return 'Stale'
    return 'Fresh'


def validate_citation(citation, sources):
    source = sources.get(citation.source_id)
    if source is None or not validate_source(source):
        raise ValueError('Citation references unavailable/unusable evidence')
    if ' '.join(citation.excerpt.split()) not in source_text(source):
        raise ValueError('Unsupported citation excerpt')


def validate_guidance(guidance: Guidance, sources):
    source = sources.get(guidance.affected_source_id)
    if source is None or source['id'] != guidance.cve_id or not validate_source(source):
        raise ValueError('Affected product facts require the matching published CNA record')
    affected = json.loads(source['body'])['containers']['cna'].get('affected', [])
    if json.loads(guidance.affected_json) != affected:
        raise ValueError('Unsupported affected-product/version facts')
    for citation in guidance.citations:
        validate_citation(citation, sources)
    if guidance.status == 'Supported':
        vendor = sources.get(guidance.vendor_source_id)
        if (vendor is None or vendor['kind'] != 'Vendor' or not validate_source(vendor)
                or not guidance.instructions or guidance.instructions not in source_text(vendor)
                or not guidance.fixed_version or guidance.fixed_version not in source_text(vendor)
                or guidance.fixed_version not in guidance.instructions
                or re.fullmatch(r'\d+\.\d+(?:\.\d+)?(?:p\d+)?', guidance.fixed_version) is None
                or not any(c.source_id == guidance.vendor_source_id for c in guidance.citations)):
            raise ValueError('Unsupported patch/remediation instruction')
        references = {r['url'] for r in json.loads(source['body'])['containers']['cna'].get('references', [])}
        if guidance.cve_id not in source_text(vendor) and vendor['url'] not in references:
            raise ValueError('Vendor guidance is not bound to this CVE')
    elif guidance.instructions is not None or guidance.fixed_version is not None or not guidance.gaps:
        raise ValueError('Missing/conflicting guidance must not assert a selected patch')


def validate_rule(rule: RemediationRule, guidance_by_cve, sources):
    source = sources.get(rule.source_id)
    if source is None or not validate_source(source) or source['kind'] != 'Vendor':
        raise ValueError('Remediation rule needs verified vendor evidence')
    text = source_text(source)
    if rule.instruction not in text or rule.affected_excerpt not in text or rule.target_version not in rule.instruction:
        raise ValueError('Unsupported shared remediation action')
    # The implemented rule interpreter intentionally supports only this explicitly reviewed
    # upstream advisory range; RPM/Windows/prerelease semantics are not guessed.
    if (rule.product != 'OpenSSL (upstream)' or rule.affected_min != '3.0.0'
            or rule.affected_max_inclusive != '3.0.6' or rule.target_version != '3.0.7'
            or rule.source_id != 'openssl'
            or set(rule.cve_ids) != {'CVE-2022-3602', 'CVE-2022-3786'}
            or 'versions 3.0.0 to 3.0.6' not in rule.affected_excerpt):
        raise ValueError('Unreviewed version/action rule requires analyst review')
    for cve in rule.cve_ids:
        guidance = guidance_by_cve[cve]
        if (guidance.status != 'Supported' or guidance.vendor_source_id != rule.source_id
                or guidance.fixed_version != rule.target_version or cve not in text):
            raise ValueError('CVE does not share this verified action')


def version_applies(installed, rule):
    try:
        return Version(rule.affected_min) <= Version(installed) <= Version(rule.affected_max_inclusive)
    except InvalidVersion:
        return False


def validate_candidate(candidate: BatchCandidate, findings, assumption, rule, sources, as_of):
    if assumption is None or assumption.product != rule.product or not version_applies(assumption.installed_version, rule):
        raise ValueError('Unknown or unsupported asset applicability')
    if len(candidate.member_ids) < 2 or len(set(candidate.member_ids)) != len(candidate.member_ids):
        raise ValueError('A batch requires at least two distinct findings')
    selected = [f for f in findings if f['id'] in candidate.member_ids]
    if (len(selected) != len(candidate.member_ids) or any(f['asset_id'] != candidate.asset_id for f in selected)
            or len({f['component_id'] for f in selected}) != 1
            or any(f['cve_id'] not in rule.cve_ids or f['status'] not in ('Open', 'In Remediation') for f in selected)
            or candidate.action_key != rule.action_key):
        raise ValueError('Cross-asset, incompatible component/action or invalid finding batch')
    required = {rule.source_id} | {f['cve_id'] for f in selected}
    if set(candidate.source_ids) != required or any(
            name not in sources or not validate_source(sources[name]) or freshness(sources[name], as_of) != 'Fresh'
            for name in required):
        raise ValueError('Batch evidence is unavailable, stale or incomplete')


def validate_threat(threat: ThreatAssessment, sources):
    if threat.model_dump() != assess_threat(threat.cve_id, sources).model_dump():
        raise ValueError('Threat assertion differs from validated KEV/EPSS/advisory evidence')


def assess_threat(cve, sources):
    gaps = []
    kev_source = next((s for name in ('kev-cisa', 'kev-mirror')
                       if (s := sources.get(name)) and validate_source(s)), None)
    member, entry = None, None
    if kev_source:
        data = json.loads(kev_source['body'])
        entry = next((r for r in data['vulnerabilities'] if r['cveID'] == cve), None)
        member = entry is not None
    else:
        gaps.append('KEV unavailable; absence of retrieval is not non-membership')
    epss_source = sources.get('epss')
    score = None
    if epss_source and validate_source(epss_source):
        score = next((r for r in json.loads(epss_source['body'])['data'] if r['cve'] == cve), None)
    if score is None:
        gaps.append('EPSS unavailable for this CVE')
    # A captured Log4j advisory supports exploitation, but no explicit sector claim
    # is curated here. Navigation labels and .gov ownership are not targeting evidence.
    exploitation = 'Confirmed in KEV' if member else 'Unknown'
    exploitation_citations = []
    if entry:
        exploitation_citations.append(Citation(source_id=kev_source['id'], excerpt=cve))
    advisory = sources.get('sector-log4j')
    if cve == 'CVE-2021-44228' and advisory and validate_source(advisory) and cve in source_text(advisory):
        exploitation = 'Confirmed in KEV' if member else 'Documented in advisory'
        excerpt = 'have continued to exploit CVE-2021-44228 (Log4Shell)'
        if excerpt in source_text(advisory):
            exploitation_citations.append(Citation(source_id='sector-log4j', excerpt=excerpt))
    gaps.append('Sector-specific targeting unverified; KEV and EPSS do not establish sector targeting')
    return ThreatAssessment(cve_id=cve, kev_member=member,
        kev_source_id=kev_source['id'] if kev_source else None,
        kev_added_date=entry['dateAdded'] if entry else None, kev_action=entry['requiredAction'] if entry else None,
        epss_score=float(score['epss']) if score else None,
        epss_percentile=float(score['percentile']) if score else None, epss_date=score['date'] if score else None,
        epss_source_id=epss_source['id'] if score else None, exploitation=exploitation,
        exploitation_citations=exploitation_citations,
        sector_targeting='Unknown', sector_citations=[], gaps=gaps)


def load_bundle(directory=RESEARCH_DIR):
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    for filename, expected in manifest['files'].items():
        if Path(filename).name != filename:
            raise ValueError('Invalid source path')
        if sha256((directory/filename).read_bytes()).hexdigest() != expected:
            raise ValueError('Replay file hash mismatch')
    sources = {}
    for filename in manifest['source_files']:
        if filename not in manifest['files']:
            raise ValueError('Unpinned source')
        source = json.loads((directory/filename).read_text(encoding='utf-8'))
        validate_source(source)
        if source['id'] in sources:
            raise ValueError('Duplicate source ID')
        sources[source['id']] = source
    return manifest, sources, json.loads((directory/'replay.json').read_text(encoding='utf-8'))
