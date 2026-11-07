"""Read-only, bounded authoritative-source selection and quote validation."""
import hashlib
import json
import re
from urllib.parse import urlsplit, parse_qs
from urllib.request import Request, HTTPRedirectHandler, build_opener
from .live_contracts import Agent2Result, LiveResearchError, EvidenceValidationError, redact
from .research_sources import source_text
from .services import utc

OFFICIAL = {'cveawg.mitre.org', 'services.nvd.nist.gov', 'nvd.nist.gov', 'www.cisa.gov',
            'openssl-library.org', 'curl.se', 'logging.apache.org', 'access.redhat.com',
            'msrc.microsoft.com', 'api.msrc.microsoft.com', 'www.openssh.com', 'www.openssh.org'}
VENDORS = OFFICIAL - {'cveawg.mitre.org', 'services.nvd.nist.gov', 'nvd.nist.gov', 'www.cisa.gov'}
CLAIM_FIELDS = ('description', 'affected_product', 'affected_versions', 'vendor_remediation', 'advisory_identifiers')


def official_url(url):
    try:
        p = urlsplit(url)
        return (p.scheme == 'https' and p.hostname in OFFICIAL and not p.username and not p.password
                and p.port in (None, 443) and not p.fragment and not any(
                    k.lower() in ('key', 'api_key', 'token', 'access_token') for k in parse_qs(p.query)))
    except ValueError:
        return False


def normalize(text):
    return ' '.join(text.split())


def context(data, cve, secret=''):
    findings = [f for f in data['findings'] if f['cve_id'] == cve]
    if not findings:
        raise LiveResearchError('Selected CVE is not in this workspace register.')
    guidance = [json.loads(s['output_json'])['guidance'] for s in data['agent_steps']
                if s['role_number'] == 2 and s['step_key'] == cve and s['output_json']
                and 'guidance' in json.loads(s['output_json'])]
    names = {cve} | {g[k] for g in guidance for k in ('affected_source_id', 'vendor_source_id') if g.get(k)}
    ids = {c['source_id'] for c in data['evidence_claims'] if c['cve_id'] == cve}
    sources = []
    for s in data['sources']:
        if s['fetch_status'] != 'Success' or not s['snapshot_json'] or not official_url(s['url']):
            continue
        capture = json.loads(s['snapshot_json'])
        if s['id'] not in ids and capture.get('id') not in names:
            continue
        if capture.get('kind') not in ('CVE', 'Vendor') or not isinstance(capture.get('body'), str):
            continue
        if hashlib.sha256(capture['body'].encode()).hexdigest() != s['content_hash']:
            continue  # Never supply a corrupted capture to the model.
        text = source_text(capture)
        # A bounded, CVE-centered excerpt. No model-generated source discovery.
        pos = text.upper().find(cve)
        if pos < 0:
            continue
        start = max(0, pos-2500)
        sources.append(dict(id=s['id'], url=s['url'], retrieved_at=s['retrieved_at'],
            content_hash=s['content_hash'], kind=capture['kind'], text=redact(text[start:start+10000], secret),
            text_hash=hashlib.sha256(redact(text[start:start+10000], secret).encode()).hexdigest(),
            provenance='Existing captured public evidence; not retrieved by this model run'))
    component_ids = {f['component_id'] for f in findings}
    components = {f['component_id']: f for f in findings}
    assumptions = sorted({components[a['component_id']]['asset_key']+'/'+components[a['component_id']]['component_key']+
                          ': '+a['product']+' '+a['installed_version']+' - '+a['label']
                          for a in data['synthetic_applicability'] if a['component_id'] in component_ids})
    return redact(dict(cve_id=cve, workspace_id=data['workspace_id'], synthetic_clock=data['as_of'],
                findings=[{k: f[k] for k in ('asset_key', 'component_key', 'cve_id', 'product', 'installed_version', 'severity', 'status')}
                          for f in findings], synthetic_assumptions=redact(assumptions, secret),
                historical_guidance_conflict=any(g['status'] == 'Conflicting' for g in guidance), sources=sources,
                source_limitations=['Captures are dated, not guaranteed current. Inventory applicability remains unverified.',
                                    'Each assumption applies only to its named asset/component; all other installations remain Unknown.']), secret)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise LiveResearchError('Public retrieval redirect blocked; analyst must review the destination.')


def retrieve(url):
    """One unauthenticated GET; no redirect, retry, arbitrary URL or model tool."""
    if not official_url(url):
        raise LiveResearchError('Source URL is not an approved official public endpoint.')
    request = Request(url, headers={'User-Agent': 'VulnerabilityResearchCaseStudy/1.0',
                                   'Accept': 'application/json,text/plain,text/html'})
    with build_opener(NoRedirect()).open(request, timeout=15) as response:
        if response.geturl() != url:
            raise LiveResearchError('Source destination changed.')
        body = response.read(256001)
    if len(body) > 256000:
        raise LiveResearchError('Public source exceeds the 256 KB research limit.')
    return {'body': body.decode('utf-8'), 'retrieved_at': utc()}


def normalized_supported(field, value, quotes):
    """Conservative lexical extraction, never a semantic entailment certificate."""
    if any(value == q for q in quotes):
        return True
    if field == 'affected_product' and re.fullmatch(r'[A-Za-z][A-Za-z0-9 .+_()/:-]{0,99}', value):
        return any(re.search(r'(?<![\w])'+re.escape(value)+r'(?![\w])', q) for q in quotes)
    if field == 'affected_versions':
        version = r'\d+\.\d+(?:\.\d+)*(?:[a-zA-Z0-9.+-]*)'
        match = re.fullmatch(r'(?P<product>[A-Za-z][A-Za-z0-9 .+_()/:-]{0,79}?) (?P<low>'+version+r') (?:to|through|-) (?P<high>'+version+r')', value)
        if match:
            pattern = (r'(?<![\w])'+re.escape(match['product'])+r' (?:versions? )?'+re.escape(match['low'])+
                       r' (?:to|through|-) '+re.escape(match['high'])+r' (?:are|is) (?:vulnerable|affected)\b')
            return any(re.search(pattern, q) for q in quotes)
    # Descriptions and remediation/advisory instructions stay exact quotations.
    return False


def assess(candidate, supplied):
    """Return all safe field diagnostics. Pydantic errors are handled at the boundary.

    Sources come from the application's raw-body-hash-verified capture pipeline;
    text_hash binds the exact rendered excerpt supplied to the model. Neither hash
    nor substring membership establishes semantic truth or current applicability.
    """
    result = Agent2Result.model_validate(candidate)
    diagnostics = []
    def add(field, category, outcome='Fail'):
        diagnostics.append(dict(field=field, category=category, result=outcome))
    if result.cve_id != supplied['cve_id']:
        add('cve_id', 'CVEIdentityMismatch')
    sources = {s['id']: s for s in supplied['sources']}
    fields = {}
    for field in CLAIM_FIELDS:
        start = len(diagnostics)
        claim = getattr(result, field)
        if claim.status == 'Unknown':
            if claim.value is not None or claim.evidence:
                add(field, 'UnknownClaimAssertsFacts')
            else:
                add(field, 'UnknownEvidence', 'Review')
        else:
            if not claim.evidence or (claim.status == 'Supported' and not claim.value):
                add(field, 'MissingFactualEvidence')
            for quote in claim.evidence:
                source = sources.get(quote.source_id)
                if not source or not official_url(source['url']):
                    add(field, 'UnknownSourceReference')
                    continue
                if hashlib.sha256(source['text'].encode()).hexdigest() != source.get('text_hash'):
                    add(field, 'SourceIntegrityFailure')
                    continue
                if '...' in quote.excerpt or '\u2026' in quote.excerpt:
                    add(field, 'StitchedOrModifiedQuotation')
                elif quote.excerpt not in source['text']:
                    add(field, 'QuotationNotFound')
                if field in ('vendor_remediation', 'advisory_identifiers') and urlsplit(source['url']).hostname not in VENDORS:
                    add(field, 'UnsupportedVendorRemediation')
            if claim.status == 'Supported' and claim.value and not normalized_supported(field, claim.value, [q.excerpt for q in claim.evidence]):
                add(field, 'UnsupportedVendorRemediation' if field == 'vendor_remediation' else 'UnsupportedNormalizedValue')
            if claim.status == 'Conflicting Evidence':
                if len({q.source_id for q in claim.evidence}) < 2:
                    add(field, 'ConflictingEvidenceNeedsTwoSources')
                else:
                    add(field, 'ConflictingEvidenceRequiresAnalystReview', 'Review')
        entries = diagnostics[start:]
        fields[field] = 'Fail' if any(d['result'] == 'Fail' for d in entries) else 'Review' if claim.status != 'Supported' else 'Pass'
        # Interpretation never becomes a fact, even if its adjacent quote matches.
        if claim.interpretation:
            add(field, 'UnverifiedInterpretation', 'Review')
    if not set(result.synthetic_assumptions) <= set(supplied['synthetic_assumptions']):
        add('applicability', 'InventedSyntheticAssumption')
    if result.applicability == 'Synthetic assumption' and not result.synthetic_assumptions:
        add('applicability', 'MissingSyntheticAssumption')
    add('applicability', 'UnknownAssetApplicability' if result.applicability == 'Unknown' else 'UnverifiedAssetApplicability', 'Review')
    if supplied['historical_guidance_conflict'] and (result.vendor_remediation.status == 'Supported' or not result.conflicting_or_missing_evidence):
        add('vendor_remediation', 'HistoricalGuidanceConflict')
        fields['vendor_remediation'] = 'Fail'
    if not any(item.strip() for item in result.analyst_validation):
        add('analyst_validation', 'MissingAnalystValidation')
    add('vendor_remediation', 'HistoricalGuidanceNotCurrentReleaseCertification', 'Review')
    return dict(accepted=not any(d['result'] == 'Fail' for d in diagnostics), fields=fields,
                diagnostics=diagnostics, semantic_status='Analyst review required; lexical grounding only')


def validate(candidate, supplied):
    assessment = assess(candidate, supplied)
    if not assessment['accepted']:
        raise EvidenceValidationError(assessment)
    return Agent2Result.model_validate(candidate)
