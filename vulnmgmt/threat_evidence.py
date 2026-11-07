"""Official-source parsing and hash/quote/curated-attribution enforcement. No model."""
from datetime import date, timedelta
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .enrichment_evidence import timestamp, validate_source, freshness
from .research_sources import fetch_source, source_text
from .services import canonical
from .live_contracts import LiveResearchError, redact
from .threat_contracts import ThreatInput, Agent4Result, ReportFact

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT/'fixtures/threat/v1'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
KEV_MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'


def official(url, kind):
    p = urlsplit(url)
    if p.scheme != 'https' or p.username or p.password or p.fragment or p.port not in (None,443):
        return False
    if kind == 'KEV':
        return url in (KEV_URL, KEV_MIRROR)
    if kind == 'EPSS':
        return p.hostname == 'api.first.org' and p.path == '/data/v1/epss' and set(parse_qs(p.query)) <= {'cve','date','limit'}
    return kind == 'Sector' and p.hostname == 'www.cisa.gov' and p.path.startswith('/news-events/cybersecurity-advisories/') and not p.query


def retrieve(source_id, url, kind):
    if not official(url, kind):
        raise LiveResearchError('Agent 4 source endpoint rejected.')
    # Existing bounded capture utility, one attempt only; retains failures.
    return fetch_source(source_id, url, kind, attempts=1)


def bundle():
    manifest = json.loads((FIXTURES/'manifest.json').read_text(encoding='utf-8'))
    sources = []
    for item in manifest['sources']:
        path = (ROOT/item['path']).resolve()
        if not path.is_relative_to(ROOT/'fixtures') or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise LiveResearchError('Agent 4 fixture integrity failed.')
        sources.append(json.loads(path.read_text(encoding='utf-8')))
    return manifest, sources


def empty_signal(state='Not evaluated'):
    return dict(state=state, value=None, percentile=None, observed_at=None, checked_at=None,
                source_ids=[], freshness='Unavailable')


def build(cve, workspace, as_of, captures, curated=()):
    now = timestamp(as_of)
    signals = {'KEV': [], 'EPSS': []}
    sources, facts, limitations = [], [], []
    for capture in captures:
        kind = capture.get('kind')
        if kind not in ('KEV','EPSS','Sector'):
            continue
        sid = capture['id']
        if not official(capture['url'],kind) or not official(capture['final_url'],kind):
            raise LiveResearchError('Agent 4 source identity rejected.')
        try:
            usable = validate_source(capture)
        except (ValueError,KeyError,TypeError):
            raise LiveResearchError('Agent 4 capture integrity or feed structure rejected.') from None
        if not usable:
            limitations.append(sid+': retrieval unavailable; absence is not negative evidence.')
            sources.append(dict(id=sid,url=capture['url'],kind=kind,retrieved_at=capture['retrieved_at'],
                expires_at=capture['expires_at'],content_hash=None,text='',text_hash=hashlib.sha256(b'').hexdigest(),
                freshness='Unavailable',confidence='unavailable'))
            if kind in signals:
                signals[kind].append(empty_signal('Unknown'))
            continue
        state = freshness(capture,as_of)
        text = source_text(capture)
        if kind == 'KEV':
            payload = json.loads(capture['body'])
            if any(date.fromisoformat(r['dateAdded']) > timestamp(payload['dateReleased']).date() for r in payload['vulnerabilities']):
                raise LiveResearchError('KEV entry date exceeds catalog release date.')
            entry = next((r for r in payload['vulnerabilities'] if r['cveID']==cve),None)
            text = canonical(entry) if entry else canonical({'checked_cve':cve,'catalog_count':payload['count'],'membership':False})
            signals[kind].append(dict(state='Confirmed' if entry else 'Not listed',value=entry is not None,
                percentile=None,observed_at=payload['dateReleased'],checked_at=capture['retrieved_at'],source_ids=[sid],freshness=state))
        elif kind == 'EPSS':
            payload = json.loads(capture['body'])
            # A partial/paginated or duplicate response cannot prove a complete lookup.
            if payload.get('offset',0) != 0 or len({r['cve'] for r in payload['data']}) != len(payload['data']):
                raise LiveResearchError('Agent 4 EPSS response is partial or duplicated.')
            record = next((r for r in payload['data'] if r['cve']==cve),None)
            text = canonical(record) if record else canonical({'checked_cve':cve,'record':None})
            value, percentile = (float(record['epss']),float(record['percentile'])) if record else (None,None)
            if record and (not math.isfinite(value) or not math.isfinite(percentile)):
                raise LiveResearchError('Agent 4 EPSS score is not finite.')
            if record and now.date() > date.fromisoformat(record['date']):
                state = 'Stale'
            signals[kind].append(dict(state='Confirmed' if record else 'Unknown',value=value,
                percentile=percentile,observed_at=record['date'] if record else None,checked_at=capture['retrieved_at'],source_ids=[sid],freshness=state))
        else:
            # Bind source-bound curated report assertions to this exact capture and CVE.
            for item in curated:
                if item['cve_id'] == cve and item['content_hash'] == capture['content_sha256']:
                    if item['excerpt'] not in text or cve not in text:
                        raise LiveResearchError('Curated threat assertion is not supported by its bound capture.')
                    facts.append(dict(source_id=sid, **{k:item[k] for k in ('topic','stance','excerpt','provenance')}))
            pos = text.find(cve)
            start = max(0,pos-1200)
            text = text[start:start+12000] if pos>=0 else ''
        sources.append(dict(id=sid,url=capture['url'],kind=kind,retrieved_at=capture['retrieved_at'],
            expires_at=capture['expires_at'],content_hash=capture['content_sha256'],text=text,
            text_hash=hashlib.sha256(text.encode()).hexdigest(),freshness=state,confidence='primary_source'))
        if state != 'Fresh':
            limitations.append(sid+': '+state+'; historical evidence does not establish current threat state.')
    def combine(kind):
        rows=signals[kind]
        valid=[r for r in rows if r['source_ids']]
        if not valid:
            return empty_signal('Unknown' if rows else 'Not evaluated')
        if len({canonical([r['state'],r['value'],r['observed_at']]) for r in valid})>1:
            return dict(empty_signal('Conflicting'),source_ids=sorted({s for r in valid for s in r['source_ids']}),freshness='Conflicting')
        return dict(valid[0],source_ids=sorted({s for r in valid for s in r['source_ids']}))
    # Facts outside bounded excerpts are deliberately withheld, never stitched.
    facts=[f for f in facts if any(s['id']==f['source_id'] and f['excerpt'] in s['text'] for s in sources)]
    return ThreatInput.model_validate(dict(cve_id=cve,workspace_id=workspace,as_of=as_of,sources=sources,
        report_facts=facts,kev=combine('KEV'),epss=combine('EPSS'),source_limitations=limitations+[
            'EPSS estimates exploitation probability over the next 30 days; it is not proof of exploitation.',
            'KEV membership does not prove government targeting or an active attack on an asset.',
            'Interpretations/prioritization are unverified; inventory applicability remains unknown.'])).model_dump()


def context(data, cve, secret=''):
    if not any(f['cve_id']==cve for f in data['findings']):
        raise LiveResearchError('Selected CVE is not in this workspace.')
    manifest,_ = bundle()
    captures=[]
    for source in data['sources']:
        if source['snapshot_json']:
            capture=json.loads(source['snapshot_json'])
            if capture.get('kind') in ('KEV','EPSS','Sector'):
                if capture.get('content_sha256') != source['content_hash']:
                    raise LiveResearchError('Workspace threat capture integrity failed.')
                captures.append(dict(capture,id=source['id']))
        elif source['publisher']=='Agent 4 official source' and source['fetch_status']=='Failed':
            captures.append(dict(id=source['id'],url=source['url'],final_url=source['url'],kind='Sector',
                retrieved_at=source['retrieved_at'],expires_at=source['retrieved_at'],fetch_status='Failed'))
    return redact(build(cve,data['workspace_id'],data['as_of'],captures,manifest['report_facts']),secret)


def validate(candidate, supplied):
    trusted=ThreatInput.model_validate(supplied)
    result=Agent4Result.model_validate(candidate)
    def reject():
        raise LiveResearchError('Agent 4 unsupported assertion, citation, feed signal or attribution rejected.')
    if (result.cve_id!=trusted.cve_id or canonical(result.kev.model_dump())!=canonical(trusted.kev.model_dump())
            or canonical(result.epss.model_dump())!=canonical(trusted.epss.model_dump())):
        reject()
    sources={s.id:s for s in trusted.sources}
    for s in sources.values():
        if not official(s.url,s.kind) or hashlib.sha256(s.text.encode()).hexdigest()!=s.text_hash:
            reject()
    for name in ('exploitation','government_targeting'):
        claim=getattr(result,name)
        supported={f.stance for f in trusted.report_facts if f.topic==name}
        if name=='exploitation' and trusted.kev.state=='Confirmed' and trusted.kev.value is True:
            supported.add('Confirmed')
        if len(supported)>1 and claim.status!='Conflicting':
            reject()
        if supported=={'Confirmed'} and claim.status!='Confirmed':
            reject()
        if claim.status in ('Unknown','Not evaluated'):
            if claim.value is not None or claim.evidence:
                reject()
            continue
        if not claim.evidence or not claim.value or claim.value not in [q.excerpt for q in claim.evidence]:
            reject()
        stances=set()
        for q in claim.evidence:
            s=sources.get(q.source_id)
            if s is None or '...' in q.excerpt or '\u2026' in q.excerpt or q.excerpt not in s.text:
                reject()
            eligible=[f for f in trusted.report_facts if f.source_id==q.source_id and f.topic==name and f.excerpt==q.excerpt]
            if name=='exploitation' and s.kind=='KEV' and trusted.kev.state=='Confirmed' and trusted.kev.value is True and q.source_id in trusted.kev.source_ids and trusted.cve_id in q.excerpt:
                stances.add('Confirmed')
            elif eligible:
                stances.update(f.stance for f in eligible)
            else:
                reject()
        if claim.status=='Confirmed' and stances!={'Confirmed'}:
            reject()
        if claim.status=='Conflicting' and (stances!={'Confirmed','Contradicted'} or len({sources[q.source_id].url for q in claim.evidence})<2):
            reject()
    return result


def assess(candidate, supplied):
    validate(candidate,supplied)
    return dict(accepted=True,semantic_status='Exact source attribution checked; interpretations and analyst applicability require review',
                diagnostics=[dict(field='interpretation',category='UnverifiedInterpretation',result='Review')])
