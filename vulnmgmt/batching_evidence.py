"""Deterministic Agent 3 candidate safety envelope over existing workspace evidence."""
from hashlib import sha256
import json
from .batching_contracts import BatchInput, Agent3Result
from .dashboard_queries import revision_token
from .enrichment_evidence import validate_source, validate_rule, validate_guidance, freshness, version_applies
from .research_contracts import Guidance, RemediationRule
from .research_sources import source_text
from .live_evidence import official_url
from .live_contracts import LiveResearchError, redact, Agent2Result
from .threat_contracts import Agent4Result
from .services import digest, canonical


def review_token(data):
    """Bind source/research revisions as well as the existing operational token."""
    steps = [s for s in data['agent_steps'] if s['role_number'] in (2, 4)]
    return digest(dict(operational=revision_token(data), identity=data['workspace_identity'],generation=data['generation'],
                       research=steps, sources=data['sources'],
                       actions=data['remediation_actions'], members=data['batch_proposal_members'],
                       components=data['asset_components']))


def separate_actions(findings):
    """Conservative replay classification of two explicitly named product actions.

    Different release numbers/product aliases alone do not prove incompatibility.
    General action equivalence still requires a reviewed deterministic rule.
    """
    families=[]
    for f in findings:
        if f.exclusion or not f.historical_instruction:
            continue
        prefix=f.historical_instruction.split()[0]
        if prefix not in ('OpenSSL','OpenSSH'):
            return False
        families.append(prefix)
    return len(families)>=2 and len(set(families))>1


def context(data, component_id, secret='', finding_ids=None):
    rows = data['findings']
    scoped = [f for f in rows if f['component_id'] == component_id]
    if not scoped:
        raise LiveResearchError('Selected component is not in this workspace register.')
    anchor = scoped[0]
    ids = finding_ids if finding_ids is not None else [f['id'] for f in scoped]
    if not ids or len(ids) > 20 or len(set(ids)) != len(ids):
        raise LiveResearchError('Select one to twenty distinct workspace findings.')
    selected = [f for f in rows if f['id'] in ids]
    if len(selected) != len(ids):
        raise LiveResearchError('Unknown or foreign workspace finding selected.')
    cves = {f['cve_id'] for f in selected}
    recorded_guidance=[json.loads(s['output_json'])['guidance'] for s in data['agent_steps']
        if s['role_number']==2 and s['output_json'] and 'guidance' in json.loads(s['output_json'])
        and json.loads(s['output_json'])['guidance']['cve_id'] in cves]
    names={g[k] for g in recorded_guidance for k in ('vendor_source_id','affected_source_id') if g.get(k)}
    raw, sources, conflicted_sources = {}, [], set()
    for s in data['sources']:
        if s['workspace_id'] != data['workspace_id']:
            raise LiveResearchError('Foreign source in batching context.')
        if not s['snapshot_json'] or s['fetch_status'] != 'Success' or not official_url(s['url']):
            continue
        capture = json.loads(s['snapshot_json'])
        if capture.get('kind') not in ('CVE', 'Vendor') or not validate_source(capture):
            continue
        if capture.get('content_sha256') != s['content_hash'] or capture.get('url') != s['url']:
            continue
        text = source_text(capture)
        name=capture['id']
        if name in raw and digest(raw[name])!=digest(capture):
            conflicted_sources.add(name)
        raw[name] = capture
        if capture['kind']=='CVE' and len(text)>16000:
            text=canonical(json.loads(capture['body'])['containers']['cna'].get('affected',[]))
        if capture['kind']=='Vendor' and len(text)>16000:
            passages=sorted({q['excerpt'] for g in recorded_guidance for q in g['citations']
                             if q['source_id']==capture['id'] and q['excerpt'] in text} |
                            {g['instructions'] for g in recorded_guidance if g.get('instructions')
                             and g.get('vendor_source_id')==capture['id'] and g['instructions'] in text})
            text='\n[Separate captured passage]\n'.join(passages)
        if not text or len(text) > 16000 or not (capture['id'] in names or capture['id'] in cves or any(cve in text for cve in cves)):
            continue  # Fail closed rather than truncate action/version context.
        sources.append(dict(id=s['id'], url=s['url'], kind=capture['kind'], retrieved_at=s['retrieved_at'],
            content_hash=s['content_hash'], text=text, text_hash=sha256(text.encode()).hexdigest(),
            provenance='Hash-verified capture; bounded CNA affected JSON/vendor passages when needed. Historical, not a current deployment recommendation'))
    for name in conflicted_sources:
        raw.pop(name,None)  # Never choose one of conflicting capture revisions silently.
    guidance, references, research_conflicts = {}, [], set()
    for step in sorted(data['agent_steps'], key=lambda s:(s['run_id'], s['id'])):
        if step['role_number'] not in (2, 4) or not step['output_json']:
            continue
        if step['workspace_id']!=data['workspace_id']:
            raise LiveResearchError('Foreign research step in batching context.')
        payload = json.loads(step['output_json'])
        if 'guidance' in payload and payload['guidance']['cve_id'] in cves:
            g = Guidance.model_validate(payload['guidance'])
            try:
                validate_guidance(g, raw)
            except (ValueError, KeyError):
                continue
            # Conflicting guidance must never be overwritten by a later supported claim.
            rank={'Supported':0,'Missing':1,'Conflicting':2}
            if g.cve_id not in guidance or rank[g.status]>rank[guidance[g.cve_id].status]:
                guidance[g.cve_id] = g
            content, cve = g.model_dump(), g.cve_id
            origin, phash, status = payload.get('origin', 'human_curated_source_backed_replay'), None, 'Curated replay; not analyst approval'
            source_names={g.affected_source_id,g.vendor_source_id}|{q.source_id for q in g.citations}
            provenance=[q for q in data['sources'] if q['snapshot_json'] and json.loads(q['snapshot_json']).get('id') in source_names]
        elif payload.get('result') and payload.get('cve_id') in cves:
            if (payload.get('workspace_id') != data['workspace_id'] or
                    payload.get('workspace_identity') != data['workspace_identity'] or payload.get('generation') != data['generation'] or
                    digest({k:v for k,v in payload.items() if k!='proposal_hash'}) != payload.get('proposal_hash')):
                raise LiveResearchError('Research provenance is foreign or altered.')
            content, cve = payload['result'], payload['cve_id']
            origin, phash, status = payload['execution']['origin'], payload['proposal_hash'], payload['review_status']
            if payload.get('error') or not payload['execution'].get('evidence_validation', {}).get('accepted'):
                continue
            (Agent2Result if step['role_number']==2 else Agent4Result).model_validate(content)
            provenance=payload['sources']
            by_id={q['id']:q for q in data['sources']}
            for q in provenance:
                saved=by_id.get(q['id'])
                if (not saved or any(saved[k]!=q[k] for k in ('url','content_hash','retrieved_at')) or
                        (q['content_hash'] is not None and (not saved['snapshot_json'] or
                         sha256(json.loads(saved['snapshot_json'])['body'].encode()).hexdigest()!=q['content_hash']))):
                    raise LiveResearchError('Research source provenance is missing or altered.')
            if step['role_number']==2 and (content.get('applicability')=='Conflicting Evidence' or any(
                    content.get(k,{}).get('status')=='Conflicting Evidence'
                    for k in ('vendor_remediation','affected_product','affected_versions'))):
                research_conflicts.add(cve)
        elif 'threat' in payload and payload['threat']['cve_id'] in cves:
            content, cve = payload['threat'], payload['threat']['cve_id']
            origin, phash, status = payload.get('origin','deterministic_captured_feed_parser'), None, 'Captured replay; not analyst approval'
            source_names={content.get('kev_source_id'),content.get('epss_source_id')} | {
                q['source_id'] for k in ('exploitation_citations','sector_citations') for q in content.get(k,[])}
            provenance=[q for q in data['sources'] if q['snapshot_json'] and json.loads(q['snapshot_json']).get('id') in source_names]
        else:
            continue
        if len(canonical(content)) > 16000:
            continue
        references.append(dict(step_id=step['id'], run_id=step['run_id'], role=step['role_number'], cve_id=cve,
            origin=origin, proposal_hash=phash, review_status=status, content_json=canonical(content),
            source_provenance_json=canonical([{k:q[k] for k in ('id','url','retrieved_at','content_hash')}
                for q in provenance])))
    findings = []
    for f in sorted(selected, key=lambda f:f['id']):
        g = guidance.get(f['cve_id'])
        assumptions = [a for a in data['synthetic_applicability'] if a['component_id']==f['component_id']]
        component = next(x for x in data['asset_components'] if x['id']==f['component_id'])
        assumptions = [a for a in assumptions if a['expected_component_revision']==component['revision']]
        applicable = 'Synthetic assumption' if len(assumptions)==1 and f['installed_version'] is None else 'Unknown'
        exclusion = ('Cross-asset' if f['asset_id'] != anchor['asset_id'] else
                     'Different component' if f['component_id'] != component_id else
                     'Not unresolved' if f['status'] not in ('Open','In Remediation') else
                     'Conflicting vendor guidance' if f['cve_id'] in research_conflicts or (g and g.status=='Conflicting') else None)
        quotes = []
        if g and g.status=='Supported':
            source = next((s for s in sources if raw.get(g.vendor_source_id,{}).get('url')==s['url']),None)
            if source:
                quotes=[dict(source_id=source['id'], excerpt=g.instructions)]
        findings.append(dict(finding_id=f['id'],cve_id=f['cve_id'],asset_id=f['asset_id'],component_id=f['component_id'],
            product=f['product'],published_products=sorted({p.get('product') or p.get('packageName') for p in
                json.loads(g.affected_json) if p.get('product') or p.get('packageName')}) if g else [],
            installed_version=f['installed_version'],status=f['status'],severity=f['severity'],
            applicability=applicable,assumption=canonical(assumptions[0]) if applicable=='Synthetic assumption' else None,
            remediation_evidence=quotes,historical_instruction=g.instructions if quotes else None,exclusion=exclusion))
    options=[]
    for action in sorted(data['remediation_actions'], key=lambda a:a['id']):
        if action['status']!='Confirmed':
            continue
        try:
            rule=RemediationRule.model_validate_json(action['applicability_json'])
            if (action['action_key'],action['product'],action['instructions']) != (rule.action_key,rule.product,rule.instruction):
                continue
            validate_rule(rule,guidance,raw)
            source=next(s for s in sources if s['url']==raw[rule.source_id]['url'])
            if freshness(raw[rule.source_id],data['as_of'])!='Fresh':
                continue
        except (ValueError, KeyError, StopIteration):
            continue
        members=[]
        for f in findings:
            if f['exclusion'] or f['cve_id'] not in rule.cve_ids:
                continue
            # CNA freshness and affected-product guidance are required as in the original engine.
            g=guidance[f['cve_id']]
            if freshness(raw[g.affected_source_id],data['as_of'])!='Fresh':
                continue
            if f['assumption']:
                a=json.loads(f['assumption'])
                if a['product']!=rule.product or not version_applies(a['installed_version'],rule):
                    continue
            elif f['installed_version'] is not None:
                continue  # No reviewed real-inventory applicability path is implemented.
            members.append(f['finding_id'])
        if len(members)<2:
            continue
        options.append(dict(action_id=action['id'],rule=rule.model_dump(),source_id=source['id'],
            evidence=[dict(source_id=source['id'],excerpt=rule.instruction),
                      dict(source_id=source['id'],excerpt=rule.affected_excerpt)],finding_ids=sorted(members),
            existing_proposal_ids=[b['id'] for b in data['remediation_batches']
                if b['asset_id']==anchor['asset_id'] and b['action_id']==action['id']]))
    limitations=['Historical vendor fixes do not establish a currently supported secure deployment target.',
        'Synthetic assumptions are not scanner-verified product/version applicability; unknowns require analyst validation.',
        'Agent 2/4 research review is separate from operational batch approval; pending research is not approved.',
        'Threat evidence affects prioritization considerations only, never patch equivalence or deterministic SLA.',
        'Only existing reviewed deterministic vendor rules are eligible; the model cannot invent new action equivalence.']
    shared=[]
    if len(canonical(references).encode('utf-8'))>30000:
        # Lossless request-local dictionary: preserve EVERY research reference and
        # exact original JSON text. Never drop old/conflicting research or raise caps.
        counts={}
        for ref in references:
            for key in ('content_json','source_provenance_json'):counts[ref[key]]=counts.get(ref[key],0)+1
        texts={digest(text):text for text,count in counts.items() if count>1 and len(text)>200}
        shared=[dict(sha256=key,json_text=text) for key,text in sorted(texts.items())]
        for ref in references:
            for key in ('content_json','source_provenance_json'):
                token=digest(ref[key])
                if token in texts:ref[key]=canonical({'shared_research_text_sha256':token})
    return BatchInput.model_validate(redact(dict(workspace_id=data['workspace_id'],asset_id=anchor['asset_id'],
        asset_key=anchor['asset_key'],component_id=component_id,component_key=anchor['component_key'],as_of=data['as_of'],
        findings=findings,options=options,research=references,shared_research_text=shared,sources=sources,source_limitations=limitations),secret)).model_dump()


def validate(candidate, supplied):
    """A model may decline eligible groups, but cannot enlarge the deterministic envelope."""
    s=BatchInput.model_validate(supplied)
    r=Agent3Result.model_validate(candidate)
    def require(ok, message):
        if not ok:
            raise LiveResearchError(message)
    require((r.workspace_id,r.asset_id,r.component_id)==(s.workspace_id,s.asset_id,s.component_id),'Batch identity mismatch.')
    findings={f.finding_id:f for f in s.findings}
    options={o.action_id:o for o in s.options}
    sources={q.id:q for q in s.sources}
    used=[]
    for group in r.batches:
        option=options.get(group.action_id)
        require(option is not None,'No verified shared action supports this batch.')
        rule=option.rule
        require(set(group.finding_ids)<=set(option.finding_ids),'Cross-asset/component or unsupported action member.')
        selected=[findings[f] for f in group.finding_ids]
        require(len(set(group.finding_ids))==len(group.finding_ids),'Duplicate batch members.')
        require(sorted(group.cve_ids)==sorted(f.cve_id for f in selected),'Batch CVEs do not match normalized findings.')
        require((group.product,group.affected_versions,group.historical_target_version,group.historical_instruction)==
            (rule.product,rule.affected_min+' to '+rule.affected_max_inclusive,rule.target_version,rule.instruction),
            'Altered product/version/patch action facts.')
        require(group.vendor_evidence==option.evidence,'Missing or fabricated vendor citations.')
        for quote in group.vendor_evidence:
            src=sources.get(quote.source_id)
            require(src is not None and src.kind=='Vendor' and official_url(src.url) and
                sha256(src.text.encode()).hexdigest()==src.text_hash and quote.excerpt in src.text,
                'Invalid vendor source or quotation.')
        assumed=all(f.applicability=='Synthetic assumption' for f in selected)
        require((group.applicability,group.decision)==(('Synthetic assumption','Shared action proposed') if assumed
            else ('Unknown','Needs applicability review')),'Unverified applicability promoted to a supported batch.')
        used+=group.finding_ids
    for excluded in r.excluded:
        f=findings.get(excluded.finding_id)
        require(f is not None,'Foreign excluded finding.')
        require(not f.exclusion or excluded.reason==f.exclusion,'Deterministic exclusion was overridden.')
        require(excluded.reason!='Separate remediation' or separate_actions(s.findings),
            'Different versions alone do not prove separate remediation actions.')
        used.append(excluded.finding_id)
    require(len(used)==len(set(used)) and set(used)==set(findings),'All selected findings must be accounted for exactly once.')
    require(len(set(r.research_step_ids))==len(r.research_step_ids) and set(r.research_step_ids)=={x.step_id for x in s.research},
        'Research references missing or fabricated.')
    return r


def assess(candidate, supplied):
    validate(candidate,supplied)
    return dict(accepted=True,semantic_status='Deterministic identity/action/citation envelope checked; reasoning requires analyst review',
        diagnostics=[dict(field='interpretation',category='UnverifiedInterpretation',result='Review')])


def canonicalize(candidate, supplied):
    """New evaluations only: lossless quote ordering and source-bound range extraction.

    Legacy validate() and historical stored outcomes intentionally remain unchanged.
    No whitespace edits, fuzzy matching, new boundaries or citation deduplication.
    """
    s=BatchInput.model_validate(supplied)
    result=Agent3Result.model_validate(candidate).model_dump()
    options={o.action_id:o for o in s.options}
    for group in result['batches']:
        option=options.get(group['action_id'])
        if option is None:
            raise LiveResearchError('No verified shared action supports this batch.')
        expected=[q.model_dump() for q in option.evidence]
        actual=group['vendor_evidence']
        identities=lambda quotes:[(q['source_id'],q['excerpt']) for q in quotes]
        if len(actual)!=len(expected) or sorted(identities(actual))!=sorted(identities(expected)):
            raise LiveResearchError('Missing, duplicated, altered or fabricated vendor citations.')
        normalized=option.rule.affected_min+' to '+option.rule.affected_max_inclusive
        if group['affected_versions']!=normalized:
            quote=dict(source_id=option.source_id,excerpt=option.rule.affected_excerpt)
            if group['affected_versions']!=option.rule.affected_excerpt or quote not in actual:
                raise LiveResearchError('Affected range is not the exact reviewed range or its bound vendor quotation.')
            group['affected_versions']=normalized
        group['vendor_evidence']=expected
    validate(result,supplied)  # Still enforces source hashes, association, identity and applicability.
    return result


def validate_canonical(candidate,supplied):
    return validate(canonicalize(candidate,supplied),supplied)


def assess_canonical(candidate,supplied):
    normalized=canonicalize(candidate,supplied)
    result=assess(normalized,supplied)
    result['canonicalization']=dict(policy='m6d-agent3-source-bound-v2',original_sha256=digest(candidate),
        canonical_sha256=digest(normalized),changed=normalized!=candidate,
        limitation='Only exact source-bound range extraction and citation permutation; original model candidate retained.')
    return result


def research_text(supplied,value):
    parsed=json.loads(value)
    if not isinstance(parsed,dict) or set(parsed)!={'shared_research_text_sha256'}:return value
    token=parsed['shared_research_text_sha256']
    matches=[item.json_text for item in supplied.shared_research_text if item.sha256==token]
    if len(matches)!=1 or digest(matches[0])!=token:
        raise LiveResearchError('Shared research text missing, ambiguous or altered.')
    return matches[0]
