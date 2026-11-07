"""Agent 6 fact registry from existing deterministic ownership, SLA and evidence."""
from hashlib import sha256
import json
import re
from .drafting_contracts import DraftInput,Agent6Result
from .dashboard_queries import revision_token
from .lifecycle import _snapshot,_match,_latest_version,material_changes,_source
from .live_evidence import official_url
from .research_sources import source_text
from .live_contracts import LiveResearchError,redact
from .services import canonical,digest


OWNER_ACTION='Validate applicability and current vendor guidance; propose a schedule and provide subsequent scanner evidence.'


def review_token(data):
    return digest(dict(operational=revision_token(data),identity=data['workspace_identity'],generation=data['generation'],
        owners=data['owners'],assignments=data['asset_owners'],components=data['asset_components'],
        sources=data['sources'],scopes=data['lifecycle_scopes'],memberships=data['batch_memberships'],
        reviews=data['lifecycle_reviews'],actions=data['remediation_actions'],
        threat_research=[s for s in data['agent_steps'] if s['role_number']==4],
        threat_decisions=[a for a in data['audit_events'] if a['event_type']=='Agent4ResearchReviewRecorded']))


def prepare_context(c,data,scope_id):
    scope=next((s for s in data['lifecycle_scopes'] if s['id']==scope_id),None)
    if not scope:raise LiveResearchError('Selected drafting scope is not in this workspace.')
    snapshot=_snapshot(c,data['workspace_id'],scope_id,data['as_of'])
    ticket=_match(c,data['workspace_id'],scope)
    changes=['NewEscalation']
    if ticket:
        previous=_latest_version(c,data['workspace_id'],ticket['id'])
        if not previous:raise LiveResearchError('Existing ticket history requires reconciliation.')
        changes=material_changes(json.loads(previous['snapshot_json'])['report']['material'],snapshot['material'])
    facts=[];citations=[];raw_sources={}
    def fact(id,category,text):
        value=dict(id=id,category=category,text=text)
        prior=next((f for f in facts if f['id']==id),None)
        if prior is not None:
            if prior!=value:raise LiveResearchError('Conflicting deterministic drafting fact identity.')
            return
        facts.append(value)
    fact('synthetic-label','Warning','SYNTHETIC LOCAL DRAFT - NO EXTERNAL DELIVERY. Not an approved ticket or communication.')
    fact('asset','Deterministic policy fact','Affected asset: '+snapshot['asset']['key']+' ('+snapshot['asset']['hostname']+').')
    route=snapshot['resolver_group']
    fact('resolver','Deterministic policy fact','Assigned resolver group: '+route['name']+'; synthetic recipient: '+route['email']+'.')
    fact('deadline','Deterministic policy fact','Hypothetical first-seen SLA deadline: '+str(snapshot['material']['due_at'])+
        '; priority: '+str(snapshot['material']['priority'])+'. This is illustrative policy, not a binding agency deadline.')
    fact('action','Deterministic policy fact',snapshot['guidance'])
    fact('owner-action','Deterministic policy fact',OWNER_ACTION)
    fact('unknown-applicability','Unknown','Actual installed product/version/build and currently supported secure deployment target are unverified. Historical fixes and synthetic assumptions cannot establish them.')
    fact('approval-warning','Warning','Separate exact-revision analyst approvals are required for tickets and communications. This draft grants neither. Only adequate subsequent scanner evidence can verify remediation; owner claims remain Pending Verification.')
    fact('duplicate-state','Deterministic policy fact','Existing escalation lookup: '+('ticket '+ticket['id'] if ticket else 'no ticket')+
        '; material-change reasons: '+(', '.join(changes) if changes else 'none')+'. Final duplicate/revision decisions remain deterministic on staging.')
    ids={f['id'] for f in snapshot['findings']};cves={f['cve_id'] for f in snapshot['findings']}
    for f in snapshot['findings']:
        fact('finding:'+f['id'],'Deterministic policy fact',f['cve_id']+': scanner severity '+f['severity']+
            '; status '+f['status']+'; first seen '+f['first_seen']+'; hypothetical deadline '+str(f['sla']['due_at'])+'.')
        fact('exploitation:'+f['id'],'Verified source fact' if f['known_exploitation'] else 'Unknown',
            f['cve_id']+(': captured KEV membership supports known exploitation, not local compromise or sector targeting.'
            if f['known_exploitation'] else ': no qualifying confirmed exploitation evidence selected in this scoped snapshot; current exploitation remains Unknown, not disproven.'))
    for a in snapshot['assumptions']:
        fact('assumption:'+a['id'],'Synthetic assumption',a['label']+': '+a['product']+' '+a['installed_version']+
            ' on the named component only; not scanner-verified inventory.')
    # Accepted threat research is advisory context, never patch-equivalence,
    # scanner severity/SLA authority or a substitute for the vendor quotations.
    # Choose one current accepted record per CVE; all originals remain immutable.
    accepted={}
    for step in data['agent_steps']:
        if step['role_number']!=4 or step['step_key']!='agent4-threat-result':continue
        p=json.loads(step['output_json'])
        if not p.get('result') or p.get('cve_id') not in cves or not p.get('assessment_input'):continue
        decisions=[json.loads(a['payload_json']) for a in data['audit_events'] if a['entity_id']==p['run_id'] and a['event_type']=='Agent4ResearchReviewRecorded']
        if not any(a['decision']=='Accepted for analyst use' and a['proposal_hash']==p['proposal_hash'] for a in decisions):continue
        from .agent0 import _accepted
        _accepted(data,p,'Agent4Research')
        from .threat_evidence import validate as validate_threat
        validate_threat(p['result'],p['assessment_input'])
        old=accepted.get(p['cve_id'])
        if old is None or p['ended_at']>old['ended_at']:accepted[p['cve_id']]=p
    for cve,p in sorted(accepted.items()):
        r=p['result'];quotes=[q['excerpt'] for topic in ('exploitation','government_targeting') for q in r[topic]['evidence']]
        fact('reviewed-threat:'+cve,'Warning','ACCEPTED DATED RESEARCH CONTEXT, NOT OPERATIONAL AUTHORITY. '+cve+
            '; processing '+p['execution']['origin']+'; evidence as of '+p['evidence_as_of']+
            '. KEV '+r['kev']['state']+' (checked '+str(r['kev']['checked_at'])+'); EPSS probability '+str(r['epss']['value'])+
            ' (observed '+str(r['epss']['observed_at'])+'); public exploitation '+r['exploitation']['status']+
            '; government-sector targeting '+r['government_targeting']['status']+'. Captured report quotations: '+('; '.join(quotes) if quotes else 'None; do not infer absence of exploitation.')+
            ' Missing/conflicting information: '+'; '.join(r['conflicting_or_missing_evidence'])+
            '. EPSS is probability, KEV does not establish government targeting; no local compromise, patch equivalence or policy change is inferred.')
        for source in p['sources']:
            provenance={k:source.get(k) for k in ('url','retrieved_at','content_hash','freshness')}
            fact('reviewed-threat-source:'+digest(provenance),'Warning',
                'Agent 4 retained source (not a new retrieval by this draft): '+source['url']+'; captured '+source['retrieved_at']+
                '; SHA256 '+str(source.get('content_hash'))+'; freshness '+str(source.get('freshness'))+'.')
    for s in data['sources']:
        if s['id'] not in snapshot['sources'] or not s['snapshot_json']:continue
        _,capture,state=_source(c,data['workspace_id'],s['id'],data['as_of'])
        if 'body' not in capture or not official_url(s['url']):continue
        raw_sources[s['id']]=(s,capture,state)
    for claim in data['evidence_claims']:
        if (claim['cve_id'] not in cves or claim['claim_type']!='VendorRemediation' or
            claim['validation_status']!='Confirmed' or claim['source_id'] not in raw_sources):continue
        if not scope['individual_finding_id'] and claim['id'] not in {
            m['evidence_claim_id'] for m in data['batch_memberships'] if m['batch_id']==scope['batch_id'] and m['left_at'] is None}:
            continue  # Only the exact approved batch's action claims, never unrelated/pending research.
        source,capture,state=raw_sources[claim['source_id']]
        if capture.get('kind')!='Vendor' or claim['supporting_excerpt'] not in source_text(capture):
            raise LiveResearchError('Draft remediation claim is not supported by its captured vendor source.')
        fid='vendor:'+claim['id']
        fact(fid,'Verified source fact','Historical vendor quotation for '+claim['cve_id']+': '+claim['supporting_excerpt'])
        citations.append(dict(fact_id=fid,source_id=source['id'],excerpt=claim['supporting_excerpt']))
    for f in snapshot['findings']:
        if not f['known_exploitation']:continue
        for sid,(s,capture,state) in raw_sources.items():
            if capture.get('kind')=='KEV' and any(r['cveID']==f['cve_id'] for r in json.loads(capture['body'])['vulnerabilities']):
                citations.append(dict(fact_id='exploitation:'+f['id'],source_id=sid,excerpt=f['cve_id']))
    sources=[]
    for sid,(row,capture,state) in raw_sources.items():
        text=source_text(capture)
        if len(text)>16000 and capture.get('kind')=='CVE':
            text=canonical(json.loads(capture['body'])['containers']['cna'].get('affected',[]))
        if len(text)>16000:
            # Full body hash was checked above; only exact cited passages enter the bounded prompt.
            text='\n[Separate captured passage]\n'.join(sorted({q['excerpt'] for q in citations if q['source_id']==sid}))
        if not text:continue
        sources.append(dict(id=sid,url=row['url'],kind=capture['kind'],retrieved_at=row['retrieved_at'],
            content_hash=row['content_hash'],text=text,text_hash=sha256(text.encode()).hexdigest(),
            provenance='Saved authoritative capture; freshness '+state+' at '+data['as_of']+'; not a current-source retrieval'))
        fact('source:'+sid,'Verified source fact','Source: '+row['url']+'; captured '+row['retrieved_at']+
            '; SHA256 '+row['content_hash']+'; freshness '+state+' at the recorded assessment, not a new current-source check.')
    supplied=dict(workspace_id=data['workspace_id'],workspace_identity=data['workspace_identity'],generation=data['generation'],
        scope_id=scope_id,snapshot_binding_hash=snapshot['binding_hash'],snapshot_material_hash=snapshot['material_hash'],
        as_of=data['as_of'],asset_id=snapshot['asset']['id'],resolver_group_id=route['id'],recipient=route['email'],
        finding_ids=sorted(ids),cve_ids=sorted(cves),hypothetical_deadline=snapshot['material']['due_at'],facts=facts,
        citations=citations,sources=sources,source_limitations=['Historical guidance only; current safe target and real applicability unknown.',
            'No quarantined Agent 3 result is consumed as accepted research.',
            'Interpretations are unverified; analyst review of exact rendered content is required.'])
    return dict(data,_agent6_input=DraftInput.model_validate(supplied).model_dump())


def context(data,scope_id,secret=''):
    supplied=data.get('_agent6_input')
    if not supplied or supplied['scope_id']!=scope_id:raise LiveResearchError('Missing deterministic drafting snapshot.')
    return redact(supplied,secret)


def validate(candidate,supplied):
    s=DraftInput.model_validate(supplied);r=Agent6Result.model_validate(candidate)
    def require(ok,message):
        if not ok:raise LiveResearchError(message)
    for key in ('workspace_id','scope_id','snapshot_binding_hash','asset_id','resolver_group_id','recipient','hypothetical_deadline'):
        require(getattr(r,key)==getattr(s,key),'Draft identity/ownership/deadline differs from deterministic facts.')
    for key in ('finding_ids','cve_ids'):
        require(sorted(getattr(r,key))==sorted(getattr(s,key)),'Draft findings/CVEs differ from the approved scope.')
    expected=[q.model_dump() for q in s.citations];actual=[q.model_dump() for q in r.citations]
    require(len(actual)==len(expected) and sorted(map(canonical,actual))==sorted(map(canonical,expected)),
        'Missing, duplicated, reassociated or fabricated draft citations.')
    sources={q.id:q for q in s.sources};facts={f.id:f for f in s.facts}
    for q in r.citations:
        source=sources.get(q.source_id)
        require(q.fact_id in facts and source is not None and official_url(source.url) and
            sha256(source.text.encode()).hexdigest()==source.text_hash and q.excerpt in source.text,
            'Draft source integrity or quotation validation failed.')
    for composition in (r.consolidated_report,r.ticket_description,r.synthetic_email):
        require(len(composition.fact_order)==len(facts) and set(composition.fact_order)==set(facts) and
                composition.fact_order[0]=='synthetic-label','Draft omits or invents required source facts/warnings.')
        require(len(set(composition.interpretation_indices))==len(composition.interpretation_indices) and all(
            0<=i<len(r.interpretations) for i in composition.interpretation_indices),'Draft interpretation reference invalid.')
    # Fact-bearing prose is rendered from the registry, not editable by the model.
    # Conditional prose still needs human semantic review; these guards reject concrete invented facts.
    unsafe=re.compile(r'\d|https?://|@|\b(?:CVE|KB|deploy|install|patched|confirmed|guaranteed|compromised|remediated)\b|upgrade\s+to|currently\s+supported|is\s+fixed|\b(?:is|are)\s+(?:safe|secure|unaffected|resolved)\b|accept\s+risk|bypass|disable\s+verification|(?:auto|automatically)\s+approve',re.I)
    for interpretation in r.interpretations:
        require(set(interpretation.basis_fact_ids)<=set(facts),'Interpretation cites unknown fact IDs.')
        require(not unsafe.search(interpretation.reasoning),'Conditional draft prose introduces unsupported concrete/operational assertions.')
    require(all(not unsafe.search(v) for v in r.analyst_validation),'Analyst review text introduces unsupported facts.')
    return r


def render(result,supplied):
    s=DraftInput.model_validate(supplied);r=validate(result.model_dump(),supplied);facts={f.id:f for f in s.facts}
    def body(composition):
        lines=['['+facts[i].category+'] '+facts[i].text for i in composition.fact_order]
        lines+=['UNVERIFIED CONDITIONAL INTERPRETATION: '+r.interpretations[i].reasoning for i in composition.interpretation_indices]
        lines+=['Analyst review required: '+v for v in r.analyst_validation]
        return '\n'.join(lines)
    return dict(consolidated_report=body(r.consolidated_report),ticket_description=body(r.ticket_description),
        email_body=body(r.synthetic_email),subject='SYNTHETIC '+r.subject_style+': '+next(f.text for f in s.facts if f.id=='asset'),
        to=s.recipient)


def assess(candidate,supplied):
    validate(candidate,supplied)
    return dict(accepted=True,semantic_status='Source/policy fact composition checked; conditional prose requires human review',
        diagnostics=[dict(field='interpretations',category='UnverifiedInterpretation',result='Review')])
