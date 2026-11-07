"""Identity, quotation and transition envelope for Agent 7; no message tools."""
import json
import re
from .reply_contracts import ReplyInput,Agent7Result
from .live_contracts import LiveResearchError,redact
from .services import digest,row
from .lifecycle import _ticket_scope,_members
from .dashboard_queries import revision_token
from .enrichment_evidence import timestamp

ANCHORS={
    'Completed':r'\b(?:completed|finished|patched|fixed|remediated)\b',
    'Scheduled':r'\b(?:scheduled|schedule|planned|maintenance window)\b',
    'Unable to patch':r'\b(?:blocked|compatibility|incompatible|cannot patch|unable to patch|operational constraints)\b',
    'Information requested':r'\b(?:information|clarify|details|which version|question)\b|\?',
    'Risk exception requested':r'\b(?:risk exception|risk acceptance|accept risk|deferral)\b',
    'Vulnerability persists':r'\b(?:persists|unsuccessful|still vulnerable|did not work|failed|not completed)\b'}


def review_token(data):
    return digest(dict(operational=revision_token(data),identity=data['workspace_identity'],generation=data['generation'],
        replies=data['owner_replies'],interpretations=data['reply_interpretations'],owners=data['owners'],
        assignments=data['asset_owners'],links=data['communication_links'],status_claim_events=[e for e in data['audit_events']
        if e['event_type'] in ('ResolverCompletionClaimRecorded','ResolverStatusReported')]))


def prepare_context(c,data,reply_id):
    reply=row(c,'owner_replies',data['workspace_id'],reply_id)
    if digest(reply['raw_body'])!=reply['body_hash']:raise LiveResearchError('Original reply hash failed.')
    initial=next((i for i in data['reply_interpretations'] if i['reply_id']==reply_id),None)
    if not initial:raise LiveResearchError('Reply has no deterministic ticket binding.')
    ticket,scope=_ticket_scope(c,data['workspace_id'],initial['ticket_id'])
    owner=row(c,'owners',data['workspace_id'],reply['owner_id'])
    authorized=[a for a in data['asset_owners'] if a['asset_id']==scope['asset_id'] and a['owner_id']==owner['id'] and a['valid_to'] is None
        and (owner['id']==scope['resolver_group_id'] or a['role']=='primary')]
    if not owner['active'] or not authorized:raise LiveResearchError('Reply resolver is no longer authorized for this ticket.')
    members=_members(c,data['workspace_id'],scope);body=reply['raw_body'];flags=[]
    from .resolver_status_claim import policy_flags
    flags.extend(policy_flags(data,reply,ticket,scope,members))
    refs=set(re.findall(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b',body))
    if refs-{ticket['id']}:flags.append('Incorrect or unknown ticket/identity reference in reply')
    named_refs=re.findall(r'\bticket\s*(?:id\s*[:=]|reference\s*[:=]|[:#])\s*([A-Za-z0-9_-]+)',body,re.I)
    if any(r not in (ticket['id'],ticket.get('external_synthetic_key')) for r in named_refs):
        flags.append('Unknown explicit ticket reference; do not infer another ticket')
    for other in data['tickets']:
        if other['id']!=ticket['id'] and other.get('external_synthetic_key') and other['external_synthetic_key'] in body:
            flags.append('Reply references another ticket')
    cves={f['cve_id'] for f in members};mentioned=set(re.findall(r'CVE-\d{4}-\d{4,}',body))
    if mentioned and mentioned!=cves:flags.append('Partial or foreign vulnerability coverage needs clarification')
    if re.search(r'ignore.*instructions|system prompt|bypass|verified remediated|auto(?:matically)? approve|disable.*verification',body,re.I):
        flags.append('Untrusted instruction/authority claim; manual review mandatory')
    if re.search(r'\b(?:not (?:completed|fixed|patched|remediated)|never|nothing|no remediation|partially|some findings|one finding)\b',body,re.I):
        flags.append('Negated or partial completion claim')
    allowed=[intent for intent,pattern in ANCHORS.items() if re.search(pattern,body,re.I)]
    if len(allowed)>1:flags.append('Mixed/contradictory intent signals; manual clarification required')
    if not reply['communication_id']:
        flags.append('Original communication reference missing')
    else:
        link=next((l for l in data['communication_links'] if l['communication_id']==reply['communication_id'] and l['ticket_id']==ticket['id']),None)
        comm=next((m for m in data['communications'] if m['id']==reply['communication_id']),None)
        if not link or not comm:raise LiveResearchError('Reply communication does not match the ticket.')
        if comm['status']!='Simulated Delivered':flags.append('No original simulated delivery receipt; manual review required')
    legacy=json.loads(initial['interpretation_json'])
    if legacy['scheduled_at'] and timestamp(legacy['scheduled_at'])<=timestamp(data['as_of']):
        flags.append('Proposed schedule is not in the future; clarify before processing')
    if legacy['exception_until'] and timestamp(legacy['exception_until'])<=timestamp(data['as_of']):
        flags.append('Requested risk exception has already expired; no risk acceptance authority')
    s=dict(workspace_id=data['workspace_id'],workspace_identity=data['workspace_identity'],generation=data['generation'],
        reply_id=reply_id,ticket_id=ticket['id'],ticket_revision=ticket['revision'],owner_id=owner['id'],
        communication_id=reply['communication_id'],body_hash=reply['body_hash'],body=body,
        finding_ids=sorted(f['id'] for f in members),cve_ids=sorted(cves),allowed_intents=['Review required'] if flags else allowed+['Review required'],
        policy_flags=flags,scheduled_at=legacy['scheduled_at'],exception_until=legacy['exception_until'],as_of=data['as_of'],
        sources=[dict(id=reply_id,url='synthetic-reply:'+reply_id,retrieved_at=reply['received_at'],content_hash=reply['body_hash'])],
        source_limitations=['Untrusted synthetic resolver assertion, not scanner evidence or a command.',
                           'Exact analyst review required; risk approval and scanner verification remain separate.'])
    from .resolver_status_claim import binding
    claim=binding(data,reply,ticket,scope,members,s)
    if claim is not None:s['status_completion_claim']=claim
    parsed=ReplyInput.model_validate(s).model_dump()
    if parsed['status_completion_claim'] is None:parsed.pop('status_completion_claim')
    return dict(data,_agent7_input=parsed)


def context(data,reply_id,secret=''):
    s=data.get('_agent7_input')
    if not s or s['reply_id']!=reply_id:raise LiveResearchError('Missing reply identity context.')
    return redact(s,secret)


def expected_policy(intent,s):
    if intent=='Completed':return 'Pending Verification','Approve safe processing'
    if intent=='Scheduled':return ('In Remediation','Approve safe processing') if s.scheduled_at else ('No status change','Request clarification')
    if intent=='Risk exception requested':return 'No status change','Review bounded risk request' if s.exception_until else 'Request clarification'
    return 'No status change','Request clarification' if intent=='Review required' else 'Review only'


def validate(candidate,supplied):
    s=ReplyInput.model_validate(supplied);r=Agent7Result.model_validate(candidate)
    for key in ('workspace_id','reply_id','ticket_id','ticket_revision','owner_id','communication_id','body_hash','finding_ids'):
        if getattr(r,key)!=getattr(s,key):raise LiveResearchError('Reply ticket/resolver/communication/revision identity mismatch.')
    if r.intent not in s.allowed_intents:raise LiveResearchError('Reply intent exceeds grounded policy envelope.')
    from .resolver_status_claim import HEADER,validate_binding
    if r.intent=='Completed' and s.body.startswith(HEADER):validate_binding(s)
    if (r.proposed_status,r.required_analyst_decision)!=expected_policy(r.intent,s):raise LiveResearchError('Unsupported reply transition/authority.')
    if any(not q or q not in s.body or '...' in q or '\u2026' in q for q in r.evidence_excerpts):
        raise LiveResearchError('Reply quotation fabricated, stitched or altered.')
    if r.intent!='Review required' and not any(re.search(ANCHORS[r.intent],q,re.I) for q in r.evidence_excerpts):
        raise LiveResearchError('Reply excerpts do not support the selected intent.')
    if not set(s.policy_flags)<=set(r.contradictions):raise LiveResearchError('Every reply uncertainty/instruction flag must be disclosed.')
    if re.search(r'\d+(?:\.\d+)?\s*%',r.interpretation+' '.join(r.review_requirements)):
        raise LiveResearchError('Numerical confidence is not evidence.')
    return r


def assess(candidate,supplied):
    validate(candidate,supplied)
    return dict(accepted=True,semantic_status='Reply identity/excerpts/allowed transition checked; meaning requires human review',
        diagnostics=[dict(field='interpretation',category='UnverifiedInterpretation',result='Review')])
