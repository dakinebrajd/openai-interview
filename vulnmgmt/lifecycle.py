"""Local synthetic Agents 5/6/7 services. No email, ITSM, HTTP or model client."""
from datetime import timedelta
import json
from typing import Protocol
from uuid import uuid4

from sqlalchemy import func, select

from .contracts import ScannerFinding, StatusTransition
from .database import tables
from .enrichment_evidence import (freshness, source_text, timestamp, validate_source, version_applies,
                                 validate_guidance, validate_rule)
from .lifecycle_contracts import AnalystDecision, ResolverReply, ScannerResult, RenderedDraft
from .research_contracts import RemediationRule, Guidance
from .services import (RevisionConflict, audit as _base_audit, canonical, digest, link_observation, row, stable,
                       transition_finding, utc, context)
from .sla import POLICY, calculate_sla, overdue_state


class ApprovalRequired(ValueError):
    pass


def audit(c,w,event_type,entity_type,entity_id,revision,payload,*,recorded_at=None,**kwargs):
    # Audit recording time is real UTC; simulated/effective time is explicitly payload data.
    data=dict(payload)
    if recorded_at is not None:data['synthetic_effective_at']=utc(recorded_at)
    return _base_audit(c,w,event_type,entity_type,entity_id,revision,data,**kwargs)


def _workspace(c, w):
    value = c.execute(select(tables['demo_workspaces']).where(tables['demo_workspaces'].c.id == str(w))).mappings().one_or_none()
    if value is None or not value['synthetic_only'] or value['state'] != 'Ready':
        raise ValueError('Ready synthetic workspace required')
    return value


def _analyst(actor, reason):
    if not isinstance(actor, str) or not actor.strip() or not isinstance(reason, str) or not reason.strip():
        raise ApprovalRequired('Explicit named analyst and decision rationale required')


def _cached(c, w, key, payload):
    _workspace(c, w)
    t = tables['lifecycle_operations']
    old = c.execute(select(t).where(t.c.workspace_id == w, t.c.operation_key == key)).mappings().first()
    if old:
        if old['payload_hash'] != digest(payload):
            raise RevisionConflict('Idempotency key reused with different input')
        return json.loads(old['result_json'])
    return None


def _finish(c, w, key, payload, result, now):
    c.execute(tables['lifecycle_operations'].insert().values(id=stable(w, 'lifecycle-op', key), workspace_id=w,
        operation_key=key, payload_hash=digest(payload), result_json=canonical(result), created_at=utc(timestamp(now))))
    audit(c, w, 'LifecycleOperation', 'lifecycle_operations', key, 0,
          {'operation_key': key, 'result': result}, recorded_at=timestamp(now))
    return result


def _update(c, w, name, old, changes):
    t = tables[name]
    result = c.execute(t.update().where(t.c.workspace_id == w, t.c.id == old['id'],
        t.c.revision == old['revision']).values(**changes, revision=old['revision']+1))
    if result.rowcount != 1:
        raise RevisionConflict('Concurrent revision conflict')
    return row(c, name, w, old['id'])


def _source(c, w, id, now, require_fresh=False):
    source = row(c, 'evidence_sources', w, id)
    if source['fetch_status'] != 'Success' or timestamp(source['retrieved_at']) > timestamp(now):
        raise ValueError('Unavailable or future evidence')
    snapshot = json.loads(source['snapshot_json'])
    if 'body' in snapshot:
        if snapshot.get('content_sha256') != source['content_hash'] or snapshot.get('url') != source['url']:
            raise ApprovalRequired('Source metadata does not match captured evidence')
        if not validate_source(snapshot):
            raise ValueError('Unusable public-source snapshot')
        state = freshness(snapshot, now)
    else:
        state = 'IdentifierOnly'
    if require_fresh and state != 'Fresh':
        raise ApprovalRequired('Current usable vendor evidence required for batch approval')
    return source, snapshot, state


def batch_review_payload(c, w, batch_id, member_ids, now, *, _approved_use=False):
    batch = row(c, 'remediation_batches', w, batch_id)
    if batch['status']=='Cancelled' or (batch['status']=='Verified Remediated' and not _approved_use) or not member_ids or len(set(member_ids)) != len(member_ids):
        raise ValueError('Batch review needs distinct members of an unresolved batch')
    action = row(c, 'remediation_actions', w, batch['action_id'])
    if action['status'] != 'Confirmed':
        raise ApprovalRequired('Source-validated remediation action required')
    rule = RemediationRule.model_validate_json(action['applicability_json'])
    if (action['action_key'],action['product'],action['instructions']) != (rule.action_key,rule.product,rule.instruction):
        raise ApprovalRequired('Action differs from its reviewed vendor rule')
    sources, source_bindings = {}, []
    for s in c.execute(select(tables['evidence_sources']).where(tables['evidence_sources'].c.workspace_id==w)).mappings():
        if not s['snapshot_json']:
            continue
        capture=json.loads(s['snapshot_json'])
        if capture.get('id') not in {rule.source_id,*rule.cve_ids}:
            continue
        _,capture,state=_source(c,w,s['id'],now,require_fresh=not _approved_use)
        if capture['id'] in sources and digest(sources[capture['id']])!=digest(capture):
            raise ApprovalRequired('Conflicting source revisions require a new reviewed action')
        sources[capture['id']]=capture
        source_bindings.append(dict(id=s['id'],url=s['url'],content_hash=s['content_hash'],snapshot_hash=digest(capture)))
    guidance, research_bindings = {}, []
    for step in c.execute(select(tables['agent_steps']).where(tables['agent_steps'].c.workspace_id==w,
                                                           tables['agent_steps'].c.role_number==2)).mappings():
        if not step['output_json']:
            continue
        p=json.loads(step['output_json'])
        g=p.get('guidance')
        if g and g['cve_id'] in rule.cve_ids:
            g=Guidance.model_validate(g)
            validate_guidance(g,sources)
            if g.status!='Supported':
                raise ApprovalRequired('Conflicting or missing vendor guidance requires review')
            guidance[g.cve_id]=g
            research_bindings.append(dict(id=step['id'],output_hash=digest(p)))
    try:
        validate_rule(rule,guidance,sources)
    except (ValueError,KeyError):
        raise ApprovalRequired('Shared remediation rule lacks validated per-CVE vendor evidence') from None
    bindings = []
    identities,components,claims,assumptions=[],[],[],[]
    for finding_id in sorted(member_ids):
        finding = row(c, 'asset_cves', w, finding_id)
        if not _approved_use and finding['status'] not in ('Open','In Remediation'):
            raise ApprovalRequired('Only unresolved eligible findings can receive new batch approval')
        if finding['asset_id'] != batch['asset_id']:
            raise ValueError('Cross-asset batching is forbidden')
        proposed = c.execute(select(tables['batch_proposal_members']).where(
            tables['batch_proposal_members'].c.workspace_id == w,
            tables['batch_proposal_members'].c.batch_id == batch_id,
            tables['batch_proposal_members'].c.asset_cve_id == finding_id)).mappings().one_or_none()
        if not proposed:
            raise ApprovalRequired('Member must have an evidence-backed M3 proposal')
        assumption = row(c, 'synthetic_applicability', w, proposed['assumption_id'])
        component = row(c, 'asset_components', w, finding['component_id'])
        if (assumption['component_id'] != component['id'] or assumption['expected_component_revision'] != component['revision']
                or component['asset_id'] != batch['asset_id'] or component['installed_version'] is not None
                or assumption['product'] != rule.product or not version_applies(assumption['installed_version'], rule)
                or finding['cve_id'] not in rule.cve_ids):
            raise ApprovalRequired('Synthetic applicability binding requires re-review')
        claim = row(c, 'evidence_claims', w, proposed['evidence_claim_id'])
        source, snapshot, state = _source(c, w, claim['source_id'], now, require_fresh=not _approved_use)
        if (claim['validation_status'] != 'Confirmed' or claim['claim_type'] != 'VendorRemediation'
                or claim['cve_id'] != finding['cve_id'] or claim['supporting_excerpt'] not in source_text(snapshot)
                or claim['supporting_excerpt'] != rule.instruction or snapshot.get('id') != rule.source_id
                or source['content_hash'] != proposed['source_hash']):
            raise ApprovalRequired('Member remediation evidence is not supported')
        if component['id'] not in {x['id'] for x in components}:
            components.append(dict(component))
        identities.append({k:finding[k] for k in ('id','asset_id','component_id','cve_id')})
        claims.append(dict(claim));assumptions.append(dict(assumption))
        bindings.append({'finding_id': finding_id, 'finding_revision': finding['revision'],
            'component_revision': component['revision'], 'claim_id': claim['id'], 'source_hash': source['content_hash'],
            'assumption_id': assumption['id'], 'label': assumption['label'], 'freshness': state})
    if len(components)!=1:
        raise ApprovalRequired('Cross-component shared remediation is forbidden')
    workspace=_workspace(c,w)
    proposals=[dict(r) for r in c.execute(select(tables['batch_proposal_members']).where(
        tables['batch_proposal_members'].c.workspace_id==w,tables['batch_proposal_members'].c.batch_id==batch_id)
        .order_by(tables['batch_proposal_members'].c.id)).mappings()]
    material=dict(binding_version=2,workspace_id=w,database_identity=workspace['database_identity'],
        generation=workspace['generation'],batch_id=batch_id,asset_id=batch['asset_id'],cycle=batch['cycle'],
        action=dict(action),identities=identities,components=components,claims=claims,assumptions=assumptions,
        proposal_members=proposals,sources=sorted(source_bindings,key=lambda x:x['id']),
        research=sorted(research_bindings,key=lambda x:x['id']))
    return {'batch_id': batch_id, 'batch_revision': batch['revision'], 'members': bindings,
            'action_id': action['id'], 'generation': workspace['generation'],'material':material,
            'material_hash':digest(material),
            'limitations':['Historical vendor fix only; current supported deployment version is unknown.',
                          'Installed version is an explicit synthetic assumption, not scanner verification.']}


def require_batch_approval(c,w,batch_id,now):
    """Validate exact adopted material on every use; do not rewrite old approvals."""
    batch=row(c,'remediation_batches',w,batch_id)
    reviews=list(c.execute(select(tables['lifecycle_reviews']).where(tables['lifecycle_reviews'].c.workspace_id==w,
        tables['lifecycle_reviews'].c.target_id==batch_id,tables['lifecycle_reviews'].c.kind=='Batch',
        tables['lifecycle_reviews'].c.status=='Approved').order_by(tables['lifecycle_reviews'].c.created_at.desc(),
        tables['lifecycle_reviews'].c.id.desc())).mappings())
    if not reviews:
        raise ApprovalRequired('Exact batch revision/evidence approval required')
    events=list(c.execute(select(tables['audit_events']).where(tables['audit_events'].c.workspace_id==w,
        tables['audit_events'].c.entity_id==batch_id)).mappings())
    stamps=[e for e in events if e['event_type']=='BatchRevisionApproved']
    if not stamps:
        raise ApprovalRequired('Legacy approval requires exact evidence re-review')
    stamp=max(stamps,key=lambda e:e['revision'])
    review=next((r for r in reviews if r['id']==json.loads(stamp['payload_json'])['review_id']),None)
    if not review:
        raise ApprovalRequired('Latest exact batch approval is unavailable')
    body=json.loads(review['payload_json'])
    ids=[m['finding_id'] for m in body['members']]
    memberships=sorted(c.scalars(select(tables['batch_memberships'].c.asset_cve_id).where(
        tables['batch_memberships'].c.workspace_id==w,tables['batch_memberships'].c.batch_id==batch_id,
        tables['batch_memberships'].c.left_at.is_(None))))
    if memberships!=sorted(ids):
        raise ApprovalRequired('Approved membership changed; exact re-review required')
    current=batch_review_payload(c,w,batch_id,ids,now,_approved_use=True)
    if not body.get('material_hash') or current['material_hash']!=body['material_hash']:
        raise ApprovalRequired('Approved action/evidence/applicability changed; exact re-review required')
    approved=[e for e in events if e['event_type']=='BatchRevisionApproved' and
        json.loads(e['payload_json']).get('review_id')==review['id']]
    if not approved:
        raise ApprovalRequired('Legacy approval requires exact evidence re-review')
    revision=approved[-1]['revision']
    allowed={e['revision'] for e in events if e['event_type']=='BatchAggregateStatus'}
    if batch['revision']<revision or any(n not in allowed for n in range(revision+1,batch['revision']+1)):
        raise ApprovalRequired('Unreviewed batch revision cannot reuse earlier approval')


def request_batch_review(c, w, batch_id, member_ids, now, operation_key):
    payload = {'batch_id': batch_id, 'members': sorted(member_ids), 'now': now}
    if (cached := _cached(c, w, operation_key, payload)) is not None: return cached
    reviewed = batch_review_payload(c, w, batch_id, member_ids, now)
    review_id = stable(w, 'batch-review', digest(reviewed))
    if not c.scalar(select(tables['lifecycle_reviews'].c.id).where(tables['lifecycle_reviews'].c.id == review_id)):
        c.execute(tables['lifecycle_reviews'].insert().values(id=review_id, workspace_id=w, kind='Batch', target_id=batch_id,
            payload_json=canonical(reviewed), payload_hash=digest(reviewed), workspace_generation=reviewed['generation'],
            status='Awaiting Approval', revision=0, created_at=utc(timestamp(now)),
            expires_at=utc(timestamp(now)+timedelta(hours=24))))
    return _finish(c, w, operation_key, payload, {'review_id': review_id, 'payload_hash': digest(reviewed)}, now)


def decide_review(c, request: AnalystDecision):
    context(c,request)
    w, now = str(request.workspace_id), utc(request.decided_at)
    _analyst(request.analyst_id, request.reason)
    payload = request.model_dump(mode='json')
    if (cached := _cached(c, w, request.operation_key, payload)) is not None: return cached
    review = row(c, 'lifecycle_reviews', w, request.target_id)
    if (review['status'] != 'Awaiting Approval' or review['payload_hash'] != request.payload_hash
            or review['workspace_generation'] != _workspace(c, w)['generation']
            or timestamp(now) >= timestamp(review['expires_at'])):
        raise ApprovalRequired('Review is stale, expired or not awaiting approval')
    body = json.loads(review['payload_json'])
    if request.decision == 'Approved':
        if review['kind'] == 'Batch':
            member_ids = [m['finding_id'] for m in body['members']]
            current = batch_review_payload(c, w, review['target_id'], member_ids, now)
            if digest(current) != review['payload_hash']:
                raise RevisionConflict('Batch facts changed since review was requested')
            batch = row(c, 'remediation_batches', w, review['target_id'])
            _update(c, w, 'remediation_batches', batch, {'status': 'Confirmed',
                'confirmed_by': request.analyst_id, 'confirmed_at': now})
            audit(c,w,'BatchRevisionApproved','remediation_batches',batch['id'],batch['revision']+1,
                dict(review_id=review['id'],payload_hash=review['payload_hash'],material_hash=body['material_hash']),
                actor_id=request.analyst_id,actor_type='analyst')
            for member in body['members']:
                t = tables['batch_memberships']
                old = c.scalar(select(t.c.id).where(t.c.workspace_id == w, t.c.batch_id == batch['id'],
                    t.c.asset_cve_id == member['finding_id'], t.c.left_at.is_(None)))
                if not old:
                    c.execute(t.insert().values(id=stable(w, 'approved-member', batch['id'], member['finding_id']),
                        workspace_id=w, batch_id=batch['id'], asset_cve_id=member['finding_id'], joined_at=now,
                        evidence_claim_id=member['claim_id']))
            _sync_batch(c, w, batch['id'], now)
        else:
            ticket, scope = _ticket_scope(c, w, review['target_id'])
            current = _risk_binding(c, w, ticket, scope, body['until'], now)
            if digest(current) != review['payload_hash']:
                raise RevisionConflict('Risk request changed or expired')
            for finding in _members(c, w, scope):
                exception_id = stable(w, 'risk-exception', review['id'], finding['id'])
                c.execute(tables['exceptions'].insert().values(id=exception_id, workspace_id=w,
                    asset_cve_id=finding['id'], analyst_id=request.analyst_id, reason=request.reason,
                    expires_at=body['until'], status='Active'))
                c.execute(tables['exception_review_links'].insert().values(
                    id=stable(w, 'exception-review', exception_id), workspace_id=w,
                    exception_id=exception_id, review_id=review['id']))
            _record_ticket(c, w, ticket, 'RiskExceptionApproved', request.reason, request.analyst_id, now,
                           changes={}, snapshot=_snapshot(c, w, scope['id'], now))
    _update(c, w, 'lifecycle_reviews', review, {'status': request.decision})
    c.execute(tables['lifecycle_decisions'].insert().values(id=stable(w, 'review-decision', review['id']),
        workspace_id=w, review_id=review['id'], payload_hash=request.payload_hash, decision=request.decision,
        analyst_id=request.analyst_id, reason=request.reason, decided_at=now))
    audit(c, w, 'AnalystReviewDecision', 'lifecycle_reviews', review['id'], review['revision']+1,
          payload, actor_id=request.analyst_id, actor_type='analyst', recorded_at=request.decided_at)
    return _finish(c, w, request.operation_key, payload, {'review_id': review['id'], 'decision': request.decision}, now)


def _route(c, w, asset_id):
    t = tables['asset_owners']
    groups = list(c.scalars(select(t.c.owner_id).where(t.c.workspace_id == w, t.c.asset_id == asset_id,
        t.c.role == 'secondary', t.c.valid_to.is_(None))))
    if len(groups) != 1:
        raise ApprovalRequired('A single explicit resolver-group assignment is required')
    group = row(c, 'owners', w, groups[0])
    if not group['active']: raise ApprovalRequired('Resolver group is inactive')
    return group


def create_scope(c, w, *, batch_id=None, finding_id=None, now):
    _workspace(c, w)
    if (batch_id is None) == (finding_id is None): raise ValueError('Choose a batch or one individual finding')
    if finding_id:
        finding = row(c, 'asset_cves', w, finding_id)
        batch_id = stable(w, 'individual-review-batch', finding_id)
        action_id = stable(w, 'individual-review-action', finding_id)
        if not c.scalar(select(tables['remediation_batches'].c.id).where(tables['remediation_batches'].c.id == batch_id)):
            c.execute(tables['remediation_actions'].insert().values(id=action_id, workspace_id=w,
                action_key='individual-review:'+finding_id, revision=0, product='Unknown applicability',
                applicability_json='{}', instructions='Analyst review required; no shared remediation asserted', status='Proposed'))
            c.execute(tables['remediation_batches'].insert().values(id=batch_id, workspace_id=w,
                asset_id=finding['asset_id'], action_id=action_id, cycle=1, status='Proposed', revision=0))
    batch = row(c, 'remediation_batches', w, batch_id)
    if not finding_id and (batch['confirmed_by'] is None or batch['status'] in ('Proposed','Cancelled')):
        raise ApprovalRequired('Analyst batch approval required before escalation')
    if not finding_id:
        require_batch_approval(c,w,batch_id,now)
    action = row(c, 'remediation_actions', w, batch['action_id'])
    group = _route(c, w, batch['asset_id'])
    identity = f'{action["action_key"]}:cycle-{batch["cycle"]}'
    scope_id = stable(w, 'escalation-scope', batch['asset_id'], group['id'], identity)
    existing=c.execute(select(tables['lifecycle_scopes']).where(tables['lifecycle_scopes'].c.id==scope_id)).mappings().first()
    if existing and existing['batch_id']!=batch_id:
        raise ApprovalRequired('Existing remediation identity has another batch; reconcile rather than duplicate')
    if not existing:
        c.execute(tables['lifecycle_scopes'].insert().values(id=scope_id, workspace_id=w,
            asset_id=batch['asset_id'], resolver_group_id=group['id'], batch_id=batch_id,
            individual_finding_id=finding_id, remediation_identity=identity, created_at=utc(timestamp(now))))
    return scope_id


def _members(c, w, scope):
    if scope['individual_finding_id']:
        return [row(c, 'asset_cves', w, scope['individual_finding_id'])]
    t = tables['batch_memberships']
    return [row(c, 'asset_cves', w, id) for id in c.scalars(select(t.c.asset_cve_id).where(
        t.c.workspace_id == w, t.c.batch_id == scope['batch_id'], t.c.left_at.is_(None)).order_by(t.c.asset_cve_id))]


def _ticket_scope(c, w, ticket_id):
    ticket = row(c, 'tickets', w, ticket_id)
    t = tables['ticket_bindings']
    scope_id = c.scalar(select(t.c.scope_id).where(t.c.workspace_id == w, t.c.ticket_id == ticket_id))
    if scope_id is None: raise ApprovalRequired('Legacy ticket routing requires analyst reconciliation')
    return ticket, row(c, 'lifecycle_scopes', w, scope_id)


def _match(c, w, scope):
    t = tables['ticket_bindings']
    id = c.scalar(select(t.c.ticket_id).where(t.c.workspace_id == w, t.c.scope_id == scope['id']))
    if id: return row(c, 'tickets', w, id)
    legacy = c.scalar(select(tables['tickets'].c.id).where(tables['tickets'].c.workspace_id == w,
        tables['tickets'].c.batch_id == scope['batch_id'], tables['tickets'].c.status != 'Closed'))
    if legacy: raise ApprovalRequired('Existing unbound ticket requires routing reconciliation; creation suppressed')
    return None


def _snapshot(c, w, scope_id, now):
    scope=row(c,'lifecycle_scopes',w,scope_id)
    if not scope['individual_finding_id']:
        require_batch_approval(c,w,scope['batch_id'],now)
    scope = row(c, 'lifecycle_scopes', w, scope_id)
    group = _route(c, w, scope['asset_id'])
    if group['id'] != scope['resolver_group_id']: raise ApprovalRequired('Resolver assignment changed; re-route review required')
    asset = row(c, 'assets', w, scope['asset_id'])
    batch = row(c, 'remediation_batches', w, scope['batch_id'])
    action = row(c, 'remediation_actions', w, batch['action_id'])
    members = _members(c, w, scope)
    if not members: raise ApprovalRequired('No approved findings in escalation scope')
    details, sources, exploit_cves, assumptions = [], {}, [], []
    for f in members:
        known, exploitable = False, False
        vendor_facts=[]
        claims = list(c.execute(select(tables['evidence_claims']).where(tables['evidence_claims'].c.workspace_id == w,
            tables['evidence_claims'].c.cve_id == f['cve_id'])).mappings())
        intel = list(c.execute(select(tables['threat_intel']).where(tables['threat_intel'].c.workspace_id == w,
            tables['threat_intel'].c.cve_id == f['cve_id'], tables['threat_intel'].c.kind == 'KEV',
            tables['threat_intel'].c.kev_member == 1, tables['threat_intel'].c.validation_status == 'Confirmed')).mappings())
        for item in intel:
            try:
                source, data, state = _source(c, w, item['source_id'], now)
                if data.get('kind') == 'KEV' and any(r['cveID']==f['cve_id'] for r in json.loads(data['body'])['vulnerabilities']):
                    known = True
                    sources[source['id']] = {'url': source['url'], 'retrieved_at': source['retrieved_at'],
                        'hash': source['content_hash'], 'freshness': state, 'scope': 'Confirmed known exploitation, not active attack on this asset'}
            except ValueError:
                pass  # Future/unavailable evidence remains unknown, not fabricated.
        for claim in claims:
            if claim['validation_status'] != 'Confirmed': continue
            try: source, data, state = _source(c, w, claim['source_id'], now)
            except ValueError: continue
            sources[source['id']] = {'url': source['url'], 'retrieved_at': source['retrieved_at'],
                'hash': source['content_hash'], 'freshness': state, 'scope': claim['claim_type'], 'published_at': source['published_at']}
            if claim['claim_type'] == 'Exploitability' and state == 'Fresh' and claim['supporting_excerpt'] in source_text(data):
                exploitable = True
            if (claim['claim_type']=='VendorRemediation' and 'body' in data
                and claim['supporting_excerpt'] in source_text(data)):
                vendor_facts.append(claim['supporting_excerpt'])
        if known: exploit_cves.append(f['cve_id'])
        severity = {4:'Critical',3:'High',2:'Medium',1:'Low',0:'Informational',None:'Unknown'}[f['max_severity_rank']]
        sla = calculate_sla(severity, f['first_seen'], actively_exploited=known, exploitable=exploitable)
        exception_rows = list(c.execute(select(tables['exceptions']).where(tables['exceptions'].c.workspace_id == w,
            tables['exceptions'].c.asset_cve_id == f['id'], tables['exceptions'].c.status == 'Active')).mappings())
        until = max((e['expires_at'] for e in exception_rows if timestamp(e['expires_at']) > timestamp(now)), default=None)
        details.append({'id': f['id'], 'cve_id': f['cve_id'], 'component_id': f['component_id'],
            'severity': severity, 'severity_rank': f['max_severity_rank'], 'status': f['status'],
            'first_seen': f['first_seen'], 'last_seen': f['last_seen'], 'revision': f['revision'],
            'known_exploitation': known, 'explicit_exploitability': exploitable, 'sla': sla,
            'verified_vendor_facts':sorted(set(vendor_facts)),
            'overdue': overdue_state(sla['due_at'], now, exception_until=until, verified=f['status']=='Verified Remediated')})
    if not scope['individual_finding_id']:
        links = c.execute(select(tables['batch_proposal_members']).where(
            tables['batch_proposal_members'].c.workspace_id == w,
            tables['batch_proposal_members'].c.batch_id == batch['id'])).mappings()
        for link in links:
            if link['asset_cve_id'] in {f['id'] for f in members}:
                a = row(c, 'synthetic_applicability', w, link['assumption_id'])
                component = row(c, 'asset_components', w, a['component_id'])
                if component['revision'] != a['expected_component_revision']:
                    raise ApprovalRequired('Approved synthetic applicability is stale')
                # Operational creation time remains in SQLite; report assumptions are
                # versioned facts, so fresh replay reports do not depend on wall clock.
                assumptions.append({key:value for key,value in dict(a).items() if key!='created_at'})
    due = min((d['sla']['due_at'] for d in details if d['sla']['due_at']), default=None)
    urgent = min(details, key=lambda d: d['sla']['hours'] if d['sla']['hours'] is not None else float('inf'))
    ranks = [d['severity_rank'] for d in details if d['severity_rank'] is not None]
    guidance=action['instructions']
    if scope['individual_finding_id']:
        facts=sorted({fact for finding in details for fact in finding['verified_vendor_facts']})
        if facts:guidance+='\nHistorical vendor facts (asset applicability unverified):\n'+'\n'.join(facts)
    guidance = ('Historical advisory boundary - not a current secure-release recommendation. '
                'Validate current vendor guidance and real product/version applicability before any real action.\n' + guidance)
    if assumptions:
        guidance += '\nSynthetic installed-version assumptions: ' + '; '.join(sorted({a['product']+' '+a['installed_version'] for a in assumptions}))
    guidance += '\nVendor advisory dates: ' + '; '.join(sorted({str(s.get('published_at') or 'Unknown')+' ('+s['url']+')' for s in sources.values() if s['scope'] == 'VendorRemediation'}))
    material = {'asset_id': asset['id'], 'resolver_group_id': group['id'], 'remediation_identity': scope['remediation_identity'],
        'cves': sorted(d['cve_id'] for d in details), 'finding_ids': sorted(d['id'] for d in details),
        'severity_rank': max(ranks) if ranks else None, 'priority': urgent['sla']['category'],
        'known_exploitation_cves': sorted(set(exploit_cves)), 'guidance': guidance, 'due_at': due}
    binding = {'generation': _workspace(c,w)['generation'], 'batch_revision': batch['revision'],
        'group_revision': group['revision'], 'findings': [(d['id'],d['revision'],d['status']) for d in details],
        'sources': sources, 'assumptions': [(a['id'],a['assumption_hash']) for a in assumptions]}
    return {'label': 'SYNTHETIC LOCAL WORKFLOW - NO EXTERNAL DELIVERY', 'scope_id': scope_id,
        'as_of': now, 'asset': {'id': asset['id'], 'key': asset['asset_key'], 'hostname': asset['hostname']},
        'resolver_group': {'id': group['id'], 'name': group['display_name'], 'email': group['synthetic_email']},
        'findings': details, 'guidance': guidance, 'sources': sources, 'assumptions': assumptions,
        'review_flags': ['Hypothetical agency SLA policy', 'No sector targeting inferred from KEV/EPSS',
                         'Known-exploitation urgency is not proof of an active attack on this asset']+
            (['Individual triage; product/version/remediation applicability unverified'] if scope['individual_finding_id'] else
             ['Historical vendor fix with explicit synthetic applicability; analyst reviewed, not scanner-confirmed product version']),
        'material': material, 'material_hash': digest(material), 'binding_hash': digest(binding),
        'batch_revision': batch['revision'], 'generation': binding['generation']}


class DraftRenderer(Protocol):
    def render(self, snapshot: dict) -> dict: ...


class DeterministicRenderer:
    def render(self, snapshot):
        lines = [snapshot['label'], f'Asset: {snapshot["asset"]["key"]} ({snapshot["asset"]["hostname"]})',
            f'Resolver: {snapshot["resolver_group"]["name"]}', f'As of: {snapshot["as_of"]}',
            f'Priority: {snapshot["material"]["priority"]}; deadline: {snapshot["material"]["due_at"]}',
            f'Guidance: {snapshot["guidance"]}', POLICY['label'],'SLA clock: '+POLICY['clock']]
        lines += [f'{d["cve_id"]}: {d["severity"]}; status {d["status"]}; known exploitation={d["known_exploitation"]}; '
                  f'due={d["sla"]["due_at"]}' for d in snapshot['findings']]
        lines += ['Review: '+flag for flag in snapshot['review_flags']]
        lines += [a['label']+': '+a['product']+' '+a['installed_version'] for a in snapshot['assumptions']]
        lines += [f'Source: {s["url"]}; retrieved {s["retrieved_at"]}; {s["freshness"]}' for s in snapshot['sources'].values()]
        text = '\n'.join(lines)
        return {'subject': f'SYNTHETIC remediation: {snapshot["asset"]["key"]}',
                'ticket_description': text, 'email_body': text, 'to': snapshot['resolver_group']['email']}


def _render(snapshot,renderer=None):
    draft=RenderedDraft.model_validate((renderer or DeterministicRenderer()).render(snapshot))
    if draft.to!=snapshot['resolver_group']['email'] or not draft.subject.startswith('SYNTHETIC '):
        raise ValueError('Synthetic draft must address the assigned resolver and retain its label')
    return draft.model_dump()


def material_changes(old, new):
    reasons = []
    if set(new['cves']) - set(old['cves']): reasons.append('NewCVEs')
    if set(old['cves']) - set(new['cves']): reasons.append('RemovedCVEs')
    for key, label in [('severity_rank','SeverityChanged'),('priority','PriorityChanged'),
                       ('guidance','RemediationGuidanceChanged'),('due_at','DeadlineChanged'),
                       ('resolver_group_id','ResolverChanged'),('finding_ids','MembershipChanged')]:
        if old.get(key) != new.get(key): reasons.append(label)
    if set(new['known_exploitation_cves']) - set(old['known_exploitation_cves']): reasons.append('NewVerifiedExploitationEvidence')
    if set(old['known_exploitation_cves']) - set(new['known_exploitation_cves']): reasons.append('ExploitationEvidenceChanged')
    return sorted(set(reasons))


def _latest_version(c, w, ticket_id):
    t=tables['ticket_versions']
    return c.execute(select(t).where(t.c.workspace_id==w,t.c.ticket_id==ticket_id)
                     .order_by(t.c.ticket_revision.desc()).limit(1)).mappings().first()


def _proposal(c, w, scope, kind, payload, now):
    t=tables['proposals']
    revision = c.scalar(select(func.max(t.c.revision)).where(t.c.workspace_id==w,t.c.batch_id==scope['batch_id'],t.c.kind==kind))
    id=stable(w,'lifecycle-proposal',scope['id'],kind,digest(payload))
    if c.scalar(select(t.c.id).where(t.c.id==id)): return id
    batch=row(c,'remediation_batches',w,scope['batch_id'])
    c.execute(t.insert().values(id=id,workspace_id=w,batch_id=batch['id'],kind=kind,revision=(revision or 0)+1,
        payload_json=canonical(payload),payload_hash=digest(payload),status='Awaiting Approval',
        expected_batch_revision=batch['revision'],workspace_generation=_workspace(c,w)['generation']))
    return id


def queue_escalation(c, w, scope_id, now, operation_key, renderer=None):
    payload={'scope_id':scope_id,'now':now}
    if (cached:=_cached(c,w,operation_key,payload)) is not None:return cached
    snapshot=_snapshot(c,w,scope_id,now)
    scope=row(c,'lifecycle_scopes',w,scope_id)
    ticket=_match(c,w,scope)
    if all(f['status']=='Verified Remediated' for f in snapshot['findings']):
        return _finish(c,w,operation_key,payload,{'outcome':'Suppressed','ticket_id':ticket['id'] if ticket else None,
            'reasons':['AllFindingsScannerVerified']},now)
    reasons=['NewEscalation']
    if ticket:
        previous=_latest_version(c,w,ticket['id'])
        if not previous:raise ApprovalRequired('Historical ticket version missing; reconciliation required')
        old=json.loads(previous['snapshot_json'])['report']['material']
        reasons=material_changes(old,snapshot['material'])
        if not reasons:
            result={'outcome':'Suppressed','ticket_id':ticket['id'],'reasons':['NoMaterialChange']}
            audit(c,w,'DuplicateEscalationSuppressed','tickets',ticket['id'],ticket['revision'],result,recorded_at=timestamp(now))
            return _finish(c,w,operation_key,payload,result,now)
    t=tables['proposals']
    pending=c.execute(select(t).where(t.c.workspace_id==w,t.c.batch_id==scope['batch_id'],t.c.kind=='Ticket',
        t.c.status.in_(['Awaiting Approval','Approved']))).mappings().all()
    for proposal in pending:
        prior=json.loads(proposal['payload_json'])
        if prior.get('scope_id')!=scope_id:continue
        if (prior['snapshot']['material_hash']==snapshot['material_hash']
            and prior['snapshot']['binding_hash']==snapshot['binding_hash']
            and prior['expected_ticket_revision']==(ticket['revision'] if ticket else None)):
            result={'outcome':'Suppressed','proposal_id':proposal['id'],'reasons':['PendingDraftNoMaterialChange']}
            audit(c,w,'DuplicateEscalationSuppressed','proposals',proposal['id'],proposal['revision'],result,recorded_at=timestamp(now))
            return _finish(c,w,operation_key,payload,result,now)
        c.execute(t.update().where(t.c.id==proposal['id']).values(status='Invalidated'))
    draft={'scope_id':scope_id,'snapshot':snapshot,'rendered':_render(snapshot,renderer),
           'ticket_id':ticket['id'] if ticket else None,'expected_ticket_revision':ticket['revision'] if ticket else None,
           'change_reasons':reasons,'created_at':utc(timestamp(now)),
           'expires_at':utc(timestamp(now)+timedelta(hours=24))}
    proposal_id=_proposal(c,w,scope,'Ticket',draft,now)
    result={'outcome':'Awaiting Approval','proposal_id':proposal_id,'payload_hash':digest(draft),
            'ticket_id':draft['ticket_id'],'reasons':reasons}
    audit(c,w,'EscalationDrafted','proposals',proposal_id,0,result,recorded_at=timestamp(now))
    return _finish(c,w,operation_key,payload,result,now)


def _validate_proposal(c,w,proposal,now):
    body=json.loads(proposal['payload_json'])
    current=_snapshot(c,w,body['scope_id'],now)
    scope=row(c,'lifecycle_scopes',w,body['scope_id'])
    batch=row(c,'remediation_batches',w,scope['batch_id'])
    if (digest(body)!=proposal['payload_hash'] or current['binding_hash']!=body['snapshot']['binding_hash']
        or current['material_hash']!=body['snapshot']['material_hash']
        or _workspace(c,w)['generation']!=proposal['workspace_generation']
        or batch['revision']!=proposal['expected_batch_revision']
        or timestamp(now)>=timestamp(body['expires_at']) or timestamp(now)<timestamp(body['created_at'])):
        raise ApprovalRequired('Draft changed, expired or requires fresh analyst review')
    if body['rendered']['to']!=current['resolver_group']['email']:
        raise ApprovalRequired('Draft recipient no longer matches resolver assignment')
    ticket_id=body.get('ticket_id')
    if ticket_id and row(c,'tickets',w,ticket_id)['revision']!=body['expected_ticket_revision']:
        raise RevisionConflict('Ticket changed since draft creation')
    return body,current,scope


def decide_proposal(c,request:AnalystDecision):
    context(c,request)
    w,now=str(request.workspace_id),utc(request.decided_at)
    _analyst(request.analyst_id,request.reason)
    payload=request.model_dump(mode='json')
    if (cached:=_cached(c,w,request.operation_key,payload)) is not None:return cached
    proposal=row(c,'proposals',w,request.target_id)
    if proposal['status']!='Awaiting Approval' or proposal['payload_hash']!=request.payload_hash:
        raise ApprovalRequired('Exact pending draft hash required')
    _validate_proposal(c,w,proposal,now)
    c.execute(tables['approvals'].insert().values(id=stable(w,'lifecycle-approval',proposal['id']),workspace_id=w,
        proposal_id=proposal['id'],proposal_hash=proposal['payload_hash'],decision=request.decision,
        analyst_id=request.analyst_id,decided_at=now,expires_at=json.loads(proposal['payload_json'])['expires_at'],reason=request.reason))
    c.execute(tables['proposals'].update().where(tables['proposals'].c.id==proposal['id']).values(status=request.decision))
    audit(c,w,'AnalystProposalDecision','proposals',proposal['id'],proposal['revision'],payload,
          actor_id=request.analyst_id,actor_type='analyst',recorded_at=request.decided_at)
    return _finish(c,w,request.operation_key,payload,{'proposal_id':proposal['id'],'decision':request.decision},now)


def _approved(c,w,proposal,now):
    if proposal['status']!='Approved':raise ApprovalRequired('Explicit analyst approval required')
    t=tables['approvals']
    approval=c.execute(select(t).where(t.c.workspace_id==w,t.c.proposal_id==proposal['id'])).mappings().one_or_none()
    if (not approval or approval['decision']!='Approved' or approval['proposal_hash']!=proposal['payload_hash']
        or timestamp(now)<timestamp(approval['decided_at']) or not approval['expires_at']
        or timestamp(now)>=timestamp(approval['expires_at'])):
        raise ApprovalRequired('Approval is missing, expired or not bound to this revision')
    return approval


def _record_ticket(c,w,ticket,event,reason,actor,now,*,changes,snapshot,proposal_id=None):
    _chronology(c,w,ticket,now)
    ticket=_update(c,w,'tickets',ticket,changes)
    rendered=_render(snapshot)
    c.execute(tables['ticket_versions'].insert().values(id=stable(w,'ticket-version',ticket['id'],ticket['revision']),
        workspace_id=w,ticket_id=ticket['id'],proposal_id=proposal_id,ticket_revision=ticket['revision'],
        snapshot_json=canonical({'report':snapshot,'rendered':rendered,'status':ticket['status']}),
        material_hash=snapshot['material_hash'],event_type=event,reason=reason,actor_id=actor,created_at=utc(timestamp(now))))
    audit(c,w,event,'tickets',ticket['id'],ticket['revision'],{'reason':reason},actor_id=actor,recorded_at=timestamp(now))
    return ticket


def _chronology(c,w,ticket,now):
    previous=_latest_version(c,w,ticket['id'])
    if previous and timestamp(now)<timestamp(previous['created_at']):
        raise ValueError('Ticket action cannot predate recorded ticket history')


def _transition(c,w,finding,status,now,actor,reason,*,claim_id=None,event_id=None):
    if finding['status']==status:return
    workspace=_workspace(c,w)
    request=StatusTransition.model_validate_json(canonical(dict(workspace_id=w,
        scenario_version_id=workspace['scenario_version_id'],correlation_id=str(uuid4()),mode='replay',
        asset_cve_id=finding['id'],expected_revision=finding['revision'],from_status=finding['status'],to_status=status,
        actor_id=actor,reason=reason,occurred_at=now,reply_claim_id=claim_id,verification_event_id=event_id)))
    transition_finding(c,request)


def _sync_batch(c,w,batch_id,now):
    batch=row(c,'remediation_batches',w,batch_id)
    if batch['confirmed_by'] is None:return
    t=tables['batch_memberships']
    statuses=[row(c,'asset_cves',w,id)['status'] for id in c.scalars(select(t.c.asset_cve_id).where(
        t.c.workspace_id==w,t.c.batch_id==batch_id,t.c.left_at.is_(None)))]
    if not statuses:return
    status=('Verified Remediated' if all(s=='Verified Remediated' for s in statuses) else
            'Pending Verification' if all(s in ('Pending Verification','Verified Remediated') for s in statuses) else
            'Active' if any(s in ('In Remediation','Pending Verification') for s in statuses)
                or batch['status'] in ('Active','Pending Verification','Verified Remediated') else 'Confirmed')
    if status!=batch['status']:
        _update(c,w,'remediation_batches',batch,{'status':status})
        audit(c,w,'BatchAggregateStatus','remediation_batches',batch_id,batch['revision']+1,{'status':status},recorded_at=timestamp(now))


def _deadlines(c,w,snapshot,now):
    policy_id=stable(w,'sla-policy',POLICY['key'],POLICY['version'])
    if not c.scalar(select(tables['policy_versions'].c.id).where(tables['policy_versions'].c.id==policy_id)):
        c.execute(tables['policy_versions'].insert().values(id=policy_id,workspace_id=w,policy_key=POLICY['key'],
            version=POLICY['version'],config_json=canonical(POLICY)))
    for f in snapshot['findings']:
        if f['sla']['due_at'] is None:continue
        t=tables['finding_deadlines']
        old=c.execute(select(t).where(t.c.workspace_id==w,t.c.asset_cve_id==f['id'],t.c.superseded_at.is_(None))).mappings().first()
        if old and old['due_at']==f['sla']['due_at']:continue
        if old:
            c.execute(t.update().where(t.c.id==old['id']).values(superseded_at=utc(timestamp(now))))
        c.execute(t.insert().values(id=str(uuid4()),workspace_id=w,asset_cve_id=f['id'],policy_id=policy_id,
            anchor_at=f['sla']['clock_start'],due_at=f['sla']['due_at'],rationale=f['sla']['category']))
        audit(c,w,'SLADeadlineCalculated','asset_cves',f['id'],0,f['sla'],recorded_at=timestamp(now))


def execute_escalation(c,w,proposal_id,now,operation_key):
    payload={'proposal_id':proposal_id,'now':now}
    if (cached:=_cached(c,w,operation_key,payload)) is not None:return cached
    proposal=row(c,'proposals',w,proposal_id)
    if proposal['kind']!='Ticket':raise ValueError('Ticket proposal required')
    approval=_approved(c,w,proposal,now)
    body,snapshot,scope=_validate_proposal(c,w,proposal,now)
    existing=_match(c,w,scope)
    if body['ticket_id'] is None and existing:raise RevisionConflict('Another ticket now occupies this scope')
    ticket_id=body['ticket_id'] or stable(w,'synthetic-ticket',scope['id'])
    if existing:
        if existing['id']!=ticket_id:raise RevisionConflict('Ticket identity changed')
        ticket=_update(c,w,'tickets',existing,{'proposal_id':proposal_id} if existing['origin']=='generated' else {})
        event='TicketRevised'
    else:
        c.execute(tables['tickets'].insert().values(id=ticket_id,workspace_id=w,batch_id=scope['batch_id'],
            action_key=digest({'scope':scope['id']}),origin='generated',status='Simulated Open',
            proposal_id=proposal_id,created_at=utc(timestamp(now)),revision=0))
        c.execute(tables['ticket_bindings'].insert().values(id=stable(w,'ticket-binding',ticket_id),workspace_id=w,
            ticket_id=ticket_id,scope_id=scope['id']))
        ticket=row(c,'tickets',w,ticket_id)
        event='TicketCreated'
    for f in _members(c,w,scope):
        t=tables['ticket_findings']
        if not c.scalar(select(t.c.id).where(t.c.workspace_id==w,t.c.ticket_id==ticket_id,t.c.asset_cve_id==f['id'])):
            c.execute(t.insert().values(id=stable(w,'ticket-finding',ticket_id,f['id']),workspace_id=w,ticket_id=ticket_id,asset_cve_id=f['id']))
        if f['status']=='Open':_transition(c,w,f,'In Remediation',now,approval['analyst_id'],'Approved synthetic escalation')
    _deadlines(c,w,snapshot,now)
    c.execute(tables['ticket_versions'].insert().values(id=stable(w,'ticket-version',ticket_id,ticket['revision']),
        workspace_id=w,ticket_id=ticket_id,proposal_id=proposal_id,ticket_revision=ticket['revision'],
        snapshot_json=canonical({'report':snapshot,'rendered':body['rendered'],'status':ticket['status']}),
        material_hash=snapshot['material_hash'],event_type=event,reason=','.join(body['change_reasons']),
        actor_id=approval['analyst_id'],created_at=utc(timestamp(now))))
    c.execute(tables['proposals'].update().where(tables['proposals'].c.id==proposal_id).values(status='Simulated Executed'))
    _sync_batch(c,w,scope['batch_id'],now)
    audit(c,w,event,'tickets',ticket_id,ticket['revision'],{'reasons':body['change_reasons']},recorded_at=timestamp(now))
    return _finish(c,w,operation_key,payload,{'ticket_id':ticket_id,'event':event,'revision':ticket['revision']},now)


def seed_historical_ticket(c,w,scope_id,now,operation_key):
    """Explicit synthetic pre-existing history; never fabricate an analyst approval."""
    payload={'scope_id':scope_id,'now':now}
    if (cached:=_cached(c,w,operation_key,payload)) is not None:return cached
    scope=row(c,'lifecycle_scopes',w,scope_id)
    if _match(c,w,scope):raise RevisionConflict('Scope already has a ticket')
    snapshot=_snapshot(c,w,scope_id,now)
    ticket_id=stable(w,'synthetic-ticket',scope_id)
    c.execute(tables['tickets'].insert().values(id=ticket_id,workspace_id=w,batch_id=scope['batch_id'],
        action_key=digest({'scope':scope_id}),origin='seeded',status='Open',proposal_id=None,created_at=utc(timestamp(now)),revision=0))
    c.execute(tables['ticket_bindings'].insert().values(id=stable(w,'ticket-binding',ticket_id),workspace_id=w,
        ticket_id=ticket_id,scope_id=scope_id))
    for f in _members(c,w,scope):
        c.execute(tables['ticket_findings'].insert().values(id=stable(w,'ticket-finding',ticket_id,f['id']),
            workspace_id=w,ticket_id=ticket_id,asset_cve_id=f['id']))
    c.execute(tables['ticket_versions'].insert().values(id=stable(w,'ticket-version',ticket_id,0),workspace_id=w,
        ticket_id=ticket_id,proposal_id=None,ticket_revision=0,snapshot_json=canonical({'report':snapshot,
        'rendered':_render(snapshot),'status':'Open'}),material_hash=snapshot['material_hash'],
        event_type='SyntheticHistoricalSeed',reason='Explicit hypothetical pre-existing ticket; no approval fabricated',
        actor_id='scenario-seed',created_at=utc(timestamp(now))))
    _deadlines(c,w,snapshot,now)
    return _finish(c,w,operation_key,payload,{'ticket_id':ticket_id,'event':'SyntheticHistoricalSeed'},now)


def draft_notification(c,w,ticket_id,now,operation_key,renderer=None):
    payload={'ticket_id':ticket_id,'now':now}
    if (cached:=_cached(c,w,operation_key,payload)) is not None:return cached
    ticket,scope=_ticket_scope(c,w,ticket_id)
    snapshot=_snapshot(c,w,scope['id'],now)
    links=tables['communication_links']
    for id in c.scalars(select(links.c.communication_id).where(links.c.workspace_id==w,links.c.ticket_id==ticket_id)):
        old=row(c,'communications',w,id)
        prior=row(c,'proposals',w,old['proposal_id'])
        body=json.loads(prior['payload_json'])
        if (prior['status'] in ('Awaiting Approval','Approved','Simulated Executed')
            and body['expected_ticket_revision']==ticket['revision']
            and body['snapshot']['binding_hash']==snapshot['binding_hash']):
            return _finish(c,w,operation_key,payload,{'communication_id':old['id'],'proposal_id':prior['id'],
                'payload_hash':prior['payload_hash']},now)
    body={'scope_id':scope['id'],'snapshot':snapshot,'rendered':_render(snapshot,renderer),
          'ticket_id':ticket_id,'expected_ticket_revision':ticket['revision'],
          'created_at':utc(timestamp(now)),'expires_at':utc(timestamp(now)+timedelta(hours=24))}
    proposal_id=_proposal(c,w,scope,'Communication',body,now)
    id=stable(w,'synthetic-email',proposal_id)
    c.execute(tables['communications'].insert().values(id=id,workspace_id=w,batch_id=scope['batch_id'],
        proposal_id=proposal_id,channel='Email',recipient_owner_id=scope['resolver_group_id'],
        body_hash=digest(body['rendered']),delivery_key=digest({'proposal':proposal_id,'recipient':scope['resolver_group_id']}),
        status='Draft',revision=0))
    c.execute(tables['communication_links'].insert().values(id=stable(w,'communication-link',id),workspace_id=w,
        communication_id=id,ticket_id=ticket_id))
    return _finish(c,w,operation_key,payload,{'communication_id':id,'proposal_id':proposal_id,'payload_hash':digest(body)},now)


def simulate_send(c,w,communication_id,now,operation_key):
    payload={'communication_id':communication_id,'now':now}
    if (cached:=_cached(c,w,operation_key,payload)) is not None:return cached
    communication=row(c,'communications',w,communication_id)
    if communication['status']=='Simulated Delivered':return _finish(c,w,operation_key,payload,{'communication_id':communication_id,'outcome':'Already Simulated Delivered'},now)
    proposal=row(c,'proposals',w,communication['proposal_id'])
    _approved(c,w,proposal,now)
    body,_,scope=_validate_proposal(c,w,proposal,now)
    if communication['body_hash']!=digest(body['rendered']) or communication['recipient_owner_id']!=scope['resolver_group_id']:
        raise ApprovalRequired('Draft body or recipient changed')
    _update(c,w,'communications',communication,{'status':'Simulated Delivered'})
    c.execute(tables['simulated_deliveries'].insert().values(id=stable(w,'simulated-receipt',communication_id),
        workspace_id=w,communication_id=communication_id,receipt_key=communication['delivery_key'],
        persisted_at=utc(timestamp(now)),outcome='Simulated Delivered'))
    c.execute(tables['proposals'].update().where(tables['proposals'].c.id==proposal['id']).values(status='Simulated Executed'))
    audit(c,w,'SyntheticMessageDelivered','communications',communication_id,communication['revision']+1,
          {'real_delivery':False},recorded_at=timestamp(now))
    return _finish(c,w,operation_key,payload,{'communication_id':communication_id,'outcome':'Simulated Delivered'},now)


class ReplyInterpreter(Protocol):
    def interpret(self, body:str)->dict: ...


class TemplateReplyInterpreter:
    def interpret(self,body):
        head=body.split(':',1)[0].strip().casefold()
        kind={'completed':'Completed','scheduled':'Scheduled','unable to patch':'Unable to patch',
              'risk exception requested':'Risk exception requested','vulnerability persists':'Vulnerability persists'}.get(head,'Review required')
        return {'intent':kind,'origin':'deterministic_explicit_prefix','requires_review':True,
                'proposed_status':'Pending Verification' if kind=='Completed' else 'In Remediation' if kind=='Scheduled' else None,
                'verified_remediation':False}


def receive_reply(c,request:ResolverReply,interpreter=None):
    context(c,request)
    w,now=str(request.workspace_id),utc(request.received_at)
    payload=request.model_dump(mode='json')
    if (cached:=_cached(c,w,request.operation_key,payload)) is not None:return cached
    ticket,scope=_ticket_scope(c,w,str(request.ticket_id))
    if timestamp(now)<timestamp(ticket['created_at']):raise ValueError('Reply predates ticket creation')
    row(c,'owners',w,request.owner_id)
    t=tables['asset_owners']
    authorized=c.scalar(select(t.c.id).where(t.c.workspace_id==w,t.c.asset_id==scope['asset_id'],
        t.c.owner_id==str(request.owner_id),t.c.valid_to.is_(None)))
    if not authorized:raise ValueError('Reply owner is not assigned to this asset')
    if str(request.owner_id)!=scope['resolver_group_id']:
        primary=c.scalar(select(t.c.id).where(t.c.workspace_id==w,t.c.asset_id==scope['asset_id'],
            t.c.owner_id==str(request.owner_id),t.c.role=='primary',t.c.valid_to.is_(None)))
        if not primary:raise ValueError('Wrong resolver group')
    if request.communication_id is not None:
        communication=row(c,'communications',w,str(request.communication_id))
        linked=c.scalar(select(tables['communication_links'].c.id).where(
            tables['communication_links'].c.workspace_id==w,tables['communication_links'].c.ticket_id==ticket['id'],
            tables['communication_links'].c.communication_id==communication['id']))
        if not linked:raise ValueError('Original communication belongs to another ticket')
    reply_id=stable(w,'resolver-reply',request.operation_key)
    c.execute(tables['owner_replies'].insert().values(id=reply_id,workspace_id=w,owner_id=str(request.owner_id),
        native_reply_key=request.operation_key,received_at=now,raw_body=request.body,body_hash=digest(request.body),
        communication_id=str(request.communication_id) if request.communication_id else None))
    interpreted=(interpreter or TemplateReplyInterpreter()).interpret(request.body)
    interpreted.update(scheduled_at=utc(request.scheduled_at) if request.scheduled_at else None,
                       exception_until=utc(request.exception_until) if request.exception_until else None)
    c.execute(tables['reply_interpretations'].insert().values(id=stable(w,'reply-interpretation',reply_id),workspace_id=w,
        reply_id=reply_id,ticket_id=ticket['id'],intent=interpreted['intent'],interpretation_json=canonical(interpreted),created_at=now))
    return _finish(c,w,request.operation_key,payload,{'reply_id':reply_id,'interpretation':interpreted},now)


def _risk_binding(c,w,ticket,scope,until,now):
    if not until or timestamp(until)<=timestamp(now):raise ApprovalRequired('Future, time-bounded exception expiry required')
    return {'ticket_id':ticket['id'],'ticket_revision':ticket['revision'],'scope_id':scope['id'],
            'members':[(f['id'],f['revision'],f['status']) for f in _members(c,w,scope)],
            'material_hash':_snapshot(c,w,scope['id'],now)['material_hash'],
            'generation':_workspace(c,w)['generation'],'until':until}


def apply_reply(c,w,reply_id,now,operation_key,analyst_id,reason,*,research_run_id=None,proposal_hash=None):
    _analyst(analyst_id,reason)
    payload=dict(reply_id=reply_id,now=now,analyst_id=analyst_id,reason=reason)
    if research_run_id is not None:payload.update(research_run_id=research_run_id,proposal_hash=proposal_hash)
    if (cached:=_cached(c,w,operation_key,payload)) is not None:return cached
    reply=row(c,'owner_replies',w,reply_id)
    if timestamp(now)<timestamp(reply['received_at']):raise ValueError('Cannot process a future reply')
    t=tables['reply_interpretations']
    interpretation=c.execute(select(t).where(t.c.workspace_id==w,t.c.reply_id==reply_id)).mappings().one()
    data=json.loads(interpretation['interpretation_json'])
    ticket,scope=_ticket_scope(c,w,interpretation['ticket_id'])
    if research_run_id is not None:
        from .agent7 import approved_interpretation
        data=approved_interpretation(c,w,reply_id,research_run_id,proposal_hash,now)
    _chronology(c,w,ticket,now)
    intent=data['intent']
    previous=c.scalar(select(tables['audit_events'].c.id).where(tables['audit_events'].c.workspace_id==w,
        tables['audit_events'].c.event_type=='ResolverReplyApplied',tables['audit_events'].c.entity_id==reply_id))
    if previous:raise RevisionConflict('Reply already applied; reuse original operation key')
    result={'reply_id':reply_id,'intent':intent,'requires_review':False}
    if research_run_id is not None:result['research_reference']=dict(run_id=research_run_id,proposal_hash=proposal_hash)
    if intent=='Scheduled' and data['scheduled_at'] is None:result['requires_review']=True
    for finding in _members(c,w,scope):
        claim_id=stable(w,'reply-claim',reply_id,finding['id'])
        c.execute(tables['reply_claims'].insert().values(id=claim_id,workspace_id=w,reply_id=reply_id,
            asset_cve_id=finding['id'],claimed_action=intent,claimed_at=reply['received_at'],extraction_status='Matched'))
        if intent=='Completed' and finding['status'] in ('Open','In Remediation'):
            _transition(c,w,finding,'Pending Verification',now,analyst_id,reason,claim_id=claim_id)
        elif intent=='Scheduled' and finding['status']=='Open':
            _transition(c,w,finding,'In Remediation',now,analyst_id,reason)
        elif intent not in ('Completed','Scheduled'):result['requires_review']=True
    if intent=='Risk exception requested':
        binding=_risk_binding(c,w,ticket,scope,data['exception_until'],now)
        id=stable(w,'risk-review',reply_id)
        c.execute(tables['lifecycle_reviews'].insert().values(id=id,workspace_id=w,kind='Risk',target_id=ticket['id'],
            payload_json=canonical(binding),payload_hash=digest(binding),workspace_generation=binding['generation'],
            status='Awaiting Approval',revision=0,created_at=utc(timestamp(now)),expires_at=utc(timestamp(now)+timedelta(hours=24))))
        result.update(review_id=id,payload_hash=digest(binding))
    if intent in ('Completed','Scheduled'):
        statuses=[f['status'] for f in _members(c,w,scope)]
        status='Closed' if all(s=='Verified Remediated' for s in statuses) else 'Pending Verification' if all(s in ('Pending Verification','Verified Remediated') for s in statuses) else 'In Progress'
        _record_ticket(c,w,ticket,'ResolverStatusUpdate',reason,analyst_id,now,changes={'status':status},snapshot=_snapshot(c,w,scope['id'],now))
    _sync_batch(c,w,scope['batch_id'],now)
    audit(c,w,'ResolverReplyApplied','owner_replies',reply_id,0,result,actor_id=analyst_id,actor_type='analyst',recorded_at=timestamp(now))
    return _finish(c,w,operation_key,payload,result,now)


def record_scanner_result(c,request:ScannerResult):
    context(c,request)
    w,now=str(request.workspace_id),utc(request.recorded_at)
    payload=request.model_dump(mode='json')
    if (cached:=_cached(c,w,request.operation_key,payload)) is not None:return cached
    ticket,scope=_ticket_scope(c,w,str(request.ticket_id))
    _chronology(c,w,ticket,now)
    members={f['id']:f for f in _members(c,w,scope)}
    if set(request.outcomes)-set(members):raise ValueError('Scanner result contains out-of-scope finding')
    batch_id=stable(w,'verification-import',request.operation_key)
    aliases=tables['asset_aliases']
    alias=c.execute(select(aliases).where(aliases.c.workspace_id==w,aliases.c.asset_id==scope['asset_id'],aliases.c.scanner=='Tenable')).mappings().first()
    if not alias:raise ValueError('Explicit Tenable asset alias needed for synthetic verification')
    observed=utc(request.assessed_at)
    c.execute(tables['ingestion_batches'].insert().values(id=batch_id,workspace_id=w,scanner='Tenable',
        scanner_tenant=alias['scanner_tenant'],native_scan_id=request.operation_key,export_hash=digest(payload),
        observed_at=observed,ingested_at=now,status='Imported',duplicate_rows=0))
    outcomes=[]
    for finding_id,result in request.outcomes.items():
        finding=members[finding_id]
        assessment_id=stable(w,'assessment',request.operation_key,finding_id)
        raw_id=stable(w,'assessment-raw',assessment_id)
        raw={'synthetic':True,'asset_id':scope['asset_id'],'component_id':finding['component_id'],
             'cve_id':finding['cve_id'],'result':result,'scan_status':request.scan_status,'assessed_at':observed,
             'severity':{4:'Critical',3:'High',2:'Medium',1:'Low',0:'Informational',None:'Unknown'}[finding['max_severity_rank']] if result=='Fail' else 'Informational'}
        c.execute(tables['raw_findings'].insert().values(id=raw_id,workspace_id=w,ingestion_batch_id=batch_id,
            native_finding_id=request.operation_key+':'+finding['cve_id'],row_key=finding_id,payload_json=canonical(raw),
            payload_hash=digest(raw),raw_severity=raw['severity'],observed_at=observed,
            validation_status='Valid',validation_errors_json='[]'))
        if result=='Fail' and request.scan_status=='Success':
            observation=ScannerFinding.model_validate_json(canonical(dict(workspace_id=w,
                scenario_version_id=_workspace(c,w)['scenario_version_id'],correlation_id=str(uuid4()),mode='replay',
                scanner='Tenable',scanner_tenant=alias['scanner_tenant'],native_scan_id=request.operation_key,
                native_asset_id=alias['native_asset_id'],native_finding_id=request.operation_key+':'+finding['cve_id'],
                asset_id=scope['asset_id'],component_id=finding['component_id'],observed_at=observed,
                raw_severity=raw['severity'],mapped_severity_rank=finding['max_severity_rank'],
                mapping_version='m4-verification-v1',cve_ids=[finding['cve_id']],payload=raw)))
            link_observation(c,observation,raw_id,batch_id)
            finding=row(c,'asset_cves',w,finding_id)
        c.execute(tables['scan_assessments'].insert().values(id=assessment_id,workspace_id=w,
            asset_id=scope['asset_id'],component_id=finding['component_id'],ingestion_batch_id=batch_id,
            assessed_at=observed,scan_status=request.scan_status,
            coverage_json=canonical({'cve_ids':[finding['cve_id']],'explicit_results':{finding['cve_id']:result}})))
        event_id=stable(w,'verification-event',assessment_id)
        c.execute(tables['verification_events'].insert().values(id=event_id,workspace_id=w,asset_cve_id=finding_id,
            assessment_id=assessment_id,result=result,decided_at=now,reason='Explicit synthetic scanner assessment, not a real scan'))
        outcome='Recorded; no closure'
        history=tables['status_history']
        last_status=c.scalar(select(func.max(history.c.occurred_at)).where(history.c.workspace_id==w,history.c.asset_cve_id==finding_id))
        newer_than_claim=timestamp(observed)>timestamp(max(finding['last_seen'],last_status or finding['last_seen']))
        if request.scan_status=='Success' and result=='Pass' and finding['status']=='Pending Verification' and newer_than_claim:
            _transition(c,w,finding,'Verified Remediated',now,'synthetic-scanner','Subsequent explicit passing scanner evidence',event_id=event_id)
            outcome='Verified Remediated'
        elif (request.scan_status=='Success' and result=='Fail' and finding['status'] in ('Pending Verification','Verified Remediated')
              and (last_status is None or timestamp(observed)>timestamp(last_status))):
            _transition(c,w,finding,'Open',now,'synthetic-scanner','Subsequent vulnerable scanner evidence',event_id=event_id)
            outcome='Reopened'
        outcomes.append({'finding_id':finding_id,'scanner_result':result,'decision':outcome})
    statuses=[f['status'] for f in _members(c,w,scope)]
    status='Closed' if all(s=='Verified Remediated' for s in statuses) else 'Pending Verification' if all(
        s in ('Pending Verification','Verified Remediated') for s in statuses) else 'In Progress'
    _record_ticket(c,w,ticket,'ScannerVerification',request.operation_key,'synthetic-scanner',now,
                   changes={'status':status},snapshot=_snapshot(c,w,scope['id'],now))
    _sync_batch(c,w,scope['batch_id'],now)
    return _finish(c,w,request.operation_key,payload,{'ticket_id':ticket['id'],'ticket_status':status,'results':outcomes},now)


def queues(c,w,now):
    _workspace(c,w)
    def records(name):
        t=tables[name]
        return [dict(v) for v in c.execute(select(t).where(t.c.workspace_id==w)).mappings()]
    ticket_list=[]
    for ticket in records('tickets'):
        try: _,scope=_ticket_scope(c,w,ticket['id'])
        except ApprovalRequired:continue
        ticket_list.append({'ticket':ticket,'report':_snapshot(c,w,scope['id'],now)})
    outbox=[]
    for comm in records('communications'):
        proposal=row(c,'proposals',w,comm['proposal_id'])
        outbox.append(dict(comm)|{'rendered':json.loads(proposal['payload_json'])['rendered'],'real_delivery':False})
    return {'tickets':ticket_list,'escalation_queue':[p for p in records('proposals') if p['kind']=='Ticket' and p['status']=='Awaiting Approval'],
            'analyst_approval_queue':[p for p in records('proposals') if p['status']=='Awaiting Approval']+
                                     [r for r in records('lifecycle_reviews') if r['status']=='Awaiting Approval'],
            'inbox':records('owner_replies'),'outbox':outbox,
            'ticket_versions':records('ticket_versions'),'communication_history':records('communication_links')}
