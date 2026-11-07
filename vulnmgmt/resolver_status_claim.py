"""Versioned status-only completion CLAIM; no finding transition authority."""
import json
from .services import digest, audit
from .database import make_engine

PROTOCOL = 'resolver-status-completion-claim-v1'
HEADER = 'Resolver status completion claim v1: '
EVENT = 'ResolverCompletionClaimRecorded'


def submission_binding(data,ticket,status,parent,previous=None):
    """Same unchanged form submission retries its original payload-bound operation."""
    signature=digest([data['workspace_id'],data['workspace_identity'],data['generation'],
                      ticket['id'],ticket['revision'],status,parent['refs']['communication_id']])
    if isinstance(previous,dict) and previous.get('signature')==signature:
        return previous
    from uuid import uuid4
    return dict(signature=signature,operation_key=str(uuid4()),
                parent_run_id=parent['run_id'],parent_hash=parent['state_hash'])


def body(status, ticket_id, revision):
    if status not in ('Closed', 'Resolved'):
        raise ValueError('Completion claim requires Closed or Resolved')
    return (HEADER + status + '. Ticket ' + ticket_id + ' revision ' + str(revision) +
            '. Resolver reports remediation completed for the entire assigned ticket scope. '
            'This is a resolver completion claim, not proof of remediation. '
            'No new work note, implementation evidence or scanner result was supplied. '
            'Independent scanner verification and named analyst review are required.')


def prior_notes(data, ticket_id, exclude_reply=None):
    status_replies=set()
    replies={r['id']:r for r in data['owner_replies']}
    for event in data['audit_events']:
        if event['event_type']!='ResolverStatusReported' or event['entity_id']!=ticket_id:
            continue
        p=json.loads(event['payload_json']);reply=replies.get(p.get('reply_id'))
        if not reply or p.get('source')!='status-control' or p.get('work_note_changed') is not False:
            continue
        status=p.get('status');revision=p.get('ticket_revision')
        old=('Resolver status selection: '+str(status)+'. Ticket '+ticket_id+' revision '+str(revision)+
             '. No new work note, remediation completion evidence or scanner result was supplied. This is a literal status-control event, not a new resolver work note.')
        if status in ('New','In Progress','Resolved','Closed') and reply['raw_body']==old:
            status_replies.add(reply['id']);continue
        if status not in ('Closed','Resolved') or reply['raw_body']!=body(status,ticket_id,revision):
            continue
        receipts=[e for e in data['audit_events'] if e['event_type']==EVENT and e['entity_id']==reply['id']]
        if len(receipts)!=1:continue
        receipt=receipts[0];claim=json.loads(receipt['payload_json'])
        bound=dict(protocol=PROTOCOL,status=status,ticket_id=ticket_id,ticket_revision=revision,
                   reply_id=reply['id'],body_hash=digest(reply['raw_body']),owner_id=reply.get('owner_id'),
                   communication_id=reply.get('communication_id'),workspace_id=data['workspace_id'],
                   workspace_identity=data['workspace_identity'],generation=data['generation'],
                   actor=event.get('actor_id'),work_note_changed=False,completion_claim=True,verified_remediation=False)
        if all(claim.get(k)==v for k,v in bound.items()) and receipt.get('actor_id')==claim.get('actor'):
            status_replies.add(reply['id'])
    ticket_replies = {r['reply_id'] for r in data['reply_interpretations'] if r['ticket_id'] == ticket_id}
    return sorted(r['id'] for r in data['owner_replies'] if r['id'] in ticket_replies
                  and r['id'] not in status_replies and r['id'] != exclude_reply)


def record(manager, generation, *, data, ticket, scope, reply_id, status, actor, raw_body):
    if raw_body != body(status, ticket['id'], ticket['revision']):
        raise ValueError('Exact status completion claim body required')
    payload = dict(protocol=PROTOCOL, status=status, ticket_id=ticket['id'],
                   ticket_revision=ticket['revision'], reply_id=reply_id,
                   owner_id=scope['resolver_group_id'], communication_id=scope['_communication_id'],
                   workspace_id=data['workspace_id'], workspace_identity=data['workspace_identity'],
                   generation=generation, body_hash=digest(raw_body),
                   finding_ids=sorted(r['asset_cve_id'] for r in data['ticket_findings'] if r['ticket_id'] == ticket['id']),
                   prior_note_ids=prior_notes(data,ticket['id'],reply_id), actor=actor,
                   completion_claim=True, verified_remediation=False, work_note_changed=False)
    with manager.execution(generation, 'record_resolver_completion_claim') as (path,w,clock,receipt):
        engine=make_engine(path)
        try:
            with engine.begin() as c:
                from sqlalchemy import select
                from .database import tables
                events=c.execute(select(tables['audit_events']).where(
                    tables['audit_events'].c.workspace_id==w['id'],
                    tables['audit_events'].c.event_type==EVENT,
                    tables['audit_events'].c.entity_id==reply_id)).mappings().all()
                if events:
                    if len(events)!=1 or json.loads(events[0]['payload_json'])!=payload:
                        raise ValueError('Completion claim receipt already exists with different bindings')
                    return
                audit(c,w['id'],EVENT,'owner_replies',reply_id,ticket['revision'],payload,
                      actor_type='analyst',actor_id=actor)
        finally:engine.dispose()


def policy_flags(data, reply, ticket, scope, members):
    if not reply['raw_body'].startswith(HEADER):
        return []
    invalid = ['Status completion claim receipt is missing, stale or mismatched; clarify before processing']
    events = [e for e in data['audit_events'] if e['event_type'] == EVENT and e['entity_id'] == reply['id']]
    if len(events) != 1:
        return invalid
    event=events[0]; p=json.loads(event['payload_json'])
    if not p.get('actor') or event.get('actor_id')!=p['actor']:
        return invalid
    status=p.get('status')
    if status not in ('Closed','Resolved') or reply['raw_body'] != body(status,ticket['id'],ticket['revision']):
        return invalid
    expected=dict(protocol=PROTOCOL,ticket_id=ticket['id'],ticket_revision=ticket['revision'],
                  reply_id=reply['id'],owner_id=reply['owner_id'],communication_id=reply['communication_id'],
                  workspace_id=data['workspace_id'],workspace_identity=data['workspace_identity'],
                  generation=data['generation'],body_hash=reply['body_hash'],
                  finding_ids=sorted(f['id'] for f in members),completion_claim=True,
                  verified_remediation=False,work_note_changed=False)
    if any(p.get(k)!=v for k,v in expected.items()) or p.get('owner_id')!=scope['resolver_group_id']:
        return invalid
    reports=[e for e in data['audit_events'] if e['event_type']=='ResolverStatusReported' and e['entity_id']==ticket['id']]
    latest=max(reports,key=lambda e:(e.get('recorded_at',''),e.get('id','')),default=None)
    if not latest or json.loads(latest['payload_json']).get('reply_id')!=reply['id']:
        return invalid
    from .enrichment_evidence import timestamp
    if timestamp(event['recorded_at']) < timestamp(latest['recorded_at']):
        return invalid
    status_events=[json.loads(e['payload_json']) for e in reports if e.get('actor_id')==p.get('actor')]
    if not any(e.get('reply_id')==reply['id'] and e.get('status')==status and e.get('ticket_revision')==ticket['revision'] for e in status_events):
        return invalid
    notes=prior_notes(data,ticket['id'],reply['id'])
    if p.get('prior_note_ids')!=notes:
        return invalid
    return ['Retained resolver work notes require clarification; a status claim cannot override their meaning'] if notes else []


def scope_hash(supplied):
    return digest({k:supplied[k] for k in ('workspace_id','workspace_identity','generation','reply_id',
        'ticket_id','ticket_revision','owner_id','communication_id','body_hash','finding_ids')})


def binding(data,reply,ticket,scope,members,supplied):
    if not reply['raw_body'].startswith(HEADER) or policy_flags(data,reply,ticket,scope,members):
        return None
    event=next(e for e in data['audit_events'] if e['event_type']==EVENT and e['entity_id']==reply['id'])
    payload=json.loads(event['payload_json'])
    return dict(protocol=PROTOCOL,event_id=event['id'],event_hash=digest(event),scope_hash=scope_hash(supplied),
                status=payload['status'],actor=payload['actor'],body_hash=reply['body_hash'])


def validate_binding(supplied):
    from .live_contracts import LiveResearchError
    claim=supplied.status_completion_claim
    if (claim is None or not claim.event_id or not claim.event_hash or not claim.actor or
        claim.scope_hash!=scope_hash(supplied.model_dump()) or claim.body_hash!=supplied.body_hash or
        supplied.body!=body(claim.status,supplied.ticket_id,supplied.ticket_revision)):
        raise LiveResearchError('Typed audited completion claim binding required; literal status text has no authority.')
