"""Resolver demo perspective: saved work notes, never direct finding transitions."""
import json
from . import agent0, dashboard_service as commands
from .services import digest
from .enrichment_evidence import timestamp

STATUSES = ('New', 'In Progress', 'Resolved', 'Closed')
PREFIXES = {
    'Closed': 'Resolver-reported status: Closed. This records the resolver ticket closure assertion. The work note supplies any remediation claim; independent scanner verification remains separate.',
    'New': 'Resolver-reported status: New. Remediation work has not started.',
    'In Progress': 'Resolver-reported status: In Progress. Work is underway; no completion is claimed.',
    'Resolved': 'Resolver-reported status: Resolved. Remediation completed for the entire ticket. Please verify through independent scanning.',
}


def ticket_replies(data, ticket_id):
    ids = {r['reply_id'] for r in data['reply_interpretations'] if r['ticket_id'] == ticket_id}
    started = {r['id']: r['started_at'] for r in data['runs']}
    order = {s['refs']['reply_id']: started.get(s['run_id'], '') for s in agent0.stored(data)
             if s['refs'].get('reply_id') and s['refs'].get('ticket_id') == ticket_id}
    return sorted((r for r in data['owner_replies'] if r['id'] in ids),
                  key=lambda r: (order.get(r['id'], ''), r['received_at'], r['id']))


def reported_status(data, ticket_id):
    events=[e for e in data.get('audit_events',[]) if e['event_type']=='ResolverStatusReported' and e['entity_id']==ticket_id]
    if events:return json.loads(max(events,key=lambda e:(e['recorded_at'],e['id']))['payload_json'])['status']
    replies = ticket_replies(data, ticket_id)
    for reply in reversed(replies):
        body = reply['raw_body']
        for status, prefix in PREFIXES.items():
            if body.startswith(prefix):
                return status
    return 'No resolver update'


def ticket_rows(data):
    """Display immutable approved report bodies and current independent lifecycle state."""
    rows = []
    versions = data['ticket_versions']
    for ticket in data['tickets']:
        approved = [v for v in versions if v['ticket_id'] == ticket['id'] and v.get('proposal_id')]
        version = max(approved, key=lambda v: v['ticket_revision'], default=None)
        # The current operational snapshot can change after scanner verification.
        # Ticket fields must continue to show the exact historically approved report.
        payload = json.loads(version['snapshot_json']) if version else None
        report = payload.get('report') if isinstance(payload, dict) else None
        if not report:
            item = next((r for r in data['lifecycle'].get('tickets', []) if r['ticket']['id'] == ticket['id']), None)
            report = item['report'] if item else None
        rendered=payload.get('rendered',{}) if isinstance(payload,dict) else {}
        subject=next((rendered[key] for key in ('subject','title') if isinstance(rendered.get(key),str) and rendered[key].strip()),None)
        description=rendered.get('ticket_description') or ''
        short_description=subject if subject is not None else next((line.strip() for line in description.splitlines() if line.strip()),'Not recorded')
        finding_ids={f['asset_cve_id'] for f in data.get('ticket_findings',[]) if f['ticket_id']==ticket['id']}
        related={ticket['id']}|finding_ids|{v['id'] for v in versions if v['ticket_id']==ticket['id']}|{reply['id'] for reply in ticket_replies(data,ticket['id'])}
        events=[event for event in data.get('audit_events',[]) if event.get('entity_id') in related and event.get('recorded_at')]
        latest=max(events,key=lambda event:timestamp(event['recorded_at']),default=None)
        rows.append(dict(ticket=ticket, report=report,short_description=short_description,
                         due_at=(report or {}).get('material',{}).get('due_at'),
                         last_activity_at=latest['recorded_at'] if latest else 'Not recorded',
                         last_activity_event_id=latest['id'] if latest else None,
                         last_activity_type=latest['event_type'] if latest else 'Not recorded',
                         reference=ticket.get('external_synthetic_key') or 'Local '+ticket['id'][:8],
                         reported_status=reported_status(data, ticket['id'])))
    return rows


def submit_update(manager, generation, *, parent_run_id, parent_hash, ticket_id,
                  status, note, operation_key, confirmed, actor, mode='replay',
                  spend_confirmed=False, application=None, status_only=False):
    """Intake + linked interpretation cycle only. Agent execution stays explicit.

    New/In Progress/Resolved/Closed are resolver assertions embedded in immutable intake.
    No schema/status-trigger change or lifecycle authority is granted to a dropdown.
    """
    if status not in STATUSES:
        raise ValueError('Choose a supported resolver-reported status; scanner verification remains separate')
    if type(status_only) is not bool or (status_only and note.strip()):raise ValueError('Status-only input cannot introduce or overwrite a work note')
    if not confirmed or not actor.strip() or (not status_only and not note.strip()) or not operation_key:
        raise ValueError('A named, confirmed resolver update and work note are required')
    if mode not in ('replay', 'mixed'):
        raise ValueError('Choose Replay or separately authorized Live AI interpretation')
    if mode == 'mixed':
        if not spend_confirmed or application is None:
            raise ValueError('Separate one-request live interpretation authorization required')
        from .local_security import require_local_operator
        require_local_operator()
    data = commands.view(manager)
    parent = agent0._load(data, parent_run_id)
    if parent['generation'] != generation or parent['state_hash'] != parent_hash:
        raise ValueError('Assessment changed; refresh the exact resolver update context')
    refs = parent['refs']
    if refs.get('ticket_id') != ticket_id or not refs.get('communication_id'):
        raise ValueError('Exact assigned ticket and approved communication are required')
    ticket = next((t for t in data['tickets'] if t['id'] == ticket_id), None)
    if ticket is None or ticket['status'] == 'Closed':
        raise ValueError('Closed/verified tickets cannot be reopened by a resolver assertion; use scanner evidence')
    scope = next(s for s in data['lifecycle_scopes'] if s['id'] == refs['scope_id'])
    body = ('Resolver status selection: '+status+'. Ticket '+ticket_id+' revision '+str(ticket['revision'])+'. No new work note, remediation completion evidence or scanner result was supplied. This is a literal status-control event, not a new resolver work note.' if status_only else PREFIXES[status]+'\nWork note: '+note.strip())
    if status_only and status in ('Closed','Resolved'):
        from . import resolver_status_claim
        body=resolver_status_claim.body(status,ticket_id,ticket['revision'])
    reply = commands.receive_research_reply(
        manager, generation, ticket_id=ticket_id, owner_id=scope['resolver_group_id'],
        communication_id=refs['communication_id'], body=body, confirmed=True,
        actor=actor, reason='Synthetic resolver ticket status/work note; no direct finding transition',
        operation_key='resolver-note-'+operation_key)
    if status_only:
        from .workflow_control import record_status_event
        record_status_event(manager,generation,ticket_id=ticket_id,reply_id=reply['reply_id'],status=status,ticket_revision=ticket['revision'],actor=actor)
        if status in ('Closed','Resolved'):
            resolver_status_claim.record(manager,generation,data=data,ticket=ticket,
                scope=dict(scope,_communication_id=refs['communication_id']),reply_id=reply['reply_id'],
                status=status,actor=actor,raw_body=body)
    child = commands.start_reply_cycle(
        manager, generation, parent_run_id=parent_run_id, parent_hash=parent_hash,
        reply_id=reply['reply_id'], mode=mode, confirmed=True, actor=actor,
        reason='Interpret this resolver update only; retain linked approved prerequisites',
        operation_key='resolver-cycle-'+operation_key)
    if mode == 'mixed':
        from . import m7_campaign
        m7_campaign.authorize(application, manager, child, confirmed=True, actor=actor,
                              reason='One explicitly authorized resolver ticket interpretation',
                              max_attempts=1, allowance_micro_usd=100000)
    return dict(reply_id=reply['reply_id'], run_id=child['run_id'],
                reported_status=status, operational_status=ticket['status'],
                processing='Awaiting explicit Agent 7 execution', verified=False)
