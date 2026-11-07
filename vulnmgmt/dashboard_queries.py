"""Agent 8 read models. Every operational query is workspace-scoped."""
from collections import Counter
import json
from sqlalchemy import select
from .database import tables
from .enrichment_evidence import timestamp
from .register import build_register
from .sla import calculate_sla, overdue_state
from .lifecycle import queues, _source
from .research_sources import source_text
from .services import digest


def revision_token(data):
    """Reviewed operational context, excluding append-only UI receipts/audit noise."""
    return digest({k: data[k] for k in ('workspace_id', 'as_of', 'findings', 'tickets',
        'remediation_batches', 'proposals', 'lifecycle_reviews', 'communications',
        'synthetic_applicability', 'evidence_claims', 'threat_intel', 'exceptions')})


def executive(data):
    """All finding metrics count unique workspace/asset/component/CVE obligations."""
    rows = data['findings']
    now = timestamp(data['as_of'])
    from datetime import timedelta
    open_rows = [r for r in rows if r['status'] != 'Verified Remediated']
    review = [r for r in rows if 'review required' in r['applicability'].lower()
              or r['threat_freshness'] in ('Stale', 'Unavailable')]
    pending = data['lifecycle'].get('analyst_approval_queue', [])
    suppressed = [a for a in data['audit_events'] if a['event_type'] == 'DuplicateEscalationSuppressed']
    upcoming = [r for r in open_rows if r['due_at'] and now <= timestamp(r['due_at']) <= now+timedelta(days=7)]
    metrics = dict(data['metrics'], critical_high=sum(r['severity'] in ('Critical', 'High') for r in open_rows),
        known_exploitation=sum(r['known_exploitation'] for r in open_rows), upcoming=len(upcoming),
        awaiting_approval=len(pending), duplicate_escalations_prevented=len(suppressed), review_required=len(review))
    action_queue = sorted(open_rows, key=lambda r: (not r['overdue'], not r['known_exploitation'],
        -(r['max_severity_rank'] if r['max_severity_rank'] is not None else -1), r['due_at'] or 'z', r['id']))
    return {'metrics': metrics, 'action_queue': action_queue, 'review_ids': [r['id'] for r in review],
            'upcoming_ids': [r['id'] for r in upcoming],
            'definitions': {
                'findings': 'All unique workspace + asset + software-component + CVE records, including verified records.',
                'critical_high': 'Unverified records whose highest scanner severity is Critical or High.',
                'known_exploitation': 'Unverified asset/component/CVE records linked to confirmed captured KEV evidence; not unique CVEs or active agency attacks.',
                'overdue': 'Unverified records beyond the hypothetical policy due date, excluding currently approved deferments.',
                'upcoming': 'Unverified records due from the displayed synthetic time through the next seven calendar days.',
                'awaiting_approval': 'Pending batch/risk reviews plus ticket/message proposals; counts decision items, not vulnerabilities.',
                'duplicate_escalations_prevented': 'Recorded DuplicateEscalationSuppressed decisions, including pending-draft suppression. Not measured email notifications prevented or analyst time saved.',
                'review_required': 'Unique findings with unknown/synthetic applicability or stale/unavailable threat evidence; a broad review workload indicator.',
                'sla_compliance_percent': '100 × open obligations not effectively overdue / all open obligations; N/A if none.',
                'verified_remediated': 'Records closed by adequate subsequent scanner evidence; simulated scanners in this prototype.'}}


def records(c, name, w):
    t = tables[name]
    return [dict(r) for r in c.execute(select(t).where(t.c.workspace_id == w)).mappings()]


def dashboard(c, w, now, *, search='', severity=None, status=None, asset_type=None,
              resolver_group=None, scanner=None):
    register = build_register(c, w)
    intel = records(c, 'threat_intel', w)
    sources = {s['id']: s for s in records(c, 'evidence_sources', w)}
    assumptions = records(c, 'synthetic_applicability', w)
    exceptions = records(c, 'exceptions', w)
    claims = records(c, 'evidence_claims', w)
    rows = []
    for f in register['vulnerabilities']:
        facts = [i for i in intel if i['cve_id'] == f['cve_id']
                 and i['validation_status'] == 'Confirmed' and timestamp(i['as_of']) <= timestamp(now)]
        kev = [i for i in facts if i['kind'] == 'KEV']
        known = any(i['kev_member'] == 1 for i in kev)
        epss = sorted([i for i in facts if i['kind'] == 'EPSS'], key=lambda i: i['as_of'])
        exploitable = False
        for claim in claims:
            if (claim['cve_id'] == f['cve_id'] and claim['claim_type'] == 'Exploitability'
                    and claim['validation_status'] == 'Confirmed'):
                try:
                    _, payload, freshness = _source(c, w, claim['source_id'], now)
                    if freshness == 'Fresh' and claim['supporting_excerpt'] in source_text(payload):
                        exploitable = True
                except ValueError:
                    pass
        sla = calculate_sla(f['severity'], f['first_seen'], actively_exploited=known, exploitable=exploitable)
        until = max((e['expires_at'] for e in exceptions if e['asset_cve_id'] == f['id']
                     and e['status'] == 'Active' and timestamp(e['expires_at']) > timestamp(now)), default=None)
        f.update(known_exploitation=known, kev_state='Captured KEV member' if known else
                 'Not in captured catalog' if kev else 'Unknown',
                 epss=epss[-1]['epss_score'] if epss else None,
                 epss_as_of=epss[-1]['as_of'] if epss else None,
                 sector_targeting='Unknown', priority=sla['category'], due_at=sla['due_at'],
                 applicability='Synthetic assumption; review required' if any(
                     a['component_id'] == f['component_id'] for a in assumptions) else 'Unknown installed version; review required',
                 threat_freshness='Stale' if facts and any(timestamp(i['expires_at']) < timestamp(now) for i in facts)
                                 else 'Captured evidence' if facts else 'Unavailable',
                 **overdue_state(sla['due_at'], now, exception_until=until,
                                 verified=f['status'] == 'Verified Remediated'))
        text = json.dumps(f, ensure_ascii=False).casefold()
        if search.casefold() not in text:
            continue
        if any(value and f[key] != value for key, value in
               [('severity', severity), ('status', status), ('asset_type', asset_type)]):
            continue
        if resolver_group and resolver_group not in f['resolver_groups']:
            continue
        if scanner and not any(o['scanner'] == scanner for o in f['observations']):
            continue
        rows.append(f)
    counts = {key: dict(Counter(f[key] for f in rows)) for key in
              ('severity', 'asset_type', 'status', 'priority', 'kev_state', 'applicability')}
    counts['resolver_group'] = dict(Counter(g for f in rows for g in f['resolver_groups']))
    closed = sum(f['status'] == 'Verified Remediated' for f in rows)
    overdue = sum(f['overdue'] for f in rows)
    open_count = len(rows) - closed
    try:
        lifecycle = queues(c, w, now)
        lifecycle_error = None
    except ValueError as exc:
        lifecycle, lifecycle_error = {}, str(exc)
    workspace=c.execute(select(tables['demo_workspaces']).where(tables['demo_workspaces'].c.id==w)).mappings().one()
    return dict(workspace_id=w, workspace_identity=workspace['database_identity'], generation=workspace['generation'],
                as_of=now, summary=register['summary'], findings=rows, counts=counts,
                metrics={'findings': len(rows), 'verified_remediated': closed, 'overdue': overdue,
                         'open': open_count, 'within_sla_open': open_count-overdue,
                         'sla_compliance_percent': round(100*(open_count-overdue)/open_count, 1) if open_count else None},
                sources=list(sources.values()), quarantine=register['quarantine'], lifecycle=lifecycle,
                lifecycle_error=lifecycle_error,
                **{name: records(c, name, w) for name in
                   ('owners', 'asset_owners', 'asset_components', 'remediation_actions', 'evidence_claims', 'threat_intel', 'synthetic_applicability', 'remediation_batches',
                    'batch_proposal_members', 'batch_memberships', 'runs', 'agent_steps', 'audit_events',
                    'proposals', 'lifecycle_reviews', 'tickets', 'ticket_versions', 'communications',
                    'owner_replies', 'reply_interpretations', 'communication_links', 'verification_events', 'status_history',
                    'exceptions', 'lifecycle_scopes', 'ticket_bindings', 'simulated_deliveries', 'approvals',
                    'ticket_findings', 'scan_assessments', 'raw_findings', 'ingestion_batches')})
