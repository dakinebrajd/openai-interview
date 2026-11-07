"""Pure presentation projections over the existing workspace-scoped dashboard.

No writes, policy decisions, external lookups or reconstructed historical events.
See VISUALIZATION_ACCEPTANCE.md for denominators and provenance.
"""
from collections import Counter
import json


def command_center(data):
    findings = data['findings']
    open_rows = [f for f in findings if f['status'] != 'Verified Remediated']
    checked = [f for f in open_rows if f['kev_state'] != 'Unknown']
    # Usable means a confirmed remediation claim with a retained, fetched source.
    sources = {s['id']: s for s in data['sources']}
    usable = {c['cve_id'] for c in data['evidence_claims']
              if c['claim_type'] == 'VendorRemediation' and c['validation_status'] == 'Confirmed'
              and sources.get(c['source_id'], {}).get('fetch_status') == 'Success'
              and c['cve_id'] in {f['cve_id'] for f in findings}}
    return dict(pipeline=dict(data['summary']), open=len(open_rows),
                kev_checked=len(checked), kev_unknown=len(open_rows)-len(checked),
                kev_exposed=sum(f['known_exploitation'] for f in open_rows),
                unknown_deadlines=sum(not f['due_at'] for f in open_rows),
                outcomes={
                    'Duplicate observation links consolidated': data['summary']['duplicates_consolidated'],
                    'CVEs with captured remediation evidence': len(usable),
                    'Proposed batches (current)': sum(b['status'] == 'Proposed' for b in data['remediation_batches']),
                    'Approved batches (current)': sum(bool(b['confirmed_by']) and b['status'] != 'Cancelled' for b in data['remediation_batches']),
                    'Duplicate escalations suppressed (events)': sum(e['event_type'] == 'DuplicateEscalationSuppressed' for e in data['audit_events']),
                    'Material ticket revisions (events)': sum(v['event_type'] == 'TicketRevised' for v in data['ticket_versions'])})


def intake(data):
    """Distinct retained raw IDs, not CVE links (one raw row can contain many CVEs)."""
    batches = {b['id']: b for b in data['ingestion_batches']}
    rows = [{'scanner': batches[r['ingestion_batch_id']]['scanner'],
             'result': 'Quarantined' if r['validation_status'] == 'Quarantined' else 'Accepted'}
            for r in data['raw_findings']]
    counts = Counter((r['scanner'], r['result']) for r in rows)
    return [{'scanner': scanner, 'accepted': counts[scanner, 'Accepted'],
             'quarantined': counts[scanner, 'Quarantined'],
             'received': counts[scanner, 'Accepted']+counts[scanner, 'Quarantined']}
            for scanner in sorted({r['scanner'] for r in rows})]


def case_events(data, ticket_id=None):
    """Chronological retained events, joined through exact ticket/proposal IDs."""
    tickets = {t['id'] for t in data['tickets'] if ticket_id is None or t['id'] == ticket_id}
    proposals = {}
    for p in data['proposals']:
        payload = json.loads(p['payload_json'])
        if payload.get('ticket_id') in tickets or (p.get('executed_ticket_id') in tickets):
            proposals[p['id']] = p
    # Ticket proposal linkage is authoritative in ticket_versions, including revisions.
    proposals.update({p['id']: p for p in data['proposals'] if any(
        v['ticket_id'] in tickets and v['proposal_id'] == p['id'] for v in data['ticket_versions'])})
    events = []
    def add(at, event, detail, reference, basis='Synthetic effective time', recorded_at=None):
        events.append(dict(at=at, event=event, detail=detail, evidence_reference=reference,
                           time_basis=basis if at else 'Timestamp not recorded', recorded_at=recorded_at))
    for p in proposals.values():
        add(None, p['kind']+' draft', p['status']+' · creation time not recorded', p['id'])
    for a in data['approvals']:
        if a['proposal_id'] in proposals:
            add(a.get('decided_at') or a.get('created_at'), 'Analyst decision', a['decision'], a['id'])
    for v in data['ticket_versions']:
        if v['ticket_id'] in tickets:
            add(v['created_at'], v['event_type'], 'Revision '+str(v['ticket_revision'])+' · '+v['reason'], v['id'])
    comms = {c['id']: c for c in data['communications'] if c['proposal_id'] in proposals}
    for c in comms.values():
        add(None, 'Synthetic notification', c['status']+' · creation time not recorded', c['id'])
    for receipt in data['simulated_deliveries']:
        if receipt['communication_id'] in comms:
            add(receipt['persisted_at'], 'Simulated receipt', 'Local only; no external delivery', receipt['id'])
    for r in data['owner_replies']:
        if any(i['reply_id'] == r['id'] and i['ticket_id'] in tickets for i in data['reply_interpretations']):
            add(r['received_at'], 'Resolver response', r['raw_body'], r['id'])
    for v in data['verification_events']:
        if any(link['ticket_id'] in tickets and link['asset_cve_id'] == v['asset_cve_id'] for link in data['ticket_findings']):
            add(v['decided_at'], 'Scanner verification', v['result']+' · '+v['reason'], v['id'])
    # Suppression may reference a scope rather than a ticket. Never attribute it
    # to a selected case without an exact relationship.
    for a in data['audit_events']:
        if (a['event_type'] == 'DuplicateEscalationSuppressed' and
                (ticket_id is None or a['entity_id'] in tickets or a['entity_id'] in proposals)):
            payload = json.loads(a['payload_json'])
            effective = payload.get('synthetic_effective_at')
            add(effective or a['recorded_at'], 'Suppress unchanged duplicate',
                'No new ticket or notification created by this decision', a['id'],
                'Synthetic effective time' if effective else 'Actual audit recording time', a['recorded_at'])
    return sorted(events, key=lambda r: (r['at'] is None, r['at'] or '', r['evidence_reference']))


def verification_rows(data):
    """Link each actual verification decision to its exact scanner assessment."""
    findings = {f['id']: f for f in data['findings']}
    assessments = {a['id']: a for a in data['scan_assessments']}
    return [dict(finding=findings[v['asset_cve_id']]['asset_key']+' · '+findings[v['asset_cve_id']]['cve_id'],
                 result=v['result'], assessed_at=assessments[v['assessment_id']]['assessed_at'],
                 scan_status=assessments[v['assessment_id']]['scan_status'], reason=v['reason'])
            for v in data['verification_events'] if v['asset_cve_id'] in findings]


def has_recorded_live(data, role=None):
    """Recorded live execution (including failure) differs from current enablement."""
    for step in data['agent_steps']:
        if (role is None or step['role_number'] == role) and step.get('output_json'):
            output = json.loads(step['output_json'])
            if (output.get('execution', {}).get('origin') == 'live_model' and
                    (output.get('result') or output.get('quarantined_candidate') or
                     output.get('execution',{}).get('provider_attempts',0)>0)):
                return True
    return False


def output_summary(step):
    """Describe only recorded output values; execution status is shown separately."""
    if not step.get('output_json'):
        return 'No output recorded'
    output = json.loads(step['output_json'])
    if output.get('contract_version')=='m6e-agent6-v1':
        execution=output['execution'];mode={'offline_mock':'Offline Mock','human_curated_source_backed_replay':'Replay','live_model':'Live AI'}[execution['origin']]
        return mode+' | Agent 6 '+output['review_status']+'; proposed report/ticket/email only; separate operational approvals required.'
    if output.get('contract_version') in ('m6d-agent3-v1','m6d-agent3-v2','m6d-agent3-live-evaluation-v1'):
        mode={'offline_mock':'Offline Mock','human_curated_source_backed_replay':'Replay','live_model':'Live AI'}[output['execution']['origin']]
        result=output.get('result')
        return (mode+' | '+str(len(result['batches']))+' proposed groups; '+str(len(result['excluded']))+
            ' excluded findings; analyst review required, no operational adoption.') if result else mode+' | Rejected/quarantined batching assessment'
    if output.get('contract_version') in ('m6c-agent4-v1', 'm6c-agent4-live-evaluation-v1'):
        execution = output['execution']
        mode = {'live_model':'Live AI', 'offline_mock':'Offline mock',
                'human_curated_source_backed_replay':'Replay'}[execution['origin']]
        return (mode+' | '+output['cve_id']+' | '+output['review_status']+
                '; threat research requires analyst review, not operational approval.')
    if output.get('contract_version') == 'm6a-agent2-v1':
        return (output['execution']['origin']+' · '+output['review_status']+' · requested model '+
                output['execution']['model_requested']+'; provider attempts '+str(output['execution']['provider_attempts'])+
                '. Research is not operational approval.')
    if 'guidance' in output:
        g = output['guidance']
        return f"{g['cve_id']}: {g['status']} historical guidance; confidence {g['confidence']}; {len(g['gaps'])} recorded gaps. Applicability requires validation."
    if 'threat' in output:
        t = output['threat']
        kev = 'Unknown' if t.get('kev_member') is None else 'Captured member' if t['kev_member'] else 'Checked, not listed'
        return f"KEV: {kev}; EPSS: {t.get('epss_score') if t.get('epss_score') is not None else 'Unknown'}; sector: {t.get('sector_targeting', 'Unknown')}. Captured feed interpretation."
    if 'summary' in output:
        s = output['summary']
        fields = [('supported_guidance', 'supported historical guidance dossiers'),
                  ('conflicting_guidance', 'conflicting dossiers'), ('missing_patch_guidance', 'missing selected fixes'),
                  ('proposed_batches', 'proposed batches'), ('real_model_calls', 'recorded real model calls')]
        return '; '.join(str(s[k])+' '+label for k, label in fields if k in s) or 'Recorded summary available in exact output'
    return 'Stored output available for review; no presentation summary defined for this output type'


def guidance_body(report):
    """De-duplicate display wrappers only; never modify the immutable report/draft."""
    text = report['guidance']
    boundary = ('Historical advisory boundary - not a current secure-release recommendation. '
                'Validate current vendor guidance and real product/version applicability before any real action.\n')
    if text.startswith(boundary):
        text = text[len(boundary):]
    assumed = '; '.join(sorted({a['product']+' '+a['installed_version'] for a in report.get('assumptions', [])}))
    return '\n'.join(line for line in text.splitlines()
                     if not assumed or line != 'Synthetic installed-version assumptions: '+assumed)
