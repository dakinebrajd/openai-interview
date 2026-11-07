"""Read-only eight-stage planner. Navigation never executes or approves anything."""
import json
from .enrichment_evidence import timestamp

STAGES = [
    ('Import scanner exports', 'Agent 1 · deterministic Python', 'Bring two synthetic scanner formats into one auditable inventory.',
     'Hash-pinned Tenable-style and Defender-style JSON exports.', 'Explain that these are synthetic adapters, not production integrations.'),
    ('Inspect deduplication', 'Agent 1 · deterministic Python', 'Separate scanner observations from distinct remediation obligations.',
     'Persisted observations, aliases, component identities and source links.', 'Ask why the same CVE on two assets must remain two obligations.'),
    ('Research and review evidence', 'Agents 2 / 4 · source-backed replay', 'Ground guidance in dated, attributable public sources.',
     'Twelve real CVE IDs and the pinned public-source evidence bundle.', 'Replay is human-curated historical evidence, not a live model call or fresh retrieval.'),
    ('Evaluate intelligence and batching', 'Agents 3 / 4 · deterministic validation', 'Require shared verified remediation and explicit applicability before grouping.',
     'KEV, EPSS, unknown targeting and a labeled synthetic OpenSSL version overlay.', 'KEV is known exploitation; EPSS predicts likelihood; neither establishes agency targeting.'),
    ('Approve resolver escalation', 'Agents 0 / 5 / 6 · local approval services', 'Route an obligation to its resolver with separate ticket and message permissions.',
     'Reviewed batch, exact proposal payload, source citations and hypothetical SLA.', 'Read the payload before each approval. Approval never follows from navigation.'),
    ('Prove duplicate suppression', 'Agent 5 · deterministic comparison', 'Avoid another ticket when no material facts have changed.',
     'Existing ticket snapshot compared with the current remediation identity.', 'Show the actual Suppressed reason and before/after ticket versions; do not claim time savings.'),
    ('Verify remediation', 'Agent 7 · synthetic reply and scanner evidence', 'Treat an owner claim as a hypothesis until subsequent independent evidence supports it.',
     'Explicit Completed reply, later synthetic assessment and full member coverage.', 'Pause at Pending Verification. A passing scanner fixture is simulated, not a real asset scan.'),
    ('Review outcomes and audit', 'Agents 8 / 9 · SQLite projections', 'Explain measured progress and remaining uncertainty without overstating impact.',
     'Current dashboard counts, immutable status history and actual execution receipts.', 'Return to ChatGPT and have participants validate a cited proposal and approval boundary.'),
]


def plan(data, stage):
    """Return one explicit next action, without mutating state."""
    def action(name, label, **kw):
        return dict(action=name, label=label, **kw)
    if stage == 0:
        return action('fresh_scan', 'Import synthetic scanner exports')
    if not data['findings']:
        return {'blocked': 'Import scanner findings in stage 1 first.'}
    if stage == 1:
        return action('inspect_normalization', 'Validate the stored normalization summary')
    if stage == 2:
        return action('evidence_replay', 'Run source-backed evidence replay')
    batches = [b for b in data['remediation_batches'] if any(
        m['batch_id'] == b['id'] for m in data['batch_proposal_members'])]
    if not batches:
        return {'blocked': 'Run evidence replay in stage 3. Missing or stale vendor evidence may prevent a batch.'}
    batch = batches[0]
    reviews = [r for r in data['lifecycle_reviews'] if r['kind'] == 'Batch' and r['target_id'] == batch['id']]
    pending_review = next((r for r in reviews if r['status'] == 'Awaiting Approval'), None)
    def decision(item, review=False):
        return action('decide_review' if review else 'decide_proposal',
                      'Approve reviewed '+('batch' if review else 'ticket' if item['kind'] == 'Ticket' else 'message'),
                      target=item['id'], payload_hash=item['payload_hash'], preview=json.loads(item['payload_json']))
    if stage == 3:
        if pending_review or batch['confirmed_by']:
            return {'complete': 'Batch review is recorded. Inspect the evidence below; approval remains a separate stage.'}
        return action('batch_review', 'Prepare a batch review — no approval', target=batch['id'])
    if not batch['confirmed_by']:
        if stage != 4:
            return {'blocked': 'Approve the batch and create the escalation in stage 5 first.'}
        return decision(pending_review, True) if pending_review else {'blocked': 'Prepare the batch review in stage 4 first.'}
    tickets = [t for t in data['tickets'] if t['batch_id'] == batch['id']]
    if stage == 4:
        proposals = [p for p in data['proposals'] if p['batch_id'] == batch['id'] and p['kind'] == 'Ticket']
        if not tickets:
            pending = next((p for p in proposals if p['status'] in ('Awaiting Approval', 'Approved')), None)
            if not pending:
                return action('queue_batch', 'Prepare synthetic ticket proposal', target=batch['id'])
            if pending['status'] == 'Awaiting Approval':
                return decision(pending)
            return action('execute_ticket', 'Create the approved synthetic ticket', target=pending['id'])
        ticket = tickets[0]
        linked = {l['communication_id'] for l in data['lifecycle'].get('communication_history', []) if l['ticket_id'] == ticket['id']}
        messages = [m for m in data['communications'] if m['id'] in linked]
        if not messages:
            return action('draft_notification', 'Draft synthetic resolver email', target=ticket['id'])
        message = messages[-1]
        proposal = next(p for p in data['proposals'] if p['id'] == message['proposal_id'])
        if proposal['status'] == 'Awaiting Approval':
            return decision(proposal)
        if proposal['status'] == 'Approved':
            return action('simulate_send', 'Store simulated send receipt — local only', target=message['id'])
        if message['status'] == 'Simulated Delivered':
            return {'complete': 'Approved ticket and separately approved simulated message are recorded.'}
        return {'blocked': 'Message was rejected or invalidated. Inspect it in Escalation Center and prepare a new draft.'}
    if not tickets:
        return {'blocked': 'Create an approved ticket in stage 5 first.'}
    ticket = tickets[0]
    if stage == 5:
        return action('queue_batch', 'Compare current facts with the existing ticket', target=batch['id'])
    if stage == 6:
        if ticket['status'] == 'Closed':
            return {'complete': 'Subsequent synthetic scanner evidence verified every ticket finding.'}
        if ticket['status'] != 'Pending Verification':
            return action('reply', 'Record owner completion — Pending Verification only', target=ticket['id'],
                          body='Completed: explicitly simulated resolver assertion for guided demonstration')
        history = [h for h in data['status_history'] if h['to_status'] == 'Pending Verification']
        latest = max((timestamp(h['occurred_at']) for h in history), default=timestamp(data['as_of']))
        if timestamp(data['as_of']) <= latest:
            return action('advance_clock', 'Advance synthetic clock before the subsequent assessment')
        return action('verify_pass', 'Apply subsequent synthetic scanner evidence', target=ticket['id'])
    return action('inspect_results', 'Validate current outcomes and audit history')
