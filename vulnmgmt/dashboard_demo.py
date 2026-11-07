"""Offline M5 smoke walkthrough. Explicit --simulate-analyst gates fixture decisions."""
import argparse
import json
from pathlib import Path
from .demo_manager import DemoManager
from .dashboard_service import command, view


def run(root, *, simulate_analyst=False):
    if not simulate_analyst:
        raise ValueError('Explicit --simulate-analyst confirmation is required')
    m = DemoManager(root)
    g = m.state()['generation']
    previous = [e for e in m.history()['events'] if e['generation'] == g and e['kind'] == 'M5WalkthroughCompleted']
    if previous:
        return json.loads(previous[-1]['payload'])
    args = dict(confirmed=True, actor='explicit-synthetic-demo-analyst',
                reason='Explicitly requested offline walkthrough decision; no external actions')
    def execute(action, key, **kw):
        return command(m, g, action, key='m5-walkthrough-'+key, **args, **kw)
    execute('fresh_scan', 'scan')
    enrichment = execute('evidence_replay', 'replay')
    batch = next(b for b in view(m)['remediation_batches'] if b['status'] == 'Proposed')['id']
    review = execute('batch_review', 'batch-review', target=batch)
    execute('decide_review', 'approve-batch', target=review['review_id'], payload_hash=review['payload_hash'])
    draft = execute('queue_batch', 'queue', target=batch)
    execute('decide_proposal', 'approve-ticket', target=draft['proposal_id'], payload_hash=draft['payload_hash'])
    ticket = execute('execute_ticket', 'create-ticket', target=draft['proposal_id'])['ticket_id']
    message = execute('draft_notification', 'draft-message', target=ticket)
    execute('decide_proposal', 'approve-message', target=message['proposal_id'], payload_hash=message['payload_hash'])
    execute('simulate_send', 'simulate-send', target=message['communication_id'])
    duplicate = execute('queue_batch', 'duplicate', target=batch)
    m.advance(g)
    execute('reply', 'owner-completed', target=ticket, body='Completed: synthetic owner assertion, not verification')
    pending = view(m)['counts']['status'].get('Pending Verification', 0)
    m.advance(g)
    verification = execute('verify_pass', 'scanner-pass', target=ticket)
    final = view(m)
    result = {'label': 'SYNTHETIC M5 WALKTHROUGH — local decisions and scanner simulation',
              'generation': g, 'enrichment': enrichment['summary'], 'duplicate_result': duplicate,
              'pending_verification_checkpoint': pending, 'verification': verification,
              'dashboard_metrics': final['metrics'], 'tickets': len(final['tickets']),
              'synthetic_receipts': len(final['simulated_deliveries'])}
    with m._control() as c:
        m._event(c, g, 'M5WalkthroughCompleted', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('artifacts/dashboard-walkthrough'))
    parser.add_argument('--simulate-analyst', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.root, simulate_analyst=args.simulate_analyst), indent=2))
