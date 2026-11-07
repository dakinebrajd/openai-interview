"""Settled-action guard over the canonical cumulative M7 and project accounting."""
import json,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from vulnmgmt.application import CAMPAIGN
from vulnmgmt import m7_budget

def ledger(path=CAMPAIGN):
    policy,usage=m7_budget.snapshot(path,verify_sources=True)
    if not policy['migrated']:raise RuntimeError('Audited project commitments must be installed explicitly before this validation')
    return policy,policy['rows'],usage

def main():
    from audit_tools import workflow_browser_acceptance as runner
    output=Path(sys.argv[sys.argv.index('--output')+1]).resolve()
    _,baseline,_=ledger();sessions={r['session'] for r in baseline};checkpoints=[]
    original=runner.WorkflowOperator.button
    def guarded(self,text):
        original(self,text)
        policy,rows,usage=ledger();new=[r for r in rows if r['session'] not in sessions]
        mapped={u.get('session_id'):u for u in usage}
        unknown=[r['session'] for r in new if not mapped.get(r['session'],{}).get('usage')]
        rejected=[r['session'] for r in new if mapped.get(r['session'],{}).get('status')=='Rejected/quarantined']
        reserved=sum(r['micro_usd'] for r in rows);project=policy['historical_micro_usd']+reserved
        checkpoints.append(dict(at=datetime.now(timezone.utc).isoformat(),action=text,total_m7_attempts=len(rows),effective_internal_attempt_limit=policy['effective_limit'],original_attempt_limit=40,new_attempts=len(new),total_m7_reserved_usd=reserved/1e6,historical_plus_m7_reserved_usd=project/1e6,unknown_usage_sessions=unknown,rejected_sessions=rejected,checkpoint_granularity='after settled UI action; may contain multiple already bounded provider calls'))
        (output/'usage-checkpoints.json').write_text(json.dumps(checkpoints,indent=2),encoding='utf-8')
        if unknown or rejected:raise RuntimeError('Stop: unknown usage or rejected result; no retry')
        if len(rows)>policy['effective_limit'] or reserved>m7_budget.CAMPAIGN_USD or project>=m7_budget.PROJECT_USD:
            raise RuntimeError('Stop: cumulative campaign/project boundary')
    runner.WorkflowOperator.button=guarded
    return runner.main()

if __name__=='__main__':raise SystemExit(main())
