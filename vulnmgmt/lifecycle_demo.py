"""Reproducible local M4 lifecycle using M2/M3 data; no network or paid models."""
import argparse
import json
from pathlib import Path
from uuid import UUID, uuid5
from sqlalchemy import func, select

from .database import make_engine, migrate, tables
from .enrichment_demo import run_enrichment_demo
from .fixture_builder import FIXTURE_DIR
from .lifecycle import (apply_reply, create_scope, decide_proposal, decide_review, draft_notification,
    execute_escalation, queue_escalation, queues, receive_reply, record_scanner_result,
    request_batch_review, seed_historical_ticket, simulate_send)
from .lifecycle_contracts import AnalystDecision, ResolverReply, ScannerResult
from .scanners import ingest_export
from .services import canonical, digest

SCENARIO_FILE=Path(__file__).resolve().parent.parent/'fixtures/lifecycle/v1/scenario.json'


def _request(cls,w,version,**fields):
    key=fields['operation_key']
    return cls.model_validate_json(canonical(dict(workspace_id=w,scenario_version_id=version,
        correlation_id=str(uuid5(UUID(w),key)),mode='replay',**fields)))


def run_lifecycle_demo(database=Path('artifacts/m4-lifecycle-v1.sqlite3'),output_dir=Path('artifacts/m4')):
    database,output_dir=Path(database),Path(output_dir)
    scenario=json.loads(SCENARIO_FILE.read_text(encoding='utf-8'))
    if not database.exists():
        run_enrichment_demo(database,output_dir/'m3-baseline')
    engine=make_engine(database)
    try:
        migrate(engine)
        with engine.begin() as c:
            workspace=c.execute(select(tables['demo_workspaces'])).mappings().one()
            w,version=workspace['id'],workspace['scenario_version_id']
            previous=c.execute(select(tables['lifecycle_operations']).where(
                tables['lifecycle_operations'].c.workspace_id==w,
                tables['lifecycle_operations'].c.operation_key=='m4-demo-complete')).mappings().one_or_none()
            if previous:
                if previous['payload_hash']!=digest(scenario):raise ValueError('Scenario changed without version increment')
                result=json.loads(previous['result_json'])
            else:
                # Every actor decision below is an explicit, labeled synthetic analyst action.
                actor=scenario['analyst_id']
                def approve(item,key,now,review=False):
                    request=_request(AnalystDecision,w,version,operation_key=key,
                        target_id=item['review_id'] if review else item['proposal_id'],payload_hash=item['payload_hash'],
                        analyst_id=actor,reason='Explicit synthetic analyst decision for '+key,decision='Approved',decided_at=now)
                    return (decide_review if review else decide_proposal)(c,request)
                def notify(ticket,key,now):
                    message=draft_notification(c,w,ticket,now,key+'-draft')
                    approve(message,key+'-approve',now)
                    return simulate_send(c,w,message['communication_id'],now,key+'-simulate')
                def reply(ticket,body,key,now,until=None):
                    from .lifecycle import _ticket_scope
                    _,scope=_ticket_scope(c,w,ticket)
                    received=receive_reply(c,_request(ResolverReply,w,version,operation_key=key+'-receive',
                        ticket_id=ticket,owner_id=scope['resolver_group_id'],body=body,received_at=now,exception_until=until))
                    return apply_reply(c,w,received['reply_id'],now,key+'-apply',actor,'Review synthetic reply: '+key)
                batch=c.execute(select(tables['remediation_batches']).where(
                    tables['remediation_batches'].c.status=='Proposed')).mappings().one()
                proposed=list(c.scalars(select(tables['batch_proposal_members'].c.asset_cve_id).where(
                    tables['batch_proposal_members'].c.batch_id==batch['id'])))
                by_cve={c.scalar(select(tables['asset_cves'].c.cve_id).where(tables['asset_cves'].c.id==id)):id for id in proposed}
                first=by_cve['CVE-2022-3602']
                review=request_batch_review(c,w,batch['id'],[first],scenario['start_at'],'batch-first-review')
                approve(review,'batch-first-approve',scenario['start_at'],review=True)
                scope_id=create_scope(c,w,batch_id=batch['id'],now=scenario['start_at'])
                new=queue_escalation(c,w,scope_id,'2026-11-03T23:54:05Z','new-escalation')
                approve(new,'new-ticket-approve','2026-11-03T23:54:10Z')
                ticket=execute_escalation(c,w,new['proposal_id'],'2026-11-03T23:54:15Z','new-ticket-execute')['ticket_id']
                notify(ticket,'initial-notification','2026-11-03T23:54:20Z')
                reply(ticket,'Scheduled: synthetic maintenance window','scheduled','2026-11-03T23:54:30Z')
                repeated=ingest_export(c,w,version,(FIXTURE_DIR/'tenable_repeat.json').read_bytes(),'synthetic-tenable')
                suppressed=queue_escalation(c,w,scope_id,'2026-11-03T23:54:40Z','repeated-scan-escalation')
                review=request_batch_review(c,w,batch['id'],proposed,'2026-11-03T23:55:00Z','batch-expand-review')
                approve(review,'batch-expand-approve','2026-11-03T23:55:00Z',review=True)
                change=queue_escalation(c,w,scope_id,'2026-11-03T23:55:05Z','new-cve-escalation')
                approve(change,'new-cve-approve','2026-11-03T23:55:10Z')
                execute_escalation(c,w,change['proposal_id'],'2026-11-03T23:55:15Z','new-cve-execute')
                notify(ticket,'new-cve-notification','2026-11-03T23:55:20Z')
                # Seed an explicitly historical pre-enrichment ticket. No approval or
                # "new global exploitation" is fabricated for this synthetic history.
                f,t=tables['asset_cves'],tables['assets']
                log4j=c.scalar(select(f.c.id).join(t,(f.c.asset_id==t.c.id)&(f.c.workspace_id==t.c.workspace_id)).where(
                    f.c.workspace_id==w,t.c.asset_key=='WEB-003',f.c.cve_id=='CVE-2021-44228'))
                old_scope=create_scope(c,w,finding_id=log4j,now=scenario['historical_ticket_at'])
                old_ticket=seed_historical_ticket(c,w,old_scope,scenario['historical_ticket_at'],'historical-ticket')['ticket_id']
                intelligence=queue_escalation(c,w,old_scope,'2026-11-03T23:55:30Z','new-verified-exploitation')
                approve(intelligence,'intelligence-approve','2026-11-03T23:55:35Z')
                execute_escalation(c,w,intelligence['proposal_id'],'2026-11-03T23:55:40Z','intelligence-execute')
                notify(old_ticket,'intel-notification','2026-11-03T23:55:45Z')
                reply(old_ticket,'Unable to patch: synthetic business constraint','unable','2026-11-03T23:56:00Z')
                completed=reply(ticket,'Completed: synthetic owner assertion only','completed','2026-11-03T23:56:20Z')
                pending=[c.scalar(select(f.c.status).where(f.c.id==id)) for id in proposed]
                partial=record_scanner_result(c,_request(ScannerResult,w,version,operation_key='partial-verification',ticket_id=ticket,
                    assessed_at='2026-11-03T23:56:30Z',recorded_at='2026-11-03T23:56:31Z',scan_status='Partial',outcomes={first:'Pass'}))
                verified=record_scanner_result(c,_request(ScannerResult,w,version,operation_key='passing-verification',ticket_id=ticket,
                    assessed_at='2026-11-03T23:56:40Z',recorded_at='2026-11-03T23:56:45Z',scan_status='Success',outcomes={id:'Pass' for id in proposed}))
                risk=reply(old_ticket,'Risk exception requested: synthetic temporary deferment','risk','2026-11-03T23:57:00Z',scenario['exception_until'])
                risk_before=c.scalar(select(func.count()).select_from(tables['exceptions']))
                approve(risk,'risk-approve','2026-11-03T23:57:10Z',review=True)
                reply(ticket,'Vulnerability persists: please rescan; owner statement is not scanner evidence','persists','2026-11-03T23:58:00Z')
                reopened=record_scanner_result(c,_request(ScannerResult,w,version,operation_key='positive-recurrence',ticket_id=ticket,
                    assessed_at='2026-11-03T23:58:10Z',recorded_at='2026-11-03T23:58:15Z',scan_status='Success',outcomes={first:'Fail'}))
                end='2026-11-03T23:59:00Z'
                state=queues(c,w,end)
                def count(name):return c.scalar(select(func.count()).select_from(tables[name]))
                events=[v['event_type'] for v in state['ticket_versions']]
                summary=dict(tickets_created=events.count('TicketCreated'),historical_tickets_seeded=events.count('SyntheticHistoricalSeed'),
                    tickets_total=count('tickets'),duplicate_escalations_suppressed=c.scalar(select(func.count()).select_from(tables['audit_events']).where(
                        tables['audit_events'].c.event_type=='DuplicateEscalationSuppressed')),
                    material_ticket_revisions=events.count('TicketRevised'),ticket_version_records=count('ticket_versions'),
                    synthetic_messages_generated=count('communications'),synthetic_messages_simulated_sent=count('simulated_deliveries'),
                    resolver_responses_processed=count('reply_interpretations'),
                    scanner_confirmed_closures=sum(r['decision']=='Verified Remediated' for r in verified['results']),
                    scanner_confirmed_reopenings=sum(r['decision']=='Reopened' for r in reopened['results']),
                    partial_scans_without_closure=1 if partial['ticket_status']=='Pending Verification' else 0,
                    risk_exceptions_approved=count('exceptions'),real_deliveries=0,model_calls=0)
                result={'label':scenario['label'],'scenario_version':scenario['version'],'summary':summary,
                    'checkpoints':{'repeated_import':repeated,'suppression':suppressed,'new_cve_reasons':change['reasons'],
                        'new_exploitation_reasons':intelligence['reasons'],'owner_completed_statuses':pending,
                        'partial_verification':partial,'verification':verified,'exceptions_before_approval':risk_before,'recurrence':reopened},
                    'queues':state,'policy':'HYPOTHETICAL AGENCY POLICY - DEMONSTRATION ONLY'}
                assert summary['tickets_created']==1 and summary['material_ticket_revisions']==2
                assert summary['synthetic_messages_simulated_sent']==3 and summary['scanner_confirmed_closures']==2
                assert pending==['Pending Verification']*2 and risk_before==0
                from .lifecycle import _finish
                _finish(c,w,'m4-demo-complete',scenario,result,end)
        output_dir.mkdir(parents=True,exist_ok=True)
        (output_dir/'lifecycle.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        lines=['# Synthetic M4 lifecycle demonstration','','No real delivery or model calls. All analyst, resolver and scanner actions are simulated.','',
               POLICY_LABEL,'']+[f'- {k}: {v}' for k,v in result['summary'].items()]
        lines+=['','## Checkpoints','', '```json',json.dumps(result['checkpoints'],indent=2),'```',
                '', 'Full ticket snapshots, reports, inbox/outbox and immutable versions are in lifecycle.json and SQLite.']
        (output_dir/'lifecycle.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
        return result
    finally:engine.dispose()


POLICY_LABEL='HYPOTHETICAL AGENCY POLICY: Critical known-exploitation trigger 24h; Critical exploitable 72h; Critical 14d; High 30d; Medium 60d; Low 90d.'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,default=Path('artifacts/m4-lifecycle-v1.sqlite3'))
    parser.add_argument('--output-dir',type=Path,default=Path('artifacts/m4'))
    args=parser.parse_args()
    print(json.dumps(run_lifecycle_demo(args.database,args.output_dir)['summary'],indent=2))
