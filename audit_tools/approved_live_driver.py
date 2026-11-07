"""Explicit reviewed synthetic validation driver using the same actions as the UI.

No executable CLI or default application; import/render never runs this workflow.
Recorded synthetic test reviews do not represent human semantic acceptance.
"""
import json
from pathlib import Path
from vulnmgmt import approved_execution as actions,agent0,agent3,agent4,agent6,agent7,live_research
from vulnmgmt.dashboard_service import view,command,followup_scan
from vulnmgmt.live_contracts import LiveResearchError


def review_gate(manager,state,args):
    refs=state['refs'];i=state['cursor'];generation=state['generation'];data=view(manager)
    if i==4:
        for name,module in (('agent2',live_research),('agent4',agent4)):
            for p in refs[name]:module.review(manager,generation,run_id=p['run_id'],proposal_hash=p['proposal_hash'],decision='Accepted for analyst use',**args)
    elif i in (6,10,15):
        name,module={6:('agent3',agent3),10:('report',agent6),15:('mail',agent6)}[i];p=refs[name]
        module.review(manager,generation,run_id=p['run_id'],proposal_hash=p['proposal_hash'],decision='Accepted for analyst use',**args)
    elif i==7:
        g=refs['agent3']['result']['batches'][0]
        bid=next(b['id'] for b in data['remediation_batches'] if b['action_id']==g['action_id'] and set(g['finding_ids'])=={m['asset_cve_id'] for m in data['batch_proposal_members'] if m['batch_id']==b['id']})
        p=command(manager,generation,'batch_review',target=bid,**args)
        command(manager,generation,'decide_review',target=p['review_id'],payload_hash=p['payload_hash'],**args)
    elif i in (12,17):
        p=refs['ticket_proposal' if i==12 else 'communication_proposal']
        command(manager,generation,'decide_proposal',target=p['proposal_id'],payload_hash=p['payload_hash'],**args)
    else:raise LiveResearchError('Unexpected review gate; stop without recovery')


def scope(manager,state):
    data=view(manager);ticket_id=state['refs']['ticket_id']
    ids={r['asset_cve_id'] for r in data['ticket_findings'] if r['ticket_id']==ticket_id}
    return dict(ticket=next(t for t in data['tickets'] if t['id']==ticket_id),
                findings=sorted((f for f in data['findings'] if f['id'] in ids),key=lambda f:f['id']))


def drive(app,manager,output,*,confirmed=False,on_pause=None):
    if confirmed is not True:raise LiveResearchError('Explicit driver execution confirmation required')
    plan=actions.load_plan(app,manager);generation=plan['generation'];parents=[];children=[]
    args=dict(confirmed=True,actor=plan['actor'],reason='Synthetic validation analyst decision; not human semantic acceptance')
    report=dict(status='Started; preserve partial results',human_acceptance=False,parents=parents,children=children)
    try:
        for slot in (g for g in plan['grants'] if g['kind']=='main'):
            state=actions.start(app,manager,slot['component_id'],operation_key=slot['operation_key'])
            for _ in range(45):
                if state['cursor']==19:break
                if state['status']=='Paused':
                    if on_pause is None:raise LiveResearchError('Paused; explicit Resume required')
                    on_pause(state)
                elif state['status']=='Review required':review_gate(manager,state,args)
                elif state['status']!='Ready':raise LiveResearchError('Workflow failure; no retry: '+state['reason'])
                state=actions.advance(app,manager,run_id=state['run_id'],state_hash=state['state_hash'])
            else:raise LiveResearchError('Finite main action bound exhausted')
            parents.append(state)
        if len(parents)!=2:raise LiveResearchError('Exactly two main runs required')
        b_before=scope(manager,parents[1])
        for index,parent in enumerate(parents):
            slot=next(g for g in plan['grants'] if g['kind']=='resolver' and g['parent_run_id']==parent['run_id'])
            receipt=actions.submit_status(app,manager,parent_run_id=parent['run_id'],parent_hash=parent['state_hash'],
                ticket_id=parent['refs']['ticket_id'],status='Closed',operation_key=slot['operation_key'])
            child=agent0._load(view(manager),receipt['run_id']);children.append(child)
            if any(f['status']=='Verified Remediated' for f in scope(manager,parent)['findings']):raise LiveResearchError('Status intake verified a finding')
            child=actions.advance(app,manager,run_id=child['run_id'],state_hash=child['state_hash']);children[-1]=child
            p=child['refs']['agent7']
            if not p.get('result') or p['result']['intent']!='Completed':raise LiveResearchError('Model did not propose completion; no result repair')
            if not p['assessment_input'].get('status_completion_claim'):raise LiveResearchError('Typed status-only receipt missing from actual model input')
            agent7.review(manager,generation,run_id=p['run_id'],proposal_hash=p['proposal_hash'],decision='Accepted for analyst use',**args)
            agent7.apply(manager,generation,run_id=p['run_id'],proposal_hash=p['proposal_hash'],operation_key=slot['operation_key']+'-apply',**args)
            if any(f['status']!='Pending Verification' for f in scope(manager,parent)['findings']):raise LiveResearchError('Separate reviewed safe processing did not yield pending verification')
            if index==0 and scope(manager,parents[1])!=b_before:raise LiveResearchError('A processing changed B')
            followup_scan(manager,generation,ticket_id=parent['refs']['ticket_id'],outcome='Pass',operation_key=slot['operation_key']+'-scan',**args)
            if any(f['status']!='Verified Remediated' for f in scope(manager,parent)['findings']):raise LiveResearchError('Adequate scanner verification missing')
            if index==0 and scope(manager,parents[1])!=b_before:raise LiveResearchError('A scanner changed B')
        actions.load_plan(app,manager)
        report['status']='Executed; independent postrun and human review still required'
        return report
    finally:Path(output).write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__=='__main__':
    raise SystemExit('No default execution. A new independently reviewed exact plan/runtime/assessment binding is required.')
