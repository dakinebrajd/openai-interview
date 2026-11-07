"""Read-only pipeline projection and explicit commands in existing SOC surfaces."""
import json
from uuid import uuid4
import streamlit as st
from . import agent0,agent7,reply_evidence
from .ui_components import table
from .services import digest
from . import dashboard_service as commands

def summary(data):
    states=agent0.stored(data)
    if not states:
        st.caption('No Agent 0 orchestration recorded in this workspace. Navigation does not start a run.')
        return
    for s in states:
        if s['identity']!=data['workspace_identity'] or s['generation']!=data['generation']:
            st.warning('Restored historical run: these are copied records, not new execution or current authorization. Start a new run to continue.')
        st.write('**Agent 0 · '+s['status']+' · '+agent0.STAGES[s['cursor']]+'**')
        st.caption('Run '+s['run_id']+' · exact revision '+str(s['revision'])+' · '+s['state_hash'])
        if s['reason']:st.warning(s['reason'])
        history={h['stage']:h for h in s['history']}
        table([dict(stage=name,status='Linked prior execution; not rerun' if n<s['manifest'].get('resume_from',0) else 'Completed' if name in history else s['status'] if n==s['cursor'] else 'Not evaluated',
            execution=history[name]['mode'] if name in history else 'Not executed') for n,name in enumerate(agent0.STAGES)],['stage','status','execution'],height=280)
        with st.expander('Stage inputs, outputs, source dates and human gates · '+s['run_id'][:8]):st.json(s)

def panel(manager,data,busy):
    st.subheader('Agent 0 · Controlled orchestration')
    st.info('These advanced controls use Replay. M7 Run Assessment supports separately authorized live stages. Named research, exact batch, ticket, communication and safe reply-processing decisions remain distinct; no model can approve them.')
    summary(data)
    components={c['id']:c for c in data['asset_components']}
    with st.form('flow_start',enter_to_submit=False):
        component=st.selectbox('Workflow component',list(components),format_func=lambda k:components[k]['component_key']+' · '+k[:8])
        actor=st.text_input('Workflow analyst',key='flow_actor');reason=st.text_input('Workflow rationale',key='flow_reason')
        confirm=st.checkbox('I confirm one explicit replay workflow action',key='flow_confirm')
        start=st.form_submit_button('Start isolated workflow record',disabled=busy)
    if start:
        try:
            key=st.session_state.setdefault('flow_start_key',str(uuid4()))
            commands.start_orchestration(manager,data['generation'],component_id=component,operation_key=key,confirmed=confirm,actor=actor,reason=reason);st.rerun()
        except ValueError as exc:st.error(str(exc))
    states=agent0.stored(data)
    if states:
        selected=st.selectbox('Recorded orchestration',[s['run_id'] for s in states],key='flow_selected')
        s=next(s for s in states if s['run_id']==selected)
        with st.form('flow_advance',enter_to_submit=False):
            actor=st.text_input('Advancing analyst');reason=st.text_input('Advance rationale')
            confirm=st.checkbox('I reviewed this exact workflow revision')
            recover=st.checkbox('Recover an interrupted replay stage using its original operation identity')
            go=st.form_submit_button('Advance one recorded stage',disabled=busy or s['status']=='Completed')
        if go:
            try:
                commands.advance_orchestration(manager,data['generation'],run_id=selected,state_hash=s['state_hash'],confirmed=confirm,actor=actor,reason=reason,recover=recover);st.rerun()
            except ValueError as exc:st.error(str(exc))
        research=[]
        for name in ('agent2','agent4','agent3','report','mail','agent7'):
            ref=s['refs'].get(name,[])
            for p in ref if isinstance(ref,list) else [ref]:
                if p.get('result'):research.append((name,p))
        if research:
            st.caption('Research decisions below accept only the selected exact research proposal; batch, ticket and communication approvals stay separate.')
            options={name+' · '+p.get('cve_id',p.get('component_id',p.get('scope_id',p.get('reply_id',''))))+' · '+p['proposal_hash']:(name,p) for name,p in research}
            with st.form('flow_research_review',enter_to_submit=False):
                chosen=st.selectbox('Exact upstream research proposal',list(options))
                decision=st.selectbox('Research decision',['Rejected','Accepted for analyst use'])
                actor=st.text_input('Upstream research analyst');reason=st.text_input('Upstream research rationale')
                confirm=st.checkbox('I independently reviewed source meaning, dates, assumptions and this exact proposal')
                review=st.form_submit_button('Record separate research decision',disabled=busy)
            if review:
                from . import research_replay,agent3,agent4,agent6
                name,p=options[chosen];module=dict(agent2=research_replay,agent3=agent3,agent4=agent4,report=agent6,mail=agent6,agent7=agent7)[name]
                try:
                    commands.review_orchestration_research(manager,data['generation'],agent=name,run_id=p['run_id'],proposal_hash=p['proposal_hash'],decision=decision,
                        confirmed=confirm,actor=actor,reason=reason);st.rerun()
                except ValueError as exc:st.error(str(exc))

def replies(manager,data,busy):
    st.subheader('Agent 7 · Untrusted resolver interpretation')
    st.caption('Use synthetic messages only. Interpretation is a proposal; completion cannot verify remediation. No mailbox connection or real delivery exists.')
    values=[]
    for step in data['agent_steps']:
        if step['role_number']==7 and step['step_key']==agent7.Spec.result_key:
            p=json.loads(step['output_json'])
            if digest({k:v for k,v in p.items() if k!='proposal_hash'})==p['proposal_hash']:values.append(p)
    with st.form('reply7_intake',enter_to_submit=False):
        ticket=st.selectbox('Synthetic reply ticket',[t['id'] for t in data['tickets']],index=None)
        owner=st.selectbox('Resolver identity',[o['id'] for o in data['owners']],index=None)
        comm=st.selectbox('Original synthetic communication',[c['id'] for c in data['communications']],index=None)
        body=st.text_area('Untrusted synthetic resolver message')
        actor=st.text_input('Reply intake analyst');reason=st.text_input('Reply intake rationale');confirm=st.checkbox('Confirm synthetic reply intake only')
        submit=st.form_submit_button('Record reply for interpretation',disabled=busy)
    if submit:
        try:
            commands.receive_research_reply(manager,data['generation'],ticket_id=ticket,owner_id=owner,communication_id=comm,body=body,
                operation_key=st.session_state.setdefault('reply7_intake_key',str(uuid4())),confirmed=confirm,actor=actor,reason=reason);st.rerun()
        except ValueError as exc:st.error(str(exc))
    for p in values:
        st.write('**Recorded Agent 7 proposal · '+p['review_status']+'**')
        st.caption('Origin '+p['execution']['origin']+' · model served '+str(p['execution'].get('model_served'))+' · hash '+p['proposal_hash'])
        st.json(p['result'] or dict(error=p['error']))
        table([dict(json.loads(a['payload_json']),analyst=a['actor_id'],recorded_at=a['recorded_at']) for a in data['audit_events']
            if a['entity_id']==p['run_id'] and a['event_type']=='Agent7ResearchReviewRecorded'],['decision','analyst','recorded_at','proposal_hash'],height=100)
    if not data['owner_replies']:return
    with st.form('reply7_action',enter_to_submit=False):
        reply=st.selectbox('Stored reply',[r['id'] for r in data['owner_replies']])
        action=st.selectbox('Reply decision',['Interpret replay','Accept research for analyst use','Reject research','Apply reviewed safe processing'])
        actor=st.text_input('Reply reviewing analyst');reason=st.text_input('Reply decision rationale');confirm=st.checkbox('I reviewed the exact reply and proposal; this grants no scanner verification')
        go=st.form_submit_button('Record explicit reply action',disabled=busy)
    if go:
        try:
            common=dict(confirmed=confirm,actor=actor,reason=reason)
            if action=='Interpret replay':commands.run_reply_research(manager,data['generation'],reply_id=reply,operation_key='ui-reply-'+reply,reviewed_token=reply_evidence.review_token(data),**common)
            else:
                p=next(p for p in reversed(values) if p['reply_id']==reply)
                if action=='Apply reviewed safe processing':commands.apply_reply_research(manager,data['generation'],run_id=p['run_id'],proposal_hash=p['proposal_hash'],operation_key='ui-safe-'+reply,**common)
                else:commands.review_reply_research(manager,data['generation'],run_id=p['run_id'],proposal_hash=p['proposal_hash'],decision='Rejected' if action=='Reject research' else 'Accepted for analyst use',**common)
            st.rerun()
        except (ValueError,StopIteration) as exc:st.error(str(exc) or 'No proposal recorded for selected reply')
