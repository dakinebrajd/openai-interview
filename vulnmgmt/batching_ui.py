"""Existing SOC panels over proposed Agent 3 research, never automatic adoption."""
import json
from uuid import uuid4
import streamlit as st
from .dashboard_service import run_batching_research, review_batching_research
from .batching_evidence import review_token
from .live_contracts import LiveResearchError
from .services import digest
from .ui_components import table


def stored(data):
    results=[]
    for step in data['agent_steps']:
        if step['role_number']!=3 or step['step_key']!='agent3-batching-result' or not step['output_json']:
            continue
        payload=json.loads(step['output_json'])
        if (payload['workspace_id']==data['workspace_id'] and
                digest({k:v for k,v in payload.items() if k!='proposal_hash'})==payload['proposal_hash']):
            results.append(payload)
    return sorted(results,key=lambda p:p['started_at'])


def detail(payload,data):
    mode={'offline_mock':'Offline Mock','human_curated_source_backed_replay':'Replay','live_model':'Live AI'}[payload['execution']['origin']]
    st.write('**Agent 3 processing mode:** '+mode)
    st.caption('Requested model: '+str(payload['execution'].get('model_requested'))+
        ' · served model: '+str(payload['execution'].get('model_served') or 'Not exposed / not applicable'))
    st.caption('Research status: '+payload['review_status']+'. No operational adoption, ticket, communication or scanner verification follows from this output.')
    st.caption('Exact research proposal hash: '+payload['proposal_hash']+' · generation '+str(payload['generation'])+
        ' · evidence assessment '+payload.get('evidence_as_of',payload['synthetic_effective_at']))
    if payload['execution'].get('usage'):
        table([payload['execution']['usage']],['requests','input_tokens','output_tokens','total_tokens'],height=90)
    table(payload['assessment_input']['findings'],['finding_id','cve_id','asset_id','component_id','severity','applicability','historical_instruction'],height=180)
    result=payload['result']
    if not result:
        st.warning('Rejected/quarantined execution: no validated batching proposal. Candidate claims are unaccepted and cannot be adopted or accepted through research review.')
        st.caption('Recorded validation/provider error: '+str(payload.get('error') or 'Unknown'))
        candidate=payload.get('quarantined_candidate')
        if isinstance(candidate,dict):
            st.write('**Quarantined candidate only — not validated included findings or an approved batch**')
            table(candidate.get('batches',[]),['finding_ids','cve_ids','historical_instruction','applicability','decision'],height=180)
            table(candidate.get('excluded',[]),['finding_id','reason','interpretation'],height=100)
        for option in payload['assessment_input']['options']:
            st.caption('Saved authoritative option for comparison only; it does not accept the model candidate.')
            for quote in option['evidence']:
                source=next(s for s in payload['sources'] if s['id']==quote['source_id'])
                st.caption(source['url']+' · captured '+source['retrieved_at'])
                st.text(quote['excerpt'])
        st.caption('Real applicability and current supported deployment target remain unknown. Separate exact-revision human approval is mandatory before operational adoption.')
        with st.expander('Original quarantined response, evidence input and execution metadata'):
            st.json(payload)
        return
    for group in result['batches']:
        st.write('**'+group['decision']+'** · '+', '.join(group['cve_ids']))
        st.caption('Applicability: '+group['applicability']+' · historical affected range '+group['affected_versions']+
            ' · historical fixed version '+group['historical_target_version']+'; current supported deployment target not established.')
        st.text(group['historical_instruction'])
        st.write('Unverified reasoning: '+group['interpretation'])
        for quote in group['vendor_evidence']:
            source=next(s for s in payload['sources'] if s['id']==quote['source_id'])
            st.caption(source['url']+' · captured '+source['retrieved_at']+' · SHA256 '+source['content_hash'])
            st.text(quote['excerpt'])
        option=next(o for o in payload['assessment_input']['options'] if o['action_id']==group['action_id'])
        proposals=[b for b in data['remediation_batches'] if b['id'] in option['existing_proposal_ids']]
        table(proposals,['id','status','revision','confirmed_by'],height=100)
        st.caption('Existing operational proposal status shown separately. Research review does not approve a batch; use the existing Batch review controls.')
    if not result['batches']:
        st.info('Agent 3 did not propose a shared action for these findings.')
    inputs={f['finding_id']:f for f in payload['assessment_input']['findings']}
    table([dict(e,cve_id=inputs[e['finding_id']]['cve_id'],asset_id=inputs[e['finding_id']]['asset_id'])
        for e in result['excluded']],['finding_id','cve_id','asset_id','reason','interpretation'],height=180)
    for field in ('conflicting_or_missing_evidence','threat_considerations','analyst_validation'):
        for item in result[field]:
            st.write(field.replace('_',' ').title()+': '+item)
    with st.expander('Agent 2/4 research references and exact Agent 3 execution'):
        table(payload['assessment_input']['research'],['role','cve_id','origin','review_status','step_id'],height=180)
        for ref in payload['assessment_input']['research']:
            st.caption('Research step '+ref['step_id']+' · '+ref['review_status'])
            table(json.loads(ref['source_provenance_json']),['url','retrieved_at','content_hash'],height=100)
        st.json(payload)


def panel(manager,data,busy):
    st.subheader('Agent 3 · Remediation batching assessment')
    if any(p['execution']['origin']=='live_model' for p in stored(data)):
        st.info('Recorded live Agent 3 execution available; inspect accepted versus quarantined status. New live requests disabled; research acceptance and operational approval remain separate.')
    else:
        st.info('Live Agent 3 disabled and not live-validated. Replay is curated; Offline Mock is SDK execution against mocked HTTP. Research acceptance and operational batch approval are separate.')
    components={f['component_id']:f['asset_key']+' / '+f['component_key'] for f in data['findings']}
    if not components:
        st.caption('Import synthetic scanner findings and evidence replay first.')
        return
    component=st.selectbox('Batching asset / component',sorted(components,key=components.get),format_func=components.get,key='batch3_component')
    candidates=[f for f in data['findings'] if f['component_id']==component]
    st.caption('Candidate relationships and counts below come from this SQLite workspace. Cross-asset assessment tests retain separate obligations.')
    operation=st.session_state.setdefault('batch3_operation','agent3-replay-'+str(uuid4()))
    with st.form('batch3_form',enter_to_submit=False):
        actor=st.text_input('Batching research analyst',value='demo-analyst',key='batch3_actor')
        reason=st.text_input('Batching research reason',key='batch3_reason')
        confirmed=st.checkbox('I confirm assessing these findings with source-backed replay',key='batch3_confirm')
        submitted=st.form_submit_button('Run Agent 3 Evidence Replay',disabled=busy,key='batch3_run')
    if submitted:
        try:
            run_batching_research(manager,data['manager']['generation'],component_id=component,
                finding_ids=[f['id'] for f in candidates],confirmed=confirmed,actor=actor,reason=reason,
                operation_key=operation+'-'+component,reviewed_token=review_token(data))
            st.rerun()
        except LiveResearchError as exc:
            st.error(str(exc))
    matches=[p for p in stored(data) if p['component_id']==component]
    if not matches:
        st.caption('No Agent 3 assessment recorded for this component.')
        return
    payload=matches[-1]
    detail(payload,data)
    if not payload.get('result'):
        return  # No acceptance form for a rejected/quarantined execution.
    reviews=[e for e in data['audit_events'] if e['event_type']=='Agent3ResearchReviewRecorded' and e['entity_id']==payload['run_id']]
    if reviews:
        st.caption('Recorded research decision: '+json.loads(reviews[-1]['payload_json'])['decision']+'; not operational approval.')
    else:
        with st.form('batch3_review_form',enter_to_submit=False):
            reviewer=st.text_input('Reviewing batching analyst',key='batch3_reviewer')
            why=st.text_input('Batching review reason',key='batch3_review_reason')
            decision=st.radio('Batching research decision',['Accepted for analyst use','Rejected'],key='batch3_decision')
            confirm=st.checkbox('I reviewed this exact batching proposal',key='batch3_review_confirm')
            save=st.form_submit_button('Record batching research review',disabled=busy,key='batch3_review')
        if save:
            try:
                review_batching_research(manager,data['manager']['generation'],run_id=payload['run_id'],proposal_hash=payload['proposal_hash'],
                    confirmed=confirm,actor=reviewer,reason=why,decision=decision)
                st.rerun()
            except LiveResearchError as exc:
                st.error(str(exc))
