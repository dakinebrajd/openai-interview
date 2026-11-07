"""Existing SOC draft views; render never requests a model, key or delivery."""
import json
from uuid import uuid4
import streamlit as st
from .dashboard_service import run_drafting_research,review_drafting_research,stage_drafting_research
from .drafting_evidence import review_token
from .live_contracts import LiveResearchError
from .services import digest
from .ui_components import table


def stored(data):
    result=[]
    for step in data['agent_steps']:
        if step['role_number']!=6 or step['step_key']!='agent6-drafting-result' or not step['output_json']:continue
        payload=json.loads(step['output_json'])
        if payload['workspace_id']==data['workspace_id'] and digest({k:v for k,v in payload.items() if k!='proposal_hash'})==payload['proposal_hash']:
            result.append(payload)
    return sorted(result,key=lambda p:p['started_at'])


def detail(payload,data):
    mode={'human_curated_source_backed_replay':'Replay','offline_mock':'Offline Mock','live_model':'Live AI'}[payload['execution']['origin']]
    st.write('**Agent 6 processing mode:** '+mode)
    st.caption('Draft research status: '+payload['review_status']+' · exact hash '+payload['proposal_hash'])
    st.caption('Requested model '+str(payload['execution']['model_requested'])+' · served model '+str(payload['execution'].get('model_served'))+
        ' · provider attempts '+str(payload['execution']['provider_attempts'])+' · recorded assessment '+payload['evidence_as_of'])
    if payload['execution'].get('usage'):table([payload['execution']['usage']],height=90)
    st.warning('Historical guidance and synthetic assumptions do not establish actual applicability or a current supported deployment target. Separate ticket and communication approval required; no delivery follows from this draft.')
    source_facts=payload['assessment_input']['facts']
    table(source_facts,['category','text','id'],height=230)
    if not payload['result']:
        st.warning('Rejected/quarantined Agent 6 output: '+str(payload['error']))
        with st.expander('Original rejected draft execution'):st.json(payload)
        return
    rendered=payload['rendered']
    st.write('**AI-assisted proposed consolidated report**');st.text(rendered['consolidated_report'])
    with st.expander('Synthetic ticket description'):st.text(rendered['ticket_description'])
    with st.expander('Synthetic email preview'):
        st.write('To: '+rendered['to']);st.write('Subject: '+rendered['subject']);st.text(rendered['email_body'])
    scope=next((s for s in data['lifecycle_scopes'] if s['id']==payload['scope_id']),None)
    proposals=[p for p in data['proposals'] if scope and p['batch_id']==scope['batch_id']]
    table(proposals,['kind','status','revision','payload_hash'],height=130)
    table([c for c in data['communications'] if scope and c['batch_id']==scope['batch_id']],['status','revision','id'],height=100)
    st.caption('Operational draft/approval statuses above come from SQLite. Research acceptance alone creates no approved ticket, communication or remediation outcome.')
    with st.expander('Source provenance and exact Agent 6 execution'):
        table(payload['sources'],['url','retrieved_at','content_hash','provenance'],height=180)
        st.json(payload)


def panel(manager,data,busy):
    st.subheader('Agent 6 · Resolver drafting')
    st.info('These advanced controls run human-curated Replay. Authorized M7 Live AI is available through Run Assessment; inspect each recorded origin and validation result. Offline Mock is mocked SDK execution. Rendering makes no source or credential request.')
    scopes={s['id']:s for s in data['lifecycle_scopes']}
    if not scopes:
        st.caption('Prepare an eligible scope through existing deterministic batch review/individual-triage controls first. No approval is granted here.')
        return
    def scope_label(id):
        value=scopes[id]
        asset=next((f['asset_key'] for f in data['findings'] if f['asset_id']==value['asset_id']),'Unknown asset')
        owner=next((o['display_name'] for o in data['owners'] if o['id']==value['resolver_group_id']),'Unknown resolver')
        return asset+' · '+owner+' · '+('Individual' if value['individual_finding_id'] else 'Batch')+' · '+id[:8]
    scope=st.selectbox('Agent 6 escalation scope',sorted(scopes),format_func=scope_label,key='draft6_scope')
    identity=st.session_state.setdefault('draft6_operation','agent6-'+str(uuid4()))
    with st.form('draft6_replay',enter_to_submit=False):
        actor=st.text_input('Drafting analyst',value='demo-analyst',key='draft6_actor')
        reason=st.text_input('Drafting reason',key='draft6_reason')
        confirm=st.checkbox('I confirm source-backed drafting replay for this scope',key='draft6_confirm')
        submit=st.form_submit_button('Run Agent 6 Evidence Replay',disabled=busy,key='draft6_run')
    if submit:
        try:
            run_drafting_research(manager,data['manager']['generation'],scope_id=scope,confirmed=confirm,actor=actor,reason=reason,
                operation_key=identity+'-'+scope,reviewed_token=review_token(data))
            st.rerun()
        except (LiveResearchError,ValueError) as exc:st.error(str(exc))
    values=[p for p in stored(data) if p['scope_id']==scope]
    if not values:
        st.caption('No Agent 6 draft assessment recorded for this scope.');return
    payload=values[-1];detail(payload,data)
    if not payload['result']:return
    reviews=[json.loads(e['payload_json']) for e in data['audit_events']
        if e['event_type']=='Agent6ResearchReviewRecorded' and e['entity_id']==payload['run_id']]
    if not reviews:
        with st.form('draft6_review_form',enter_to_submit=False):
            reviewer=st.text_input('Reviewing drafting analyst',key='draft6_reviewer')
            why=st.text_input('Draft review reason',key='draft6_review_reason')
            decision=st.radio('Draft research decision',['Accepted for analyst use','Rejected'],key='draft6_decision')
            reviewed=st.checkbox('I reviewed the exact rendered draft and research hash',key='draft6_review_confirm')
            accept=st.form_submit_button('Record Agent 6 research review',disabled=busy,key='draft6_review')
        if accept:
            try:
                review_drafting_research(manager,data['manager']['generation'],run_id=payload['run_id'],proposal_hash=payload['proposal_hash'],
                    confirmed=reviewed,actor=reviewer,reason=why,decision=decision)
                st.rerun()
            except (LiveResearchError,ValueError) as exc:st.error(str(exc))
    elif reviews[-1]['decision']=='Accepted for analyst use':
        st.caption('Research accepted for analyst use only; stage a draft explicitly, then use existing separate operational approval controls.')
        with st.form('draft6_stage_form',enter_to_submit=False):
            kind=st.radio('Draft to stage',['Ticket','Communication'],key='draft6_kind')
            who=st.text_input('Staging analyst',key='draft6_stager')
            why=st.text_input('Staging reason',key='draft6_stage_reason')
            confirm=st.checkbox('Stage this exact draft only; no approval, ticket execution or delivery',key='draft6_stage_confirm')
            stage=st.form_submit_button('Stage reviewed draft',disabled=busy,key='draft6_stage')
        if stage:
            try:
                stage_drafting_research(manager,data['manager']['generation'],run_id=payload['run_id'],proposal_hash=payload['proposal_hash'],
                    kind=kind,confirmed=confirm,actor=who,reason=why,operation_key='stage-'+payload['run_id']+'-'+kind)
                st.rerun()
            except (LiveResearchError,ValueError) as exc:st.error(str(exc))
    else:st.caption('Research rejected; no staging authority.')
