"""Agent 4 views over persisted research; render never invokes an SDK or retrieval."""
import json
from uuid import uuid4
import streamlit as st
from .dashboard_queries import revision_token
from .dashboard_service import load_threat_sources, run_threat_research, review_threat_research, view
from .live_contracts import LiveResearchError
from .services import digest
from .ui_components import table


def stored(data):
    results=[]
    for step in data['agent_steps']:
        if step['role_number']!=4 or step['step_key']!='agent4-threat-result' or not step['output_json']:
            continue
        value=json.loads(step['output_json'])
        if (value['workspace_id']==data['workspace_id'] and value.get('result') and
                digest({k:v for k,v in value.items() if k!='proposal_hash'})==value['proposal_hash']):
            results.append(value)
    return sorted(results,key=lambda r:r['started_at'])


def rows(data):
    latest={r['cve_id']:r for r in stored(data)}
    return [dict(f,agent4=latest.get(f['cve_id'])) for f in data['findings']]


def detail(payload):
    execution=payload['execution']
    mode={'live_model':'Live AI','offline_mock':'Offline mock (not live AI)',
          'human_curated_source_backed_replay':'Replay (human curated; zero model calls)'}[execution['origin']]
    st.write('**Processing mode:** '+mode)
    st.caption('Research proposal only; human review required. Operational severity, SLA and remediation status are unchanged.')
    st.caption('Requested model: '+str(execution.get('model_requested'))+
        ' | served model: '+str(execution.get('model_served') or 'Not exposed / not applicable')+
        ' | provider attempts: '+str(execution['provider_attempts']))
    if execution.get('usage'):
        table([execution['usage']],['requests','input_tokens','output_tokens','total_tokens'],height=90)
    clock=payload.get('evidence_as_of',payload['synthetic_effective_at'])
    basis='Evidence assessment UTC' if payload.get('evidence_as_of') and execution['origin']=='live_model' else 'Recorded/synthetic evidence assessment clock'
    st.caption(basis+': '+clock+'. Freshness below describes that recorded assessment, not a new current-source check.')
    result=payload['result']
    if not result:
        st.warning(payload.get('error') or 'Research unavailable')
        return
    table([dict(signal=name,**dict(result[name],value=str(result[name]['value']))) for name in ('kev','epss')],height=160)
    st.caption('EPSS is a probability estimate for exploitation in the next 30 days, not proof of exploitation.')
    for field in ('exploitation','government_targeting'):
        fact=result[field]
        st.write('**'+field.replace('_',' ').title()+':** '+fact['status'])
        if fact['value']:
            st.text(fact['value'])
        st.write('Unverified interpretation: '+fact['interpretation'])
        for quote in fact['evidence']:
            source=next(s for s in payload['sources'] if s['id']==quote['source_id'])
            st.caption(source['url']+' · captured '+source['retrieved_at']+' · '+source['freshness'])
            st.text(quote['excerpt'])
    for field in ('prioritization_considerations','conflicting_or_missing_evidence','analyst_validation'):
        for item in result[field]:
            st.write(field.replace('_',' ').title()+': '+item)
    with st.expander('Source provenance and freshness'):
        table(payload['sources'],['url','retrieved_at','expires_at','content_hash','freshness','confidence'])
        st.caption('Freshness is assessed relative to the recorded research as-of clock; captures are dated historical evidence.')
    with st.expander('Recorded Agent 4 execution'):
        st.json(payload)


def panel(manager,data,busy):
    st.subheader('Agent 4 · Threat Intelligence')
    if any(p['execution']['origin']=='live_model' for p in stored(data)):
        st.info('Recorded live Agent 4 output is available; new live execution is disabled. Analyst acceptance remains separate. Replay is labeled independently.')
    else:
        st.info('Live Agent 4 is disabled and unvalidated. Replay is human-curated source-backed evidence, never model-recorded output.')
    choices=sorted({f['cve_id'] for f in data['findings']})
    if not choices:
        st.caption('Import synthetic scanner findings first.')
        return
    cve=st.selectbox('Threat intelligence CVE',choices,key='threat4_cve')
    identity=st.session_state.setdefault('threat4_operation','agent4-replay-'+str(uuid4()))
    with st.form('threat4_replay_form',enter_to_submit=False):
        actor=st.text_input('Threat research analyst',value='demo-analyst',key='threat4_actor')
        reason=st.text_input('Threat research reason',key='threat4_reason')
        confirmed=st.checkbox('I confirm loading historical sources and replaying this CVE',key='threat4_confirm')
        submitted=st.form_submit_button('Run Agent 4 Evidence Replay',disabled=busy,key='threat4_run')
    if submitted:
        try:
            if not confirmed or not actor.strip() or not reason.strip():
                raise LiveResearchError('Explicit confirmation, analyst and reason required.')
            load_threat_sources(manager,data['manager']['generation'],confirmed=True,actor=actor)
            updated=view(manager)
            run_threat_research(manager,data['manager']['generation'],cve=cve,confirmed=True,actor=actor,reason=reason,
                operation_key=identity+'-'+cve,reviewed_token=revision_token(updated))
            st.rerun()
        except LiveResearchError as exc:
            st.error(str(exc))
    results=[r for r in stored(data) if r['cve_id']==cve]
    if not results:
        st.caption('No Agent 4 proposal recorded for this CVE.')
        return
    payload=results[-1]
    detail(payload)
    decisions=[e for e in data['audit_events'] if e['event_type']=='Agent4ResearchReviewRecorded' and e['entity_id']==payload['run_id']]
    if decisions:
        st.caption('Recorded human research decision: '+json.loads(decisions[-1]['payload_json'])['decision']+'; not operational approval.')
    else:
        with st.form('threat4_review_form',enter_to_submit=False):
            reviewer=st.text_input('Reviewing threat analyst',key='threat4_reviewer')
            why=st.text_input('Threat review reason',key='threat4_review_reason')
            decision=st.radio('Threat research decision',['Accepted for analyst use','Rejected'],key='threat4_decision')
            accept=st.checkbox('I reviewed this exact threat proposal',key='threat4_review_confirm')
            save=st.form_submit_button('Record threat research review',disabled=busy,key='threat4_review')
        if save:
            try:
                review_threat_research(manager,data['manager']['generation'],run_id=payload['run_id'],proposal_hash=payload['proposal_hash'],
                    decision=decision,confirmed=accept,actor=reviewer,reason=why)
                st.rerun()
            except LiveResearchError as exc:
                st.error(str(exc))
