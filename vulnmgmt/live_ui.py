"""Focused Agent Operations tab; no model execution on render or selection."""
import json
from uuid import uuid4
import streamlit as st
from .dashboard_queries import revision_token
from .dashboard_service import run_live_research, review_live_research
from .live_contracts import LiveConfig, LiveResearchError, execution_summary
from .live_evidence import context, CLAIM_FIELDS
from .live_research import RESULT_KEY
from .ui_components import readable, table


def panel(manager, data, busy):
    st.subheader('Agent 2 · Live CVE Remediation Research')
    st.caption('Live AI uses an OpenAI API model when separately enabled and authorized. Evidence Replay is historical human-curated analysis, not a model execution.')
    try:
        config = LiveConfig.environment()
        config.require_authorization()
        unavailable = None
    except LiveResearchError as exc:
        config = None
        unavailable = str(exc)
    if unavailable:
        st.info(unavailable)
    st.caption('Live validation is pending until an authorized real run is independently evaluated. Local analyst names are not authenticated enterprise identities.')
    cves = sorted({f['cve_id'] for f in data['findings']})
    if not cves:
        st.info('Import scanner findings first. Replay can load existing dated evidence for comparison.')
        return
    cve = st.selectbox('Live research CVE', cves, key='live2_cve')
    if st.button('Inspect original scanner findings', key='live2_original'):
        st.session_state['explorer_search'] = cve
        st.session_state['next_page'] = 'Vulnerability Explorer'
        st.rerun()
    supplied = context(data, cve)
    st.write('**Selected source evidence · before execution**')
    for s in supplied['sources']:
        st.write(s['url'])
        st.caption('Retrieved '+readable(s['retrieved_at'], 'retrieved_at')+' · '+s['provenance'])
        with st.expander('Captured source excerpt · '+s['id'][:8]):
            st.text(s['text'])
    if not supplied['sources']:
        st.warning('No usable captured source. Load replay or separately authorize official public retrieval. Missing evidence is not zero risk.')
    with st.expander('Exact selected synthetic context and source hashes'):
        st.json(supplied, expanded=False)
    if config:
        st.caption(f'Requested model: {config.model} · maximum 1 provider request/run · output ceiling {config.max_output_tokens} tokens · session attempt limit {config.max_session_requests} · estimated budget ${config.budget_usd:.2f}')
    st.caption('Request/output limits are enforced locally. Dollar reservations are estimates, not guaranteed provider billing limits. Failed/uncertain attempts consume reservations; no automatic retries.')
    identity = str(data['manager']['generation'])+':'+cve
    requests = st.session_state.setdefault('live2_requests', {})
    request = requests.setdefault(identity, {'key': str(uuid4()), 'reviewed_token': revision_token(data)})
    if st.button('Prepare another research request (no execution)', key='live2_new', disabled=busy or config is None):
        requests[identity] = {'key': str(uuid4()), 'reviewed_token': revision_token(data)}
        st.rerun()
    with st.form('live2_run_form', enter_to_submit=False):
        actor = st.text_input('Research analyst', value='demo-analyst', key='live2_actor')
        reason = st.text_input('Research purpose / reason', key='live2_reason')
        refresh = st.checkbox('Retrieve official public evidence for this run', key='live2_refresh',
                              disabled=config is None or not config.allow_public_fetch)
        confirmed = st.checkbox('I approve this one configured live research request', key='live2_confirm', disabled=config is None)
        submitted = st.form_submit_button('Run Live Research', key='live2_run', disabled=busy or config is None)
    if submitted:
        try:
            with st.spinner('Running Agent 2; validating quoted evidence and recording a review proposal…'):
                result = run_live_research(manager, data['manager']['generation'], cve=cve, confirmed=confirmed,
                    actor=actor, reason=reason, operation_key=request['key'], reviewed_token=request['reviewed_token'],
                    refresh_sources=refresh)
            st.session_state['live2_receipt'] = result['run_id']
            st.rerun()
        except LiveResearchError as exc:
            st.error(str(exc))
    show_results(manager, data, cve, busy)


def show_results(manager, data, cve, busy):
    steps = [s for s in data['agent_steps'] if s['step_key'] == RESULT_KEY]
    results = [json.loads(s['output_json']) for s in steps if s['output_json']]
    results = sorted([r for r in results if r['cve_id'] == cve], key=lambda r: r['started_at'], reverse=True)
    if not results:
        st.caption('No Agent 2 live research result recorded for this CVE. No model call is implied.')
        return
    labels = {r['started_at']+' · '+r['execution']['origin']+' · '+r['run_id'][:8]: r for r in results}
    chosen = st.selectbox('Recorded research run', list(labels), key='live2_selected')
    payload = labels[chosen]
    execution = payload['execution']
    outcome = execution_summary(payload)
    st.info('Provider: '+outcome['provider_status']+' | Research: '+outcome['research_status'])
    assessment = execution.get('evidence_validation')
    if assessment:
        table(assessment['diagnostics'], height=220)
    st.write('**Recorded mode:** '+execution['origin']+' · **Requested model:** '+execution['model_requested'])
    st.caption('Started '+readable(payload['started_at'], 'started_at')+' · ended '+readable(payload['ended_at'], 'ended_at')+
               f" · workflow duration {payload['workflow_duration_seconds']:.2f}s")
    st.caption('Served model identity: '+str(execution.get('model_served') or 'Not exposed by the SDK result')+
               ' · provider attempts: '+str(execution['provider_attempts']))
    if execution.get('usage') is not None:
        table([{k: execution['usage'].get(k) for k in ('requests', 'input_tokens', 'output_tokens', 'total_tokens')}], height=90)
    else:
        st.caption('Token usage unavailable; no zero usage or cost is inferred.')
    if payload['error']:
        st.error('Rejected/quarantined research: '+payload['error'])
    result = payload['result']
    if result:
        st.warning('Proposed research · human validation required. Historical vendor facts do not establish current release safety or synthetic asset applicability.')
        for field in CLAIM_FIELDS:
            claim = result[field]
            st.write('**'+field.replace('_', ' ').title()+' · '+claim['status']+'**')
            st.text(claim['value'] or 'Unknown')
            if claim['interpretation']:
                st.write('Unverified model interpretation: '+claim['interpretation'])
            with st.expander('Supporting quotations · '+field.replace('_', ' ')):
                for q in claim['evidence']:
                    source = next(s for s in payload['sources'] if s['id'] == q['source_id'])
                    st.write(source['url'])
                    st.caption('Retrieved '+readable(source['retrieved_at'], 'retrieved_at'))
                    st.text(q['excerpt'])
        st.write('**Unverified applicability assessment:** '+result['applicability'])
        st.caption('Any synthetic overlay applies only to its named asset/component. Other installations remain Unknown.')
        for label in result['synthetic_assumptions']:
            st.write('Synthetic assumption: '+label)
        for gap in result['conflicting_or_missing_evidence']:
            st.write('Evidence limitation: '+gap)
        for item in result['analyst_validation']:
            st.write('Analyst validation required: '+item)
        decisions = [e for e in data['audit_events'] if e['event_type'] == 'LiveResearchReviewRecorded' and e['entity_id'] == payload['run_id']]
        if decisions:
            st.info('Recorded research review: '+json.loads(decisions[-1]['payload_json'])['decision']+' · not operational approval.')
        else:
            with st.form('live2_review_form', enter_to_submit=False):
                actor = st.text_input('Reviewing analyst', key='live2_reviewer')
                reason = st.text_input('Research review reason', key='live2_review_reason')
                decision = st.radio('Research decision', ['Accepted for analyst use', 'Rejected'], key='live2_decision')
                confirmed = st.checkbox('I reviewed this exact research proposal', key='live2_review_confirm')
                submit = st.form_submit_button('Record research review', key='live2_review', disabled=busy or payload['generation'] != data['manager']['generation'])
            if submit:
                try:
                    review_live_research(manager, data['manager']['generation'], run_id=payload['run_id'],
                        proposal_hash=payload['proposal_hash'], decision=decision, actor=actor, reason=reason, confirmed=confirmed)
                    st.rerun()
                except LiveResearchError as exc:
                    st.error(str(exc))
    with st.expander('Compare with historical human-curated replay baseline'):
        baseline = [json.loads(s['output_json'])['guidance'] for s in data['agent_steps']
                    if s['role_number'] == 2 and s['step_key'] == cve and s['output_json']]
        for g in baseline:
            st.write(g['status']+' · '+str(g['instructions'] or 'Guidance unavailable'))
            st.write(g['gaps'])
        if not baseline:
            st.caption('Replay baseline not loaded; no comparison outcome inferred.')
    with st.expander('Sanitized execution record, response references and exact structured output'):
        st.json(payload, expanded=False)
