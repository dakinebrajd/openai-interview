"""Workflow-led application shell; all mutations delegate to existing services."""
from html import escape
import json
from uuid import uuid4
import streamlit as st
from . import live_ui_policy
from . import assessment_ui as assessment, dashboard_service as commands, agent0, soc_views
from . import resolver_portal
from .services import digest
from .ui_components import table, readable

DESTINATIONS = ['Scenario', 'Scan files', 'AI workflow', 'Dashboard', 'Resolver tickets', 'Verification']


def go(destination):
    st.session_state['next_page'] = destination
    st.rerun()


def current(data):
    states = assessment.current_runs(data)
    selected=st.session_state.get('wx_active_run',st.session_state.get('m7_active_run'))
    return next((s for s in states if s['run_id'] == selected), states[-1] if states else None)


def phase(data):
    state = current(data)
    if not state:
        return 'Ready to run' if data['findings'] else 'Awaiting scanner files'
    ticket = next((t for t in data['tickets'] if t['id'] == state['refs'].get('ticket_id')), None)
    if state['status'] == 'Completed':
        return 'Scanner verified' if ticket and ticket['status'] == 'Closed' else 'Scanner outcome recorded · work remains open'
    if state['cursor'] == 19:
        return 'First pass complete · awaiting resolver update'
    if state['cursor'] >= 23:
        return 'Awaiting independent scanner evidence'
    return state['status']+' · '+agent0.STAGES[state['cursor']]


def header(data):
    st.caption('LOCAL SYNTHETIC ASSESSMENT · '+phase(data))
    if current(data):
        state = current(data)
        modes = sorted({friendly_mode(h['mode']) for h in state['history'] if h.get('role') in (2, 3, 4, 6, 7)})
        st.caption('Actual recorded processing: '+(' / '.join(modes) if modes else 'No reasoning stage recorded yet')+
                   ' · current-run provider attempts: '+str(state.get('provider_attempts', 0)))


def friendly_mode(value):
    return {'human_curated_source_backed_replay':'Replay (curated sources)',
            'live_model':'Live AI', 'offline_mock':'Offline Mock',
            'Evidence replay':'Dated source evidence'}.get(value, value)


def research_content(payload):
    """Render saved fields and exact excerpts; never generate a new interpretation."""
    rendered = payload.get('rendered')
    if rendered:
        st.write('**Proposed consolidated report**');st.text(rendered.get('consolidated_report',''))
        with st.expander('Ticket description and communication draft'):
            st.text(rendered.get('ticket_description',''));st.write('To: '+rendered.get('to','Unknown'))
            st.write('Subject: '+rendered.get('subject','Unknown'));st.text(rendered.get('email_body',''))
        return
    sources={source['id']:source for source in payload.get('sources',[]) if isinstance(source,dict) and 'id' in source}
    def show(name,value,depth=0):
        if name.endswith('_id') or name in ('workspace_id','body_hash','finding_ids','ticket_revision','communication_id','owner_id'):
            return
        label=name.replace('_',' ').capitalize()
        if isinstance(value,dict) and 'value' in value:
            st.write('**'+label+'**');st.caption(str(value.get('status',value.get('state','Saved claim'))))
            st.text(str(value['value']) if value['value'] is not None else 'Unknown')
            if value.get('interpretation'):st.text(value['interpretation'])
            for quote in value.get('evidence',value.get('citations',[])):
                if isinstance(quote,dict):
                    source=sources.get(quote.get('source_id'),{})
                    st.caption('Evidence: '+source.get('url',quote.get('source_id','Source not recorded')))
                    if quote.get('excerpt') or quote.get('quote'):st.text(quote.get('excerpt') or quote['quote'])
            metadata={k:v for k,v in value.items() if k not in ('value','interpretation','evidence','citations') and not isinstance(v,(list,dict))}
            if metadata:st.caption(' · '.join(k.replace('_',' ')+': '+str(v) for k,v in metadata.items()))
        elif isinstance(value,dict):
            st.write('**'+label+'**')
            for key,item in value.items():show(key,item,depth+1)
        elif isinstance(value,list):
            if value:
                st.write('**'+label+'**')
                for item in value:
                    if isinstance(item,dict):
                        with st.container(border=True):
                            for key,detail in item.items():show(key,detail,depth+1)
                    else:st.text(str(item))
        elif value is not None:
            st.write('**'+label+'**');st.text(str(value))
    for name,value in (payload.get('result') or {}).items():show(name,value)


def saved_agent_details(state,role):
    names={2:('agent2',),4:('agent4',),3:('agent3',),6:('report','mail'),7:('agent7',)}
    found=False
    st.subheader('Selected agent · saved output and evidence')
    st.caption('Saved proposals and interpretations remain subject to their exact independent reviews. Selecting a node never runs it.')
    for name in names.get(role,()):
        values=state['refs'].get(name,[])
        for payload in values if isinstance(values,list) else [values]:
            found=True;st.write('**'+name.replace('agent','Agent ')+'**')
            execution=payload.get('execution',{})
            st.caption('Actual mode: '+friendly_mode(execution.get('origin','Not recorded'))+
                       ' · provider attempts: '+str(execution.get('provider_attempts','Not recorded'))+
                       ' · model: '+str(execution.get('model_served') or execution.get('model_requested') or 'Not recorded'))
            if payload.get('result'):research_content(payload)
            else:st.warning('No validated result is saved for this output. Inspect the exact record for failure or quarantine details.')
            sources=payload.get('sources',[])
            if sources:
                st.write('**Source provenance**');table(sources,['url','retrieved_at','kind'],height=180)
            supplied=payload.get('assessment_input')
            if supplied:
                if supplied.get('findings'):
                    st.write('**Saved input scope**');table(supplied['findings'],['asset_key','component_key','cve_id','severity'],height=160)
                for label in ('synthetic_assumptions','source_limitations'):
                    for item in supplied.get(label,[]):st.text(str(item))
            else:st.caption('A separate saved input object is not recorded in this output; no input has been reconstructed.')
            if execution.get('usage'):
                st.write('**Recorded model usage**');table([execution['usage']],height=100)
            with st.expander('Exact saved input, output and technical audit record · '+name):st.json(payload)
    if not found:
        st.caption('No saved reasoning output for this node. Recorded deterministic stage history:')
        table([h for h in state['history'] if h['role']==role])


def managed_assessment(manager):
    return manager.root.parent == assessment.application().root/'assessments'


def scenario(manager, data, busy):
    st.write('Choose a starting point. Each assessment keeps its own files, execution, decisions and history.')
    choices = [('Start fresh', 'Create a separate synthetic assessment. Existing history is retained.'),
               ('Continue working', 'Resume a saved assessment at its current decision or verification gate.'),
               ('Use a demo scenario', 'Load the supplied synthetic scanner story into the selected assessment.')]
    action = st.radio('Scenario action', [c[0] for c in choices]+['Snapshots & restart'],
                      horizontal=True, key='wx_scenario_action')
    if action != 'Snapshots & restart':
        st.caption(dict(choices)[action])
    if action == 'Start fresh':
        assessment.assessments(manager, data, busy, compact=True)
    elif action == 'Continue working':
        table(assessment.catalogue_rows(), ['name','status','pending_stage','pending_reason','last_action','last_action_at','current_ticket_outcomes'], height=240)
        st.info('Choose the saved assessment in the sidebar. Its saved state is authoritative; navigating does not rerun agents.')
        if current(data):st.caption('Selected assessment: '+phase(data)+' · '+current(data).get('reason',''))
        if st.button('Resume selected assessment', key='wx_resume'):
            go('AI workflow' if current(data) else 'Scan files')
        with st.expander('Manage saved assessments · archive retains history'):
            assessment.assessment_management(assessment.application(),busy)
    elif action == 'Use a demo scenario':
        st.selectbox('Demo story', ['Owner reports completion; scanner Pass or Fail decides the outcome'], key='wx_story')
        st.caption('The same evidence supports both outcomes; choose the later scanner result in Verification. Loading never approves or executes agents.')
        allowed = managed_assessment(manager)
        if not allowed:
            st.warning('Create an isolated assessment first. Demo loading here cannot modify the preserved dashboard.')
        with st.form('wx_load_scenario', enter_to_submit=False):
            actor = st.text_input('Scenario analyst', value='demo-analyst', key='m7_scenario_actor')
            confirm = st.checkbox('Load the predefined synthetic agency scanner scenario', key='m7_scenario_confirm')
            submit = st.form_submit_button('Load Synthetic Scenario', key='m7_scenario_load', disabled=busy or not allowed)
        if submit:
            try:
                commands.command(manager, data['generation'], 'fresh_scan', confirmed=confirm, actor=actor,
                                 reason='Load synthetic scanner scenario into isolated assessment',
                                 key='wx-scenario-'+str(data['generation']))
                go('Scan files')
            except ValueError as exc:st.error(str(exc))
    else:
        snapshots(manager, data, busy)


def snapshots(manager, data, busy):
    if not managed_assessment(manager):
        st.info('Select an isolated assessment to use snapshot/restart controls. The original dashboard is preserved.');return
    history = manager.history();generation = data['generation']
    st.caption('Snapshots and restart retain prior generations and audit history. Restore invalidates copied actionable approvals; spending reservations are never refunded.')
    with st.form('snapshot', enter_to_submit=False):
        name = st.text_input('Snapshot name', key='snapshot_name')
        confirm = st.checkbox('Confirm saving a local snapshot', key='snapshot_confirm')
        save = st.form_submit_button('Save snapshot', key='snapshot_run', disabled=busy)
    if save:
        try:
            if not confirm:raise ValueError('Explicit snapshot confirmation required')
            manager.snapshot(generation, name, operation_key=digest([generation, name, data['as_of']]))
            st.session_state['post_reset'] = 'Snapshot saved; history retained.';st.rerun()
        except ValueError as exc:st.error(str(exc))
    options = {'Fresh inventory': None, **{s['name']+' · '+s['id'][:8]: s['id'] for s in history['snapshots']}}
    target = st.selectbox('Reset target', list(options), key='reset_target')
    with st.form('reset', enter_to_submit=False):
        confirmation = st.text_input('Type RESET DEMO to confirm reset / restore', key='reset_confirmation')
        reset = st.form_submit_button('Reset isolated synthetic demo', key='reset_run', disabled=busy)
    if reset:
        try:
            manager.reset(generation, confirmation, options[target])
            st.session_state['post_reset'] = 'Reset verified; old generations retained and copied approvals invalidated.';st.rerun()
        except ValueError as exc:st.error(str(exc))
    with st.expander('Saved snapshots and retained history'):
        table(history['snapshots'], ['name', 'generation', 'clock', 'sha256', 'created_at'])
        table(history['events'], ['generation', 'kind', 'recorded_at'])


def scan_files(manager, data, busy):
    if not managed_assessment(manager):
        st.info('This legacy workspace is inspectable. New scanner data belongs in an isolated assessment.')
        if st.button('Create an assessment to load new scanner files',key='wx_legacy_create'):
            st.session_state['wx_scenario_action']='Start fresh';go('Scenario')
        if st.button('Choose an existing assessment',key='wx_legacy_select'):
            st.session_state['wx_scenario_action']='Continue working';go('Scenario')
        return
    st.info('Load new data here: choose one synthetic scanner file, Preview and Validate, review the reconciliation, then Import. Repeat for additional files; matching asset/component/CVE observations consolidate automatically.')
    from . import two_resolver_demo
    prepared=any(e['event_type']==two_resolver_demo.EVENT for e in data['audit_events'])
    with st.expander('Two resolver demo · four overlapping scanner exports',expanded=not data['findings']):
        st.write('Two synthetic assets, two resolver groups, two CVEs per asset. This prepares inventory only; import all four files below and run each asset separately. Historical OpenSSL guidance and synthetic version assumptions are explicitly labelled.')
        if not prepared:
            with st.form('wx_two_resolver_prepare',enter_to_submit=False):
                actor=st.text_input('Demo inventory analyst',value='demo-analyst')
                reason=st.text_input('Demo inventory rationale',value='Prepare isolated two-resolver synthetic assessment')
                confirm=st.checkbox('Confirm adding the two synthetic assets before any scanner import')
                prepare=st.form_submit_button('Prepare two resolver demo inventory',disabled=busy or bool(data['findings']))
            if prepare:
                try:
                    two_resolver_demo.prepare(manager,data['generation'],confirmed=confirm,actor=actor,reason=reason)
                    st.rerun()
                except ValueError as exc:st.error(str(exc))
        else:
            st.success('Two resolver inventory prepared. Import each file once; reimporting the same file is idempotent.')
            for filename in ('tenable-a.json','defender-a.json','tenable-b.json','defender-b.json'):
                st.download_button('Download '+filename,(two_resolver_demo.DIRECTORY/filename).read_bytes(),file_name=filename,mime='application/json',key='wx_demo_'+filename)
    assessment.scanner_upload(manager, data, busy)
    if data['raw_findings']:
        for col,(label,value) in zip(st.columns(3),[
                ('Raw observations',len(data['raw_findings'])),
                ('Quarantined observations',len(data['quarantine'])),
                ('Normalized obligations',len(data['findings']))]):
            col.metric(label,value)
        st.caption('Observations and asset/component/CVE obligations use different denominators. Original rows and identity conflicts are retained; repeat imports do not add duplicate obligations.')
        with st.expander('Normalized register and quarantine details'):
            table(data['findings'], ['asset_key', 'component_key', 'cve_id', 'severity', 'status'])
            table(data['quarantine'], ['scanner', 'native_finding_id', 'errors'])
    if st.button('Continue to AI workflow', key='wx_files_next', disabled=not data['findings']):go('AI workflow')


AGENTS = [(1, 'Normalize scans', (0,)), (2, 'Research remediation', (1, 2, 4)),
          (4, 'Assess threat context', (3, 4)), (3, 'Group common fixes', (5, 6, 7)),
          (5, 'Check existing tickets', (8,)), (6, 'Draft owner report', tuple(range(9, 19))),
          (7, 'Interpret resolver update', (20, 21, 22))]


def node_rows(state):
    rows = []
    for role, label, stages in AGENTS:
        status = 'Not started';detail = 'Deterministic Python' if role in (1, 5) else 'No reasoning output yet'
        if state:
            cursor = state['cursor']
            if cursor > max(stages):status = 'Complete'
            elif cursor >= min(stages):
                status = 'Needs analyst review' if state['status'] == 'Review required' else state['status']
            if role == 7 and cursor == 19:status = 'Awaiting resolver update'
            children = state['refs'].get('agent'+str(role), []) if role != 6 else [state['refs'][k] for k in ('report', 'mail') if k in state['refs']]
            children = children if isinstance(children, list) else [children]
            modes = sorted({p['execution']['origin'] for p in children if isinstance(p, dict) and 'execution' in p})
            if modes:detail = ' / '.join(friendly_mode(mode) for mode in modes)
            if state['manifest'].get('resume_from', 0) >= 20 and role != 7:
                status = 'Linked prior result';detail = 'Not reexecuted; no new inherited usage'
        rows.append(dict(role=role, label=label, status=status, detail=detail))
    return rows



def approved_fact_panel(report):
    """Read-only presentation of facts and context retained in the approved snapshot."""
    material = report.get('material', {})
    st.caption('Retained common action identity: '+str(material.get('remediation_identity') or 'Unknown'))
    st.caption('Assigned CVEs: '+', '.join(material.get('cves', [])))
    st.caption('Retained asset: '+str(report.get('asset', {}).get('key') or 'Unknown'))
    for finding in report.get('findings', []):
        st.write('**'+str(finding.get('cve_id', 'Assigned CVE'))+'**')
        st.caption('Retained approved vendor facts — historical guidance, not a current secure-release recommendation.')
        facts = finding.get('verified_vendor_facts', [])
        for fact in facts:
            st.text(fact)
        if not facts:
            st.caption('No approved vendor fact retained for this finding.')
        for assumption in report.get('assumptions', []):
            if assumption.get('component_id') == finding.get('component_id'):
                st.caption(str(assumption.get('label') or 'Retained assumption')+': '+
                           str(assumption.get('product') or 'Unknown')+' '+
                           str(assumption.get('installed_version') or 'Unknown'))
                break
    st.write('**Retained vendor source context**')
    st.caption('The snapshot does not retain a per-quotation source link. These vendor-remediation sources are report context; no exact quotation-to-source mapping is inferred.')
    for source in report.get('sources', {}).values():
        if source.get('scope') != 'VendorRemediation':
            continue
        if source.get('url'):
            st.link_button('Open retained vendor source URL', source['url'])
        st.caption('Vendor publication date: '+str(source.get('published_at') or 'Unknown'))
        st.caption('Retained capture: '+str(source.get('retrieved_at') or 'Unknown'))
        st.caption('Retained source SHA256: '+str(source.get('hash') or 'Unknown'))


def process_graph(state, *, executing=False):
    """Readable wrapped sequence; only an actual invocation marks a role active."""
    from textwrap import wrap
    rows=node_rows(state)
    lines=['digraph agents {','rankdir=TB;',
           'graph [bgcolor="#ffffff" pad="0.2" nodesep="0.3" ranksep="0.5"];',
           'node [shape=box style="rounded,filled" fontname="Arial" fontsize=14 fontcolor="#0f172a" color="#475569" margin="0.15,0.1" width="2.3"];',
           'edge [color="#475569" fontcolor="#0f172a" fontname="Arial" fontsize=12 arrowsize=0.8];']
    for row in rows:
        status=row['status']
        active=bool(executing and state and {0:1,2:2,3:4,5:3,8:5,9:6,14:6,20:7}.get(state['cursor'])==row['role'])
        if active:status='Executing current stage'
        color='#dbeafe' if active else '#dcfce7' if status=='Complete' else '#fef3c7' if status in ('Needs analyst review','Review required','Awaiting resolver update') else '#f1f5f9'
        label='\n'.join(['Agent '+str(row['role'])]+wrap(row['label'],24)+wrap(status,24)+wrap(row['detail'],24))
        lines.append('a'+str(row['role'])+' [label='+json.dumps(label,ensure_ascii=False)+' fillcolor='+json.dumps(color)+'];')
    verification=('Scanner result recorded' if state and state['refs'].get('verification') else
                  'Awaiting independent scan' if state and state['cursor']>=23 else 'Not started')
    lines+=['{rank=same; a1; a2; a4;}', '{rank=same; a3; a5; a6;}', '{rank=same; a7; verify;}',
            'a1 -> a2 -> a4 -> a3 -> a5 -> a6 [constraint=false];',
            'a1 -> a3 -> a7 [style=invis weight=100];', 'a2 -> a5 -> verify [style=invis weight=100];',
            'a4 -> a6 [style=invis weight=100];',
            'a1 -> a2 -> a4 [style=invis weight=100];',
            'a3 -> a5 -> a6 [style=invis weight=100];',
            'a6 -> a7 [label="resolver update" style=dashed constraint=false];',
            'verify [label='+json.dumps('Independent scanner\nverification\n'+verification,ensure_ascii=False)+' fillcolor="#f1f5f9"];',
            'a7 -> verify [label="separate review\nand apply" style=dashed];','}']
    return '\n'.join(lines)


def ai_workflow(manager, data, busy):
    states = assessment.current_runs(data)
    if not managed_assessment(manager):
        st.info('Create an isolated assessment in Scenario to run this workflow. Existing records remain inspectable in advanced views.');return
    state=current(data)
    if not state:
        st.subheader('Start an assessment')
        if not data['findings']:st.info('Import scanner files or load a demo scenario first.')
        assessment.run_setup(manager,data,busy,compact=True)
        return
    st.subheader('Agent 0 · '+phase(data))
    st.graphviz_chart(process_graph(state),width='content',alt='Sequential agent workflow, recorded states and processing modes; selectable agent details follow below.')
    st.caption('Sequential recorded workflow. Replay, Live AI and linked prior results are labelled individually. Review gates pause execution; navigation never runs an agent.')
    if state['reason']:
        (st.error if state['status'] in ('Failed','Blocked') else st.info)(state['reason'])
    st.subheader('Next explicit workflow action')
    if state['status']=='Review required':
        assessment.review_queue(manager,data,busy,compact=True)
        if state['cursor']==22:
            st.subheader('Apply the separately reviewed resolver interpretation')
            assessment.resolver(manager,data,busy,part='processing')
        with st.expander('Continue after the separate decision is recorded'):
            assessment.continue_run(manager,data,busy,show_summary=False)
    else:
        assessment.continue_run(manager,data,busy,show_summary=False)
        with st.expander('Other pending exact reviews'):
            assessment.review_queue(manager,data,busy,compact=True)
    if state['cursor']==19:
        if st.button('Open resolver tickets',key='wx_team_tickets'):go('Resolver tickets')
    elif state['cursor']>=23 and state['status']!='Completed':
        if st.button('Go to verification',key='wx_team_verify'):go('Verification')
    elif state['status']=='Completed':
        if st.button('View dashboard',key='wx_team_dashboard'):go('Dashboard')
    st.divider();st.subheader('Inspect the saved agent process')
    st.caption('Initial pass: 1 → 2 → 4 → 3 → 5 → 6. After a resolver update: 7 → separate safe processing → independent scanner verification.')
    rows=node_rows(state)
    selected_role=st.session_state.get('wx_selected_agent',7 if state['cursor']>=20 else 6 if state['cursor']>=9 else 2)
    for start in range(0,6,3):
        for col,row in zip(st.columns(3),rows[start:start+3]):
            with col.container(border=True):
                if st.button('Agent '+str(row['role'])+' · '+row['label'],key='wx_agent_'+str(row['role']),width='stretch'):
                    st.session_state['wx_selected_agent']=row['role'];selected_role=row['role']
                st.caption(row['status']+' · '+row['detail'])
    row=rows[6]
    with st.container(border=True):
        if st.button('Agent 7 · Interpret resolver update',key='wx_agent_7',width='stretch'):
            st.session_state['wx_selected_agent']=7;selected_role=7
        st.caption('Resolver phase · '+row['status']+' · '+row['detail'])
    saved_agent_details(state,selected_role)
    with st.expander('Assess another asset · prepare a distinct run',expanded=state['cursor']==19):
        assessment.run_setup(manager,data,busy,compact=True)


def dashboard(manager, data, busy):
    """Reuse the established metric definitions and drill-downs in the main path."""
    from .ui import overview, explorer
    context_keys = ('explorer_search', 'explorer_selected', 'filter_severity', 'filter_status',
                    'filter_asset_type', 'filter_group', 'filter_scanner', 'drill')
    # Widgets disappear while approvals are open. Keep their values in assessment-
    # scoped state, which the existing generation identity reset clears.
    for key, value in st.session_state.get('wx_explorer_context', {}).items():
        if key not in st.session_state:
            st.session_state[key] = value
    pending = st.session_state.pop('wx_dashboard_tab_pending', None)
    if pending:
        st.session_state['wx_dashboard_tabs'] = pending
    st.caption('Dashboard / '+st.session_state.get('wx_dashboard_tabs', 'Vulnerability metrics'))
    summary, records = st.tabs(['Vulnerability metrics', 'Explore vulnerabilities'],
                               key='wx_dashboard_tabs', on_change='rerun')
    with summary:
        overview(manager, data, busy)
        st.subheader('Resolver follow-through')
        ticket_rows=resolver_portal.ticket_rows(data)
        for column,label,value in zip(st.columns(3),('Resolver reported Closed','Awaiting scanner verification','Scanner-verified tickets'),(
                sum(row['reported_status']=='Closed' for row in ticket_rows),
                sum(row['ticket']['status']=='Pending Verification' for row in ticket_rows),
                sum(row['ticket']['status']=='Closed' for row in ticket_rows))):
            column.metric(label,value)
        st.caption('Ticket counts. Resolver-reported closure is not scanner-verified vulnerability remediation; the original vulnerability metrics above retain their definitions.')
    with records:
        if st.button('Return to vulnerability metrics', key='wx_dashboard_return'):
            st.session_state['wx_dashboard_tab_pending'] = 'Vulnerability metrics'
            go('Dashboard')
        explorer(manager, data, busy)
    st.session_state['wx_explorer_context'] = {
        key: st.session_state[key] for key in context_keys if key in st.session_state}


def resolver_tickets(manager, data, busy):
    st.caption('Resolver-group demo perspective · service-management simulation · no ServiceNow, SMTP or external ticket connection.')
    rows = resolver_portal.ticket_rows(data)
    groups = sorted({(r['report'] or {}).get('resolver_group', {}).get('name', 'Unknown') for r in rows})
    group = st.selectbox('Assignment group', ['All']+groups, key='wx_ticket_group')
    pending_queue=st.session_state.pop('wx_ticket_queue_after_save',None)
    if pending_queue:st.session_state['wx_ticket_queue']=pending_queue
    queue = st.radio('Ticket queue', ['Open', 'Resolver reported Closed', 'Scanner verified', 'All'], horizontal=True, key='wx_ticket_queue')
    rows = [r for r in rows if (group == 'All' or (r['report'] or {}).get('resolver_group', {}).get('name', 'Unknown') == group)
            and (queue == 'All' or (queue == 'Resolver reported Closed' and r['reported_status']=='Closed')
                 or (queue == 'Scanner verified' and r['ticket']['status']=='Closed')
                 or (queue == 'Open' and r['reported_status']!='Closed' and r['ticket']['status']!='Closed'))]
    table([dict(ticket=r['reference'], assignment_group=(r['report'] or {}).get('resolver_group', {}).get('name', 'Unknown'),
                short_description=r['short_description'],lifecycle_status=r['ticket']['status'], resolver_reported_status=r['reported_status'],
                due_at=r['due_at'],last_activity_at=r['last_activity_at']) for r in rows], height=240, alt='Resolver ticket queue')
    if not rows:
        st.info('No tickets in this queue. Complete exact ticket and communication approvals in AI workflow, or change the queue filter.');return
    options = {r['reference']+' · '+r['ticket']['status']: r for r in rows}
    label = st.selectbox('Resolver ticket', list(options), key='wx_ticket_selected')
    row = options[label];ticket = row['ticket'];report = row['report'] or {}
    st.subheader(row['reference']+' · '+report.get('asset', {}).get('key', 'Asset unavailable'))
    c1, c2, c3 = st.columns(3)
    c1.write('**Assignment:** '+report.get('resolver_group', {}).get('name', 'Unknown'))
    c2.write('**Lifecycle:** '+ticket['status'])
    c3.write('**Resolver reported:** '+row['reported_status'])
    st.caption('Deadline: '+str(readable(report.get('material', {}).get('due_at'), 'due_at'))+' · exact ticket revision '+str(ticket['revision']))
    ids = {r['asset_cve_id'] for r in data['ticket_findings'] if r['ticket_id'] == ticket['id']}
    findings = [f for f in data['findings'] if f['id'] in ids]
    st.write('**Batched findings and enrichment**')
    table(findings, ['asset_key', 'component_key', 'cve_id', 'severity', 'status', 'kev_state', 'epss', 'epss_as_of', 'sector_targeting', 'applicability'], alt='Findings assigned to the selected resolver ticket')
    st.write('**Remediation instructions and common-action rationale**')
    if report:
        from .ui import guidance_context
        from .soc_queries import guidance_body
        guidance_context(report);st.write(guidance_body(report))
        st.write('**Why these CVEs share one remediation action**')
        approved_fact_panel(report)
        st.caption('The exact approved report below retains citations and unknowns. Live-source retrieval, current secure release and real installed-version applicability remain separate validation tasks.')
    cves = {f['cve_id'] for f in findings}
    with st.expander('Threat intelligence, batch evidence and exact approved report'):
        table([t for t in data['threat_intel'] if t['cve_id'] in cves], ['cve_id', 'kind', 'kev_member', 'epss_score', 'assessment', 'as_of', 'expires_at'])
        st.json(report)
        for state in assessment.current_runs(data):
            if state['refs'].get('ticket_id') == ticket['id']:
                for key in ('agent3', 'report', 'mail'):
                    if key in state['refs']:st.json(state['refs'][key].get('rendered') or state['refs'][key].get('result'))
                break
    st.subheader('Resolver status and work note')
    st.caption('Choose Closed to record that the resolver has closed the ticket. Run Agent 7 next to interpret the saved closure, then review and apply its proposal. Resolver-reported closure and scanner-verified remediation are shown separately.')
    parents = [s for s in assessment.current_runs(data) if s['refs'].get('ticket_id') == ticket['id'] and s['refs'].get('communication_id')]
    selected=st.session_state.get('wx_active_run',st.session_state.get('m7_active_run'))
    parent = next((s for s in parents if s['run_id'] == selected), parents[-1] if parents else None)
    if ticket['status'] == 'Closed':st.success('Scanner verified · this ticket’s findings have independent scan evidence. The recorded resolver status remains visible separately.')
    elif parent and managed_assessment(manager):
        with st.form('wx_resolver_update', enter_to_submit=False):
            status = st.selectbox('Resolver status', list(resolver_portal.STATUSES), key='wx_resolver_status')
            note = st.text_area('Resolver work note', key='wx_resolver_note', help='Synthetic only. Original note and claimed status are retained for interpretation and review.')
            mode = live_ui_policy.mode_radio(st,'Resolver interpretation mode', key='wx_resolver_mode')
            actor = st.text_input('Resolver update analyst', value='demo-analyst', key='wx_resolver_actor')
            confirm = st.checkbox('Record this synthetic status and note for this exact assigned ticket', key='wx_resolver_confirm')
            spend = live_ui_policy.spend_checkbox(st,'Separately authorize one Live AI interpretation within USD 0.10 estimated allowance', key='wx_resolver_spend')
            save = st.form_submit_button('Save resolver update', key='wx_resolver_save', disabled=busy)
        if save:
            try:
                nonce = st.session_state.setdefault('wx_resolver_operation', str(uuid4()))
                receipt = resolver_portal.submit_update(manager, data['generation'], parent_run_id=parent['run_id'],
                    parent_hash=parent['state_hash'], ticket_id=ticket['id'], status=status, note=note,
                    operation_key=nonce, confirmed=confirm, actor=actor, mode='mixed' if mode == 'Live AI' else 'replay',
                    spend_confirmed=spend, application=assessment.application())
                st.session_state['m7_pending_run_id'] = receipt['run_id'];st.session_state['wx_resolver_receipt'] = receipt
                st.session_state['wx_ticket_queue_after_save']='Resolver reported Closed' if status=='Closed' else 'Open'
                st.session_state.pop('wx_resolver_operation', None)
                st.session_state['m7_clear_flags'] = ['wx_resolver_confirm', 'wx_resolver_spend'];st.rerun()
            except ValueError as exc:st.error(str(exc))
    else:st.info('Finish exact communication approval and local simulated handoff in AI workflow before recording resolver updates.')
    if st.session_state.get('wx_resolver_receipt'):
        st.success('Resolver update saved. Findings are unchanged; interpret and review the update in AI workflow.')
        if st.button('Process update in AI workflow', key='wx_process_update'):go('AI workflow')
    with st.expander('Ticket activity, original work notes and immutable versions', expanded=False):
        table([dict(last_activity_at=row['last_activity_at'],event_type=row['last_activity_type'],event_id=row['last_activity_event_id'])])
        table(resolver_portal.ticket_replies(data, ticket['id']), ['received_at', 'owner_id', 'raw_body'])
        table([v for v in data['ticket_versions'] if v['ticket_id'] == ticket['id']], ['ticket_revision', 'event_type', 'reason', 'created_at'])
        table([v for v in data['verification_events'] if v['asset_cve_id'] in ids])


def verification(manager, data, busy):
    st.caption('Later independent synthetic scanner evidence determines verified remediation. Resolver status and AI conclusions cannot close findings.')
    runs=assessment.current_runs(data)
    unavailable_ticket=False
    ticket_options={t['id']:(t.get('external_synthetic_key') or t['id'][:8])+' · '+t['status'] for t in data['tickets']}
    if managed_assessment(manager) and ticket_options:
        ids=list(ticket_options)
        selected_state=current(data);active_ticket=selected_state['refs'].get('ticket_id') if selected_state else None
        chosen=st.selectbox('Ticket to verify',ids,index=ids.index(active_ticket) if active_ticket in ids else 0,format_func=ticket_options.get,key='wx_verification_ticket')
        matching=[run for run in runs if run['refs'].get('ticket_id')==chosen]
        if matching:
            st.session_state['wx_active_run']=matching[-1]['run_id']
            st.session_state['m7_active_run']=matching[-1]['run_id']
        else:
            unavailable_ticket=True
            st.warning('This selected ticket has no matching saved workflow run. Verification actions are unavailable; another ticket’s run will not be used.')
    state=None if unavailable_ticket else current(data)
    ticket_id=chosen if unavailable_ticket else state['refs'].get('ticket_id') if state else None
    scoped_ids={row['asset_cve_id'] for row in data['ticket_findings'] if row['ticket_id']==ticket_id}
    findings=[finding for finding in data['findings'] if finding['id'] in scoped_ids]
    ticket=next((row for row in data['tickets'] if row['id']==ticket_id),None)
    if not managed_assessment(manager):
        st.info('The preserved dashboard is read-only. Create or select an isolated assessment in Scenario for new verification actions.')
    elif not state or state['cursor']<23:
        st.subheader('Next step before scanner verification')
        st.info(('No saved assessment run. Start and review an assessment in AI workflow.' if not state else
                 phase(data)+'. '+(state.get('reason') or 'Complete the separately reviewed resolver interpretation and safe processing first.')))
        if st.button('Open AI workflow for the required step',key='wx_verify_prerequisite'):go('AI workflow')
    else:
        st.subheader('Selected ticket · '+(ticket.get('external_synthetic_key') or ticket['id'][:8] if ticket else 'Not recorded'))
        st.write('**Authoritative lifecycle:** '+(ticket['status'] if ticket else 'Not recorded'))
        table(findings,['asset_key','component_key','cve_id','severity','status','due_at'],alt='Findings in the selected verification scope')
        st.caption(str(sum(f['status']=='Pending Verification' for f in findings))+' scoped findings awaiting independent verification.')
        st.caption('For another synthetic Pass/Fail assessment, open Record a distinct subsequent scanner observation below. This is not a real scan.' if state['status']=='Completed' else 'Pass/Fail below represents a synthetic subsequent scanner assessment, not a real scan.')
        st.session_state['m7_active_run']=state['run_id']
        if state['status']=='Completed':
            (st.success if ticket and ticket['status']=='Closed' else st.warning)('Recorded scanner outcome: '+(ticket['status'] if ticket else 'Not recorded'))
            with st.expander('Record a distinct subsequent scanner observation'):
                assessment.resolver(manager,data,busy,part='verification')
        else:
            assessment.resolver(manager,data,busy,part='verification')
            st.subheader('Finalize the saved workflow after scanner evidence')
            assessment.continue_run(manager,data,busy,show_summary=False)
    if st.button('Return to dashboard',key='wx_verify_dashboard'):go('Dashboard')
    with st.expander('Scanner evidence, assessment lifecycle and complete verification history'):
        from .soc_queries import verification_rows
        from .ui_components import horizontal_chart,STATUS
        horizontal_chart(data['counts']['status'],'Current finding lifecycle',STATUS)
        st.caption('Assessment-wide reference; counts and history do not substitute for the selected ticket’s subsequent scanner evidence. Risk exceptions defer work and never prove remediation.')
        table(verification_rows(data))
        for label,key in [('Scanner assessments','scan_assessments'),('Verification events','verification_events'),
                          ('Finding transitions','status_history'),('Risk exceptions','exceptions')]:
            st.write('**'+label+'**');table(data[key])


PAGES = dict(zip(DESTINATIONS, [scenario, scan_files, ai_workflow, dashboard, resolver_tickets, verification]))
