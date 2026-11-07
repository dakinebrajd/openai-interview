"""Application-level browser experience around the existing SOC/lifecycle services."""
import json,os
from pathlib import Path
from uuid import uuid4
import streamlit as st
from . import live_ui_policy
from .application import Application,MODEL
from . import dashboard_service as commands,agent0,agent7,uploads,m7_campaign,local_security
from .services import digest
from .ui_components import table

def application():return Application(Path(os.environ.get('VM_APPLICATION_ROOT','artifacts/application')))

def current_runs(data):
    started={r['id']:r['started_at'] for r in data['runs']}
    return sorted((s for s in agent0.stored(data) if s['identity']==data['workspace_identity'] and s['generation']==data['generation']),
                  key=lambda s:(started.get(s['run_id'],''),s['run_id']))

def select_manager(legacy):
    app=application();options={'Legacy workspace (separate from original dashboard)':'legacy'}
    for row in app.assessments():options[row['name']+' · '+row['id'][:8]+(' · Archived' if row['archived'] else '')]=row['id']
    pending=st.session_state.pop('application_selected_pending',None)
    if pending:st.session_state['application_assessment']=next(k for k,v in options.items() if v==pending)
    if st.session_state.get('application_assessment') not in options:st.session_state.pop('application_assessment',None)
    label=st.sidebar.selectbox('Active assessment',list(options),key='application_assessment')
    id=options[label]
    if st.sidebar.button('View original dashboard — read only', key='view_original_dashboard'):
        st.session_state['original_dashboard_readonly']=True
        st.session_state['original_section']='Vulnerability metrics'
        for key in ('wx_explorer_context','explorer_search','explorer_selected','filter_severity','filter_status','filter_asset_type','filter_group','filter_scanner','drill'):
            st.session_state.pop(key,None)
        st.rerun()
    if st.sidebar.button('New Assessment',key='open_new_assessment'):
        st.session_state['next_page']='Scenario';st.session_state['wx_scenario_action']='Start fresh';st.rerun()
    if st.sidebar.button('Settings / AI Connection',key='open_ai_settings'):
        st.session_state['next_page']='AI settings';st.rerun()
    manager=app.manager(id) if id!='legacy' else legacy
    data=commands.view(manager)
    st.sidebar.caption('Selected: '+label+' · '+str(data['metrics']['findings'])+' unique obligations · synthetic as of '+data['as_of'])
    return manager

def catalogue_rows():
    return [dict(name=r['name'],status=r['status'],
                 current_ticket_outcomes=', '.join(str(n)+' '+status for status,n in r['ticket_outcomes'].items()) or 'No current tickets',
                 retained_completed_runs=len(r['prior_completed']),archived=bool(r['archived']),
                 pending_stage=r.get('pending_stage','No saved run'),pending_reason=r.get('pending_reason',''),
                 last_action=r.get('last_action','Not recorded'),last_action_at=r.get('last_action_at','Not recorded'))
            for r in application().outcomes()]


def assessments(manager,data,busy,compact=False):
    app=application()
    st.subheader('Assessments · isolated synthetic workspaces')
    st.caption('New Assessment creates a separate managed database. Reset rotates generations; Restore invalidates actionable approvals. Archive retains all files, attempts and audit history. Permanent deletion is unavailable.')
    if compact:
        with st.expander('Saved assessments and retained completed runs'):
            table(catalogue_rows(),height=180)
    else:table(app.outcomes(),['name','status','ticket_outcomes','prior_completed','id','created_at','archived'],height=180)
    with st.form('application_create',enter_to_submit=False):
        name=st.text_input('Assessment name',key='assessment_name')
        confirm=st.checkbox('Create a new isolated synthetic assessment',key='assessment_confirm')
        go=st.form_submit_button('Create Assessment',key='assessment_create',disabled=busy)
    if go:
        try:
            key=st.session_state.setdefault('application_new_key',str(uuid4()))
            id=app.create(name,key,confirmed=confirm);st.session_state.pop('application_new_key',None)
            st.session_state['application_selected_pending']=id;st.session_state['next_page']='Scan files';st.rerun()
        except ValueError as exc:st.error(str(exc))
    if compact:return
    assessment_management(app,busy)
    st.info('Select a saved assessment in the sidebar. In Scenario, choose Snapshots & restart for retained snapshots and generation restart.')


def assessment_management(app,busy):
    names={r['id']:r['name']+' · '+r['id'][:8]+(' · Archived' if r['archived'] else '') for r in app.assessments()}
    with st.form('application_archive',enter_to_submit=False):
        ids=[r['id'] for r in app.assessments() if not r['archived']]
        id=st.selectbox('Assessment to archive',ids,index=None,format_func=lambda value:names[value],key='m7_archive_assessment')
        confirm=st.checkbox('Archive only; preserve all files and spending records')
        if st.form_submit_button('Archive Assessment',disabled=busy or not ids):
            try:app.archive(id,confirmed=confirm);st.rerun()
            except ValueError as exc:st.error(str(exc))

def _store_callback():
    # Callback runs before widget reconstruction; clear server AND rendered values.
    first=st.session_state.pop('m7_key','');second=st.session_state.pop('m7_key_repeat','')
    try:
        message=local_security.credential_action('store',confirmed=st.session_state.get('m7_store_confirm',False),value=first,repeat=second)
        st.session_state['m7_credential_message']=('success',message)
    except ValueError as exc:st.session_state['m7_credential_message']=('error',str(exc))
    finally:
        first=second=None;st.session_state['m7_key']='';st.session_state['m7_key_repeat']='';st.session_state['m7_store_confirm']=False

def settings(manager,data,busy):
    app=application();saved=app.settings();usage=app.usage()
    st.subheader('Settings / AI Connection')
    st.caption('One shared Windows Credential Manager project key. Credentials never authorize spending. Configuration tests make no model request. Local synthetic prototype; no external communications.')
    remaining,cost=st.columns(2)
    remaining.metric('M7 requests remaining',usage['remaining_attempts'])
    cost.metric('M7 estimated allowance remaining',format(usage['remaining_estimated_allowance_usd'],'.6f')+' USD')
    st.caption('Existing cumulative campaign limits remain 40 attempts / USD 10 across assessments and resets. Configuration and credentials do not authorize a run.')
    try:local_security.require_local_operator();local=True
    except ValueError as exc:local=False;st.warning(str(exc))
    if local:
        if st.button('Check Credential Availability',key='m7_credential_check',disabled=busy):
            try:st.success(local_security.credential_action('status',confirmed=True))
            except ValueError as exc:st.error(str(exc))
    with st.form('m7_settings',enter_to_submit=False):
        model=st.selectbox('Approved model',[MODEL],key='m7_model')
        mode=live_ui_policy.mode_radio(st,'Assessment execution mode',index=0 if saved['mode']=='Replay' else 1,key='m7_mode')
        requests=st.number_input('Maximum requests for a new run',min_value=1,max_value=40,value=saved['max_attempts'],step=1,key='m7_requests')
        allowance=st.number_input('Estimated allowance for a new run ($)',min_value=.10,max_value=10.,value=saved['allowance_micro_usd']/1e6,step=.10,key='m7_allowance')
        confirm=st.checkbox('Save configuration only; this does not authorize spending',key='m7_config_confirm')
        save=st.form_submit_button('Save AI Configuration',key='m7_config_save',disabled=busy)
    if save:
        try:
            app.configure(dict(model=model,mode=mode,max_attempts=int(requests),allowance_micro_usd=round(allowance*1e6)),confirmed=confirm)
            st.session_state.pop('m7_run_mode',None)
            st.success('Configuration saved. Live execution still requires a separate confirmed run authorization.')
        except ValueError as exc:st.error(str(exc))
    if st.button('Test Configuration (no model call)',key='m7_config_test'):
        current=app.settings();st.success('Configuration valid: '+current['model']+' / '+current['mode']+'. No authentication or model execution is inferred.')
    if local:
        with st.expander('Store or rotate the private connection key'):
            with st.form('m7_credential_setup',enter_to_submit=False):
                st.text_input('Dedicated replacement API key',type='password',autocomplete='off',key='m7_key')
                st.text_input('Repeat replacement key',type='password',autocomplete='off',key='m7_key_repeat')
                st.checkbox('Store or rotate this private key under my Windows account',key='m7_store_confirm')
                st.form_submit_button('Securely Store / Rotate Credential',on_click=_store_callback,disabled=busy,key='m7_store')
            if 'm7_credential_message' in st.session_state:
                level,message=st.session_state['m7_credential_message'];getattr(st,level)(message)
        st.caption('Do not reuse the exposed chat key. Enter a replacement privately. Masked fields are cleared after submission; do not capture credential entry in recordings. No key is exported to environment variables or a dashboard response.')
        with st.expander('Remove the stored credential · explicit confirmation required'):
            remove=st.checkbox('Confirm removing the local shared credential',key='m7_remove_confirm')
            if st.button('Remove Credential',key='m7_remove',disabled=busy):
                try:st.success(local_security.credential_action('remove',confirmed=remove))
                except ValueError as exc:st.error(str(exc))
        with st.expander('Troubleshoot local credential storage · dummy test only'):
            if st.button('Test Temporary Dummy Credential Roundtrip',key='m7_dummy_test',disabled=busy):
                try:
                    st.json(local_security.dummy_roundtrip());st.success('Temporary dummy roundtrip passed; production target unchanged.')
                except (ValueError,AssertionError) as exc:st.error(str(exc) or 'Dummy credential test failed; production target unchanged')
    with st.expander('Technical limits, permanent reservations and recorded usage'):
        table([dict(attempts=usage['attempts'],remaining_attempts=usage['remaining_attempts'],reserved_usd=usage['reserved_usd'],
            remaining_estimated_allowance_usd=usage['remaining_estimated_allowance_usd'],estimated_actual_cost_usd=usage['estimated_actual_cost_usd'])],height=100)
        st.caption('Durable M7 campaign: '+str(usage['effective_attempt_limit'])+' effective internal attempts / $10 unchanged campaign allowance, within the cumulative $50 project boundary. Original 40-slot authorization and all reservations remain retained across resets. No automatic retries; local estimates are not verified billing.')
        st.caption('Each provider attempt: 4,096 output tokens, 60 seconds, no retries; conservative reservation USD 0.075432 using project rate assumptions (USD 0.75 input / USD 4.50 output per million tokens).')
        st.json(usage)


def scanner_upload(manager,data,busy):
    st.subheader('Scanner exports · validate before import')
    st.info('Synthetic-format adapters only, not production Tenable/Defender integrations. Uploaded exports are never sent to OpenAI automatically.')
    uploaded=st.file_uploader('Upload synthetic scanner export',type=['json','csv'],key='m7_upload')
    with st.expander('Example scanner exports and format override'):
        for filename,label in (('tenable.json','Tenable'),('defender.json','Defender')):
            for csv_format in (False,True):
                extension='csv' if csv_format else 'json'
                st.download_button('Download '+label+' synthetic '+extension.upper(),uploads.sample(filename,csv_format),file_name=filename.replace('.json','.'+extension),key='sample_'+label+extension)
        selected=st.selectbox('Scanner format',['Auto detect','synthetic-tenable','synthetic-defender'],key='m7_upload_format')
    if not uploaded:return
    content=uploaded.getvalue();name=uploaded.name;identity=digest([data['workspace_identity'],data['generation'],name,content.hex()])
    if st.button('Preview and Validate Upload',key='m7_upload_preview',disabled=busy):
        try:
            result=uploads.preview(manager,data['generation'],content,name,selected)
            st.session_state['m7_upload_validated']=dict(identity=identity,result=result)
        except (ValueError,UnicodeError) as exc:st.error('Upload rejected: '+str(exc))
    preview=st.session_state.get('m7_upload_validated')
    if not preview or preview['identity']!=identity:return
    result=preview['result'];st.caption('Format: '+result['format']+' · duplicate rows: '+str(result['duplicates'])+' · repeated export: '+str(result['import_result']['repeated']))
    st.write('**Validated file:** '+name)
    table(result['rows'],['index','status','issues'],height=240)
    with st.expander('Column mapping and exact parsed records'):
        table([dict(target_field=k,source_field=v) for k,v in result['mapping'].items()])
        table(result['rows'],['index','status','issues','record'],height=240)
    with st.form('m7_upload_import',enter_to_submit=False):
        actor=st.text_input('Import analyst',value='demo-analyst',key='m7_import_actor');reason=st.text_input('Import reason',key='m7_import_reason')
        confirm=st.checkbox('I reviewed schema, identity, quarantines and duplicates; confirm import',key='m7_import_confirm')
        go=st.form_submit_button('Import Validated Scanner Export',disabled=busy,key='m7_import_run')
    if go:
        try:
            r=uploads.import_upload(manager,data['generation'],content=content,name=name,selected=selected,preview_hash=result['upload_hash'],confirmed=confirm,actor=actor,reason=reason)
            st.session_state['receipt']=r;st.session_state['m7_upload_validated']=None;st.rerun()
        except ValueError as exc:st.error(str(exc))

def workspace(manager,data,busy):
    """Compatibility/teaching workspace; primary destinations render one task at a time."""
    st.subheader('Run Assessment · evidence, approvals and verification')
    tabs=st.tabs(['Run Assessment','Analyst Review','Resolver & Verification','Scanner Uploads'],key='assessment_tabs',on_change='rerun')
    with tabs[3]:scanner_upload(manager,data,busy)
    with tabs[0]:
        run_setup(manager,data,busy,show_scenario=True)
        continue_run(manager,data,busy)
    with tabs[1]:review_queue(manager,data,busy)
    with tabs[2]:resolver(manager,data,busy)


def run_options_changed():
    # Options rerender before submission. An old check is never a new grant.
    for key in ('m7_run_confirm','m7_spend_confirm','m7_prerequisites'):
        st.session_state[key]=False


def run_setup(manager,data,busy,show_scenario=False,compact=False):
    app=application();settings=app.settings()
    if not compact:
        with st.expander('Actual usage and remaining M7 campaign budget'):st.json(app.usage())
    if show_scenario:
        with st.form('m7_scenario',enter_to_submit=False):
            confirm=st.checkbox('Load the predefined synthetic agency scanner scenario',key='m7_scenario_confirm')
            actor=st.text_input('Scenario analyst',value='demo-analyst',key='m7_scenario_actor')
            go=st.form_submit_button('Load Synthetic Scenario',key='m7_scenario_load',disabled=busy)
        if go:
            try:commands.command(manager,data['generation'],'fresh_scan',confirmed=confirm,actor=actor,reason='Browser-loaded synthetic scenario',key='m7-scenario-'+str(data['generation']));st.rerun()
            except ValueError as exc:st.error(str(exc))
    candidates={f['component_id']:f for f in data['findings']}
    if candidates:
        if compact:
            st.caption(str(len(data['findings']))+' normalized findings available. Starting requires confirmation; navigation does not execute agents.')
            scope_column,mode_column=st.columns(2)
            primary_scope=scope_column.radio('Run scope',['Full workflow','Selected stages'],key='m7_scope',on_change=run_options_changed,horizontal=True)
            primary_mode=live_ui_policy.mode_radio(mode_column,'Run processing mode',index=0 if settings['mode']=='Replay' else 1,key='m7_run_mode',on_change=run_options_changed,horizontal=True)
            primary_stages=st.multiselect('Selected AI stages',[2,4,3,6,7],default=[2,4,3,6,7],key='m7_stages',on_change=run_options_changed) if primary_scope=='Selected stages' else []
            primary_validation='Normal assessment'
            if primary_mode=='Replay':
                with st.expander('Offline validation options'):
                    primary_validation=st.selectbox('Validation scenario',['Normal assessment','Unsupported research safeguard (Offline Mock)'],key='m7_validation_scenario',on_change=run_options_changed)
        if compact and current_runs(data):
            st.write('**Assess another asset: prepare a distinct run first**')
            st.caption('1. Confirm and prepare below. 2. Choose the next asset/component in the form. 3. Review its mode and any spending limits, then confirm Run Assessment. Earlier runs, approvals and reservations remain retained.')
            again=st.checkbox('Prepare a distinct new run; earlier runs and reservations remain immutable',key='m7_new_run_confirm')
            if st.button('Prepare Another Run',key='m7_new_run',disabled=busy):
                if not again:st.error('Confirm a distinct new run before changing its operation identity')
                else:
                    st.session_state['m7_run_operation']=str(uuid4())
                    st.session_state['m7_new_run_prepared']=True
                    st.session_state['m7_clear_flags']=['m7_run_confirm','m7_spend_confirm','m7_new_run_confirm'];st.rerun()
            if st.session_state.get('m7_new_run_prepared'):st.success('Distinct run prepared. Choose the next asset/component and confirm its assessment below.')
        with st.form('m7_run',enter_to_submit=False):
            ids=sorted(candidates,key=lambda k:(candidates[k]['asset_key']!='LNX-SRV-005',candidates[k]['asset_key']))
            component=st.selectbox('Assessment asset / component',ids,format_func=lambda k:candidates[k]['asset_key']+' / '+candidates[k]['component_key'],key='m7_component')
            scope=primary_scope if compact else st.radio('Run scope',['Full workflow','Selected stages'],key='m7_scope')
            selected=primary_stages if compact else st.multiselect('Selected AI stages',[2,4,3,6,7],default=[2,4,3,6,7],key='m7_stages')
            mode=primary_mode if compact else live_ui_policy.mode_radio(st,'Run processing mode',index=0 if settings['mode']=='Replay' else 1,key='m7_run_mode')
            validation=primary_validation if compact else st.selectbox('Validation scenario',['Normal assessment','Unsupported research safeguard (Offline Mock)'],key='m7_validation_scenario')
            prerequisites=st.checkbox('For selected stages, explicitly use labeled Replay for unselected prerequisite agents',key='m7_prerequisites') if not compact or scope=='Selected stages' else False
            if compact:
                analyst_column,reason_column=st.columns(2)
                actor=analyst_column.text_input('Assessment analyst',value='demo-analyst',key='m7_run_actor')
                reason=reason_column.text_input('Assessment rationale',key='m7_run_reason')
            else:
                actor=st.text_input('Assessment analyst',value='demo-analyst',key='m7_run_actor');reason=st.text_input('Assessment rationale',key='m7_run_reason')
            confirm=st.checkbox('I confirm this exact synthetic assessment run',key='m7_run_confirm')
            spend=live_ui_policy.spend_checkbox(st,'Separately authorize Live AI spending within the saved run limits',key='m7_spend_confirm') if not compact or mode=='Live AI' else False
            go=st.form_submit_button('Run Assessment',disabled=busy,key='m7_run_start')
        if go:
            try:
                stages=[2,4,3,6,7] if scope=='Full workflow' else selected
                if not stages:raise ValueError('Select at least one stage')
                if validation!='Normal assessment' and mode!='Replay':raise ValueError('The negative control is explicitly Offline Mock: select Replay instead of Live AI; no substitution occurs')
                if scope=='Selected stages' and not prerequisites:raise ValueError('Review and explicitly confirm Replay prerequisite dependencies for a selected-stage run')
                if mode=='Live AI':
                    from .runtime_binding import require_live
                    require_live('m7-agent0-authorization')
                    local_security.require_local_operator()
                if mode=='Live AI' and not spend:raise ValueError('Separate live-spending confirmation required before creating a run')
                livekeys=[]
                for i,role in ((2,2),(3,4),(5,3),(9,6),(14,6),(20,7)):
                    if mode=='Live AI' and role in stages:
                        subjects=sorted({f['cve_id'] for f in data['findings'] if f['component_id']==component}) if i in (2,3) else [component] if i==5 else ['pending']
                        livekeys.extend(str(i)+':'+v for v in subjects)
                key=st.session_state.setdefault('m7_run_operation',str(uuid4()))
                state=commands.start_orchestration(manager,data['generation'],component_id=component,confirmed=confirm,actor=actor,reason=reason,
                    operation_key=key,mode='mixed' if mode=='Live AI' else 'replay',live_stage_keys=livekeys,use_imported_scan=True,
                    execution_limit=max({2:3,4:4,3:6,6:15,7:21}[r] for r in stages) if scope=='Selected stages' else None,offline_guard_test=validation!='Normal assessment')
                if mode=='Live AI':
                    # Scope/reply IDs are deterministic but become known later;
                    # authorize role-stage wildcard only for this exact run identity.
                    m7_campaign.authorize(app,manager,state,confirmed=spend,actor=actor,reason=reason,max_attempts=settings['max_attempts'],allowance_micro_usd=settings['allowance_micro_usd'])
                st.session_state['m7_new_run_prepared']=False
                queue_run_selection(state['run_id']);st.session_state['m7_clear_flags']=['m7_run_confirm','m7_spend_confirm'];st.rerun()
            except ValueError as exc:st.error(str(exc))
        if not compact:
            with st.expander('Distinct new run and immutable history'):
                again=st.checkbox('Prepare a distinct new run; earlier runs and reservations remain immutable',key='m7_new_run_confirm')
                if st.button('Prepare Another Run',key='m7_new_run',disabled=busy):
                    if not again:st.error('Confirm a distinct new run before changing its operation identity')
                    else:
                        st.session_state['m7_run_operation']=str(uuid4());st.session_state['m7_clear_flags']=['m7_run_confirm','m7_spend_confirm','m7_new_run_confirm'];st.rerun()

    if not compact or (candidates and primary_mode=='Live AI'):
        if st.button('Refresh Official KEV / EPSS Evidence (no model call)',key='m7_refresh_sources',disabled=busy):
            try:st.json(m7_campaign.refresh_threat(manager,data['generation'],confirmed=True,actor='local-browser-operator'))
            except (ValueError,OSError) as exc:st.error(str(exc))
        if candidates and st.button('Check Live Readiness (no model call or key access)',key='m7_live_readiness',disabled=busy):
            table(m7_campaign.readiness(app,manager,component),['check','status','detail'],height=260)
    if compact:
        with st.expander('Actual usage and remaining M7 campaign budget'):st.json(app.usage())


def queue_run_selection(run_id):
    # ui.main consumes this before any widget is instantiated on the next render.
    # Never overwrite an already-rendered m7_active_run widget on this script run.
    st.session_state['m7_pending_run_id']=run_id


def selected_run_changed():
    st.session_state['wx_active_run']=st.session_state['m7_active_run']


def continue_run(manager,data,busy,show_summary=True):
    app=application()
    from .orchestration_ui import summary

    if show_summary:summary(data)
    states=current_runs(data)
    if states:
        ids=[s['run_id'] for s in states]
        saved=st.session_state.get('wx_active_run')
        if saved in ids:st.session_state['m7_active_run']=saved
        elif st.session_state.get('m7_active_run') not in ids:st.session_state['m7_active_run']=ids[-1]
        rid=st.selectbox('Assessment run',ids,format_func=lambda value:next(s['status']+' · '+agent0.STAGES[min(s['cursor'],len(agent0.STAGES)-1)]+' · '+value[:8] for s in states if s['run_id']==value),key='m7_active_run',on_change=selected_run_changed)
        st.session_state['wx_active_run']=rid
        state=next(s for s in states if s['run_id']==rid)
        policy=m7_campaign.run_usage(app,state)
        if policy:st.caption('This run has immutable limits: '+str(policy['max_attempts'])+' attempts / $'+str(policy['allowance_usd'])+
            '; remaining '+str(policy['remaining_attempts'])+' attempts / $'+str(policy['remaining_estimated_allowance_usd'])+'. Settings changes apply to new runs only.')
        with st.form('m7_continue',enter_to_submit=False):
            actor=st.text_input('Continuing analyst',value='demo-analyst',key='m7_continue_actor');reason=st.text_input('Continuation reason',value='Continue reviewed synthetic assessment',key='m7_continue_reason')
            confirm=st.checkbox('Continue until the next review, failure or verification gate',key='m7_continue_confirm')
            recover=st.checkbox('Recover an interrupted stage without retrying a provider request',key='m7_recover')
            go=st.form_submit_button('Continue Assessment',disabled=busy or state['status']=='Completed' or state['cursor']>=state['manifest'].get('execution_limit',25),key='m7_continue')
        if go:
            try:
                if not confirm:raise ValueError('Explicit continuation confirmation required')
                with st.status('Agent 0 is coordinating the next stage',expanded=True) as progress:
                    from .workflow_ui import process_graph
                    process_display=st.empty()
                    for _ in range(25):
                        process_display.graphviz_chart(process_graph(state,executing=True),width='content')
                        st.write(agent0.STAGES[state['cursor']])
                        adapters={k:dict(application=app) for k in state['manifest']['live_stage_keys']}
                        offline={}
                        if state['manifest'].get('offline_guard_test'):
                            from .assessment_actions import unsupported_adapter
                            offline={str(2)+':'+f['cve_id']:unsupported_adapter(state) for f in data['findings'] if f['component_id']==state['manifest']['component_id']}
                        state=commands.advance_orchestration(manager,data['generation'],run_id=rid,state_hash=state['state_hash'],confirmed=True,actor=actor,reason=reason,recover=recover,live_adapters=adapters,offline_adapters=offline)
                        process_display.graphviz_chart(process_graph(state),width='content')
                        if state['status']!='Ready':break
                        if state['cursor']>=state['manifest'].get('execution_limit',25):
                            state=commands.advance_orchestration(manager,data['generation'],run_id=rid,state_hash=state['state_hash'],confirmed=True,actor=actor,reason=reason,live_adapters=adapters);break
                    progress.update(label='Assessment '+state['status'],state='complete' if state['status']=='Completed' else 'error' if state['status']=='Failed' else 'complete')
                st.session_state['m7_clear_flags']=['m7_continue_confirm'];st.rerun()
            except ValueError as exc:st.error(str(exc))

def review_queue(manager,data,busy,compact=False):
    st.subheader('Analyst Review · separate research and operational decisions')
    states=current_runs(data)
    if not states:st.info('Start an assessment to populate the review queue.');return
    options={}
    for state in states:
        for name in ('agent2','agent4','agent3','report','mail','agent7'):
            values=state['refs'].get(name,[])
            for p in values if isinstance(values,list) else [values]:
                decisions=[a for a in data['audit_events'] if a['entity_id']==p['run_id'] and a['event_type'].endswith('ReviewRecorded')]
                if not decisions:options[name+' / '+p.get('cve_id','')+' / '+p['run_id'][:8]]=(name,p)
    if options:
        label=st.selectbox('Research awaiting review',list(options),key='m7_research_selected');name,p=options[label]
        origin={'human_curated_source_backed_replay':'Replay (curated sources)','offline_mock':'Offline Mock','live_model':'Live AI'}.get(p['execution']['origin'],p['execution']['origin'])
        st.caption('Actual mode: '+origin+' · exact proposal revision '+p['proposal_hash'][:12])
        if p['result']:
            if compact:
                from .workflow_ui import research_content
                research_content(p)
            else:st.json(p.get('rendered') or p['result'])
            table(p['sources'],['url','retrieved_at'],height=180)
            with st.expander('Exact evidence, input, assumptions and validation'):st.json(p)
            if st.session_state.get('m7_review_binding')!=p['proposal_hash']:
                st.session_state['m7_review_confirm']=False;st.session_state['m7_review_binding']=p['proposal_hash']
            with st.form('m7_research_decide',enter_to_submit=False):
                actor=st.text_input('Reviewing analyst',value='demo-analyst',key='m7_review_actor');reason=st.text_input('Research decision rationale',key='m7_review_reason')
                decision=st.radio('Research decision',['Rejected','Accepted for analyst use'],key='m7_review_decision')
                confirm=st.checkbox('I reviewed exact evidence meaning, assumptions, freshness and this proposal revision',key='m7_review_confirm')
                go=st.form_submit_button('Record Research Decision',disabled=busy,key='m7_review_run')
            if go:
                try:commands.review_orchestration_research(manager,data['generation'],agent=name,run_id=p['run_id'],proposal_hash=p['proposal_hash'],decision=decision,confirmed=confirm,actor=actor,reason=reason);st.rerun()
                except ValueError as exc:st.error(str(exc))
        else:st.error('Quarantined research cannot be accepted: '+str(p['error']))
    state=next((s for s in states if s['run_id']==st.session_state.get('m7_active_run')),states[-1]);i=state['cursor'];refs=state['refs']
    if i==7:
        groups=refs.get('agent3',{}).get('result',{}).get('batches',[])
        if groups:
            group=groups[0];bid=next((b['id'] for b in data['remediation_batches'] if b['action_id']==group['action_id'] and set(group['finding_ids'])=={m['asset_cve_id'] for m in data['batch_proposal_members'] if m['batch_id']==b['id']}),None)
            if bid:
                st.warning('Batch approval is separate from research acceptance. Inventory applicability is synthetic/unverified; historical release guidance is not a current deployment target.')
                review=next((r for r in data['lifecycle_reviews'] if r['target_id']==bid and r['status']=='Awaiting Approval'),None)
                if not review:
                    if st.button('Prepare Exact Batch Review',key='m7_prepare_batch',disabled=busy):
                        commands.command(manager,data['generation'],'batch_review',target=bid,confirmed=True,actor='local-browser-operator',reason='Prepare exact revision for independent human decision');st.rerun()
                else:
                    with st.expander('Exact batch membership, evidence and applicability'):
                        st.json(json.loads(review['payload_json']))
                    operational_decision(manager,data,busy,'decide_review',review['id'],review['payload_hash'],'Batch',compact=compact)
    if i in (12,17):
        p=refs.get('ticket_proposal' if i==12 else 'communication_proposal')
        if p:operational_decision(manager,data,busy,'decide_proposal',p['proposal_id'],p['payload_hash'],'Ticket' if i==12 else 'Communication',compact=compact)
    risks=[r for r in data['lifecycle_reviews'] if r['kind']=='Risk' and r['status']=='Awaiting Approval']
    if risks:
        st.warning('A resolver risk request is not accepted risk. Review the exact bounded expiry separately; it never establishes remediation.')
        selected=st.selectbox('Pending risk exception review',[r['id'] for r in risks],key='m7_risk_review')
        risk=next(r for r in risks if r['id']==selected);st.json(json.loads(risk['payload_json']))
        operational_decision(manager,data,busy,'decide_review',risk['id'],risk['payload_hash'],'Risk exception',prefix='m7_risk',compact=compact)

def operational_decision(manager,data,busy,action,target,hash_,kind,prefix='m7_approve',compact=False):
    st.write('**Separate '+kind+' approval · exact revision '+hash_[:12]+'**')
    p=next((p for p in data['proposals'] if p['id']==target),None)
    if p:
        payload=json.loads(p['payload_json'])
        if compact:
            rendered=payload.get('rendered',{})
            content=rendered.get('email_body') if kind=='Communication' else rendered.get('ticket_description')
            if content:st.text(content)
            with st.expander('Exact proposal, full evidence and revision hash'):st.json(payload);st.code(hash_,language=None)
        else:st.json(payload)
    if st.session_state.get(prefix+'_binding')!=hash_:
        st.session_state[prefix+'_confirm']=False;st.session_state[prefix+'_binding']=hash_
    with st.form(prefix+'_form',enter_to_submit=False):
        actor=st.text_input('Approving analyst',value='demo-analyst',key=prefix+'_actor');reason=st.text_input('Operational decision rationale',key=prefix+'_reason')
        decision=st.radio('Operational decision',['Rejected','Approved'],key=prefix+'_decision')
        confirm=st.checkbox('I reviewed and authorize only this exact '+kind+' revision',key=prefix+'_confirm')
        go=st.form_submit_button('Record '+kind+' Decision',disabled=busy,key=prefix+'_run')
    if go:
        try:commands.command(manager,data['generation'],action,target=target,payload_hash=hash_,decision=decision,confirmed=confirm,actor=actor,reason=reason);st.rerun()
        except ValueError as exc:st.error(str(exc))

def resolver(manager,data,busy,part=None):
    states=current_runs(data)
    if not states:st.info('Start and review an assessment before resolver processing.');return
    state=next((s for s in states if s['run_id']==st.session_state.get('m7_active_run')),states[-1]);refs=state['refs'];ticket=refs.get('ticket_id')
    if not ticket:st.info('An approved synthetic ticket is required.');return
    table([t for t in data['tickets'] if t['id']==ticket],['id','status','revision'],height=100,alt='Selected ticket lifecycle and revision')
    if state['cursor']==19 and part in (None,'reply'):
        scope=next(s for s in data['lifecycle_scopes'] if s['id']==refs['scope_id'])
        with st.form('m7_resolver',enter_to_submit=False):
            body=st.text_area('Synthetic resolver reply',key='m7_reply_body')
            scheduled=st.text_input('Optional scheduled time (UTC ISO timestamp)',key='m7_reply_scheduled')
            expiry=st.text_input('Optional requested risk expiry (UTC ISO timestamp)',key='m7_reply_expiry')
            actor=st.text_input('Reply recording analyst',value='demo-analyst',key='m7_reply_actor')
            confirm=st.checkbox('Record this untrusted synthetic reply for the linked ticket only',key='m7_reply_confirm')
            go=st.form_submit_button('Submit Resolver Reply',disabled=busy,key='m7_reply_run')
        if go:
            try:commands.receive_research_reply(manager,data['generation'],ticket_id=ticket,owner_id=scope['resolver_group_id'],communication_id=refs['communication_id'],body=body,
                scheduled_at=scheduled.strip() or None,exception_until=expiry.strip() or None,
                confirmed=confirm,actor=actor,reason='Browser synthetic resolver reply',operation_key='m7-reply-'+state['run_id']);st.rerun()
            except ValueError as exc:st.error(str(exc))
    if state['cursor']==22 and refs.get('agent7') and part in (None,'processing'):
        p=refs['agent7'];st.json(p['result'])
        with st.form('m7_safe_reply',enter_to_submit=False):
            actor=st.text_input('Safe processing analyst',value='demo-analyst',key='m7_safe_actor')
            confirm=st.checkbox('Separately approve safe processing; completion becomes Pending Verification only',key='m7_safe_confirm')
            go=st.form_submit_button('Apply Reviewed Resolver Interpretation',disabled=busy,key='m7_safe_run')
        if go:
            try:commands.apply_reply_research(manager,data['generation'],run_id=p['run_id'],proposal_hash=p['proposal_hash'],confirmed=confirm,actor=actor,reason='Separate browser safe-processing decision',operation_key='m7-safe-'+state['run_id']);st.rerun()
            except ValueError as exc:st.error(str(exc))
    if state['cursor']>=23 and part in (None,'verification'):
        st.warning('Only explicit subsequent independent scanner evidence can verify or reopen findings. Owner claims cannot close a ticket. These controls simulate a scanner, not a real scan.')
        with st.form('m7_followup',enter_to_submit=False):
            outcome=st.radio('Follow-up synthetic scanner outcome',['Pass','Fail'],key='m7_scan_outcome')
            actor=st.text_input('Verification analyst',value='demo-analyst',key='m7_verify_actor')
            confirm=st.checkbox('Confirm a subsequent independent synthetic scanner assessment',key='m7_verify_confirm')
            go=st.form_submit_button('Record Follow-up Scanner Result',disabled=busy,key='m7_verify_run')
        if go:
            try:
                nonce=st.session_state.setdefault('m7_scan_operation',str(uuid4()))
                commands.followup_scan(manager,data['generation'],ticket_id=ticket,outcome=outcome,operation_key='m7-'+nonce+'-'+outcome,
                    confirmed=confirm,actor=actor,reason='Explicit independent synthetic scanner result')
                st.session_state['m7_clear_flags']=['m7_verify_confirm'];st.rerun()
            except ValueError as exc:st.error(str(exc))
        if st.button('Prepare Another Scanner Observation',disabled=busy,key='m7_scan_new'):
            st.session_state['m7_scan_operation']=str(uuid4());st.session_state['m7_clear_flags']=['m7_verify_confirm'];st.rerun()
    if state['cursor']>19 and part in (None,'reply'):
        with st.expander('Clarify or submit another resolver response'):
            st.caption('A new response creates a separate interpretation cycle linked to the same approved ticket and source evidence. Earlier outputs and attempts remain immutable; upstream agents are not rerun.')
            with st.form('m7_clarification',enter_to_submit=False):
                body=st.text_area('New untrusted resolver response',key='m7_clarify_body')
                scheduled=st.text_input('New optional schedule (UTC ISO)',key='m7_clarify_scheduled');expiry=st.text_input('New optional risk expiry (UTC ISO)',key='m7_clarify_expiry')
                mode=live_ui_policy.mode_radio(st,'New interpretation processing mode',key='m7_clarify_mode')
                actor=st.text_input('Clarification analyst',value='demo-analyst',key='m7_clarify_actor')
                confirm=st.checkbox('Record this new untrusted response and start a separate interpretation proposal',key='m7_clarify_confirm')
                spend=live_ui_policy.spend_checkbox(st,'Separately authorize one Live AI interpretation with $0.10 estimated allowance',key='m7_clarify_spend')
                go=st.form_submit_button('Start New Resolver Interpretation',disabled=busy,key='m7_clarify_run')
            if go:
                try:
                    if not confirm:raise ValueError('Explicit new reply-cycle confirmation required')
                    if mode=='Live AI':
                        local_security.require_local_operator()
                        if not spend:raise ValueError('Separate live-spending confirmation required')
                    scope=next(s for s in data['lifecycle_scopes'] if s['id']==refs['scope_id'])
                    nonce=st.session_state.setdefault('m7_clarify_operation',str(uuid4()))
                    reply=commands.receive_research_reply(manager,data['generation'],ticket_id=ticket,owner_id=scope['resolver_group_id'],communication_id=refs['communication_id'],body=body,
                        scheduled_at=scheduled.strip() or None,exception_until=expiry.strip() or None,confirmed=True,actor=actor,reason='New untrusted resolver response',operation_key='m7-new-reply-'+nonce)
                    child=commands.start_reply_cycle(manager,data['generation'],parent_run_id=state['run_id'],parent_hash=state['state_hash'],reply_id=reply['reply_id'],
                        mode='mixed' if mode=='Live AI' else 'replay',confirmed=True,actor=actor,reason='Separate resolver interpretation cycle',operation_key='m7-cycle-'+nonce)
                    if mode=='Live AI':m7_campaign.authorize(application(),manager,child,confirmed=True,actor=actor,reason='One separately authorized resolver interpretation',max_attempts=1,allowance_micro_usd=100000)
                    st.session_state['m7_pending_run_id']=child['run_id'];st.session_state.pop('m7_clarify_operation',None)
                    st.session_state['m7_clear_flags']=['m7_clarify_confirm','m7_clarify_spend'];st.rerun()
                except ValueError as exc:st.error(str(exc))
