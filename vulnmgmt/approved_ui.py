"""Approved four-area interface. Mutations use existing scoped services."""
from html import escape
import json
from uuid import uuid4
from pathlib import Path
import streamlit as st
from .application import Application
from .runtime_binding import runtime_configuration
from .demo_manager import DemoManager
from . import dashboard_service as service,assessment_ui as assessment,workflow_ui as workflow,agent0,uploads,resolver_portal,two_resolver_demo
from .approved_metrics import severity_models,retained_timing,retained_measures,agent_performance
from . import workflow_control
from . import approved_execution
from .services import digest
from .approved_upload_feedback import upload_scope,uploader_key,quarantine_rows,receipt_summary
from .ui_components import table

AREAS=('Data Ingestion','Agent Workflow','Vulnerability Dashboard','Resolver Ticketing')
CSS="""<style>
:root{--accent:#38bdf8} .stApp{background:#0b1220;color:#f8fafc} [data-testid=stSidebar]{background:#101b2e;border-right:1px solid #26364d} .block-container{max-width:1600px;padding:4.5rem 2.6rem} h1{font-size:2rem!important;letter-spacing:-.5px} h2{font-size:1.45rem!important} h3{font-size:1.1rem!important} [data-testid=stMetric]{background:#172338;border:1px solid #293c54;border-radius:9px;padding:16px;min-height:126px} [data-testid=stMetricValue]{font-size:1.7rem} [data-testid=stMetricLabel]{color:#b3c4db} [data-testid=stVerticalBlockBorderWrapper]{border-color:#263951} [data-testid=stSidebar] [data-testid=stRadio] label{padding:10px 12px;border-radius:7px;margin:3px 0} [data-testid=stSidebar] label:has(input[type=radio]:checked){background:#153c53;border-left:3px solid #38bdf8} .brand{font-size:25px;font-weight:750}.brand small{font-size:11px;color:#8298b4;letter-spacing:1.3px}.scope{color:#9db0c9;font-size:13px}.network{width:100%;background:#111d30;border:1px solid #263951;border-radius:10px}.running{filter:drop-shadow(0 0 8px #38bdf8)} .timing-note{color:#9db0c9;font-size:12px}.report{background:#111d30;border:1px solid #263951;border-radius:9px;padding:18px;margin:12px 0} @media(max-width:900px){.block-container{padding:1rem}.stColumn{min-width:0!important}} @media(prefers-reduced-motion:reduce){*{animation:none!important}}
</style>"""

def _config():return runtime_configuration()
def _app():return Application(_config()['application_root'])
def _manager(app):
    rows=[r for r in app.assessments() if not r['archived']]
    selected=st.session_state.get('approved_assessment')
    row=next((r for r in rows if r['id']==selected),rows[-1] if rows else None)
    if row:
        st.session_state['approved_assessment']=row['id'];return app.manager(row['id'])
    return DemoManager.open_existing(_config()['legacy_root']) if _config()['mode']=='existing-only' else DemoManager(_config()['legacy_root'])

def _ensure_assessment(app):
    if st.session_state.get('approved_assessment'):return app.manager(st.session_state['approved_assessment'])
    key=st.session_state.setdefault('approved_new_key',str(uuid4()))
    id=app.create('Approved design synthetic assessment',key,confirmed=True)
    st.session_state['approved_assessment']=id;return app.manager(id)

@st.dialog('Wipe current synthetic assessment?')
def wipe_dialog(app,manager,data):
    st.warning('This clears only the selected synthetic assessment by starting a new retained generation. Historical assessments, old generations and spending records are preserved.')
    yes,no=st.columns(2)
    if yes.button('Confirm wipe',type='primary'):
        manager=_ensure_assessment(app);fresh=service.view(manager)
        manager.reset(fresh['generation'],'RESET DEMO')
        for key in list(st.session_state):
            if key.startswith(('m7_','wx_','approved_running','approved_ticket','approved_upload')):del st.session_state[key]
        st.rerun()
    if no.button('Cancel'):st.rerun()

def ingestion(app,manager,data,busy):
    receipt=receipt_summary(manager,data,st.session_state.get('approved_upload_receipt'))
    if receipt is None:st.session_state.pop('approved_upload_receipt',None)
    st.caption('Load synthetic scans, then start the team in Agent Workflow. Vendor export formats remain explicitly validated.')
    files=st.file_uploader('Upload scan files',type=['json','csv'],accept_multiple_files=True,key=uploader_key(manager,data))
    if files:
        if st.button('Upload scan files',type='primary',disabled=busy):
            manager=_ensure_assessment(app);data=service.view(manager)
            from .approved_uploads import prepare_known_set
            prepare_known_set(manager,data,[(f.name,f.getvalue()) for f in files])
            results=[]
            for f in files:
                preview=uploads.preview(manager,data['generation'],f.getvalue(),f.name)
                results.append((f,preview))
            imported=[]
            for f,preview in results:
                imported.append(uploads.import_upload(manager,data['generation'],content=f.getvalue(),name=f.name,selected='Auto detect',preview_hash=preview['upload_hash'],confirmed=True,actor='local-analyst',reason='User confirmed upload of validated synthetic scanner exports'))
            st.session_state['approved_upload_receipt']=dict(scope=upload_scope(manager,data),files=len(results),batch_ids=[r['batch_id'] for r in imported],new_rows=sum(r['new_rows'] for r in imported),repeated=sum(r['repeated'] for r in imported));st.rerun()
    batches=data.get('ingestion_batches',[])
    if batches:table([dict(scanner=b['scanner'],scan=b['native_scan_id'],observations=sum(r['ingestion_batch_id']==b['id'] for r in data['raw_findings']),observed_at=b['observed_at'],ingested_at=b['ingested_at']) for b in batches],['scanner','scan','observations','observed_at','ingested_at'],height=210)
    a,b,c=st.columns(3)
    a.metric('Scanner observations',len(data['raw_findings']));b.metric('Normalized findings',len(data['findings']));c.metric('Quarantined rows',len(data['quarantine']))
    if receipt is not None:
        level,message=receipt
        getattr(st,level)(message)
    issues=quarantine_rows(data)
    if issues:
        st.warning('Quarantined observations are retained for audit and do not create normalized findings.')
        table(issues,['scanner','scan','source_row','code','field','reason'],height=210)
        if any(r['code']=='AssetIdentityUnresolved' for r in issues):
            st.info('Asset identity requires trusted inventory and an explicit scanner-to-asset alias. A hostname match alone is insufficient. For the bundled synthetic demo, upload the complete unchanged four-file set from one version: tenable-a.json, tenable-b.json, defender-a.json and defender-b.json. Partial, renamed, duplicated, mixed-version or altered sets do not prepare demo inventory. Repeating an unchanged export preserves its existing quarantine; it does not retry normalization. To restart this isolated demo, Wipe all Data starts a new retained generation; then select the complete set again. Historical generations remain preserved.')
    st.caption('Uploaded data stays local. Uploading does not run AI, create tickets or send communications.')
    if st.button('Wipe all Data',disabled=busy):wipe_dialog(app,manager,data)

def network(state,executing=False):
    rows=workflow.node_rows(state) if state else []
    byrole={r['role']:r for r in rows}
    nodes=[(0,'Orchestrate',500,65),(1,'Normalize scans',100,220),(2,'Research remediation',300,220),(4,'Threat context',500,220),(3,'Group shared fixes',700,220),(5,'Prevent duplicates',900,220),(6,'Draft enriched ticket',100,405),(7,'Interpret resolver',300,405),(9,'Verify scan outcome',500,405),(8,'Update dashboard',700,405)]
    colors={'Complete':'#2dd4bf','Needs analyst review':'#fbbf24','Succeeded':'#2dd4bf','Completed':'#2dd4bf','Running':'#38bdf8','Ready':'#adc4df','Review required':'#fbbf24','Failed':'#f87171','Blocked':'#fb923c'}
    paths=['M100 220H900','M900 220V325H100V405','M100 405H700','M500 105V145H100V180','M500 145H900V180']
    svg='<svg class="network" role="img" aria-label="Recorded agent handoffs and states" font-family="Arial,sans-serif" viewBox="0 0 1000 515" xmlns="http://www.w3.org/2000/svg"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="#627c9b"/></marker></defs>'
    for path in paths:svg+='<path d="'+path+'" fill="none" stroke="#627c9b" stroke-width="2" marker-end="url(#arrow)"/>'
    icons={0:'M12 0L16 8L24 12L16 16L12 24L8 16L0 12L8 8Z',1:'M2 2H22L15 11V21L9 24V11Z',2:'M16 16L24 24M18 9A9 9 0 1 1 0 9A9 9 0 1 1 18 9',4:'M12 0L23 5V13Q21 21 12 25Q3 21 1 13V5ZM12 6V15M12 19V21',3:'M4 4L12 20L22 4M4 4H5M12 20H13M22 4H23',5:'M2 3H17V19H2ZM8 8H23V24H8ZM12 14L15 18L21 11',6:'M3 0H16L23 7V25H3ZM16 0V7H23M7 12H18M7 17H18M7 22H15',7:'M1 2H23V18H10L4 24V18H1ZM5 7H19M5 12H15',9:'M3 12L10 20L23 3',8:'M2 23V13H7V23ZM10 23V3H15V23ZM18 23V8H23V23Z'}
    for role,label,x,y in nodes:
        row=byrole.get(role,{})
        status=row.get('status','Not started')
        if role==0:status='Coordinating' if state else 'Not started'
        if role==9:status='Completed' if state and state['status']=='Completed' else 'Awaiting scan' if state and state['cursor']>=23 else 'Not started'
        if role==8:status='Current persisted view'
        active=bool(executing and row and state and state['cursor'] in next((a[2] for a in workflow.AGENTS if a[0]==role),()))
        if active:status='Running'
        color=colors.get(status,'#64748b')
        if active:svg+=f'<circle cx="{x}" cy="{y}" r="43" fill="none" stroke="#38bdf8" stroke-width="3"/>'
        svg+=f'<circle cx="{x}" cy="{y}" r="35" fill="#172f43" stroke="{color}" stroke-width="2"/><text x="{x}" y="{y+8}" text-anchor="middle" fill="{color}" font-size="23"></text><g transform="translate({x-12},{y-12})" stroke="{color}" stroke-width="1.7" fill="none"><path d="{icons[role]}"/></g><text x="{x}" y="{y-48}" text-anchor="middle" fill="#bdcde1" font-size="16">AGENT {role}</text><text x="{x}" y="{y+58}" text-anchor="middle" fill="#f8fafc" font-size="16">{escape(label)}</text><text x="{x}" y="{y+77}" text-anchor="middle" fill="{color}" font-size="14">{escape(status)}</text>'
    return svg+'</svg>'

def workflow_page(app,manager,data,busy):
    states=assessment.current_runs(data);state=workflow.current(data)
    start,stop=st.columns([1,1])
    if start.button('Start',type='primary',disabled=busy or not data['findings']):
        if state and workflow_control.stopped(data,state['run_id'],manager=manager):
            workflow_control.request(manager,data['generation'],run_id=state['run_id'],stop=False,confirmed=True,actor='local-analyst')
            st.session_state['approved_running']=state['status'] in ('Ready','Paused')
            st.rerun()
        if not state or state['status']=='Completed' or state['cursor']==19:
            assigned={s['manifest']['component_id'] for s in states if s['cursor']>=19}
            components=sorted({r['component_id'] for r in data['findings']} - assigned)
            if not components:st.info('All imported components have a retained first pass. Resolver updates enter through Resolver Ticketing.')
            else:
                start_key='approved_start_'+digest([data['workspace_identity'],data['generation'],components[0]])
                state=approved_execution.start(app,manager,components[0],operation_key=st.session_state.setdefault(start_key,str(uuid4())))
                st.session_state['wx_active_run']=state['run_id'];st.session_state['m7_active_run']=state['run_id'];st.session_state['approved_running']=True;st.rerun()
        elif state['status'] in ('Ready','Paused'):
            workflow_control.request(manager,data['generation'],run_id=state['run_id'],stop=False,confirmed=True,actor='local-analyst')
            st.session_state['approved_running']=True;st.rerun()
        else:st.info('Resolve the exact review or failure below before continuing. Nothing was retried.')
    if stop.button('Stop'):
        if state:workflow_control.request(manager,data['generation'],run_id=state['run_id'],stop=True,confirmed=True,actor='local-analyst')
        st.session_state['approved_running']=False;st.info('Stopped at the next stage boundary. An already submitted provider request cannot be cancelled or refunded.')
    running=st.session_state.get('approved_running',False) and not (state and workflow_control.stopped(data,state['run_id'],manager=manager))
    st.image(network(state,executing=running),width="stretch")
    st.caption('Recorded state only. Active treatment is shown while executing the current stage; navigation does not run an agent.')
    if state:
        cols=st.columns(3);cols[0].metric('Provider attempts · current run',state.get('provider_attempts',0));cols[1].metric('Reserved estimate · current run',f"${state.get('reserved_usd',0):.4f}");cols[2].metric('Persisted stages',len(state.get('history',[])))
        st.subheader('Performance · per agent and current run')
        table([{k:('Unavailable' if v is None else v) for k,v in row.items()} for row in agent_performance(state)],height=235)
        st.caption('Validated outputs and failed/quarantined counts use saved envelopes, not a quality claim. Tokens, latency and estimated usage require recorded observations. Linked prior outputs add no current-run requests; estimates are not invoices.')
        if state['reason']:st.info(state['reason'])
        if state['status']=='Review required':
            assessment.review_queue(manager,data,busy,compact=True)
            if state['cursor']==22:assessment.resolver(manager,data,busy,part='processing')
            assessment.continue_run(manager,data,busy,show_summary=False)
        if state['cursor']>=23:workflow.verification(manager,data,busy)
        if running and state['status'] in ('Ready','Paused') and not busy:
            approved_execution.advance(app,manager,run_id=state['run_id'],state_hash=state['state_hash'])
            st.rerun()
        elif running:st.session_state['approved_running']=False
    else:st.info('Upload synthetic scans in Data Ingestion, then Start the team.')

def _number(value,summary):
    return ('N/A' if summary['total']==0 else 'Unavailable') if value is None else f'{value:g} h'

def _samples(summary):
    population=(str(summary['observed'])+' observed' if summary['observation'] else str(summary['completed'])+' completed · '+str(summary['censored'])+' still-open/right-censored')
    return population+' · '+str(summary['missing_start'])+' missing start · '+str(summary['missing_end'])+' missing end · '+str(summary['incompatible'])+' incompatible · '+summary['unit']

def _timing(summary,label):
    a,b=st.columns(2)
    for col,kind in ((a,'mean'),(b,'median')):
        col.metric(kind.title()+' '+label,_number(summary[kind],summary));col.caption(_samples(summary))

def dashboard(data):
    data=retained_timing(data)
    groups=sorted({g for row in data['findings'] for g in row.get('resolver_groups',[])})
    options={'All':None,**{name:name for name in groups}}
    selected=st.selectbox('Resolver group',list(options),key='approved_resolver_group')
    st.caption('All four severity lifecycles share this scope. Cohort: all retained findings in the selected resolver group; ticket statistics count distinct linked tickets within each severity, not additive across severities.')
    for model in severity_models(data,options[selected]):
        st.subheader(model['severity']+' lifecycle')
        for col,(label,key) in zip(st.columns(5),(('All findings','all'),('In remediation','in_remediation'),('Pending scan','pending'),('Scanner verified','verified'),('New / open','new'))):col.metric(label,model[key])
        st.caption(str(model['assets'])+' affected open assets · actual retained records, not illustrative mockup values')
        for left,right in ((('triage','triage time'),('resolution','ticket resolve time')),(('reported','reported-close time'),('verification','verified-remediation time'))):
            a,b=st.columns(2)
            with a:_timing(model[left[0]],left[1])
            with b:_timing(model[right[0]],right[1])
        a,b,c,d=st.columns(4)
        a.metric('Mean open age',_number(model['age']['mean'],model['age']));a.caption(_samples(model['age']))
        b.metric('Median open age',_number(model['age']['median'],model['age']));b.caption(_samples(model['age']))
        c.metric('Beyond-SLA findings',model['overdue']);c.caption('Open findings only; approved deferments excluded')
        d.metric('Open SLA compliance','N/A' if model['sla'] is None else str(model['sla'])+'%');d.caption('Not overdue open / all open findings')
        a,b=st.columns(2)
        with a:_timing(model['overdue_age'],'age beyond SLA')
        with b:_timing(model['dispatch'],'dispatch time')
        st.divider()
    retained=retained_measures(data,options[selected])
    st.subheader('Evidence, deadlines and retained measures')
    for col,(label,key) in zip(st.columns(4),(('Captured KEV · open','kev_open'),('Evidence review findings','review_required'),('Due within seven days','upcoming'),('Unknown open deadlines','unknown_deadlines'))):col.metric(label,retained[key])
    st.caption('Selected-group KEV coverage: '+str(retained['kev_evaluated'])+'/'+str(retained['findings'])+' evaluated; '+str(retained['kev_unknown'])+' Unknown. Captured membership is not proof of an active attack. Evidence review may include verified findings and is not the approval queue.')
    a,b=st.columns(2);a.metric('Assessment approval decisions · global',retained['approval_decisions_global']);b.metric('Duplicate suppression decisions · global',retained['duplicate_suppressions_global'])
    st.caption('Global assessment decisions are explicitly separate from the resolver filter. Source dates, EPSS and targeting/applicability gaps remain inspectable in full ticket reports. Resolver closure never increments scanner-verified findings. Actual-UTC workflow clocks and synthetic-effective scanner/age clocks are labelled and never mixed.')

def tickets(app,manager,data,busy):
    data=retained_timing(data)
    rows=resolver_portal.ticket_rows(data);selected=st.session_state.get('approved_ticket')
    row=next((r for r in rows if r['ticket']['id']==selected),None)
    if row is None:
        st.caption('Open a ticket to read its full saved report and change status in that same view. Local simulation only.')
        if not rows:st.info('No resolver tickets yet. Complete the exact escalation reviews in Agent Workflow.')
        for item in rows:
            report=item['report'] or {};cols=st.columns([2,3,2,1])
            cols[0].write(item['reference']);cols[1].write(report.get('resolver_group',{}).get('name','Unknown'));cols[2].write(item['reported_status']+' / '+item['ticket']['status'])
            if cols[3].button('Open full report',key='approved_open_'+item['ticket']['id']):st.session_state['approved_ticket']=item['ticket']['id'];st.rerun()
        return
    if st.button('× Close report / Back to queue',key='approved_close_top'):st.session_state.pop('approved_ticket',None);st.rerun()
    ticket=row['ticket'];report=row['report'] or {}
    st.subheader(row['reference']+' · Full resolver report')
    st.caption('Exact saved ticket revision '+str(ticket['revision'])+' · '+row['reported_status']+' · '+ticket['status'])
    ids={r['asset_cve_id'] for r in data['ticket_findings'] if r['ticket_id']==ticket['id']}
    findings=[f for f in data['findings'] if f['id'] in ids]
    st.subheader('Retained event timestamps')
    discovered=sorted(f['discovered_at'] for f in findings if f.get('discovered_at'))
    verified=[f.get('scanner_verified_at') for f in findings]
    dates=[('Discovered',discovered[0] if discovered else None,'synthetic-effective scanner first-seen; earliest assigned finding'),('Created NEW',ticket.get('created_new_at'),'actual-UTC creation audit'),('Explicitly RESOLVED',ticket.get('resolved_at'),'actual-UTC explicit Resolved event only'),('Dispatched',ticket.get('dispatched_at'),'actual-UTC simulated delivery audit'),('Resolver reported Closed',ticket.get('closed_reported_at'),'actual-UTC literal Closed report'),('All findings scanner verified',max(verified) if verified and all(verified) else None,'synthetic-effective subsequent scanner assessment; all assigned findings required')]
    for start in (0,3):
        for col,(label,value,basis) in zip(st.columns(3),dates[start:start+3]):
            col.write('**'+label+'**');col.write(value or 'Not recorded');col.caption(basis)
    table(findings,['asset_key','cve_id','severity','status','kev_state','epss','epss_as_of','applicability'])
    if report:
        from .ui import guidance_context
        from .soc_queries import guidance_body
        with st.container(border=True):
            st.subheader('Remediation guidance and shared basis');guidance_context(report);st.write(guidance_body(report));workflow.approved_fact_panel(report)
    cves={f['cve_id'] for f in findings}
    with st.container(border=True):
        st.subheader('Threat intelligence and evidence')
        table([r for r in data['threat_intel'] if r['cve_id'] in cves],['cve_id','kind','as_of','expires_at','kev_member','epss_score','assessment'])
        st.caption('Captured KEV, dated EPSS, applicability and targeting remain separate facts. Missing evidence is Unknown; source dates and limitations are retained.')
    st.subheader('Status history and original resolver notes')
    table([v for v in data['ticket_versions'] if v['ticket_id']==ticket['id']],['ticket_revision','event_type','created_at','reason'])
    table(resolver_portal.ticket_replies(data,ticket['id']),['received_at','owner_id','raw_body'])
    parents=[s for s in assessment.current_runs(data) if s['refs'].get('ticket_id')==ticket['id'] and s['refs'].get('communication_id')]
    if parents and ticket['status']!='Closed':
        with st.form('approved_status_form'):
            status=st.selectbox('Ticket status',resolver_portal.STATUSES)
            st.caption('Resolved or Closed asserts completion for the entire assigned ticket. This supplies no fix evidence or scanner proof; agent interpretation, analyst review and independent scanning remain required.')
            update=st.form_submit_button('Update status',disabled=busy,type='primary')
        if update:
            parent=parents[-1]
            from .resolver_status_claim import submission_binding
            submission_key='approved_resolver_submission_'+digest([data['workspace_identity'],data['generation'],ticket['id']])
            request=submission_binding(data,ticket,status,parent,st.session_state.get(submission_key))
            st.session_state[submission_key]=request
            receipt=approved_execution.submit_status(app,manager,parent_run_id=request['parent_run_id'],parent_hash=request['parent_hash'],ticket_id=ticket['id'],status=status,operation_key=request['operation_key'])
            st.session_state['wx_active_run']=receipt['run_id'];st.session_state['m7_active_run']=receipt['run_id'];st.success('Status event retained. Start Agent Workflow to interpret it; exact review and independent scanner verification remain separate.')
    elif ticket['status']=='Closed':st.success('Scanner verified. The saved resolver report and its history remain retained.')
    else:st.info('Complete the exact local handoff approval before saving resolver updates.')
    if st.button('× Close report / Back to queue',key='approved_close_bottom'):st.session_state.pop('approved_ticket',None);st.rerun()
    st.caption('Close report dismisses only this view. Update status records a resolver event; it never directly verifies a finding.')

def main():
    st.set_page_config(page_title='AgencySec | Vulnerability Operations',layout='wide')
    st.html(CSS)
    st.markdown('<div class="brand">◇ AgencySec <small>VULNERABILITY OPERATIONS</small></div>',unsafe_allow_html=True)
    config=_config();app=_app();manager=_manager(app);data=service.view(manager);history=manager.history()
    identity=(data['workspace_identity'],data['generation'])
    if st.session_state.get('approved_identity')!=identity:
        for key in ('approved_ticket','approved_running','wx_active_run','m7_active_run'):st.session_state.pop(key,None)
        st.session_state['approved_identity']=identity
    if st.session_state.get('m7_pending_run_id'):
        rid=st.session_state.pop('m7_pending_run_id');st.session_state['wx_active_run']=rid;st.session_state['m7_active_run']=rid
    busy=any(r['status']=='Running' for r in history['leases'])
    pending=st.session_state.pop('next_page',None)
    mapping={'Scenario':'Data Ingestion','Scan files':'Data Ingestion','AI workflow':'Agent Workflow','Dashboard':'Vulnerability Dashboard','Resolver tickets':'Resolver Ticketing','Verification':'Agent Workflow','Escalation Center':'Agent Workflow'}
    if pending in mapping:st.session_state['approved_area']=mapping[pending]
    st.sidebar.markdown('### ◇ AgencySec')
    area=st.sidebar.radio('Workspace',AREAS,label_visibility='collapsed',key='approved_area')
    st.title(area)
    st.caption('Synthetic local assessment · generation '+str(data['generation'])+' · effective clock '+data['as_of']+' · '+('Replay only' if config['mode']=='existing-only' and not config['live_enabled'] else 'Inspect persisted processing mode'))
    try:
        if area=='Data Ingestion':ingestion(app,manager,data,busy)
        elif area=='Agent Workflow':workflow_page(app,manager,data,busy)
        elif area=='Vulnerability Dashboard':dashboard(data)
        else:tickets(app,manager,data,busy)
    except (ValueError,KeyError) as exc:st.error('Action needs review: '+str(exc))
