"""Persisted, fail-closed coordinator. Stages delegate; rendering never executes.

Replay is the default. Explicit live stages require both an immutable cumulative
grant and the existing agent-specific campaign; old authorizations never transfer.
"""
import json
import hashlib
from sqlalchemy import select
from .database import make_engine,tables
from .services import stable,digest,canonical,utc,audit,row
from .live_contracts import redact
from .workflow_control import WorkflowStopRequested
from .dashboard_service import view,command
from . import agent3,agent4,agent6,agent7,research_replay
from . import batching_evidence,threat_evidence,drafting_evidence,reply_evidence
from .dashboard_queries import revision_token
from .lifecycle import create_scope,_snapshot,_match,require_batch_approval
from .enrichment_evidence import timestamp

STAGES=('Scanner intake','Official evidence replay','Agent 2 remediation research','Agent 4 threat research',
    'Research acceptance gate','Agent 3 batching research','Batch research acceptance gate','Exact batch approval gate',
    'Agent 5 escalation lookup','Agent 6 ticket report','Report research acceptance gate','Stage ticket draft',
    'Ticket approval gate','Execute synthetic ticket','Agent 6 communication draft','Communication research gate',
    'Stage communication','Communication approval gate','Simulate local delivery','Resolver reply gate',
    'Agent 7 interpretation','Reply research gate','Safe reply processing gate','Scanner verification gate','Final outcome')
VERSION='m6f-agent0-v1'

def stored(data):
    latest={}
    for s in data['agent_steps']:
        if s['role_number']==0 and s['step_key']=='orchestration-state':
            p=json.loads(s['output_json'])
            if s['run_id'] not in latest or p['revision']>latest[s['run_id']]['revision']:latest[s['run_id']]=p
    return list(latest.values())

def _load(data,run_id):
    rows=sorted((s for s in data['agent_steps'] if s['role_number']==0 and s['run_id']==run_id and s['step_key']=='orchestration-state'),key=lambda s:s['attempt'])
    prev=None
    receipts={a['revision']:json.loads(a['payload_json']) for a in data['audit_events']
        if a['entity_id']==run_id and a['event_type']=='OrchestrationCheckpoint'}
    for step in rows:
        p=json.loads(step['output_json'])
        if p['previous_hash']!=prev or digest({k:v for k,v in p.items() if k!='state_hash'})!=p['state_hash']:
            raise ValueError('Orchestration history integrity failure')
        if receipts.get(p['revision'],{}).get('state_hash')!=p['state_hash']:
            raise ValueError('Orchestration checkpoint differs from immutable audit history')
        prev=p['state_hash']
    if not rows:raise ValueError('Orchestration not found in this workspace')
    if p['identity']!=data['workspace_identity'] or p['generation']!=data['generation']:
        raise ValueError('Restored/foreign orchestration requires a new run')
    return p

def _save(manager,generation,state,expected):
    with manager.execution(generation,'agent0_checkpoint') as (path,w,clock,receipt):
        engine=make_engine(path)
        try:
            with engine.begin() as c:
                rows=c.execute(select(tables['agent_steps']).where(tables['agent_steps'].c.workspace_id==w['id'],
                    tables['agent_steps'].c.run_id==state['run_id'],tables['agent_steps'].c.step_key=='orchestration-state').order_by(tables['agent_steps'].c.attempt)).mappings().all()
                prior=json.loads(rows[-1]['output_json']) if rows else None
                if (prior['state_hash'] if prior else None)!=expected:raise ValueError('Stale orchestration revision')
                state=dict(state,revision=len(rows)+1,previous_hash=expected,recorded_at=utc())
                state.pop('state_hash',None);state['state_hash']=digest(state)
                status='Succeeded' if state['status']=='Completed' else 'Failed' if state['status']=='Failed' else 'Awaiting Approval'
                if not rows:
                    c.execute(tables['runs'].insert().values(id=state['run_id'],workspace_id=w['id'],scenario_version_id=w['scenario_version_id'],
                        mode='replay',effective_clock=clock,started_at=utc(),status=status,input_hash=digest(state['manifest']),contract_version=VERSION))
                else:c.execute(tables['runs'].update().where(tables['runs'].c.workspace_id==w['id'],tables['runs'].c.id==state['run_id']).values(status=status,ended_at=utc() if state['status']=='Completed' else None))
                c.execute(tables['agent_steps'].insert().values(id=stable(w['id'],state['run_id'],state['revision']),workspace_id=w['id'],run_id=state['run_id'],
                    role_number=0,step_key='orchestration-state',attempt=state['revision'],status=status,model=None,prompt_version=VERSION,
                    input_hash=expected or digest(state['manifest']),output_json=canonical(state)))
                audit(c,w['id'],'OrchestrationCheckpoint','runs',state['run_id'],state['revision'],dict(state_hash=state['state_hash'],stage=STAGES[state['cursor']],status=state['status']))
                receipt.update(run_id=state['run_id'],state_hash=state['state_hash']);return state
        finally:engine.dispose()

def start(manager,generation,*,component_id,confirmed,actor,reason,operation_key,mode='replay',live_stage_keys=None,use_imported_scan=False,execution_limit=None,offline_guard_test=False):
    if not confirmed or not actor.strip() or not reason.strip():raise ValueError('Named confirmed orchestration request required')
    if redact(actor)!=actor or redact(reason)!=reason:raise ValueError('Secret-shaped analyst or rationale refused')
    if mode not in ('replay','mixed') or (mode=='replay' and live_stage_keys):raise ValueError('Live orchestration disabled: separate per-stage and cumulative authorization required before credential access')
    if mode=='mixed' and not live_stage_keys:raise ValueError('Mixed workflow requires an explicit live stage plan; authorization remains separate')
    d=view(manager)
    if generation!=d['generation']:raise ValueError('Stale generation')
    if not any(c['id']==component_id for c in d['asset_components']):raise ValueError('Component not in this workspace')
    rid=stable(d['workspace_id'],VERSION,operation_key);manifest=dict(component_id=component_id,mode=mode,actor=actor,reason=reason,live_stage_keys=sorted(live_stage_keys or []))
    if use_imported_scan:manifest['use_imported_scan']=True
    if offline_guard_test:
        if mode!='replay':raise ValueError('Unsupported-research safeguard scenario is explicitly Offline Mock; Live AI cannot be silently substituted')
        manifest['offline_guard_test']=True
    if execution_limit is not None:
        if type(execution_limit) is not int or not 1<=execution_limit<=len(STAGES):raise ValueError('Invalid selected-stage boundary')
        manifest['execution_limit']=execution_limit
    existing=next((s for s in stored(d) if s['run_id']==rid),None)
    if existing:
        p=_load(d,rid)
        if p['manifest']!=manifest:raise ValueError('Operation identity reused with different inputs')
        return p
    return _save(manager,generation,dict(run_id=rid,manifest=manifest,identity=d['workspace_identity'],generation=generation,
        cursor=0,status='Ready',reason='',refs={},history=[],revision=0,provider_attempts=0,reserved_usd=0),None)

def _accepted(d,p,event):
    if not p.get('result') or p.get('error') or p['generation']!=d['generation'] or p['workspace_identity']!=d['workspace_identity']:
        raise ValueError('Rejected, quarantined or foreign upstream research')
    if digest({k:v for k,v in p.items() if k!='proposal_hash'})!=p['proposal_hash']:raise ValueError('Research hash failed')
    for source in p['sources']:
        if source['url'].startswith('synthetic-reply:'):continue
        current=next((s for s in d['sources'] if s['id']==source['id']),None)
        if not current or current['content_hash']!=source['content_hash']:raise ValueError('Upstream evidence changed')
        capture=json.loads(current['snapshot_json']) if current['snapshot_json'] else {}
        if current['content_hash'] is not None and 'body' in capture and hashlib.sha256(capture['body'].encode()).hexdigest()!=current['content_hash']:
            raise ValueError('Upstream captured evidence hash failed')
    if event=='Agent2ReplayResearch' and (p.get('execution',{}).get('origin')=='live_model' or p.get('contract_version','').startswith('m7-agent2')):event='LiveResearch'
    decisions=[json.loads(a['payload_json']) for a in d['audit_events'] if a['entity_id']==p['run_id'] and a['event_type']==event+'ReviewRecorded']
    if not any(x['proposal_hash']==p['proposal_hash'] and x['decision']=='Accepted for analyst use' for x in decisions):
        raise ValueError('Exact upstream research requires explicit analyst acceptance; research is not operational approval')

def _db(manager,generation,stage,fn):
    with manager.execution(generation,stage) as (path,w,clock,receipt):
        e=make_engine(path)
        try:
            with e.begin() as c:return fn(c,w,clock)
        finally:e.dispose()

def _upstream_gate(data,component_id):
    """Every structured research record that batching can consume needs review.

    Legacy curated source facts are labeled replay and separately inspected by
    the exact batch approval gate. Failed/quarantined outputs are never inputs.
    """
    cves={f['cve_id'] for f in data['findings'] if f['component_id']==component_id}
    for step in data['agent_steps']:
        if step['role_number'] not in (2,4) or not step['output_json']:continue
        p=json.loads(step['output_json'])
        if p.get('result') and p.get('cve_id') in cves:
            _accepted(data,p,'Agent2ReplayResearch' if step['role_number']==2 else 'Agent4Research')

def advance(manager,generation,*,run_id,state_hash,confirmed,actor,reason,recover=False,live_adapters=None,offline_adapters=None):
    if not confirmed or not actor.strip() or not reason.strip():raise ValueError('Explicit named advance required')
    d=view(manager);s=_load(d,run_id)
    if s['state_hash']!=state_hash:raise ValueError('Stale orchestration revision; refresh')
    from .workflow_control import stopped
    if stopped(d,run_id,manager=manager):raise ValueError('Workflow stop requested; explicitly Start to resume at the retained boundary')
    if s['status']=='Completed':return s
    if s['cursor']>=s['manifest'].get('execution_limit',len(STAGES)):
        s.update(status='Partial',reason='Selected-stage boundary reached. Downstream stages were not executed; outstanding research decisions remain separate.')
        return _save(manager,generation,s,s['state_hash'])
    if s['status']=='In flight' and not recover:raise ValueError('Interrupted stage requires explicit recovery; no automatic execution')
    index=s['cursor'];name=STAGES[index]
    # Persist the original operation/token across interruption and recovery.
    if s['status']!='In flight':
        s['pending']=dict(actor=actor,reason=reason,token=None,key='flow-'+run_id[:20]+'-'+str(index))
        s['status']='In flight';s=_save(manager,generation,s,state_hash)
    q=s['pending'];refs=s['refs'];key=q['key'];common=dict(confirmed=True,actor=q['actor'],reason=q['reason'],operation_key=key)
    def cmd(action,**kw):return command(manager,generation,action,confirmed=True,actor=q['actor'],reason=q['reason'],key=key,**kw)
    def invoke(module,subject,kwargs):
        if stopped(d,run_id,manager=manager):raise WorkflowStopRequested('Stop requested before the next request; explicitly Start to resume retained partial work')
        stage_key=str(index)+':'+str(next(iter(subject.values())))
        if stage_key in (offline_adapters or {}):
            adapter=offline_adapters[stage_key]
            if not s['manifest'].get('offline_guard_test') or adapter['gateway'].origin!='offline_mock':raise ValueError('Offline mock injection requires explicit safeguard-test intent')
            from . import live_research
            return live_research.run(manager,generation,cve=next(iter(subject.values())),**kwargs,config=adapter['config'],gateway=adapter['gateway'],spec=module.Spec())
        if stage_key not in s['manifest'].get('live_stage_keys',[]) and str(index)+':pending' in s['manifest'].get('live_stage_keys',[]):
            stage_key=str(index)+':pending'
        if stage_key in s['manifest'].get('live_stage_keys',[]):
            from .orchestration_budget import execute
            adapter=(live_adapters or {}).get(stage_key)
            if adapter is None:raise ValueError('Authorized live adapter unavailable; no credential or provider request')
            if 'application' in adapter:
                from .m7_campaign import execute as m7_execute
                return m7_execute(adapter['application'],manager,generation,state=s,stage_key=stage_key,role=module.Spec.role,
                    request=dict(kwargs,cve=next(iter(subject.values()))))
            return execute(manager,generation,run_id=run_id,stage_key=stage_key,role=module.Spec.role,
                config=adapter['config'],gateway=adapter['gateway'],request=dict(subject,**kwargs))
        return module.run(manager,generation,**subject,**kwargs)
    def research(module,subject,token):
        # Stable operation keys make interrupted replay recoverable without new requests.
        if q['token'] is None:
            q['token']=token;s.update(pending=q);saved=_save(manager,generation,s,s['state_hash']);s.update(saved)
        return invoke(module,subject,dict(common,reviewed_token=q['token']))
    try:
        if index==0:
            if s['manifest'].get('use_imported_scan'):
                if not any(f['component_id']==s['manifest']['component_id'] for f in d['findings']):raise ValueError('Upload and confirm scanner findings for the selected component first')
                out=dict(mode='Existing confirmed scanner imports',batch_ids=[b['id'] for b in d['ingestion_batches']])
            else:out=cmd('fresh_scan')
        elif index==1:out=cmd('evidence_replay')
        elif index in (2,3):
            cves=sorted({f['cve_id'] for f in d['findings'] if f['component_id']==s['manifest']['component_id']})
            if not cves:raise ValueError('Selected component has no findings')
            if index==3:agent4.load_sources(manager,generation,confirmed=True,actor=actor);d=view(manager)
            out=[]
            refs['agent2' if index==2 else 'agent4']=out
            for n,cve in enumerate(cves):
                module=research_replay if index==2 else agent4
                # Each CVE has a distinct stable operation; cached calls retain tokens.
                childkey=key+'-'+str(n);dd=view(manager)
                old=next((json.loads(x['output_json']) for x in dd['agent_steps'] if x['step_key']==module.Spec.result_key and json.loads(x['output_json']).get('cve_id')==cve and x['run_id']==stable(dd['workspace_id'],module.Spec.version,childkey)),None)
                out.append(old or invoke(module,dict(cve=cve),dict(common,operation_key=childkey,reviewed_token=revision_token(dd))))
            refs['agent2' if index==2 else 'agent4']=out
            if any(not p['result'] for p in out):raise ValueError('Research rejected; inspect immutable child execution')
        elif index==4:
            for role,event in (('agent2','Agent2ReplayResearch'),('agent4','Agent4Research')):
                for p in refs[role]:_accepted(d,p,event)
            out=dict(gate='Research accepted separately; no batch authorization')
        elif index==5:
            for role,event in (('agent2','Agent2ReplayResearch'),('agent4','Agent4Research')):
                for p in refs[role]:_accepted(d,p,event)
            _upstream_gate(d,s['manifest']['component_id'])
            out=research(agent3,dict(component_id=s['manifest']['component_id']),batching_evidence.review_token(d));refs['agent3']=out
            if not out['result']:raise ValueError('Batching output rejected')
        elif index==6:_accepted(d,refs['agent3'],'Agent3Research');out=dict(gate='Batch research accepted; operational approval still required')
        elif index==7:
            _accepted(d,refs['agent3'],'Agent3Research')
            groups=refs['agent3']['result']['batches']
            if len(groups)!=1:raise ValueError('Demonstration requires one supported proposed group')
            g=groups[0];members=set(g['finding_ids'])
            bid=next((b['id'] for b in d['remediation_batches'] if b['action_id']==g['action_id'] and members=={m['asset_cve_id'] for m in d['batch_proposal_members'] if m['batch_id']==b['id']}),None)
            if not bid:raise ValueError('No matching deterministic batch proposal')
            def scope(c,w,clock):
                require_batch_approval(c,w['id'],bid,clock)
                return create_scope(c,w['id'],batch_id=bid,now=clock)
            refs['scope_id']=_db(manager,generation,'agent0_approved_scope',scope);out=dict(scope_id=refs['scope_id'],batch_id=bid)
        elif index==8:
            def lookup(c,w,clock):
                snap=_snapshot(c,w['id'],refs['scope_id'],clock);ticket=_match(c,w['id'],row(c,'lifecycle_scopes',w['id'],refs['scope_id']))
                return dict(existing_ticket_id=ticket['id'] if ticket else None,binding_hash=snap['binding_hash'])
            out=_db(manager,generation,'agent5_lookup',lookup)
        elif index in (9,14):
            out=research(agent6,dict(scope_id=refs['scope_id']),drafting_evidence.review_token(d));refs['report' if index==9 else 'mail']=out
            if not out['result']:raise ValueError('Draft rejected')
        elif index in (10,15):_accepted(d,refs['report' if index==10 else 'mail'],'Agent6Research');out=dict(gate='Draft research accepted only')
        elif index in (11,16):
            p=refs['report' if index==11 else 'mail'];_accepted(d,p,'Agent6Research')
            out=agent6.stage(manager,generation,run_id=p['run_id'],proposal_hash=p['proposal_hash'],kind='Ticket' if index==11 else 'Communication',**common)
            if index==11 and out.get('outcome')=='Suppressed':raise ValueError('Existing escalation suppressed; no duplicate ticket/communication created')
            refs['ticket_proposal' if index==11 else 'communication_proposal']=out
        elif index in (12,17):
            p=refs['ticket_proposal' if index==12 else 'communication_proposal'];current=next(x for x in d['proposals'] if x['id']==p['proposal_id'])
            if current['status']!='Approved' or current['payload_hash']!=p['payload_hash']:raise ValueError('Separate exact ticket/communication approval required')
            out=dict(gate='Exact operational approval recorded',proposal_id=p['proposal_id'])
        elif index==13:
            out=cmd('execute_ticket',target=refs['ticket_proposal']['proposal_id']);refs['ticket_id']=out['ticket_id']
        elif index==18:
            out=cmd('simulate_send',target=refs['communication_proposal']['communication_id']);refs['communication_id']=out['communication_id']
        elif index==19:
            replies=[r for r in d['owner_replies'] if r['communication_id']==refs['communication_id']]
            if len(replies)!=1:raise ValueError('One explicitly submitted synthetic resolver reply required')
            refs['reply_id']=replies[0]['id'];out=dict(reply_id=refs['reply_id'])
        elif index==20:out=research(agent7,dict(reply_id=refs['reply_id']),reply_evidence.review_token(d));refs['agent7']=out
        elif index==21:_accepted(d,refs['agent7'],'Agent7Research');out=dict(gate='Interpretation accepted; separate processing confirmation required')
        elif index==22:
            p=refs['agent7'];_accepted(d,p,'Agent7Research')
            applied=[a for a in d['audit_events'] if a['entity_id']==refs['reply_id'] and a['event_type']=='ResolverReplyApplied']
            if not applied:raise ValueError('Separate confirmed Agent 7 safe-processing action required')
            out=dict(gate='Named analyst applied safe interpretation')
        elif index==23:
            ids=set(refs['agent3']['result']['batches'][0]['finding_ids']);findings=[f for f in d['findings'] if f['id'] in ids]
            if not findings or any(f['status'] not in ('Verified Remediated','Open') for f in findings):raise ValueError('Subsequent independent scanner evidence required; owner completion cannot close findings')
            reply=next(r for r in d['owner_replies'] if r['id']==refs['reply_id'])
            for finding in findings:
                expected='Pass' if finding['status']=='Verified Remediated' else 'Fail'
                assessments={a['id']:a for a in d['scan_assessments'] if a['scan_status']=='Success' and timestamp(a['assessed_at'])>timestamp(reply['received_at'])}
                if not any(v['asset_cve_id']==finding['id'] and v['result']==expected and v['assessment_id'] in assessments for v in d['verification_events']):
                    raise ValueError('No subsequent independent scanner verification for every included finding')
            out=dict(outcomes={f['id']:f['status'] for f in findings});refs['verification']=out
        else:out=dict(final=refs['verification'],operational_approval='See exact immutable decision records',real_delivery=False)
        outputs=out if isinstance(out,list) else [out]
        origins=sorted({p['execution']['origin'] for p in outputs if isinstance(p,dict) and 'execution' in p})
        s['history'].append(dict(stage=name,role=(1 if index==0 else 2 if index in (1,2) else 4 if index==3 else 3 if index==5 else 5 if index==8 else 6 if index in (9,14) else 7 if index==20 else 0),
            mode=', '.join(origins) if origins else 'Evidence replay' if index==1 else 'Deterministic automation / human gate',output=out,recorded_at=utc()))
        s.update(cursor=min(index+1,len(STAGES)-1),status='Completed' if index==len(STAGES)-1 else 'Ready',reason='',refs=refs)
    except WorkflowStopRequested as exc:
        s.update(status='Paused',reason=str(exc),refs=refs)
    except (ValueError,RuntimeError) as exc:
        message=str(exc)
        status='Failed' if any(word in message.lower() for word in ('rejected','quarantined','hash failed')) else 'Blocked' if 'unavailable' in message.lower() else 'Partial' if index==23 else 'Review required'
        s.update(status=status,reason=message,refs=refs)
    children={}
    for name in ('agent2','agent4','agent3','report','mail','agent7'):
        value=refs.get(name,[])
        for p in value if isinstance(value,list) else [value]:
            if isinstance(p,dict) and 'execution' in p:children[p['run_id']]=p['execution']
    inherited=set(s['manifest'].get('inherited_child_ids',[]))
    s['provider_attempts']=sum(p['provider_attempts'] for rid,p in children.items() if rid not in inherited)
    s['recorded_usage']={rid:p.get('usage') for rid,p in children.items() if rid not in inherited}
    with manager._control() as c:
        from .orchestration_budget import _events
        reservations=_events(c,run_id,'Agent0ProviderReserved')
        session_reservations=[json.loads(r['payload']) for r in c.execute("SELECT payload FROM events WHERE kind='LiveResearchReserved'")]
        s['reserved_usd']=max(sum(r['micro_usd'] for r in reservations)/1000000,
            sum(r['estimated_usd'] for r in session_reservations if r['run_id'] in children and r['run_id'] not in inherited))
    return _save(manager,generation,s,s['state_hash'])
