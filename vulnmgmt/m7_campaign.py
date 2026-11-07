"""Separately authorized M7 SDK stages; old campaign ledgers are never opened."""
from dataclasses import replace
import json
from hashlib import sha256
from datetime import timedelta
from uuid import uuid4
from sqlalchemy import select
from . import agent3,agent4,agent6,agent7,live_research,live_evidence,threat_evidence
from .agent2_sdk import SDKAgent2,INSTRUCTIONS
from .live_contracts import LiveConfig,Agent2Result,LiveResearchError
from . import m7_budget
from .services import canonical,digest,stable,utc
from .database import make_engine,tables
from .dashboard_service import view
from .application import MODEL
from .enrichment_evidence import timestamp

RESERVATION=75432

class Agent2Spec:
    role=2;version='m7-agent2-v1';mode='live';result_key='agent2-research-result';events='LiveResearch'
    instructions=INSTRUCTIONS;output_type=Agent2Result;record_input=True;record_candidate=True
    context=staticmethod(live_evidence.context);validate=staticmethod(live_evidence.validate);assess=staticmethod(live_evidence.assess)

class Agent4Spec(agent4.Spec):
    mode='live';version='m7-agent4-v1';record_input=True;record_candidate=True
    @staticmethod
    def context(data,cve,secret=''):
        latest={}
        for source in data['sources']:
            capture=json.loads(source['snapshot_json']) if source['snapshot_json'] else {}
            if capture.get('kind') in ('KEV','EPSS','Sector'):
                old=latest.get(source['url'])
                if not old or source['retrieved_at']>old['retrieved_at']:latest[source['url']]=source
        selected=list(latest.values())
        epss=[s for s in selected if json.loads(s['snapshot_json'])['kind']=='EPSS']
        if epss:
            newest=max(s['retrieved_at'] for s in epss)
            selected=[s for s in selected if json.loads(s['snapshot_json'])['kind']!='EPSS' or s['retrieved_at']==newest]
        supplied=threat_evidence.context(dict(data,sources=selected,as_of=utc()),cve,secret)
        for key in ('kev','epss'):
            if supplied[key]['freshness']!='Fresh' or supplied[key]['state'] in ('Unknown','Not evaluated','Conflicting'):
                raise LiveResearchError('Current official '+key.upper()+' evidence unavailable/stale/conflicting; refresh public sources before a paid request.')
        return supplied

def spec(role):
    if role==2:return Agent2Spec()
    if role==4:return Agent4Spec(mode='live',version='m7-agent4-v1')
    return replace({3:agent3.Spec(),6:agent6.Spec(),7:agent7.Spec()}[role],mode='live',version='m7-agent'+str(role)+'-v1',processing_mode='live')

def configuration(run_id,stage_key):
    return LiveConfig(enabled=True,authorized=True,model=MODEL,session_id='m7-'+digest([run_id,stage_key])[:50],
        max_session_requests=1,budget_usd=.10,input_rate=.75,output_rate=4.5,max_output_tokens=4096,timeout_seconds=60)

def run_usage(app,state):
    with app.campaign_db() as c:
        auth=[json.loads(r[0]) for r in c.execute("SELECT payload FROM events WHERE kind='M7RunAuthorized'")]
        policy=next((a for a in auth if a['run_id']==state['run_id'] and a['identity']==state['identity']),None)
        if not policy:return None
        prefix='m7-'+digest([state['run_id'],state['identity']])[:20]+'-'
        rows=[r for r in m7_budget.state(c,verify_sources=True)['rows'] if r['session'].startswith(prefix)]
    return dict(max_attempts=policy['max_attempts'],allowance_usd=policy['allowance_micro_usd']/1e6,
        remaining_attempts=policy['max_attempts']-len(rows),remaining_estimated_allowance_usd=(policy['allowance_micro_usd']-sum(r['micro_usd'] for r in rows))/1e6)

def authorize(app,manager,state,*,confirmed,actor,reason,max_attempts,allowance_micro_usd):
    from .runtime_binding import require_live,validate_campaign
    require_live('m7-agent0-authorization');validate_campaign(app.campaign_path)
    if not confirmed or not actor.strip() or not reason.strip():raise LiveResearchError('Separate named live spending authorization required')
    from .agent0 import _load
    d=view(manager);current=_load(d,state['run_id'])
    if manager.root.parent!=app.root/'assessments' or manager.root.name not in {r['id'] for r in app.assessments()}:raise LiveResearchError('M7 live authorization requires a registered new application assessment')
    if current['state_hash']!=state['state_hash'] or state['manifest']['mode']!='mixed':raise LiveResearchError('Stale or non-live assessment')
    if not 1<=max_attempts<=40 or not RESERVATION<=allowance_micro_usd<=10000000:raise LiveResearchError('M7 bounded run limits rejected')
    with app.campaign_db() as c:
        prior=[json.loads(r[0]) for r in c.execute("SELECT payload FROM events WHERE kind='M7RunAuthorized'")]
        old=next((p for p in prior if p['run_id']==state['run_id'] and p['identity']==d['workspace_identity']),None)
        if old:
            if old['manifest_hash']==digest(state['manifest']) and old['max_attempts']==max_attempts and old['allowance_micro_usd']==allowance_micro_usd:return old
            raise LiveResearchError('Run authorization already recorded; immutable limits cannot increase')
        prefix='m7-'+digest([state['run_id'],d['workspace_identity']])[:20]+'-'
        c.execute('INSERT INTO run_limits VALUES(?,?,?)',(prefix,max_attempts,allowance_micro_usd))
        app.event(c,'M7RunAuthorized',dict(run_id=state['run_id'],identity=d['workspace_identity'],generation=d['generation'],
            manifest_hash=digest(state['manifest']),stage_keys=state['manifest']['live_stage_keys'],actor=actor,reason=reason,
            max_attempts=max_attempts,allowance_micro_usd=allowance_micro_usd,model=MODEL))

def permission(app,manager,state,stage_key):
    from .runtime_binding import require_live,validate_campaign
    require_live('m7-agent0-permission');validate_campaign(app.campaign_path)
    d=view(manager)
    with app.campaign_db() as c:
        auth=[json.loads(r[0]) for r in c.execute("SELECT payload FROM events WHERE kind='M7RunAuthorized'")]
        a=next((a for a in auth if a['run_id']==state['run_id'] and a['identity']==d['workspace_identity']),None)
        budget=m7_budget.state(c,verify_sources=True);rows=budget['rows']
    if not a or a['generation']!=d['generation'] or a['manifest_hash']!=digest(state['manifest']) or stage_key not in a['stage_keys']:raise LiveResearchError('Exact M7 run/stage spending authorization missing')
    prefix='m7-'+digest([a['run_id'],a['identity']])[:20]+'-'
    used=[r for r in rows if r['session'].startswith(prefix)]
    if len(rows)>=budget['effective_limit'] or (budget['historical_micro_usd'] is not None and budget['historical_micro_usd']+sum(r['micro_usd'] for r in rows)+RESERVATION>m7_budget.PROJECT_USD) or sum(r['micro_usd'] for r in rows)+RESERVATION>10000000 or len(used)>=a['max_attempts'] or sum(r['micro_usd'] for r in used)+RESERVATION>a['allowance_micro_usd']:
        raise LiveResearchError('M7 cumulative campaign/run request or estimated allowance exhausted; no credential lookup or automatic retry')
    return a,prefix

def execute(app,manager,generation,*,state,stage_key,role,request,test_transport=None):
    from .runtime_binding import require_live,validate_campaign
    require_live('m7-agent'+str(role)+'-v1');validate_campaign(app.campaign_path)
    s=spec(role);operation=request['operation_key'];d=view(manager)
    index=int(stage_key.split(':',1)[0])
    if {2:2,3:4,5:3,9:6,14:6,20:7}.get(index)!=role:raise LiveResearchError('M7 stage/role mismatch')
    if role==6 and request['cve']!=state['refs'].get('scope_id'):raise LiveResearchError('M7 drafting scope mismatch')
    if role==7 and request['cve']!=state['refs'].get('reply_id'):raise LiveResearchError('M7 reply identity mismatch')
    run_id=stable(d['workspace_id'],s.version,operation)
    # Adopt the exact persisted child after interruption without another key read/debit.
    old=next((x for x in d['agent_steps'] if x['run_id']==run_id and x['step_key']==s.result_key),None)
    if old:
        p=json.loads(old['output_json'])
        subject=getattr(s,'subject_key','cve_id')
        if p['generation']!=generation or p['workspace_identity']!=d['workspace_identity'] or p[subject]!=request['cve'] or digest({k:v for k,v in p.items() if k!='proposal_hash'})!=p['proposal_hash']:
            raise LiveResearchError('Foreign/altered cached M7 result')
        return p
    from .workflow_control import stopped,WorkflowStopRequested
    if stopped(d,state['run_id'],manager=manager):raise WorkflowStopRequested('Stop requested before the next provider request')
    from .runtime_binding import runtime_configuration
    bound_live=runtime_configuration()['mode']=='existing-only' and runtime_configuration()['live_enabled']
    if bound_live:
        from .approved_execution import validate_request
        validate_request(app,manager,state,stage_key)
    if test_transport is None:
        from .local_security import require_local_operator
        require_local_operator()
        if role==4 or (role==2 and any(k.startswith('3:') for k in state['manifest']['live_stage_keys'])):
            checks=readiness(app,manager,state['manifest']['component_id'])
            blocked=[c for c in checks if c['status']!='Pass']
            if blocked:raise LiveResearchError('Live readiness blocked before credential lookup: '+blocked[0]['detail'])
    authorization,prefix=permission(app,manager,state,stage_key)
    cfg=configuration(state['run_id'],stage_key)
    cfg=cfg.model_copy(update={'session_id':prefix+digest(stage_key)[:25]})
    if test_transport is not None:
        from pydantic import SecretStr
        cfg=cfg.model_copy(update={'api_key':SecretStr('OFFLINE-ONLY-FAKE')})
    base={2:SDKAgent2,3:agent3.SDKAgent3,4:agent4.SDKAgent4,6:agent6.SDKAgent6,7:agent7.SDKAgent7}[role]
    class Gateway(base):
        reserve_mock_requests=True
        def reserve_provider(self,config,prompt):
            permission(app,manager,state,stage_key)
            if config.model_dump()!=cfg.model_dump():raise LiveResearchError('M7 exact provider configuration changed')
            m7_budget.debit(app.campaign_path,config,sha256(prompt.encode()).hexdigest(),RESERVATION)
    gateway=Gateway(test_transport=test_transport)
    # Caller supplies a minimized public/synthetic subject, never raw uploaded exports.
    actual=dict(request);actual['cve']=actual.pop('cve')
    if role==2:
        # Agent 2's legacy context uses synthetic_clock; shared specialist envelope needs as_of.
        class Bound(Agent2Spec):
            @staticmethod
            def context(data,cve,secret=''):return dict(live_evidence.context(data,cve,secret),as_of=utc())
        s=Bound()
    result=live_research.run(manager,generation,config=cfg,gateway=gateway,spec=s,**actual)
    usage=result['execution'].get('usage')
    with app.campaign_db() as c:
        app.event(c,'ModelUsageRecorded',dict(run_id=state['run_id'],child_run_id=result['run_id'],identity=d['workspace_identity'],role=role,
            origin=result['execution']['origin'],model=result['execution'].get('model_served'),usage=usage,
            estimated_cost_usd=((usage.get('input_tokens',0)*.75+usage.get('output_tokens',0)*4.5)/1e6) if usage and test_transport is None else 0 if test_transport is not None else None,
            session_id=cfg.session_id,
            status=result['review_status']))
    if bound_live:
        from .approved_execution import check_after_request
        check_after_request(app,manager)
    return result

def readiness(app,manager,component_id):
    d=view(manager);cves=sorted({f['cve_id'] for f in d['findings'] if f['component_id']==component_id})
    usage=app.usage()
    checks=[dict(check='M7 campaign',status='Pass' if usage['remaining_attempts']>0 and usage['remaining_estimated_allowance_usd']>=RESERVATION/1e6 else 'Blocked',detail='Audited effective internal attempt limit; unchanged $10 cumulative campaign ceiling; no key or provider request')]
    project_reserved=usage.get('project_reserved_usd')
    checks.append(dict(check='Project budget',status='Pass' if type(project_reserved) in (int,float) and __import__('math').isfinite(project_reserved) and project_reserved>=0 and round(project_reserved*1e6)+RESERVATION<=m7_budget.PROJECT_USD else 'Blocked',detail='An explicitly installed historical commitment inventory and room for the next full permanent reservation are required within the unchanged cumulative $50 project boundary.'))
    if not cves:return checks+[dict(check='Inventory',status='Blocked',detail='Upload and confirm synthetic scanner findings first')]
    for cve in cves:
        sources=live_evidence.context(d,cve)['sources']
        vendor=[s for s in sources if s['kind']=='Vendor']
        checks.append(dict(check=cve+' historical vendor evidence',status='Pass' if vendor else 'Blocked',detail='Historical source captures required; run the official-evidence preparation stage first. Actual deployment applicability stays unverified.'))
        try:
            supplied=Agent4Spec.context(d,cve)
            checks.append(dict(check=cve+' KEV / EPSS',status='Pass',detail='Hash-validated official captures are fresh at actual UTC; EPSS is probability, sector targeting is separate.'))
        except LiveResearchError as exc:checks.append(dict(check=cve+' KEV / EPSS',status='Blocked',detail=str(exc)))
    return checks

def refresh_threat(manager,generation,*,confirmed,actor):
    if not confirmed:raise LiveResearchError('Confirm read-only official public-source retrieval')
    urls=[('KEV',threat_evidence.KEV_URL),('KEV',threat_evidence.KEV_MIRROR),
        ('EPSS','https://api.first.org/data/v1/epss?cve=CVE-2022-3602,CVE-2022-3786')]
    captures=[threat_evidence.retrieve('m7-'+str(uuid4()),url,kind) for kind,url in urls]
    agent4.load_sources(manager,generation,confirmed=True,actor=actor,captures=captures)
    return [dict(url=c['url'],status=c['fetch_status'],retrieved_at=c['retrieved_at'],hash=c.get('content_sha256'),error=c.get('error')) for c in captures]
