"""A new resolver interpretation links approved prerequisites, never reruns them."""
import json
from . import agent0,reply_evidence
from .dashboard_service import view
from .database import make_engine
from .dashboard_queries import dashboard
from .lifecycle import _snapshot
from .services import stable,canonical
from .live_contracts import redact

def start(manager,generation,*,parent_run_id,parent_hash,reply_id,mode,operation_key,confirmed,actor,reason):
    if not confirmed or not actor.strip() or not reason.strip() or mode not in ('replay','mixed'):raise ValueError('Named confirmed resolver-cycle request required')
    if redact(actor)!=actor or redact(reason)!=reason:raise ValueError('Secret-shaped analyst/rationale refused')
    data=view(manager);parent=agent0._load(data,parent_run_id)
    if parent['state_hash']!=parent_hash:raise ValueError('Parent assessment changed; refresh the exact reviewed revision')
    refs=parent['refs']
    if not all(k in refs for k in ('ticket_id','communication_id','scope_id','agent3','report','mail')):raise ValueError('Approved ticket and original communication prerequisites required')
    for name,event in (('agent2','Agent2ReplayResearch'),('agent4','Agent4Research'),('agent3','Agent3Research'),('report','Agent6Research'),('mail','Agent6Research')):
        value=refs[name]
        for p in value if isinstance(value,list) else [value]:agent0._accepted(data,p,event)
    with manager.execution(generation,'link_resolver_cycle_prerequisites') as (path,w,clock,receipt):
        engine=make_engine(path)
        try:
            with engine.connect() as c:
                supplied=reply_evidence.context(reply_evidence.prepare_context(c,dashboard(c,w['id'],clock),reply_id),reply_id)
                if supplied['ticket_id']!=refs['ticket_id'] or supplied['communication_id']!=refs['communication_id']:raise ValueError('New reply belongs to another ticket or communication')
                _snapshot(c,w['id'],refs['scope_id'],clock) # exact batch approval still required
        finally:engine.dispose()
    manifest=dict(component_id=parent['manifest']['component_id'],mode=mode,actor=actor,reason=reason,
        live_stage_keys=['20:pending'] if mode=='mixed' else [],parent_run_id=parent_run_id,resume_from=20,
        inherited_child_ids=[p['run_id'] for value in refs.values() for p in (value if isinstance(value,list) else [value]) if isinstance(p,dict) and 'execution' in p])
    id=stable(data['workspace_id'],agent0.VERSION,operation_key)
    existing=next((s for s in agent0.stored(data) if s['run_id']==id),None)
    if existing:
        if existing['manifest']!=manifest or existing['refs']['reply_id']!=reply_id:raise ValueError('Resolver-cycle operation reused with changed inputs')
        return agent0._load(data,id)
    linked=json.loads(canonical(refs));linked.pop('agent7',None);linked['reply_id']=reply_id;linked.pop('verification',None)
    return agent0._save(manager,generation,dict(run_id=id,manifest=manifest,identity=data['workspace_identity'],generation=generation,
        cursor=20,status='Ready',reason='Approved prerequisites linked from parent; only the new reply interpretation and later verification will execute.',
        refs=linked,history=[],revision=0,provider_attempts=0,reserved_usd=0),None)
