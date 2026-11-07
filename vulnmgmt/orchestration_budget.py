"""Additional orchestration ceiling; never substitutes for an agent campaign.

Uses the manager's immutable event journal under its existing atomic lock. A
reservation survives provider failure, interruption, timeout and rejected output.
No authorization or reservation is created by rendering or ordinary replay.
"""
import json
from contextlib import contextmanager
from .services import digest
from .live_contracts import LiveResearchError

def _events(c,run_id,kind):
    return [json.loads(r['payload']) for r in c.execute('SELECT payload FROM events WHERE kind=?',(kind,))
            if json.loads(r['payload']).get('run_id')==run_id]

def authorize(manager,generation,*,run_id,state_hash,grants,max_attempts,allowance_micro_usd,confirmed,actor,reason):
    from .agent0 import _load
    from .dashboard_service import view
    if not confirmed or not actor.strip() or not reason.strip():raise LiveResearchError('Separate named cumulative authorization required')
    s=_load(view(manager),run_id)
    if s['state_hash']!=state_hash:raise LiveResearchError('Stale workflow authorization')
    if (not grants or type(max_attempts) is not int or not 1<=max_attempts<=10 or
        type(allowance_micro_usd) is not int or not 1<=allowance_micro_usd<=1000000):
        raise LiveResearchError('Bounded explicit stage and cumulative limits required')
    for key,g in grants.items():
        if key not in s['manifest'].get('live_stage_keys',[]) or set(g)!={'role','config_hash','reservation_micro_usd'} or g['role'] not in (2,3,4) or type(g['reservation_micro_usd']) is not int or not 1<=g['reservation_micro_usd']<=allowance_micro_usd:
            raise LiveResearchError('No independently authorized live adapter for this grant')
    payload=dict(run_id=run_id,identity=s['identity'],generation=generation,manifest_hash=digest(s['manifest']),
        grants=grants,max_attempts=max_attempts,allowance_micro_usd=allowance_micro_usd,actor=actor,reason=reason)
    with manager._control() as c:
        manager._guard(c,generation)
        if _events(c,run_id,'Agent0LiveAuthorized'):raise LiveResearchError('Immutable workflow authorization already exists; no reset or increase')
        manager._event(c,generation,'Agent0LiveAuthorized',payload)
    return payload

def reserve(manager,generation,run_id,stage_key,role,config,prompt):
    with manager._control() as c:
        state=manager._guard(c,generation,idle=False)
        authorizations=_events(c,run_id,'Agent0LiveAuthorized')
        if len(authorizations)!=1:raise LiveResearchError('No cumulative workflow authorization')
        a=authorizations[0];g=a['grants'].get(stage_key)
        if a['generation']!=generation or a['identity']!=state['token'] or not g or g['role']!=role or g['config_hash']!=digest(config.model_dump()):
            raise LiveResearchError('Foreign/stale stage configuration or cumulative authorization')
        prior=_events(c,run_id,'Agent0ProviderReserved')
        estimate=((config.max_input_bytes+16000)*config.input_rate+config.max_output_tokens*config.output_rate)/1000000
        if g['reservation_micro_usd']<round(estimate*1000000):raise LiveResearchError('Stage reservation understates existing session estimate')
        if any(r['stage_key']==stage_key for r in prior) or len(prior)>=a['max_attempts'] or sum(r['micro_usd'] for r in prior)+g['reservation_micro_usd']>a['allowance_micro_usd']:
            raise LiveResearchError('Cumulative request/budget exhausted; no retry or refund')
        manager._event(c,generation,'Agent0ProviderReserved',dict(run_id=run_id,stage_key=stage_key,role=role,
            config_hash=g['config_hash'],prompt_hash=digest(prompt),micro_usd=g['reservation_micro_usd']))

@contextmanager
def bounded_gateway(manager,generation,run_id,stage_key,role,gateway,config):
    """Adds a ceiling to an existing SDK instance; its own debit still runs.

    Authorization/configuration is checked before the caller can retrieve a key.
    Actual debit happens immediately before the one-request SDK transport.
    """
    from .agent2_sdk import SDKAgent2
    if not isinstance(gateway,SDKAgent2):raise LiveResearchError('Shared bounded SDK gateway required')
    with manager._control() as c:
        s=manager._guard(c,generation)
        a=_events(c,run_id,'Agent0LiveAuthorized')
        g=a[0]['grants'].get(stage_key) if len(a)==1 else None
        if not g or a[0]['identity']!=s['token'] or a[0]['generation']!=generation or g['role']!=role or g['config_hash']!=digest(config.model_dump()):
            raise LiveResearchError('Explicit exact-stage cumulative authorization missing before credential access')
        prior=_events(c,run_id,'Agent0ProviderReserved')
        if any(r['stage_key']==stage_key for r in prior) or len(prior)>=a[0]['max_attempts'] or sum(r['micro_usd'] for r in prior)+g['reservation_micro_usd']>a[0]['allowance_micro_usd']:
            raise LiveResearchError('Cumulative request/budget exhausted before credential access')
    original=gateway.reserve_provider
    def both(cfg,prompt):
        reserve(manager,generation,run_id,stage_key,role,cfg,prompt)
        original(cfg,prompt) # never replace, transfer or weaken the individual campaign
    gateway.reserve_provider=both
    try:yield gateway
    finally:gateway.reserve_provider=original

def execute(manager,generation,*,run_id,stage_key,role,config,gateway,request):
    """Only existing individually controlled roles are routable; no generic runner."""
    from . import agent3_campaign,agent4_campaign,live_research
    allowed={2:(live_research.run,None),3:(agent3_campaign.run,agent3_campaign.ControlledSDKAgent3),
        4:(agent4_campaign.run,agent4_campaign.ControlledSDKAgent4)}
    if role not in allowed:raise LiveResearchError('Agent has no separately authorized live campaign adapter')
    runner,cls=allowed[role]
    if cls is not None and type(gateway) is not cls:raise LiveResearchError('Controlled agent campaign gateway required')
    if role==2:
        from .agent2_sdk import SDKAgent2
        if type(gateway) is not SDKAgent2:raise LiveResearchError('Controlled Agent 2 shared SDK required')
    with bounded_gateway(manager,generation,run_id,stage_key,role,gateway,config):
        return runner(manager,generation,config=config,gateway=gateway,**request)
