"""Shared explicit UI/driver actions. Immutable runtime is not spending consent."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os
from . import agent0,m7_campaign,m7_budget,resolver_portal
from .dashboard_service import view
from .runtime_binding import runtime_configuration,_absolute
from .services import digest,stable
from .live_contracts import LiveResearchError,redact

PLAN_PATH='VM_APPROVED_EXECUTION_PLAN'
PLAN_SHA='VM_APPROVED_EXECUTION_PLAN_SHA256'
_PLAN_BINDING=(os.environ.get(PLAN_PATH),os.environ.get(PLAN_SHA))
FIELDS={'protocol','confirmed','actor','runtime_configuration_sha256','source_pins',
        'assessment_id','workspace_id','workspace_identity','generation','utc_day',
        'baseline_sessions','baseline_material_sha256','grants'}
GRANT_FIELDS={'kind','component_id','operation_key','run_id','parent_run_id','stage_keys',
              'max_attempts','allowance_micro_usd'}


def live_selected(app):
    config=runtime_configuration()
    return config['live_enabled'] is True and app.settings()['mode']=='Live AI'


def cumulative_guard(app,plan,*,before=False):
    policy,usage=m7_budget.snapshot(app.campaign_path,verify_sources=True)
    if not policy['migrated'] or policy['historical_micro_usd'] is None:
        raise LiveResearchError('Audited cumulative project accounting required')
    rows=policy['rows'];sessions=[r['session'] for r in rows];baseline=plan['baseline_sessions']
    if len(sessions)!=len(set(sessions)) or not set(baseline)<=set(sessions):
        raise LiveResearchError('Historical reservations missing or duplicated')
    material=dict(rows=sorted((r for r in rows if r['session'] in baseline),key=lambda r:r['session']),
                  usage=sorted((u for u in usage if u.get('session_id') in baseline),key=lambda u:u['session_id']))
    if digest(material)!=plan['baseline_material_sha256']:
        raise LiveResearchError('Historical reservation/usage material changed')
    mapped={u.get('session_id'):u for u in usage}
    if any(not mapped.get(s,{}).get('usage') for s in sessions):
        raise LiveResearchError('Unknown usage; stop without retry or refund')
    new=set(sessions)-set(baseline)
    if any(str(mapped[s].get('status','')).casefold() in ('failed','rejected','quarantined','rejected/quarantined') for s in new):
        raise LiveResearchError('New failure/quarantine; stop without retry')
    extra=m7_campaign.RESERVATION if before else 0
    reserved=sum(r['micro_usd'] for r in rows)
    if (len(rows)+int(before)>policy['effective_limit'] or len(new)+int(before)>18 or
        reserved+extra>10000000 or policy['historical_micro_usd']+reserved+extra>50000000):
        raise LiveResearchError('Cumulative attempt or dollar boundary; stop without retry')
    return set(sessions)


def load_plan(app,manager):
    config=runtime_configuration()
    if not live_selected(app):raise LiveResearchError('Explicit Live setting and live-enabled runtime required')
    if config['mode']!='existing-only':raise LiveResearchError('Live UI requires exact reviewed existing-only runtime')
    path,expected=os.environ.get(PLAN_PATH),os.environ.get(PLAN_SHA)
    if (path,expected)!=_PLAN_BINDING:raise LiveResearchError('Execution plan binding changed; start a new reviewed process')
    if not path or not expected:raise LiveResearchError('Reviewed immutable execution plan required before any live action')
    raw=_absolute(path).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise LiveResearchError('Execution plan pin changed')
    plan=json.loads(raw)
    if (set(plan)!=FIELDS or plan['protocol']!='approved-ui-live-v1' or plan['confirmed'] is not True or
        not isinstance(plan['actor'],str) or not plan['actor'].strip() or redact(plan['actor'])!=plan['actor'] or
        plan['runtime_configuration_sha256']!=digest(config) or
        plan['utc_day']!=datetime.now(timezone.utc).date().isoformat()):
        raise LiveResearchError('Live plan consent/runtime/day binding rejected')
    code=Path(config['code_root']);pins=plan['source_pins']
    if not isinstance(pins,dict) or not pins:raise LiveResearchError('Complete reviewed source inventory required')
    required={'vulnmgmt/approved_execution.py','vulnmgmt/approved_ui.py','vulnmgmt/resolver_status_claim.py',
              'vulnmgmt/m7_campaign.py','vulnmgmt/runtime_binding.py','audit_tools/approved_live_driver.py'}
    if not required<=set(pins):raise LiveResearchError('Shared route/driver source bindings missing')
    inventory={p.relative_to(code).as_posix() for p in code.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    if set(pins)!=inventory:raise LiveResearchError('Complete immutable release inventory differs')
    for name,pin in pins.items():
        target=_absolute(str(code/name))
        if not target.is_relative_to(code) or hashlib.sha256(target.read_bytes()).hexdigest()!=pin:
            raise LiveResearchError('Live source inventory changed')
    data=view(manager)
    if (Path(app.campaign_path).resolve()!=Path(config['canonical_ledger']) or
        Path(app.root).resolve()!=Path(config['application_root']) or
        manager.root!=app.root/'assessments'/plan['assessment_id'] or
        plan['assessment_id'] not in {a['id'] for a in app.assessments() if not a['archived']} or
        any(plan[k]!=data[k] for k in ('workspace_id','workspace_identity','generation'))):
        raise LiveResearchError('Live assessment/workspace/generation binding changed')
    if type(plan['generation']) is not int or not isinstance(plan['baseline_sessions'],list):
        raise LiveResearchError('Malformed live plan identity')
    grants=plan['grants']
    if not isinstance(grants,list) or len(grants)!=4:raise LiveResearchError('Exactly four immutable grant slots required')
    for g in grants:
        if set(g)!=GRANT_FIELDS or g['kind'] not in ('main','resolver'):raise LiveResearchError('Malformed grant slot')
        limits=(8,1000000) if g['kind']=='main' else (1,100000)
        if (type(g['max_attempts']) is not int or type(g['allowance_micro_usd']) is not int or
            (g['max_attempts'],g['allowance_micro_usd'])!=limits or not g['operation_key']):
            raise LiveResearchError('Grant limits cannot change')
        operation=g['operation_key'] if g['kind']=='main' else 'resolver-cycle-'+g['operation_key']
        if g['run_id']!=stable(data['workspace_id'],agent0.VERSION,operation):raise LiveResearchError('Planned run identity mismatch')
        cves=sorted({f['cve_id'] for f in data['findings'] if f['component_id']==g['component_id']})
        keys=sorted(['2:'+c for c in cves]+['3:'+c for c in cves]+['5:'+g['component_id'],'9:pending','14:pending','20:pending']) if g['kind']=='main' else ['20:pending']
        if len(cves)!=2 or g['stage_keys']!=keys:raise LiveResearchError('Exact live stage inventory mismatch')
    mains=[g for g in grants if g['kind']=='main'];children=[g for g in grants if g['kind']=='resolver']
    if (len(mains)!=2 or len(children)!=2 or len({g['component_id'] for g in mains})!=2 or
        len({g['run_id'] for g in grants})!=4 or any(g['parent_run_id'] is not None for g in mains) or
        any(sum(c['parent_run_id']==m['run_id'] and c['component_id']==m['component_id'] for c in children)!=1 for m in mains)):
        raise LiveResearchError('Two exact main/resolver pairs required')
    cumulative_guard(app,plan)
    return plan


def validate_request(app,manager,state,stage_key):
    plan=load_plan(app,manager)
    slot=next((g for g in plan['grants'] if g['run_id']==state['run_id']),None)
    if (slot is None or state['identity']!=plan['workspace_identity'] or state['generation']!=plan['generation'] or
        state['manifest']['component_id']!=slot['component_id'] or state['manifest']['mode']!='mixed' or
        state['manifest']['live_stage_keys']!=slot['stage_keys'] or stage_key not in slot['stage_keys'] or
        int(stage_key.split(':')[0]) not in ({2,3,5,9,14} if slot['kind']=='main' else {20}) or
        state['manifest'].get('parent_run_id')!=slot['parent_run_id']):
        raise LiveResearchError('Provider request differs from exact planned run/stage')
    cumulative_guard(app,plan,before=True)


def check_after_request(app,manager):
    load_plan(app,manager) # Includes fail-closed unknown-usage/quarantine inspection.


def _slot(plan,kind,component,parent=None):
    matches=[g for g in plan['grants'] if g['kind']==kind and g['component_id']==component and g['parent_run_id']==parent]
    if len(matches)!=1:raise LiveResearchError('No exact authorized action slot')
    return matches[0]


def start(app,manager,component_id,*,operation_key):
    data=view(manager)
    if not live_selected(app):
        return agent0.start(manager,data['generation'],component_id=component_id,operation_key=operation_key,
            mode='replay',use_imported_scan=True,confirmed=True,actor='local-analyst',reason='User started Replay workflow')
    plan=load_plan(app,manager);slot=_slot(plan,'main',component_id)
    state=agent0.start(manager,data['generation'],component_id=component_id,operation_key=slot['operation_key'],
        mode='mixed',live_stage_keys=slot['stage_keys'],use_imported_scan=True,confirmed=True,actor=plan['actor'],
        reason='Explicit user Start under exact reviewed immutable live plan')
    m7_campaign.authorize(app,manager,state,confirmed=True,actor=plan['actor'],reason='Bound main grant from reviewed plan',
        max_attempts=slot['max_attempts'],allowance_micro_usd=slot['allowance_micro_usd'])
    return state


def submit_status(app,manager,*,parent_run_id,parent_hash,ticket_id,status,operation_key):
    data=view(manager);parent=agent0._load(data,parent_run_id)
    # A Replay parent's provenance is never retroactively converted by runtime/settings.
    if parent['manifest']['mode']=='replay':
        return resolver_portal.submit_update(manager,data['generation'],parent_run_id=parent_run_id,parent_hash=parent_hash,
            ticket_id=ticket_id,status=status,note='',status_only=True,operation_key=operation_key,
            confirmed=True,actor='local-resolver',mode='replay')
    plan=load_plan(app,manager);slot=_slot(plan,'resolver',parent['manifest']['component_id'],parent_run_id)
    return resolver_portal.submit_update(manager,data['generation'],parent_run_id=parent_run_id,parent_hash=parent_hash,
        ticket_id=ticket_id,status=status,note='',status_only=True,operation_key=slot['operation_key'],
        confirmed=True,actor=plan['actor'],mode='mixed',spend_confirmed=True,application=app)


def advance(app,manager,*,run_id,state_hash):
    data=view(manager);state=agent0._load(data,run_id);adapters=None
    if state['manifest']['mode']=='mixed':
        plan=load_plan(app,manager)
        slot=next((s for s in plan['grants'] if s['run_id']==run_id),None)
        if (slot is None or state['identity']!=plan['workspace_identity'] or state['generation']!=plan['generation'] or
            state['manifest']['live_stage_keys']!=slot['stage_keys']):raise LiveResearchError('Run differs from exact live plan')
        adapters={key:dict(application=app) for key in slot['stage_keys']}
    return agent0.advance(manager,data['generation'],run_id=run_id,state_hash=state_hash,
        confirmed=True,actor='local-analyst',reason='Explicit user-started bounded workflow advance',live_adapters=adapters)
