"""Persisted stage-boundary stop requests; never cancels an in-flight debit."""
import json

class WorkflowStopRequested(ValueError):
    pass
from .database import make_engine
from .services import audit
from .live_contracts import redact

def stopped(data,run_id,manager=None):
    events=data.get('workflow_control_events',[])
    if manager is not None:events=manager.history()['events']
    controls=[e for e in events if e['kind']=='WorkflowControlRequested' and e['generation']==data['generation'] and json.loads(e['payload']).get('run_id')==run_id and json.loads(e['payload']).get('identity')==data['workspace_identity']]
    if controls:return json.loads(max(controls,key=lambda e:e['id'])['payload'])['stop'] is True
    # Backward-compatible display of early candidate audit controls; no rewrite.
    old=[e for e in data['audit_events'] if e['event_type']=='WorkflowControlRequested' and e['entity_id']==run_id]
    return bool(old and json.loads(max(old,key=lambda e:(e['recorded_at'],e['id']))['payload_json'])['stop'] is True)


def request(manager,generation,*,run_id,stop,confirmed,actor):
    if type(stop) is not bool or not confirmed or not actor.strip() or redact(actor)!=actor:raise ValueError('Explicit named workflow control required')
    import sqlite3
    with manager._control() as control:
        state=manager._guard(control,generation,idle=False)
        path=manager._path(state['active'])
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as c:
            c.execute('PRAGMA query_only=ON')
            found=c.execute('SELECT count(*) FROM runs r JOIN demo_workspaces w ON r.workspace_id=w.id WHERE r.id=? AND w.generation=? AND w.database_identity=?',(run_id,generation,state['token'])).fetchone()[0]
            if found!=1:raise ValueError('Run is not in this exact active workspace generation')
        manager._event(control,generation,'WorkflowControlRequested',dict(run_id=run_id,identity=state['token'],stop=stop,actor=actor,stage_boundary=True,inflight_cancelled=False))
    return dict(run_id=run_id,stop=stop,stage_boundary=True)


def record_loaded(manager,generation,finding_ids):
    if not finding_ids:return
    with manager.execution(generation,'record_actual_ingestion_clock') as (path,w,clock,receipt):
        engine=make_engine(path)
        try:
            with engine.begin() as c:
                for finding_id in sorted(finding_ids):audit(c,w['id'],'FindingFirstIngested','asset_cves',finding_id,0,dict(clock_basis='actual-UTC',synthetic=True),actor_type='analyst',actor_id='local-analyst')
        finally:engine.dispose()


def record_status_event(manager,generation,*,ticket_id,reply_id,status,ticket_revision,actor):
    from .resolver_portal import STATUSES
    if status not in STATUSES:raise ValueError('Unsupported literal status')
    with manager.execution(generation,'record_literal_resolver_status') as (path,w,clock,receipt):
        engine=make_engine(path)
        try:
            with engine.begin() as c:
                from sqlalchemy import select
                from .database import tables
                old=c.execute(select(tables['audit_events']).where(tables['audit_events'].c.workspace_id==w['id'],tables['audit_events'].c.event_type=='ResolverStatusReported',tables['audit_events'].c.entity_id==ticket_id)).mappings().all()
                if any(json.loads(e['payload_json']).get('reply_id')==reply_id for e in old):return
                audit(c,w['id'],'ResolverStatusReported','tickets',ticket_id,ticket_revision,dict(status=status,reply_id=reply_id,ticket_revision=ticket_revision,clock_basis='actual-UTC',source='status-control',work_note_changed=False,completion_evidence_added=False),actor_type='analyst',actor_id=actor)
        finally:engine.dispose()

