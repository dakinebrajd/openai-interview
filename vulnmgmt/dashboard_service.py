"""Explicit local workflow commands shared by UI, CLI and tests. No paid AI/transports."""
from datetime import timedelta
from uuid import uuid4
from sqlalchemy import select
from .database import make_engine, tables
from .dashboard_queries import dashboard, revision_token
from .enrichment import enrich
from .enrichment_evidence import timestamp
from .fixture_builder import FIXTURE_DIR
from .lifecycle import (apply_reply, create_scope, decide_proposal, decide_review,
    draft_notification, execute_escalation, queue_escalation, receive_reply,
    record_scanner_result, request_batch_review, seed_historical_ticket, simulate_send,
    _ticket_scope, _members)
from .lifecycle_contracts import AnalystDecision, ResolverReply, ScannerResult
from .lifecycle_demo import _request
from .scanners import ingest_export
from .services import row


def run_live_research(manager, generation, **request):
    """Separate lease-protected Agent 2 command; no domain-action privileges."""
    from .live_research import run
    return run(manager, generation, **request)


def run_reply_research(manager,generation,**request):
    from .agent7 import run
    return run(manager,generation,**request)


def receive_research_reply(manager,generation,**request):
    from .agent7 import receive
    return receive(manager,generation,**request)


def review_reply_research(manager,generation,**request):
    from .agent7 import review
    return review(manager,generation,**request)


def apply_reply_research(manager,generation,**request):
    from .agent7 import apply
    return apply(manager,generation,**request)


def review_orchestration_research(manager,generation,*,agent,**request):
    from . import research_replay,agent3,agent4,agent6,agent7
    modules=dict(agent2=research_replay,agent3=agent3,agent4=agent4,report=agent6,mail=agent6,agent7=agent7)
    if agent not in modules:raise ValueError('Unknown workflow research role')
    if agent=='agent2':
        data=view(manager)
        if any(s['run_id']==request['run_id'] and s['step_key']=='agent2-research-result' for s in data['agent_steps']):
            from .live_research import review
            return review(manager,generation,**request)
    return modules[agent].review(manager,generation,**request)


def start_orchestration(manager,generation,**request):
    from .agent0 import start
    return start(manager,generation,**request)


def advance_orchestration(manager,generation,**request):
    from .agent0 import advance
    return advance(manager,generation,**request)


def start_reply_cycle(manager,generation,**request):
    from .reply_cycle import start
    return start(manager,generation,**request)


def followup_scan(manager,generation,*,ticket_id,outcome,operation_key,confirmed,actor,reason):
    """One explicit synthetic scanner observation, cached before advancing time.

    Reuses lifecycle verification; no owner assertion becomes scanner evidence.
    """
    if not confirmed or not actor.strip() or not reason.strip() or outcome not in ('Pass','Fail'):
        raise ValueError('Confirmed named independent synthetic scanner assessment required')
    from .lifecycle import _cached,_finish
    from .services import utc
    payload=dict(ticket_id=ticket_id,outcome=outcome,actor=actor,reason=reason,generation=generation)
    with manager.execution(generation,'browser_followup_scanner') as (path,w,clock,receipt):
        engine=make_engine(path)
        try:
            with manager._control() as control:
                state=manager._guard(control,generation,idle=False)
                with engine.begin() as c:
                    result=_cached(c,w['id'],'browser-scan-'+operation_key,payload)
                    if result is None:
                        _,scope=_ticket_scope(c,w['id'],ticket_id);members=_members(c,w['id'],scope)
                        observed=utc(timestamp(state['clock'])+timedelta(seconds=60))
                        request=_request(ScannerResult,w['id'],w['scenario_version_id'],operation_key=operation_key,
                            ticket_id=ticket_id,assessed_at=observed,recorded_at=observed,scan_status='Success',outcomes={f['id']:outcome for f in members})
                        result=dict(record_scanner_result(c,request),synthetic_clock=observed)
                        _finish(c,w['id'],'browser-scan-'+operation_key,payload,result,observed)
                if timestamp(state['clock'])<timestamp(result['synthetic_clock']):
                    control.execute('UPDATE registry SET clock=? WHERE generation=?',(result['synthetic_clock'],generation))
                    manager._event(control,generation,'SyntheticClockAdvanced',dict(from_clock=state['clock'],to=result['synthetic_clock'],reason='Independent synthetic scanner observation'))
                receipt.update(result);return result
        finally:engine.dispose()


def review_live_research(manager, generation, **request):
    from .live_research import review
    return review(manager, generation, **request)


def run_threat_research(manager, generation, **request):
    from .agent4 import run
    return run(manager, generation, **request)


def run_batching_research(manager, generation, **request):
    from .agent3 import run
    return run(manager, generation, **request)


def run_drafting_research(manager,generation,**request):
    from .agent6 import run
    return run(manager,generation,**request)


def review_drafting_research(manager,generation,**request):
    from .agent6 import review
    return review(manager,generation,**request)


def stage_drafting_research(manager,generation,**request):
    from .agent6 import stage
    return stage(manager,generation,**request)


def review_batching_research(manager, generation, **request):
    from .agent3 import review
    return review(manager, generation, **request)


def load_threat_sources(manager, generation, **request):
    from .agent4 import load_sources
    return load_sources(manager, generation, **request)


def review_threat_research(manager, generation, **request):
    from .agent4 import review
    return review(manager, generation, **request)


def view(manager, **filters):
    from .historical_dashboard import HistoricalDashboard
    if isinstance(manager, HistoricalDashboard):
        return manager.view(**filters)
    # Holding the registry transaction makes the pointer/clock a consistent read.
    with manager._control() as control:
        s = dict(control.execute('SELECT * FROM registry WHERE id=1').fetchone())
        engine = make_engine(manager._path(s['active']))
        try:
            with engine.begin() as c:
                workspace = c.execute(select(tables['demo_workspaces'])).mappings().one()
                result = dashboard(c, workspace['id'], s['clock'], **filters)
                result['manager'] = s
                return result
        finally:
            engine.dispose()


def command(manager, expected, action, *, confirmed=False, actor='', reason='',
            target=None, payload_hash=None, decision='Approved', body='', until=None, key=None,
            reviewed_token=None, scenario_name=None, scheduled_at=None):
    if not confirmed:
        raise ValueError('Explicit confirmation required')
    if not actor.strip() or not reason.strip():
        raise ValueError('Named local analyst and reason required')
    key = key or str(uuid4())
    with manager.execution(expected, action) as (path, workspace, now, output):
        w, version = workspace['id'], workspace['scenario_version_id']
        engine = make_engine(path)
        try:
            request_payload = dict(action=action, target=target, payload_hash=payload_hash, decision=decision,
                                   body=body, until=until, actor=actor, reason=reason, reviewed_token=reviewed_token,
                                   scenario_name=scenario_name, scheduled_at=scheduled_at)
            # UI retries return the immutable receipt before checking changed state.
            if reviewed_token is not None:
                from .lifecycle import _cached
                with engine.begin() as c:
                    cached = _cached(c, w, 'ui-receipt-'+key, request_payload)
                    if cached is not None:
                        output.update(cached)
                        return cached
                    if revision_token(dashboard(c, w, now)) != reviewed_token:
                        raise ValueError('Revision conflict: records changed since review. Refresh and inspect the current proposal before submitting again.')
            if action == 'evidence_replay':
                with engine.begin() as c:
                    if not c.scalar(select(tables['asset_cves'].c.id).where(tables['asset_cves'].c.workspace_id == w)):
                        raise ValueError('Import a fresh scan before evidence replay')
                from .two_resolver_demo import replay_directory,retained_evidence
                with engine.connect() as c:
                    demo_directory=replay_directory(c,w)
                    evidence_key,existing_evidence=retained_evidence(c,w,now)
                result = existing_evidence or enrich(engine, w, version, as_of=now,**({'directory':demo_directory} if demo_directory else {}))
                if demo_directory and existing_evidence is None:
                    from .services import audit
                    with engine.begin() as c:
                        audit(c,w,'TwoResolverCuratedEvidencePrepared','runs',result['run_id'],0,dict(input_key=evidence_key,result=result,linked_paid_work=False))
                if reviewed_token is not None:
                    from .lifecycle import _finish
                    with engine.begin() as c:
                        _finish(c, w, 'ui-receipt-'+key, request_payload, result, now)
                output.update(result['summary'])
                return result
            if action in ('advance_clock', 'sla_breach'):
                from .services import utc, audit
                from .lifecycle import _finish
                clock = utc(timestamp(now)+(timedelta(days=100) if action == 'sla_breach' else timedelta(seconds=60)))
                result = {'synthetic_clock': clock, 'note': 'Synthetic clock advanced; no scanner executed.'}
                # Match view/reset lock order: registry, then operational database.
                with manager._control() as control:
                    manager._guard(control, expected, idle=False)
                    with engine.begin() as c:
                        audit(c, w, 'DashboardClockAdvanced', 'demo_workspaces', w, expected,
                              {'from': now, 'to': clock, 'actor': actor, 'reason': reason}, actor_id=actor, actor_type='analyst')
                        if reviewed_token is not None:
                            _finish(c, w, 'ui-receipt-'+key, request_payload, result, now)
                    control.execute('UPDATE registry SET clock=? WHERE generation=?', (clock, expected))
                    manager._event(control, expected, 'SyntheticClockAdvanced', {'from': now, 'to': clock})
                    if scenario_name:
                        manager._event(control, expected, 'ScenarioSelected', {'name': scenario_name})
                output.update(result)
                return result
            with engine.begin() as c:
                if reviewed_token is not None and revision_token(dashboard(c, w, now)) != reviewed_token:
                    raise ValueError('Revision conflict: refresh and review the changed records before submitting again.')
                if action == 'fresh_scan':
                    result = {'imports': [ingest_export(c, w, version, (FIXTURE_DIR/name).read_bytes(), fmt)
                              for name, fmt in [('tenable.json', 'synthetic-tenable'),
                                                ('defender.json', 'synthetic-defender'),
                                                ('tenable_repeat.json', 'synthetic-tenable')]]}
                elif action == 'batch_review':
                    members = list(c.scalars(select(tables['batch_proposal_members'].c.asset_cve_id).where(
                        tables['batch_proposal_members'].c.workspace_id == w,
                        tables['batch_proposal_members'].c.batch_id == target)))
                    result = request_batch_review(c, w, target, members, now, key)
                elif action in ('decide_review', 'decide_proposal'):
                    request = _request(AnalystDecision, w, version, operation_key=key,
                        target_id=target, payload_hash=payload_hash, analyst_id=actor, reason=reason,
                        decision=decision, decided_at=now)
                    result = (decide_review if action == 'decide_review' else decide_proposal)(c, request)
                elif action in ('queue_batch', 'queue_finding'):
                    scope = create_scope(c, w, now=now, **{
                        'batch_id' if action == 'queue_batch' else 'finding_id': target})
                    result = queue_escalation(c, w, scope, now, key)
                elif action == 'execute_ticket':
                    result = execute_escalation(c, w, target, now, key)
                elif action == 'draft_notification':
                    result = draft_notification(c, w, target, now, key)
                elif action == 'simulate_send':
                    result = simulate_send(c, w, target, now, key)
                elif action == 'reply':
                    _, scope = _ticket_scope(c, w, target)
                    received = receive_reply(c, _request(ResolverReply, w, version, operation_key=key+'-receive',
                        ticket_id=target, owner_id=scope['resolver_group_id'], body=body, received_at=now,
                        exception_until=until, scheduled_at=scheduled_at))
                    result = apply_reply(c, w, received['reply_id'], now, key+'-apply', actor, reason)
                elif action in ('verify_pass', 'verify_fail'):
                    _, scope = _ticket_scope(c, w, target)
                    members = _members(c, w, scope)
                    result = record_scanner_result(c, _request(ScannerResult, w, version, operation_key=key,
                        ticket_id=target, assessed_at=now, recorded_at=now, scan_status='Success',
                        outcomes={f['id']: 'Pass' if action == 'verify_pass' else 'Fail' for f in members}))
                elif action == 'new_threat_evidence':
                    # Captured real KEV newly compared with an explicitly seeded historical ticket.
                    f, a = tables['asset_cves'], tables['assets']
                    finding = c.scalar(select(f.c.id).join(a, f.c.asset_id == a.c.id).where(
                        f.c.workspace_id == w, a.c.workspace_id == w, a.c.asset_key == 'WEB-003',
                        f.c.cve_id == 'CVE-2021-44228'))
                    if not finding:
                        raise ValueError('Import scanner data and replay evidence first')
                    if not c.scalar(select(tables['threat_intel'].c.id).where(
                        tables['threat_intel'].c.workspace_id == w, tables['threat_intel'].c.cve_id == 'CVE-2021-44228')):
                        raise ValueError('Evidence replay is required first')
                    scope = create_scope(c, w, finding_id=finding, now=now)
                    seed_historical_ticket(c, w, scope, '2026-11-02T12:00:00Z', 'm5-historical-threat-seed')
                    result = queue_escalation(c, w, scope, now, key)
                elif action in ('inspect_normalization', 'inspect_results'):
                    state = dashboard(c, w, now)
                    result = {'inspection': action, 'summary': state['summary'], 'metrics': state['metrics'],
                              'note': 'Read and validated existing SQLite records; no scanner or model executed.'}
                else:
                    raise ValueError('Unsupported local stage: '+action)
                output.update(result)
                from .services import audit
                audit(c, w, 'DashboardCommand', 'demo_workspaces', w, expected,
                      {'action': action, 'analyst': actor, 'reason': reason, 'synthetic_effective_at': now,
                       'execution': 'deterministic Python', 'operation_key': key}, actor_id=actor, actor_type='analyst')
                if reviewed_token is not None:
                    from .lifecycle import _finish
                    _finish(c, w, 'ui-receipt-'+key, request_payload, result, now)
            if scenario_name:
                with manager._control() as control:
                    manager._event(control, expected, 'ScenarioSelected', {'name': scenario_name})
            return result
        finally:
            engine.dispose()


def scenario(manager, expected, name, *, confirmed=False, actor='', reason=''):
    """Scenarios prepare state; pending approvals are never silently approved."""
    args = dict(confirmed=confirmed, actor=actor, reason=reason)
    if not confirmed or not actor.strip() or not reason.strip():
        raise ValueError('Confirmed named analyst scenario request required')
    if name == 'fresh scan':
        return command(manager, expected, 'fresh_scan', **args)
    if name == 'existing escalation':
        data = view(manager)
        if not data['lifecycle_scopes']:
            raise ValueError('Approve a batch and queue an escalation first')
        scope = data['lifecycle_scopes'][0]
        return command(manager, expected, 'queue_finding' if scope['individual_finding_id'] else 'queue_batch',
                       target=scope['individual_finding_id'] or scope['batch_id'], **args)
    if name == 'new threat evidence':
        return command(manager, expected, 'new_threat_evidence', **args)
    if name == 'remediation verification':
        data = view(manager)
        eligible = [t for t in data['tickets'] if t['status'] == 'Pending Verification']
        if not eligible:
            raise ValueError('Process a Completed reply first; it must be Pending Verification')
        return command(manager, expected, 'verify_pass', target=eligible[0]['id'], **args)
    if name == 'SLA breach':
        manager.set_clock(expected, (timestamp(manager.state()['clock'])+timedelta(days=100)).isoformat())
        return view(manager)['metrics']
    raise ValueError('Unknown scenario')
