"""Read-only approved metrics: explicit populations, endpoints and clock bases."""
from datetime import datetime,timedelta
from statistics import mean,median
import json

SEVERITIES=('Critical','High','Medium','Low')
VERIFIED='Verified Remediated'

def _time(value):
    t=datetime.fromisoformat(value.replace('Z','+00:00'))
    if t.tzinfo is None:raise ValueError('Clock must carry a timezone')
    return t

def duration_summary(rows,start,end,*,unit='findings',observation=False):
    values=[];counts=dict(censored=0,missing_start=0,missing_end=0,incompatible=0)
    for row in rows:
        a,b=row.get(start),row.get(end);basis=row.get('timing_basis',{})
        if not a:counts['missing_start']+=1;continue
        try:_time(a)
        except (ValueError,TypeError,AttributeError):counts['incompatible']+=1;continue
        if not basis.get(start):counts['incompatible']+=1;continue
        if not b:
            counts['censored' if row.get('timing_open',{}).get(end) is True and not observation else 'missing_end']+=1
            continue
        if not basis.get(end) or basis[start]!=basis[end]:counts['incompatible']+=1;continue
        try:
            delta=(_time(b)-_time(a)).total_seconds()/3600
            if delta<0:raise ValueError('Reversed event pair')
            values.append(delta)
        except (ValueError,TypeError,AttributeError):counts['incompatible']+=1
    return dict(mean=round(mean(values),2) if values else None,median=round(median(values),2) if values else None,completed=0 if observation else len(values),observed=len(values) if observation else 0,missing=counts['missing_start']+counts['missing_end'],total=len(rows),unit=unit,start=start,end=end,observation=observation,**counts)

def scoped_rows(data,group=None):return [r for r in data.get('findings',[]) if not group or group in r.get('resolver_groups',[])]

def severity_models(data,group=None):
    rows=scoped_rows(data,group);result=[];tickets=data.get('tickets',[]);links=data.get('ticket_findings',[])
    for severity in SEVERITIES:
        all_rows=[r for r in rows if r['severity']==severity];opened=[r for r in all_rows if r['status']!=VERIFIED]
        ids={r['id'] for r in all_rows};ticket_ids={r['ticket_id'] for r in links if r['asset_cve_id'] in ids}
        scoped_tickets=[r for r in tickets if r['id'] in ticket_ids];overdue=[r for r in opened if r.get('overdue')]
        ages=[dict(row,displayed_effective_at=data.get('as_of'),timing_basis={'first_seen':'synthetic-effective','due_at':'synthetic-effective','displayed_effective_at':'synthetic-effective'}) for row in opened]
        result.append(dict(severity=severity,all=len(all_rows),open=len(opened),in_remediation=sum(r['status'] not in (VERIFIED,'Pending Verification','Open') for r in all_rows),new=sum(r['status']=='Open' for r in all_rows),pending=sum(r['status']=='Pending Verification' for r in all_rows),verified=sum(r['status']==VERIFIED for r in all_rows),assets=len({r['asset_id'] for r in opened}),overdue=len(overdue),sla=round(100*(len(opened)-len(overdue))/len(opened),1) if opened else None,
            triage=duration_summary(all_rows,'ingested_at','triaged_at'),resolution=duration_summary(scoped_tickets,'created_new_at','resolved_at',unit='tickets'),reported=duration_summary(scoped_tickets,'dispatched_at','closed_reported_at',unit='tickets'),verification=duration_summary(all_rows,'discovered_at','scanner_verified_at'),age=duration_summary(ages,'first_seen','displayed_effective_at',observation=True),overdue_age=duration_summary([r for r in ages if r.get('overdue')],'due_at','displayed_effective_at',observation=True),dispatch=duration_summary(scoped_tickets,'ingested_at','dispatched_at',unit='tickets')))
    return result

def retained_measures(data,group=None):
    rows=scoped_rows(data,group);opened=[r for r in rows if r['status']!=VERIFIED];now=_time(data['as_of'])
    return dict(kev_open=sum(bool(r.get('known_exploitation')) for r in opened),kev_evaluated=sum(r.get('kev_state','Unknown')!='Unknown' for r in rows),kev_unknown=sum(r.get('kev_state','Unknown')=='Unknown' for r in rows),findings=len(rows),review_required=sum('review required' in r.get('applicability','').lower() or r.get('threat_freshness') in ('Stale','Unavailable') for r in rows),upcoming=sum(bool(r.get('due_at')) and now<=_time(r['due_at'])<=now+timedelta(days=7) for r in opened),unknown_deadlines=sum(not r.get('due_at') for r in opened),approval_decisions_global=len(data.get('lifecycle',{}).get('analyst_approval_queue',[])),duplicate_suppressions_global=sum(e['event_type']=='DuplicateEscalationSuppressed' for e in data.get('audit_events',[])))

def retained_timing(data):
    """Project exact retained audit or synthetic-effective endpoints, never mix them."""
    from . import agent0,resolver_portal
    findings=[dict(f,timing_basis={},timing_sources={},timing_open={}) for f in data['findings']]
    tickets=[dict(t,timing_basis={},timing_sources={},timing_open={}) for t in data.get('tickets',[])]
    byid={f['id']:f for f in findings};byticket={t['id']:t for t in tickets}
    events=sorted(data.get('audit_events',[]),key=lambda e:(e['recorded_at'],e['id']));reply_times={};states=[];communication_tickets={}
    def endpoint(row,key,value,basis,source):
        if not value:return
        if key not in row or _time(value)<_time(row[key]):
            row[key]=value;row['timing_basis'][key]=basis;row['timing_sources'][key]=source
    for run in agent0.stored(data):
        if run['identity']==data['workspace_identity'] and run['generation']==data['generation']:
            state=agent0._load(data,run['run_id']);states.append(state)
            if state['refs'].get('communication_id') and state['refs'].get('ticket_id'):communication_tickets[state['refs']['communication_id']]=state['refs']['ticket_id']
    raw={row['id']:row for row in data.get('raw_findings',[])};batches={batch['id']:batch for batch in data.get('ingestion_batches',[])}
    for finding in findings:
        for observation in finding.get('observations',[]):
            if observation.get('mapping_version') not in ('synthetic-tenable:1','synthetic-defender:1'):continue
            row=raw.get(observation['raw_id']);batch=batches.get(row['ingestion_batch_id']) if row else None
            if batch:endpoint(finding,'ingested_at',batch['ingested_at'],'actual-UTC','ingestion batch:'+batch['id'])
    explicit_status={}
    for event in events:
        payload=json.loads(event['payload_json']);at=event['recorded_at'];entity=event['entity_id'];source='audit:'+event['id']
        if event['event_type']=='ScannerDiscoveryRecorded' and entity in byid:endpoint(byid[entity],'discovered_at',payload['discovered_at'],'synthetic-effective',source)
        if event['event_type']=='TicketCreated' and entity in byticket:endpoint(byticket[entity],'created_new_at',at,'actual-UTC',source)
        if event['event_type']=='SyntheticMessageDelivered' and entity in communication_tickets:endpoint(byticket[communication_tickets[entity]],'dispatched_at',at,'actual-UTC',source)
        if event['event_type']=='LifecycleOperation' and payload.get('result',{}).get('reply_id'):reply_times.setdefault(payload['result']['reply_id'],(at,source))
        if event['event_type']=='ResolverStatusReported' and entity in byticket:
            explicit_status[entity]=payload['status']
            if payload['status']=='Resolved':endpoint(byticket[entity],'resolved_at',at,'actual-UTC',source)
            if payload['status']=='Closed':endpoint(byticket[entity],'closed_reported_at',at,'actual-UTC',source)
    for state in states:
        component=state['manifest']['component_id'];ticket=byticket.get(state['refs'].get('ticket_id'))
        for stage in state['history']:
            if stage['stage']=='Research acceptance gate':
                for finding in findings:
                    if finding['component_id']==component:endpoint(finding,'triaged_at',stage.get('recorded_at'),'actual-UTC','run:'+state['run_id']+':Research acceptance gate')
        if ticket is not None:
            loaded=[f.get('ingested_at') for f in findings if f['component_id']==component]
            if loaded and all(loaded):endpoint(ticket,'ingested_at',max(loaded),'actual-UTC','latest first-ingested endpoint of assigned component findings')
    for reply in data.get('owner_replies',[]):
        links=[i for i in data.get('reply_interpretations',[]) if i['reply_id']==reply['id']]
        ticket=byticket.get(links[0]['ticket_id']) if links else None
        if ticket is None or reply['id'] not in reply_times:continue
        at,source=reply_times[reply['id']]
        if reply['raw_body'].startswith(resolver_portal.PREFIXES['Closed']):endpoint(ticket,'closed_reported_at',at,'actual-UTC',source)
        if reply['raw_body'].startswith(resolver_portal.PREFIXES['Resolved']):endpoint(ticket,'resolved_at',at,'actual-UTC',source)
    scans={s['id']:s for s in data.get('scan_assessments',[])}
    verified_events={v['id']:v for v in data.get('verification_events',[]) if v['result']=='Pass'}
    for finding in findings:
        if finding['status']==VERIFIED:
            histories=[h for h in data.get('status_history',[]) if h['asset_cve_id']==finding['id'] and h['to_status']==VERIFIED and h.get('verification_event_id') in verified_events]
            if histories:
                history=max(histories,key=lambda h:_time(h['occurred_at']));event=verified_events[history['verification_event_id']];scan=scans.get(event['assessment_id'])
                if scan and scan['scan_status']=='Success':endpoint(finding,'scanner_verified_at',scan['assessed_at'],'synthetic-effective','scanner assessment:'+scan['id'])
        finding['timing_open']={'triaged_at':finding['status']!=VERIFIED,'scanner_verified_at':finding['status']!=VERIFIED}
    for ticket in tickets:
        status=explicit_status.get(ticket['id'],resolver_portal.reported_status(data,ticket['id']))
        ticket['timing_open']={'resolved_at':status in ('New','In Progress','No resolver update') and ticket['status']!='Closed','closed_reported_at':status!='Closed' and ticket['status']!='Closed','dispatched_at':ticket['status']!='Closed'}
    return dict(data,findings=findings,tickets=tickets)


def agent_performance(state):
    """Current-run measurements only; linked prior outputs are identified, not rebilled."""
    if not state:return []
    refs=state['refs'];inherited=set(state['manifest'].get('inherited_child_ids',[]));rows=[]
    for role,keys in ((2,('agent2',)),(4,('agent4',)),(3,('agent3',)),(6,('report','mail')),(7,('agent7',))):
        outputs=[]
        for key in keys:
            value=refs.get(key,[]);outputs.extend(value if isinstance(value,list) else [value])
        outputs=[p for p in outputs if isinstance(p,dict) and isinstance(p.get('execution'),dict)]
        current=[p for p in outputs if p.get('run_id') not in inherited]
        calls=sum(p['execution'].get('provider_attempts',0) for p in current)
        durations=[p['execution'].get('duration_seconds') for p in current]
        usages=[p['execution'].get('usage') for p in current]
        tokens=sum((u.get('total_tokens') or ((u.get('input_tokens') or 0)+(u.get('output_tokens') or 0))) for u in usages) if usages and all(u is not None for u in usages) else (0 if outputs and calls==0 else None)
        costs=[p['execution'].get('estimated_cost_usd') for p in current]
        cost=sum(costs) if costs and all(v is not None for v in costs) else (0 if outputs and calls==0 else None)
        rows.append(dict(agent=role,processing=' / '.join(sorted({p['execution']['origin'] for p in outputs})) if outputs else 'Not recorded',current_requests=calls,linked_outputs=len(outputs)-len(current),validated_outputs=sum(bool(p.get('result')) for p in current),retained_outputs=len(current),total_tokens=tokens,mean_request_seconds=round(mean(durations),3) if durations and all(v is not None for v in durations) else None,estimated_usage_usd=cost,failed_or_quarantined=sum(not p.get('result') for p in current)))
    return rows
