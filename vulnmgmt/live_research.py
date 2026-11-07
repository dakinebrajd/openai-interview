"""Lease-protected Agent 2 service; existing SQLite tables, no operational authority."""
import hashlib
import json
import time
from uuid import uuid4
from sqlalchemy import select
from .database import make_engine, tables
from .dashboard_queries import dashboard, revision_token, records
from .services import audit, canonical, digest, stable, utc
from .live_contracts import LiveConfig, LiveResearchError, EvidenceValidationError, redact, provider_diagnostics
from .live_evidence import context, validate, assess, retrieve, official_url, CLAIM_FIELDS
from .research_sources import source_text
from .agent2_sdk import SDKAgent2, INSTRUCTIONS
from .live_contracts import Agent2Result

VERSION = 'm6b-agent2-v3'
RESULT_KEY = 'agent2-research-result'


def safe_failure(error, secret):
    if isinstance(error, LiveResearchError):
        return redact(str(error), secret)
    return {
        'AuthenticationError': 'OpenAI API authentication failed; verify the separately configured API credential.',
        'PermissionDeniedError': 'OpenAI API permission denied; verify project/model access.',
        'RateLimitError': 'OpenAI API rate or quota limit reached; no automatic retry.',
        'APITimeoutError': 'OpenAI API request timed out; billing/usage may be unknown; no automatic retry.',
        'APIConnectionError': 'OpenAI API connection unavailable; no automatic retry.',
        'BadRequestError': 'Provider rejected the configured model/settings/schema; verify interface support; no automatic retry.',
        'NotFoundError': 'Configured model or API resource is unavailable to this project.',
        'InternalServerError': 'Provider service unavailable; no automatic retry.',
        'TimeoutError': 'Provider request timed out; usage unknown; no automatic retry.',
        'ConnectionError': 'Provider connection failed; usage unknown; no automatic retry.',
        'ValidationError': 'Invalid or incomplete structured output; quarantined for review.',
    }.get(type(error).__name__, 'Structured output or provider execution failed; inspect safe metadata; no automatic retry.')


def reserve(manager, generation, config, run_id):
    """Durable across reset/restore: failed/uncertain attempts are never refunded."""
    estimate = ((config.max_input_bytes+16000)*config.input_rate +
                config.max_output_tokens*config.output_rate)/1_000_000
    with manager._control() as control:
        manager._guard(control, generation, idle=False)
        reservations = [json.loads(r['payload']) for r in control.execute(
            "SELECT payload FROM events WHERE kind='LiveResearchReserved'")]
        used = [r for r in reservations if r['session_id'] == config.session_id]
        if len(used) >= config.max_session_requests:
            raise LiveResearchError('Approved session request limit reached; no provider request made.')
        if sum(r['output_token_reservation'] for r in used)+config.max_output_tokens > config.session_output_tokens:
            raise LiveResearchError('Approved session output-token reservation limit reached.')
        if sum(r['estimated_usd'] for r in used)+estimate > config.budget_usd:
            raise LiveResearchError('Estimated session budget reservation would be exceeded.')
        manager._event(control, generation, 'LiveResearchReserved', dict(session_id=config.session_id,
            run_id=run_id, model=config.model, estimated_usd=estimate, output_token_reservation=config.max_output_tokens,
            notice='Local estimate, not a guaranteed provider billing cap; retries disabled, one provider request maximum.'))
    return estimate


def refresh(c, w, supplied, secret, fetcher):
    urls = list(dict.fromkeys([s['url'] for s in supplied['sources']] +
        ['https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+supplied['cve_id']]))[:3]
    fresh = []
    for url in urls:
        if not official_url(url):
            raise LiveResearchError('Unapproved evidence URL.')
        at = utc()
        try:
            capture = fetcher(url)
            body = capture['body']
            if redact(body, secret) != body or len(body.encode()) > 256000:
                raise LiveResearchError('Public source failed size or secret-safety validation.')
            # The service records its actual completed retrieval time, not a model timestamp.
            at = utc()
            text = source_text({'body': body})
            pos = text.upper().find(supplied['cve_id'])
            if pos < 0:
                raise LiveResearchError('Retrieved source does not identify the selected CVE.')
            hash_ = hashlib.sha256(body.encode()).hexdigest()
            source_id = stable(w, 'agent2-public-source', url, at, hash_)
            kind = 'Vendor' if any(s['url'] == url and s['kind'] == 'Vendor' for s in supplied['sources']) else 'CVE'
            snapshot = dict(id=source_id, url=url, body=body, kind=kind, retrieved_at=at,
                            content_sha256=hash_, provenance='Read-only public retrieval by application; not model-generated')
            c.execute(tables['evidence_sources'].insert().values(id=source_id, workspace_id=w, url=url,
                publisher='Official public source / Agent 2 capture', retrieved_at=at, published_at=None,
                content_hash=hash_, snapshot_json=canonical(snapshot), fetch_status='Success', error=None))
            start = max(0, pos-2500)
            fresh.append(dict(id=source_id, url=url, retrieved_at=at, content_hash=hash_, kind=kind,
                              text=text[start:start+10000],
                              text_hash=hashlib.sha256(text[start:start+10000].encode()).hexdigest(),
                              provenance=snapshot['provenance']))
        except Exception:
            c.execute(tables['evidence_sources'].insert().values(id=str(uuid4()), workspace_id=w, url=url,
                publisher='Official public source / failed Agent 2 capture', retrieved_at=at, published_at=None,
                content_hash=None, snapshot_json=None, fetch_status='Failed', error='Public retrieval unavailable or evidence rejected'))
            return False
    supplied['sources'] = fresh
    return True


def run(manager, generation, *, cve, confirmed, actor, reason, operation_key,
        reviewed_token, refresh_sources=False, config=None, gateway=None, fetcher=None, spec=None):
    role, version, result_key = (spec.role, spec.version, spec.result_key) if spec else (2, VERSION, RESULT_KEY)
    mode = spec.mode if spec else 'live'
    if mode=='live':
        from .runtime_binding import require_live
        require_live(version)
    config = config or LiveConfig.environment()
    context_fn, validate_fn = (spec.context, spec.validate) if spec else (context, validate)
    assess_fn = spec.assess if spec else assess
    instructions, output_type = (spec.instructions, spec.output_type) if spec else (INSTRUCTIONS, Agent2Result)
    events = spec.events if spec else 'LiveResearch'
    subject_key = getattr(spec, 'subject_key', 'cve_id')
    if mode == 'live':
        config.require_authorization()
    if not confirmed or not actor.strip() or not reason.strip() or not operation_key or len(operation_key) > 100:
        raise LiveResearchError('Explicit confirmation, named analyst, reason and bounded request identity are required.')
    if refresh_sources and not config.allow_public_fetch:
        raise LiveResearchError('Read-only public retrieval is not enabled/authorized.')
    # Render/readiness and rejected/stale operations must never open the OS store.
    secret = ''
    actor, reason = redact(actor, secret), redact(reason, secret)
    gateway = gateway or SDKAgent2()
    if role==2 and isinstance(gateway,SDKAgent2) and gateway.output_type is Agent2Result:
        gateway.transport=None
        gateway._agent2_selection_audit=None  # Request entry includes preflight failures before SDK invocation.
    request = dict(cve=cve, model=config.model, session=config.session_id, generation=generation,
                   actor=actor, reason=reason, refresh_sources=refresh_sources, reviewed_token=reviewed_token,
                   settings=config.model_dump())
    if spec and hasattr(spec, 'request_binding'):
        request['specialist_binding'] = spec.request_binding
    request_hash = digest(request)
    try:
        with manager.execution(generation, 'agent'+str(role)+'_research') as (path, workspace, clock, receipt):
            w = workspace['id']
            engine = make_engine(path)
            run_id = stable(w, version, operation_key)
            try:
                with engine.begin() as c:
                    old = c.execute(select(tables['runs']).where(tables['runs'].c.workspace_id == w,
                                                                 tables['runs'].c.id == run_id)).mappings().first()
                    if old:
                        if old['input_hash'] != request_hash:
                            raise LiveResearchError('Execution identity was reused with different reviewed inputs.')
                        stored = c.scalar(select(tables['agent_steps'].c.output_json).where(
                            tables['agent_steps'].c.workspace_id == w, tables['agent_steps'].c.run_id == run_id,
                            tables['agent_steps'].c.step_key == result_key))
                        if not stored:
                            raise LiveResearchError('Incomplete prior attempt; inspect the recorded run before recovery. No automatic retry.')
                        receipt.update(run_id=run_id, outcome='Existing result; no provider retry')
                        return json.loads(stored)
                    data = dashboard(c, w, clock)
                    if spec and hasattr(spec,'prepare_context'):
                        data=spec.prepare_context(c,data,cve)
                    token_fn = getattr(spec, 'review_token', revision_token)
                    if token_fn(data) != reviewed_token:
                        raise LiveResearchError('Reviewed context changed; refresh and inspect evidence before running.')
                    supplied = context_fn(data, cve, secret)
                if gateway.origin == 'live_model' or (spec and getattr(spec, 'runtime_credential', False)):
                    from .credentials import for_operation
                    config = for_operation(config, confirmed=confirmed)
                if mode == 'live':
                    config.require()
                secret = config.api_key.get_secret_value()
                # Redact with the runtime key only inside the authorized service.
                actor, reason = redact(actor, secret), redact(reason, secret)
                supplied = context_fn(data, cve, secret)
                reservation = reserve(manager, generation, config, run_id) if mode == 'live' else 0
                started = utc()
                with engine.begin() as c:
                    c.execute(tables['runs'].insert().values(id=run_id, workspace_id=w,
                        scenario_version_id=workspace['scenario_version_id'], mode=mode, effective_clock=clock,
                        started_at=started, ended_at=None, status='Running', input_hash=request_hash, contract_version=version))
                    audit(c, w, events+'Started', 'runs', run_id, 0,
                          dict(**{subject_key:cve}, model_requested=config.model, session_id=config.session_id,
                               synthetic_effective_at=clock, origin=gateway.origin, estimated_reservation_usd=reservation),
                          actor_id=actor, actor_type='analyst')
                metadata = dict(origin=gateway.origin, model_requested=config.model, model_served=None,
                                provider_attempts=0, usage=None, response_ids=[], request_ids=[])
                candidate, result, failure, rendered = None, None, None, None
                wall_start = time.monotonic()
                stage = 'input_preparation'
                try:
                    if refresh_sources:
                        stage = 'public_evidence_retrieval'
                        with engine.begin() as c:
                            captured = refresh(c, w, supplied, secret, fetcher or retrieve)
                        if not captured:
                            raise LiveResearchError('Public source retrieval failed; model was not invoked. Replay remains available.')
                    stage = 'input_preparation'
                    if not supplied['sources']:
                        raise LiveResearchError('No usable authoritative captures. Load evidence replay or authorize public retrieval first.')
                    prompt = canonical(supplied)
                    size = len((prompt+instructions+canonical(output_type.model_json_schema())).encode())
                    if size > config.max_input_bytes:
                        raise LiveResearchError('Evidence and structured schema exceed the approved input-byte limit.')
                    stage = 'provider_request'
                    execution = gateway.run(config, prompt)
                    candidate = redact(execution.pop('candidate'), secret)
                    metadata.update(redact(execution, secret))
                    stage = 'research_evidence_validation'
                    result = validate_fn(candidate, supplied)
                    metadata['evidence_validation'] = assess_fn(candidate, supplied)
                    if spec and hasattr(spec,'render'):
                        rendered=spec.render(result,supplied)
                except Exception as exc:
                    # Never stringify provider/validation exceptions: they may echo keys,
                    # raw outputs or input. All errors recorded below are safe categories.
                    failure = safe_failure(exc, secret)
                    transport = getattr(gateway, 'transport', None)
                    if transport is not None:
                        metadata['provider_attempts'] = transport.attempts
                        if getattr(transport, 'served_model', None) is not None:
                            metadata['model_served'] = redact(transport.served_model, secret)
                        if getattr(transport, 'reported_usage', None) is not None and metadata['usage'] is None:
                            metadata['usage'] = transport.reported_usage
                        if stage == 'provider_request' and getattr(transport, 'response_status', None) == 200:
                            stage = 'provider_response_processing'
                    if role==2 and stage in ('provider_request','provider_response_processing','research_evidence_validation'):
                        from .agent2_spans import failure_metadata
                        if isinstance(gateway,SDKAgent2) and gateway.output_type is Agent2Result:
                            selection_metadata=failure_metadata(gateway,canonical(supplied),secret)
                            if selection_metadata is not None:
                                metadata['evidence_selection']=redact(selection_metadata,secret)
                    diagnostics = provider_diagnostics(exc, secret, stage)
                    if diagnostics['http_status'] is None and transport is not None:
                        diagnostics['http_status'] = getattr(transport, 'response_status', None)
                    metadata['failure_diagnostics'] = diagnostics
                    if isinstance(exc, EvidenceValidationError):
                        metadata['evidence_validation'] = exc.assessment
                    if diagnostics['provider_request_id'] and diagnostics['provider_request_id'] not in metadata['request_ids']:
                        metadata['request_ids'].append(diagnostics['provider_request_id'])
                ended = utc()
                envelope = redact(dict(contract_version=version, run_id=run_id, **{subject_key:cve}, workspace_id=w,
                    **({'model_candidate':candidate} if spec and getattr(spec,'record_candidate',False) else {}),
                    **({'rendered':rendered} if spec and hasattr(spec,'render') else {}),
                    **({'assessment_input':supplied} if spec and getattr(spec,'record_input',False) else {}),
                    **({'evidence_as_of': supplied['as_of']} if spec else {}),
                    **({'candidate_rendering_origin':'deterministic_agent2_span_extraction_v1'} if role==2 and 'evidence_selection' in metadata else {}),
                    generation=generation, workspace_identity=workspace['database_identity'], started_at=started,
                    ended_at=ended, workflow_duration_seconds=time.monotonic()-wall_start,
                    synthetic_effective_at=clock, execution=metadata, sources=supplied['sources'],
                    result=result.model_dump() if result else None, error=failure,
                    quarantined_candidate=candidate if failure and len(canonical(candidate)) <= 20000 else None,
                    source_limitations=supplied['source_limitations'],
                    review_status='Pending analyst review' if result else 'Rejected/quarantined',
                    safety='Research recommendation only; no batch/ticket/message/closure/risk authority.'), secret)
                envelope['proposal_hash'] = digest(envelope)
                with engine.begin() as c:
                    if result:
                        for field in (() if spec else CLAIM_FIELDS):
                            claim = getattr(result, field)
                            for quote in claim.evidence:
                                c.execute(tables['evidence_claims'].insert().values(id=str(uuid4()), workspace_id=w,
                                    source_id=quote.source_id, cve_id=cve, claim_type='LiveResearch:'+field,
                                    statement=claim.value or 'Conflicting evidence; analyst review required',
                                    supporting_excerpt=quote.excerpt, validation_status='Proposed',
                                    validator=None, validated_at=None))
                    status = 'Awaiting Approval' if result else 'Failed'
                    c.execute(tables['runs'].update().where(tables['runs'].c.workspace_id == w,
                        tables['runs'].c.id == run_id).values(status=status, ended_at=ended))
                    c.execute(tables['agent_steps'].insert().values(id=stable(w, run_id, RESULT_KEY), workspace_id=w,
                        run_id=run_id, role_number=role, step_key=result_key, attempt=1, status=status,
                        model=config.model, prompt_version=version, input_hash=digest(supplied), output_json=canonical(envelope),
                        error_json=canonical({'category': 'ProviderError' if stage in ('provider_request', 'provider_response_processing')
                                             else 'ResearchValidationRejected' if stage == 'research_evidence_validation' else 'EvidenceUnavailable',
                                             'message': failure, 'diagnostics': metadata.get('failure_diagnostics')}) if failure else None,
                        token_usage_json=canonical(metadata['usage']) if metadata.get('usage') is not None else None))
                    audit(c, w, events+'Proposed' if result else events+'Failed', 'runs', run_id, 0,
                          dict(proposal_hash=envelope['proposal_hash'], origin=gateway.origin,
                               error=failure, execution=metadata), actor_id=actor, actor_type='analyst')
                receipt.update(run_id=run_id, status=status, provider_attempts=metadata['provider_attempts'])
                return envelope
            except LiveResearchError:
                raise
            except Exception as exc:
                # Translate BEFORE exiting DemoManager.execution, whose lease audit
                # records exception text. Never leak raw SDK/SQL parameters there.
                with engine.begin() as c:
                    existing = c.scalar(select(tables['runs'].c.status).where(tables['runs'].c.workspace_id == w,
                                                                                tables['runs'].c.id == run_id))
                    if existing == 'Running':
                        c.execute(tables['runs'].update().where(tables['runs'].c.workspace_id == w,
                            tables['runs'].c.id == run_id).values(status='Failed', ended_at=utc()))
                        audit(c, w, events+'PersistenceFailed', 'runs', run_id, 0,
                              {'error_category': type(exc).__name__, 'notice': 'No automatic retry; inspect the recorded attempt.'})
                raise LiveResearchError('Research persistence failed safely; inspect the run audit. No automatic retry.') from None
            finally:
                engine.dispose()
    except Exception as exc:
        if isinstance(exc, LiveResearchError):
            raise
        raise LiveResearchError('Research workflow could not complete safely; inspect recorded run/lease state. No automatic retry.') from None


def review(manager, generation, *, run_id, proposal_hash, decision, confirmed, actor, reason, spec=None):
    result_key = spec.result_key if spec else RESULT_KEY
    events = spec.events if spec else "LiveResearch"
    if not confirmed or not actor.strip() or not reason.strip() or decision not in ('Accepted for analyst use', 'Rejected'):
        raise LiveResearchError('Explicit analyst confirmation, reason and valid research decision are required.')
    with manager.execution(generation, 'review_agent'+str(spec.role if spec else 2)+'_research') as (path, workspace, clock, receipt):
        engine = make_engine(path)
        try:
            with engine.begin() as c:
                step = c.execute(select(tables['agent_steps']).where(tables['agent_steps'].c.workspace_id == workspace['id'],
                    tables['agent_steps'].c.run_id == run_id, tables['agent_steps'].c.step_key == result_key)).mappings().one_or_none()
                if not step:
                    raise LiveResearchError('Research result not found in this workspace.')
                payload = json.loads(step['output_json'])
                intact = digest({k: v for k, v in payload.items() if k != 'proposal_hash'}) == payload['proposal_hash']
                if (not intact or payload['proposal_hash'] != proposal_hash or payload['generation'] != generation
                        or payload['workspace_identity'] != workspace['database_identity'] or not payload['result']):
                    raise LiveResearchError('Research review is stale, foreign, restored or quarantined.')
                previous = [e for e in records(c, 'audit_events', workspace['id'])
                            if e['event_type'] == events+'ReviewRecorded' and e['entity_id'] == run_id]
                if previous:
                    raise LiveResearchError('Research decision already recorded; immutable history is retained.')
                audit(c, workspace['id'], events+'ReviewRecorded', 'runs', run_id, 0,
                    redact(dict(proposal_hash=proposal_hash, decision=decision, reason=reason,
                                limitation='Research review only; not operational approval.')), actor_id=redact(actor), actor_type='analyst')
                c.execute(tables['runs'].update().where(tables['runs'].c.workspace_id == workspace['id'],
                    tables['runs'].c.id == run_id).values(status='Succeeded' if decision == 'Accepted for analyst use' else 'Cancelled'))
                receipt.update(run_id=run_id, decision=decision)
                return dict(run_id=run_id, decision=decision)
        finally:
            engine.dispose()
