"""Replay-first M3 pipeline. Evidence storage/matching is deterministic and auditable."""
import json
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from .database import tables
from .enrichment_evidence import (assess_threat, freshness, load_bundle, timestamp,
                                 validate_guidance, validate_rule, validate_source, version_applies)
from .enrichment_evidence import validate_candidate
from .research_contracts import ApplicabilityAssumption, Guidance, RemediationRule, BatchCandidate, ResearchInput
from .research_sources import RESEARCH_DIR
from .services import audit, canonical, digest, stable, utc


def _put(connection, name, values):
    """Idempotent insertion of content-addressed records; never update evidence history."""
    t = tables[name]
    if connection.scalar(select(t.c.id).where(t.c.id == values['id'])) is None:
        connection.execute(t.insert().values(**values))


def _step(c, w, run_id, role, key, payload, status='Succeeded', error=None):
    run_input_hash = c.scalar(select(tables['runs'].c.input_hash).where(tables['runs'].c.id == run_id))
    c.execute(tables['agent_steps'].insert().values(
        id=stable(w, 'step', run_id, role, key), workspace_id=w, run_id=run_id,
        role_number=role, step_key=key, attempt=1, status=status, model=None,
        prompt_version='m3-v1-human-curated-replay', input_hash=digest(
            {'run_input_hash': run_input_hash, 'role': role, 'step_key': key}),
        output_json=canonical(payload) if error is None else None,
        error_json=canonical({'error': error}) if error else None, token_usage_json=None))


def _execute(c, w, version, run_id, manifest, sources, replay, as_of, use_assumptions):
    guidance = [Guidance.model_validate_json(canonical(v)) for v in replay['guidance']]
    if replay.get('origin') != 'human_curated_source_backed_replay' or replay.get('model_calls_recorded') != 0:
        raise ValueError('Replay origin must disclose human curation and zero recorded model calls')
    by_cve = {g.cve_id: g for g in guidance}
    ResearchInput.model_validate_json(canonical(dict(cve_ids=sorted(by_cve), source_ids=sorted(sources),
                                                    mode='replay', effective_at=as_of)))
    if len(by_cve) != len(guidance):
        raise ValueError('Duplicate CVE guidance')
    findings = list(c.execute(select(tables['asset_cves']).where(
        tables['asset_cves'].c.workspace_id == w)).mappings())
    if {f['cve_id'] for f in findings} - set(by_cve):
        raise ValueError('Replay missing observed CVE coverage')
    for g in guidance:
        validate_guidance(g, sources)
    rules = [RemediationRule.model_validate_json(canonical(v)) for v in replay['rules']]
    for rule in rules:
        validate_rule(rule, by_cve, sources)
    source_ids, source_states = {}, {}
    for name, source in sources.items():
        valid = validate_source(source)
        source_states[name] = {'usable': valid, 'freshness': freshness(source, as_of),
                               'url': source['url'], 'retrieved_at': source['retrieved_at'],
                               'expires_at': source['expires_at'], 'confidence': source['confidence'] if valid else 'unavailable'}
        id = stable(w, 'research-source', name, digest(source))
        source_ids[name] = id
        _put(c, 'evidence_sources', dict(id=id, workspace_id=w, url=source['url'],
            publisher=f'Public {source["kind"]} source / replay snapshot', retrieved_at=source['retrieved_at'],
            published_at=source.get('published_at'), content_hash=source['content_sha256'],
            snapshot_json=canonical(source) if source['fetch_status'] == 'Success' else None,
            fetch_status=source['fetch_status'], error=source['error']))
    audit(c, w, 'ReplayEvidenceLoaded', 'runs', run_id, 0,
          {'source_hashes': {name: s['content_sha256'] for name, s in sources.items()},
           'current_retrieval_performed': False, 'origin': replay['origin']})
    vendor_claims = {}
    dossiers = []
    for g in guidance:
        # Affected JSON is stored as a source-checked fact, not an installed asset assertion.
        claim_id = stable(w, 'cve-research', g.cve_id, digest(g.model_dump(mode='json')), source_ids[g.affected_source_id])
        _put(c, 'evidence_claims', dict(id=claim_id, workspace_id=w, source_id=source_ids[g.affected_source_id],
            cve_id=g.cve_id, claim_type='PublishedAffectedProducts', statement='Published CNA product/version data; not synthetic asset applicability',
            supporting_excerpt=g.affected_json, validation_status='Confirmed',
            validator='Deterministic CNA JSON equality check', validated_at=utc()))
        if g.status == 'Supported':
            vendor_id = stable(w, 'vendor-guidance', g.cve_id, source_ids[g.vendor_source_id], g.instructions)
            vendor_claims[g.cve_id] = vendor_id
            _put(c, 'evidence_claims', dict(id=vendor_id, workspace_id=w,
                source_id=source_ids[g.vendor_source_id], cve_id=g.cve_id, claim_type='VendorRemediation',
                statement=f'Historical CVE fix: {g.instructions}', supporting_excerpt=g.instructions,
                validation_status='Confirmed', validator='Source excerpt and curated record validation', validated_at=utc()))
        threat = assess_threat(g.cve_id, sources)
        if threat.kev_source_id:
            source = sources[threat.kev_source_id]
            published = json.loads(source['body'])['dateReleased']
            _put(c, 'threat_intel', dict(id=stable(w, 'intel', g.cve_id, 'KEV', source_ids[threat.kev_source_id]),
                workspace_id=w, cve_id=g.cve_id, kind='KEV', source_id=source_ids[threat.kev_source_id],
                as_of=published, expires_at=source['expires_at'], kev_member=int(threat.kev_member),
                kev_added_date=threat.kev_added_date, validation_status='Confirmed'))
        if threat.epss_source_id:
            source = sources[threat.epss_source_id]
            _put(c, 'threat_intel', dict(id=stable(w, 'intel', g.cve_id, 'EPSS', source_ids[threat.epss_source_id]),
                workspace_id=w, cve_id=g.cve_id, kind='EPSS', source_id=source_ids[threat.epss_source_id],
                as_of=threat.epss_date+'T00:00:00Z', expires_at=source['expires_at'],
                epss_score=threat.epss_score, epss_percentile=threat.epss_percentile, validation_status='Confirmed'))
        _put(c, 'threat_intel', dict(id=stable(w, 'intel', g.cve_id, 'Sector', source_ids[g.affected_source_id]),
            workspace_id=w, cve_id=g.cve_id, kind='Sector', source_id=source_ids[g.affected_source_id],
            as_of=sources[g.affected_source_id]['retrieved_at'], expires_at=sources[g.affected_source_id]['expires_at'],
            sector='State government', assessment='Unknown', validation_status='Proposed'))
        referenced = {g.affected_source_id, g.vendor_source_id, threat.kev_source_id, threat.epss_source_id} - {None}
        referenced |= {citation.source_id for citation in threat.exploitation_citations}
        dossier = {'remediation': g.model_dump(mode='json'), 'threat': threat.model_dump(mode='json'),
                   'freshness': {name: state['freshness'] for name, state in source_states.items()
                                 if name in (g.affected_source_id, g.vendor_source_id, threat.kev_source_id, threat.epss_source_id)},
                   'source_urls': {name: sources[name]['url'] for name in sorted(referenced)}}
        dossiers.append(dossier)
        _step(c, w, run_id, 2, g.cve_id, {'origin': replay['origin'], 'guidance': g.model_dump(mode='json')})
        _step(c, w, run_id, 4, g.cve_id, {'origin': 'deterministic_captured_feed_parser',
              'threat': threat.model_dump(mode='json'), 'current_retrieval_performed': False})
    proposals, review, assumed_members = [], [], set()
    assumptions = [ApplicabilityAssumption.model_validate_json(canonical(v)) for v in replay['assumptions']] if use_assumptions else []
    for assumption in assumptions:
        assets, components = tables['assets'], tables['asset_components']
        component = c.execute(select(components).join(assets,
            (assets.c.id == components.c.asset_id) & (assets.c.workspace_id == components.c.workspace_id)).where(
                components.c.workspace_id == w, assets.c.asset_key == assumption.asset_key,
                components.c.component_key == assumption.component_key)).mappings().one_or_none()
        if (component is None or component['revision'] != assumption.expected_component_revision
                or component['installed_version'] is not None):
            review.append(f'{assumption.asset_key}: stale/missing assumption binding; analyst review required')
            continue
        assumption_id = stable(w, 'synthetic-applicability', component['id'], replay['overlay_version'])
        prior_assumption = c.execute(select(tables['synthetic_applicability']).where(
            tables['synthetic_applicability'].c.id == assumption_id)).mappings().first()
        if prior_assumption and prior_assumption['assumption_hash'] != digest(assumption.model_dump(mode='json')):
            raise ValueError('Synthetic applicability changed without an overlay version increment')
        _put(c, 'synthetic_applicability', dict(id=assumption_id, workspace_id=w, component_id=component['id'],
            expected_component_revision=assumption.expected_component_revision, overlay_version=replay['overlay_version'],
            product=assumption.product, installed_version=assumption.installed_version, label=assumption.label,
            assumption_hash=digest(assumption.model_dump(mode='json')), created_at=utc()))
        for rule in rules:
            if rule.product != assumption.product or not version_applies(assumption.installed_version, rule):
                review.append(f'{assumption.asset_key}: product/version not covered by reviewed upstream rule')
                continue
            members = [f for f in findings if f['component_id'] == component['id'] and f['cve_id'] in rule.cve_ids
                       and f['status'] in ('Open', 'In Remediation')]
            if len(members) < 2:
                review.append(f'{assumption.asset_key}: fewer than two unresolved applicable findings')
                continue
            required = {rule.source_id} | {by_cve[f['cve_id']].affected_source_id for f in members}
            if any(source_states[name]['freshness'] != 'Fresh' for name in required):
                review.append(f'{assumption.asset_key}: stale/future evidence prevents a supported batch proposal')
                continue
            candidate = BatchCandidate(asset_id=component['asset_id'], action_key=rule.action_key,
                member_ids=[f['id'] for f in members], source_ids=sorted(required),
                assumption_label=assumption.label, status='Proposed', requires_analyst_review=True)
            validate_candidate(candidate, findings, assumption, rule, sources, as_of)
            action_id = stable(w, 'vendor-action', rule.action_key, digest(rule.model_dump(mode='json')), source_ids[rule.source_id])
            prior_revisions = list(c.scalars(select(tables['remediation_actions'].c.revision).where(
                tables['remediation_actions'].c.workspace_id == w,
                tables['remediation_actions'].c.action_key == rule.action_key)))
            action_revision = max(prior_revisions, default=-1)+1
            _put(c, 'remediation_actions', dict(id=action_id, workspace_id=w, action_key=rule.action_key,
                revision=action_revision, product=rule.product, applicability_json=canonical(rule.model_dump(mode='json')),
                instructions=rule.instruction, status='Confirmed'))  # Vendor fact only, NOT analyst batch approval.
            for f in members:
                _put(c, 'action_evidence', dict(id=stable(w, 'action-evidence', action_id, vendor_claims[f['cve_id']]),
                    workspace_id=w, action_id=action_id, claim_id=vendor_claims[f['cve_id']]))
            batch_id = stable(w, 'remediation-proposal', component['asset_id'], action_id, assumption_id)
            _put(c, 'remediation_batches', dict(id=batch_id, workspace_id=w, asset_id=component['asset_id'],
                action_id=action_id, cycle=1, status='Proposed', revision=0, confirmed_by=None, confirmed_at=None))
            for f in members:
                _put(c, 'batch_proposal_members', dict(id=stable(w, 'proposed-member', batch_id, f['id']),
                    workspace_id=w, batch_id=batch_id, asset_cve_id=f['id'], assumption_id=assumption_id,
                    evidence_claim_id=vendor_claims[f['cve_id']], source_hash=sources[rule.source_id]['content_sha256'],
                    created_at=utc()))
                assumed_members.add(f['id'])
            proposal = dict(batch_id=batch_id, asset_id=component['asset_id'], asset_key=assumption.asset_key,
                component_id=component['id'], action=rule.model_dump(mode='json'), assumption=assumption.model_dump(mode='json'),
                member_ids=sorted(f['id'] for f in members), cve_ids=sorted(f['cve_id'] for f in members),
                status='Proposed', requires_analyst_review=True, approved=False)
            proposals.append(proposal)
            audit(c, w, 'RemediationBatchProposed', 'remediation_batches', batch_id, 0,
                  {'run_id': run_id, 'origin': replay['origin'], 'approved': False, 'assumption': assumption.model_dump(mode='json')})
    review.append(f'{len(findings)-len(assumed_members)} findings have unknown product/version applicability; no batching inferred')
    gaps = sorted({gap for g in guidance for gap in g.gaps} |
                  {gap for dossier in dossiers for gap in dossier['threat']['gaps']} | set(review))
    summary = dict(cves_enriched=len(guidance), http_sources_captured=sum(s['fetch_status']=='Success' for s in sources.values()),
        sources_verified=sum(s['usable'] for s in source_states.values()),
        unusable_sources=sum(not s['usable'] for s in source_states.values()),
        stale_or_future_sources=sum(s['freshness'] != 'Fresh' for s in source_states.values()),
        supported_guidance=sum(g.status=='Supported' for g in guidance),
        conflicting_guidance=sum(g.status=='Conflicting' for g in guidance),
        missing_patch_guidance=sum(g.status=='Missing' for g in guidance),
        kev_members=sum(d['threat']['kev_member'] is True for d in dossiers),
        epss_available=sum(d['threat']['epss_score'] is not None for d in dossiers),
        sector_targeting_unknown=sum(d['threat']['sector_targeting']=='Unknown' for d in dossiers),
        proposed_batches=len(proposals), approved_batches=0, unknown_applicability_records=len(findings)-len(assumed_members),
        synthetic_assumed_applicability_records=len(assumed_members), unresolved_evidence_gaps=len(gaps),
        real_model_calls=0, current_source_retrievals=0)
    result = dict(schema_version='1', mode='replay', origin=replay['origin'], run_id=run_id,
        evidence_as_of=as_of, historical_replay=True, summary=summary, sources=source_states,
        cves=dossiers, proposed_batches=proposals, review_reasons=review, evidence_gaps=gaps)
    _step(c, w, run_id, 3, 'final-summary', result,
          status='Awaiting Approval' if proposals else 'Succeeded')
    return result


def enrich(engine, workspace_id, scenario_version_id, *, directory=RESEARCH_DIR, as_of=None,
           use_assumptions=True, mode='replay'):
    if mode != 'replay':
        from .reasoning import run_live
        run_live()  # Explicit denial before any model client, network call or DB update.
    manifest, sources, replay = load_bundle(directory)
    effective = as_of or manifest['replay_reference_time']
    if timestamp(effective) < timestamp(manifest['replay_reference_time']):
        raise ValueError('Replay cannot claim evidence was available before bundle capture')
    w = str(workspace_id)
    version = str(scenario_version_id)
    run_values = None
    try:
        with engine.begin() as c:
            workspace = c.execute(select(tables['demo_workspaces']).where(tables['demo_workspaces'].c.id == w)).mappings().one()
            if workspace['scenario_version_id'] != version or not workspace['synthetic_only'] or workspace['state'] != 'Ready':
                raise ValueError('M3 requires a ready, matching synthetic workspace')
            state = [dict(r) for r in c.execute(select(tables['asset_cves']).where(
                tables['asset_cves'].c.workspace_id == w).order_by(tables['asset_cves'].c.id)).mappings()]
            components = [dict(r) for r in c.execute(select(tables['asset_components']).where(
                tables['asset_components'].c.workspace_id == w).order_by(tables['asset_components'].c.id)).mappings()]
            implementation_hash = sha256(''.join((Path(__file__).parent/name).read_text(encoding='utf-8')
                for name in ('enrichment.py', 'enrichment_evidence.py', 'research_contracts.py')).encode('utf-8')).hexdigest()
            input_hash = digest({'manifest': manifest, 'state': state, 'components': components,
                                 'implementation_hash': implementation_hash,
                                 'generation': workspace['generation'], 'as_of': effective, 'assumptions': use_assumptions})
            run_id = stable(w, 'm3-run', input_hash)
            old = c.execute(select(tables['runs']).where(tables['runs'].c.id == run_id)).mappings().first()
            if old:
                if old['status'] == 'Failed':
                    raise ValueError('Identical input previously failed validation; see audited error')
                stored = c.scalar(select(tables['agent_steps'].c.output_json).where(
                    tables['agent_steps'].c.run_id == run_id, tables['agent_steps'].c.step_key == 'final-summary'))
                return json.loads(stored)
            run_values = dict(id=run_id, workspace_id=w, scenario_version_id=version, mode='replay',
                effective_clock=effective, started_at=utc(), input_hash=input_hash, contract_version='m3-v1')
            c.execute(tables['runs'].insert().values(**run_values, status='Running'))
            result = _execute(c, w, version, run_id, manifest, sources, replay, effective, use_assumptions)
            c.execute(tables['runs'].update().where(tables['runs'].c.id == run_id).values(
                status='Awaiting Approval' if result['proposed_batches'] else 'Succeeded', ended_at=utc()))
            audit(c, w, 'EnrichmentReplayCompleted', 'runs', run_id, 0, result['summary'])
        return result
    except Exception as error:
        if run_values is not None:
            with engine.begin() as c:
                _put(c, 'runs', run_values | {'status': 'Failed', 'ended_at': utc()})
                if c.scalar(select(tables['agent_steps'].c.id).where(tables['agent_steps'].c.run_id == run_id)) is None:
                    _step(c, w, run_id, 2, 'validation-failed', {}, status='Failed', error=str(error))
                    audit(c, w, 'EnrichmentReplayFailed', 'runs', run_id, 0, {'error': str(error)})
        raise
