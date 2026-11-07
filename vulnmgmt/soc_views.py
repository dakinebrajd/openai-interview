"""SOC presentation only. Existing UI retains ownership of all workflow actions."""
import json
import os
from html import escape
import streamlit as st
from .soc_queries import command_center, intake, case_events, verification_rows, output_summary, has_recorded_live
from .ui_components import table, readable, horizontal_chart, SEVERITY, STATUS
from .enrichment_evidence import timestamp


def style():
    # Static design tokens only. Operational text is rendered by Streamlit or escaped.
    st.html('''<style>
    .stApp {background:#0B1220;color:#F8FAFC}
    [data-testid="stSidebar"] {background:#111827}
    .block-container {max-width:1600px;padding-top:2rem;padding-bottom:2rem}
    h1 {font-size:28px!important} h2,h3 {font-size:20px!important}
    p,li,label {font-size:14px}
    [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p,
    [data-testid="stCaptionContainer"] span {color:#CBD5E1!important;font-size:13px!important;opacity:1!important}
    [data-testid="stMetricLabel"] p {white-space:normal!important;overflow:visible!important;text-overflow:clip!important;color:#F8FAFC!important;line-height:1.4}
    .soc-clock {color:#F8FAFC;background:#172338;padding:10px 12px;border:1px solid #26364D;border-radius:8px;font-size:14px;line-height:1.5}
    .soc-clock time {display:block;white-space:normal}
    .soc-matrix {width:100%;border-collapse:collapse;font-size:13px;color:#F8FAFC}
    .soc-matrix td,.soc-matrix th {padding:8px 6px;text-align:left;border-bottom:1px solid #26364D}
    .soc-matrix .identifier,.soc-matrix time {white-space:nowrap;overflow-wrap:normal;word-break:normal}
    .soc-events {list-style:none;padding:0;margin:8px 0;color:#F8FAFC}
    .soc-events li {padding:10px 12px;border-left:3px solid #38BDF8;border-bottom:1px solid #26364D;font-size:14px;overflow-wrap:anywhere}
    .soc-events small {display:block;color:#CBD5E1;font-size:13px}
    .soc-output {padding:8px 0;border-bottom:1px solid #26364D;font-size:14px;line-height:1.5;color:#F8FAFC;overflow-wrap:anywhere}
    .soc-output span {color:#CBD5E1;font-size:13px}
    [data-testid="stMetricValue"] {font-size:32px}
    [data-testid="stVerticalBlockBorderWrapper"]>div {border-color:#26364D!important;border-radius:10px;background:#172338}
    .soc-flow {display:flex;gap:12px;align-items:stretch;margin:12px 0;flex-wrap:wrap}
    .soc-node {flex:1;min-width:130px;padding:16px;background:#172338;border:1px solid #26364D;border-radius:10px}
    .soc-node strong {display:block;font-size:22px;color:#F8FAFC;overflow-wrap:anywhere}
    .soc-node span {font-size:12px;color:#94A3B8;overflow-wrap:anywhere}
    .soc-arrow {align-self:center;color:#38BDF8;font-size:22px}
    .soc-outcomes {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
    .soc-outcomes div {padding:8px 12px;background:#172338;border-left:3px solid #38BDF8;font-size:12px}
    .soc-outcomes strong {font-size:18px;margin-right:8px}
    @media(max-width:900px){.soc-outcomes{grid-template-columns:repeat(2,minmax(0,1fr))}.soc-node{padding:12px}}
    </style>''')


def clock(value):
    st.html('<div class="soc-clock"><strong>Synthetic clock · UTC</strong><time datetime="'+escape(value, quote=True)+'">'+
            escape(str(readable(value, 'as_of')))+'</time></div>')


def flow(nodes, branches=None):
    """Connected cards with real values or explicitly instructional lifecycle labels."""
    html = '<div class="soc-flow" role="list">'
    for index, (label, value, detail) in enumerate(nodes):
        if index:
            html += '<div class="soc-arrow" aria-label="then">→</div>'
        html += ('<div class="soc-node" role="listitem"><span>'+escape(str(label))+
                 '</span><strong>'+escape(str(value))+'</strong><span>'+escape(str(detail))+'</span></div>')
    html += '</div>'
    if branches:
        html += '<div style="display:flex;gap:16px;flex-wrap:wrap;color:#94A3B8;font-size:12px">'+''.join(
            '<span>↳ '+escape(branch)+'</span>' for branch in branches)+'</div>'
    st.html(html)


def consolidation(data):
    s = command_center(data)['pipeline']
    st.subheader('Scanner consolidation pipeline')
    scanners = ' · '.join(r['scanner']+': '+str(r['received']) for r in intake(data)) or 'No imports recorded'
    flow([('RAW SCANNER FINDINGS', s['raw_findings'], scanners),
          ('VALID OBSERVATIONS', s['valid_rows'], 'Accepted scanner rows'),
          ('UNIQUE NORMALIZED FINDINGS', s['normalized_records'], 'Asset + component + CVE')],
         [f"Quarantine: {s['quarantined_rows']} observations ({s['unresolved_identity_conflicts']} identity conflicts)",
          f"Reduction: {s['duplicates_consolidated']} duplicate observation-to-CVE links"])
    st.caption('Deterministic Python · originals retained. Multi-CVE observations can create several links; link reduction is not always row subtraction.')


def outcomes(data):
    values = command_center(data)['outcomes']
    st.html('<div class="soc-outcomes" aria-label="Automation Outcomes">'+''.join(
        '<div><strong>'+str(value)+'</strong>'+escape(label)+'</div>' for label, value in values.items())+'</div>')
    st.caption('Automation Outcomes · deterministic consolidation and event counts; enrichment is historical human-curated evidence replay, not live AI. No measured time or cost savings.')


def correlation(data):
    consolidation(data)
    candidates = [f for f in data['findings'] if len({o['scanner'] for o in f['observations']}) > 1]
    if not candidates:
        st.info('No cross-scanner correlation example recorded in this workspace.')
        return
    batch_ids = {m['asset_cve_id'] for m in data['batch_proposal_members']}
    candidates.sort(key=lambda f: (f['id'] not in batch_ids, f['asset_key'], f['cve_id']))
    labels = {f['asset_key']+' · '+f['cve_id']+' · '+f['component_key']: f for f in candidates}
    selected = st.selectbox('Correlated finding example', list(labels), key='soc_correlation')
    f = labels[selected]
    st.write('**Actual correlation:** '+f['asset_key']+' · '+f['cve_id']+' · '+f['component_key'])
    table([dict(scanner=o['scanner'], original_severity=o['raw_severity'], observed_at=o['observed_at'])
           for o in f['observations']], height=170)
    st.caption('Highest retained severity: '+f['severity']+' · distinct asset/component identity is preserved.')
    with st.expander('Original correlated scanner payloads'):
        st.json(f['observations'], expanded=False)


def evidence_card(data):
    batch_ids = {m['asset_cve_id'] for m in data['batch_proposal_members']}
    batch_cves = {f['cve_id'] for f in data['findings'] if f['id'] in batch_ids}
    cves = sorted({f['cve_id'] for f in data['findings']}, key=lambda c: (c not in batch_cves, c))
    if not cves:
        st.info('Import findings before inspecting remediation evidence.')
        return
    selected = st.selectbox('Evidence card CVE', cves, key='soc_evidence_cve')
    claims = [c for c in data['evidence_claims'] if c['cve_id'] == selected]
    guidance_records = [json.loads(s['output_json'])['guidance'] for s in data['agent_steps']
                        if s['role_number'] == 2 and s['step_key'] == selected and s['output_json']]
    source_ids = {c['source_id'] for c in claims}
    findings = [f for f in data['findings'] if f['cve_id'] == selected]
    with st.container(border=True):
        st.write('**CVE Intelligence and Remediation Evidence · '+selected+'**')
        for f in findings[:3]:
            st.write(f['asset_key']+' · '+str(f['product'] or 'Product unknown')+' · '+f['applicability'])
        st.warning('Historical vendor guidance is not confirmed current applicability. Synthetic installed versions are assumptions, not scanner-verified inventory. Validate current vendor guidance before real use.')
        for g in guidance_records:
            st.write('**Captured guidance assessment:** '+g['status']+' · confidence '+g['confidence'])
            for gap in g['gaps']:
                st.write('Review required: '+gap)
            with st.expander('Published affected product/version evidence'):
                st.code(g['affected_json'], language='json', wrap_lines=True)
        guidance = [c for c in claims if c['claim_type'] == 'VendorRemediation']
        for c in guidance:
            st.write(c['statement'])
            st.caption('Evidence validation: '+c['validation_status'])
        if not guidance:
            st.write('Vendor remediation guidance: Unknown / unavailable. Human review required.')
        table([{'evidence_type': c['claim_type'], 'validation': c['validation_status'], 'evidence': c['statement']}
               for c in claims if c['claim_type'] != 'VendorRemediation'], height=150)
        for s in data['sources']:
            if s['id'] in source_ids:
                st.write(s['url'])
                freshness = ('Unknown' if not s.get('expires_at') else
                             'Expired' if timestamp(s['expires_at']) < timestamp(data['as_of']) else 'Within captured validity window')
                st.caption('Retrieved '+readable(s['retrieved_at'], 'retrieved_at')+' · freshness: '+freshness+' · '+s['fetch_status'])
        table([a for a in data['synthetic_applicability'] if a['component_id'] in {f['component_id'] for f in findings}],
              ['product', 'installed_version', 'label'], 140)
        st.caption('Human validation: reconcile product/version, source date, conflicting claims and current applicability. Missing evidence remains Unknown.')


def threat_matrix(data):
    st.subheader('Threat Prioritization Matrix')
    from .dashboard_queries import executive
    rows = executive(data)['action_queue'][:5]
    st.caption('Highest-priority open records · maximum five, ordered by the existing SLA/severity policy; no new risk score.')
    # Wrapped semantic table: all requested dimensions remain visible without a
    # wide dataframe's internal horizontal scroll at the recording resolutions.
    columns = [('asset_key', 'Asset'), ('cve_id', 'CVE'), ('severity', 'Severity'),
               ('kev_state', 'Captured KEV'), ('epss', 'EPSS'), ('epss_as_of', 'EPSS date (UTC)')]
    st.html('<table class="soc-matrix"><thead><tr>'+''.join(
        '<th>'+escape(label)+'</th>' for _, label in columns)+
        '</tr></thead><tbody>'+''.join('<tr>'+''.join(
            '<td'+(' class="identifier"' if key == 'cve_id' else '')+'>'+
            ('<time datetime="'+escape(r[key], quote=True)+'">'+escape(r[key][:10])+'</time>' if key == 'epss_as_of' and r.get(key)
             else escape(str(readable(r.get(key), key))))+'</td>'
            for key, _ in columns)+'</tr>' for r in rows)+'</tbody></table>')
    for r in rows:
        with st.expander(r['asset_key']+' · '+r['cve_id']+' — priority and applicability'):
            st.write('Priority: '+r['priority'])
            st.write('Applicability: '+r['applicability'])
            st.write('Sector targeting: '+r['sector_targeting']+' · evidence freshness: '+r['threat_freshness'])
            st.caption('Human review: validate the installed product/version and captured source dates. Neither KEV nor EPSS establishes an active agency attack.')
            from .threat_ui import stored, detail
            research = [p for p in stored(data) if p['cve_id'] == r['cve_id']]
            if research:
                detail(research[-1])
            else:
                st.caption('Processing: deterministic lookup over historical replay; Agent 4 exploitation/sector research not evaluated.')
    st.caption('KEV: confirmed captured membership / checked not listed / Unknown. EPSS is dated probability, not confirmed exploitation. Sector targeting remains Unknown unless evidence is recorded. Synthetic applicability requires human validation.')
    with st.expander('Selected CVE source evidence and remediation detail'):
        evidence_card(data)


def convergence(data):
    st.subheader('CVE-to-Remediation Convergence')
    from .batching_ui import stored as batching_stored, detail as batching_detail
    assessments=batching_stored(data)
    if assessments:
        with st.expander('Agent 3 recorded batching assessments · research proposals'):
            latest={p['component_id']:p for p in assessments}
            for payload in latest.values():
                batching_detail(payload,data)
    batches = [b for b in data['remediation_batches'] if any(m['batch_id'] == b['id'] for m in data['batch_proposal_members'])]
    if not batches:
        st.info('Review Required · no evidence-supported shared remediation proposal recorded.')
        return
    labels = {b['id']: b['status']+' · '+next((f['asset_key'] for f in data['findings'] if f['asset_id'] == b['asset_id']), 'Asset unknown')+' · proposal '+str(i)
              for i, b in enumerate(batches, 1)}
    label = st.selectbox('Visualized remediation proposal', list(labels.values()), key='soc_batch')
    b = next(b for b in batches if labels[b['id']] == label)
    ids = {m['asset_cve_id'] for m in data['batch_proposal_members'] if m['batch_id'] == b['id']}
    findings = [f for f in data['findings'] if f['id'] in ids]
    action = next((a for a in data['remediation_actions'] if a['id'] == b['action_id']), None)
    flow([('Included findings', ', '.join(f['cve_id'] for f in findings), str(len(findings))+' asset-vulnerability records'),
          ('Shared remediation proposal', b['status'], 'Approved' if b['confirmed_by'] else 'Analyst review required'),
          ('Affected asset', ', '.join(sorted({f['asset_key'] for f in findings})), 'Synthetic applicability assumption'),
          ('Resolver group', ', '.join(sorted({g for f in findings for g in f['resolver_groups']})), 'Existing ownership records')])
    if action:
        st.write('**Historical shared guidance:** '+action['instructions'])
    claims = {m['evidence_claim_id'] for m in data['batch_proposal_members'] if m['batch_id'] == b['id']}
    source_ids = {c['source_id'] for c in data['evidence_claims'] if c['id'] in claims}
    for s in data['sources']:
        if s['id'] in source_ids:
            st.write(s['url'])
            st.caption('Captured vendor evidence · retrieved '+readable(s['retrieved_at'], 'retrieved_at'))
    st.caption('Grouping proposes work; it does not establish that any vulnerability is resolved. Approval is bound to the exact proposal. Validate cited vendor evidence and synthetic version assumptions.')
    table(findings, ['asset_key', 'cve_id', 'severity', 'applicability', 'status'], 150)


def timeline(data, ticket_id=None, title='Escalation Decision Timeline'):
    st.subheader(title)
    st.caption('Workflow guide: finding identified → existing ticket checked → New / Update / Suppress → exact analyst approval → synthetic notification. Guide labels are instructional; only recorded events appear below.')
    events = case_events(data, ticket_id)
    if not events:
        st.info('No case events recorded. Prepare and review a proposal using the existing workflow controls.')
    st.html('<ol class="soc-events">'+''.join('<li><strong>'+escape(e['event'])+'</strong> · '+
        escape(e['evidence_reference'][:8])+'<small>'+escape(str(readable(e['at'], 'as_of')))+' · '+escape(e['time_basis'])+
        '</small>'+escape(e['detail'][:220])+('…' if len(e['detail']) > 220 else '')+'</li>'
        for e in [e for e in events if e['at']][-8:])+'</ol>')
    undated = [e for e in events if not e['at']]
    if undated:
        st.caption('Additional retained drafts (creation timestamps unavailable; no chronology inferred)')
        table(undated, ['event', 'detail'], 140)
    st.caption('New ticket / material update / unchanged duplicate suppression are distinct outcomes. Suppression creates no new ticket or notification. Unknown timestamps are not inferred.')
    with st.expander(title+' evidence references'):
        table(events, height=250)


def verification(data):
    st.subheader('Remediation Verification Lifecycle')
    horizontal_chart(data['counts']['status'], 'Current finding lifecycle', STATUS)
    st.caption('Lifecycle guide (not event counts): Escalated → In Progress → Pending Verification → Verified Remediated. Persistent vulnerability may reopen; an authorized expiring risk exception defers work and is never a completed fix.')
    table(verification_rows(data), ['finding', 'result', 'assessed_at', 'scan_status'], 180)
    if data['exceptions']:
        st.write('**Risk exceptions · deferment, not remediation**')
        table(data['exceptions'], ['status', 'reason', 'expires_at'], 140)
    with st.expander('Scanner assessment evidence and transition history'):
        table(data['scan_assessments'], ['assessed_at', 'scan_status', 'coverage_json'], 180)
        table(data['status_history'], ['from_status', 'to_status', 'occurred_at', 'reason'], 180)
    st.caption('Human validation: owner-reported completion stays Pending Verification until an adequate subsequent scanner assessment. Missing findings alone never prove remediation.')


def guided_visual(data, stage):
    st.caption('INPUT → PROCESSING → OUTPUT → EVIDENCE → HUMAN VALIDATION')
    if stage == 0:
        st.subheader('Scanner Intake Summary')
        counts = intake(data)
        horizontal_chart({r['scanner']: r['received'] for r in counts}, 'Scanner observations received', unit='Observations')
        table(counts, ['scanner', 'received', 'accepted', 'quarantined'], 150)
        st.caption('Identity conflicts requiring review: '+str(data['summary']['unresolved_identity_conflicts']))
        if data['findings']:
            with st.expander('Example original scanner payload'):
                st.json(data['findings'][0]['observations'][0]['payload'], expanded=False)
    elif stage == 1:
        correlation(data)
    elif stage == 2:
        evidence_card(data)
    elif stage == 3:
        convergence(data)
        threat_matrix(data)
    elif stage == 4:
        convergence(data)
    elif stage == 5:
        timeline(data)
    elif stage == 6:
        timeline(data, title='Resolver Communication Timeline')
        verification(data)
    else:
        verification(data)


COMPONENTS = [
    ('Orchestration', 'Route exact approved actions', 'Deterministic automation'),
    ('Scanner normalization', 'Validate identity, preserve severity and correlate observations', 'Deterministic automation'),
    ('Remediation research', 'Interpret retained vendor guidance', 'Historical evidence replay'),
    ('Remediation batching', 'Propose shared action; validate compatibility', 'Historical evidence replay + deterministic validation'),
    ('Threat intelligence', 'Separate dated KEV, EPSS and unknown targeting', 'Historical evidence replay'),
    ('Escalation identity', 'Compare New / Update / Suppress', 'Deterministic automation'),
    ('Reports and communications', 'Draft, separately approve and simulate notification', 'Deterministic automation'),
    ('Resolver and verification', 'Interpret claims; enforce scanner closure', 'Deterministic automation'),
    ('Dashboard', 'Render workspace-scoped records', 'Deterministic automation'),
    ('Scenario replay', 'Isolate synthetic scenarios, snapshot and rotate generations', 'Deterministic automation')]


def components(data, history):
    st.subheader('Component execution and evidence')
    for number, (name, responsibility, processing) in enumerate(COMPONENTS):
        steps = [s for s in data['agent_steps'] if s['role_number'] == number]
        if number == 2 and any(s['prompt_version'] == 'm6a-agent2-v1' for s in steps):
            processing = 'Historical replay + separately recorded research; inspect per-run mode'
        if number == 3 and any(s['step_key'] == 'agent3-batching-result' for s in steps):
            processing = 'Recorded batching research; inspect Replay / Offline Mock / Live AI origin'
        if number == 6 and any(s['step_key']=='agent6-drafting-result' for s in steps):
            processing = 'Recorded report/draft research; separate ticket and communication approvals'
        if number == 0 and any(s['step_key']=='orchestration-state' for s in steps):
            processing = 'Persisted deterministic coordination; inspect individual research modes and human gates'
        if number == 7 and any(s['step_key']=='agent7-reply-result' for s in steps):
            processing = 'Recorded reply interpretation; inspect Replay / Offline Mock origin; scanner-only verification'
        recorded_threat = number in (2,3,4,6,7) and has_recorded_live(data, role=number)
        if recorded_threat:
            processing = 'Historical replay + recorded Live AI research; analyst review required'
        with st.expander(f'{number} · {name} · {processing}', expanded=bool(steps)):
            st.write(responsibility)
            live = ('Live AI: opt-in requested; inspect configured gates and actual run records. Live validation remains separate.'
                    if os.environ.get('VM_LIVE_ENABLED') == '1' else 'Live AI: disabled and unvalidated.')
            if recorded_threat:
                live = 'Recorded live Agent '+str(number)+' execution available; inspect accepted/quarantined status. Human acceptance is separate. New live requests remain disabled.'
            st.caption('Human review: evidence/applicability validation and exact approvals remain mandatory. '+live)
            if steps:
                st.html(''.join('<div class="soc-output" data-step="'+escape(s['step_key'], quote=True)+'"><strong>'+escape(s['step_key'])+'</strong> · <span>'+escape(s['status'])+
                                '</span><div>'+escape(output_summary(s))+'</div></div>' for s in steps))
                with st.expander('Exact recorded component inputs and outputs'):
                    st.json(steps, expanded=False)
            else:
                st.caption('No component-level execution trace recorded. Logical component definition does not imply a model call.')
    st.write('**Recorded local workflow executions**')
    table(history['leases'], ['stage', 'status', 'started_at', 'ended_at', 'error'], 220)
    st.caption('Lease timestamps describe local workflow executions; no model duration, token usage or live trace is inferred.')
