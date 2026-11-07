# M4 local synthetic lifecycle scenario

`scenario.json` defines explicitly synthetic analyst, resolver and scanner actions. It reuses the unchanged versioned M2 scanner fixtures and captured M3 enrichment, without public retrieval, model calls, ServiceNow or email transport.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m vulnmgmt.lifecycle_demo
```

Default database: `artifacts/m4-lifecycle-v1.sqlite3`; reports: `artifacts/m4/lifecycle.json` and `lifecycle.md`. This dedicated database is seeded from the existing M2/M3 data, preserving the standalone earlier demo databases. A repeat invocation returns the saved scenario checkpoint without replaying side effects. Use `--database` and `--output-dir` for a separate fresh run; no reset/delete operation is implemented. A modified scenario under the same checkpoint is rejected by its content hash.

## Scenarios and honest evidence boundaries

1. Explicitly approve one member of the evidence-backed M3 OpenSSL proposal; separately approve its escalation and synthetic email. A proposed batch alone cannot create a ticket.
2. Import the exact repeated synthetic scanner export. The unchanged escalation is suppressed with `NoMaterialChange`; no new ticket, ticket revision or notification results.
3. Approve the second already-observed OpenSSL CVE into the same asset-level obligation. This is a **new CVE to the approved batch/ticket**, not a newly discovered global CVE or a fabricated third OpenSSL remediation equivalence. Update the existing ticket and separately approve its new message.
4. Seed a clearly hypothetical pre-enrichment Log4j ticket, with origin=seeded and no fabricated initial approval. Captured real KEV evidence and vendor guidance become newly available to that ticket after the capture clock, causing an approved revision with increased urgency/changed deadline. This is **new to the ticket**, not a claim that exploitation was globally discovered during replay.
5. Process a synthetic resolver completion claim into Pending Verification. A named analyst explicitly applies each interpretation. The claim does not prove successful remediation.
6. Record a partial synthetic scan that cannot close findings. Subsequent complete, explicit per-finding passing assessments close both findings and their ticket. These are synthetic fixture results, not executed real scanner tools.
7. Request an expiring risk exception, show zero accepted exceptions before review, then explicitly approve one. The finding remains unresolved and its underlying SLA due date is preserved.
8. Record an owner “vulnerability persists” reply without reopening a scanner-verified finding. Subsequent positive synthetic scanner evidence reopens one finding and the ticket, retaining the previous closure.

The CLI contains explicit simulated analyst decisions for demonstration. Those decisions are labeled and persisted. Application services never infer analyst approval from a resolver reply, a draft, an AI response or a general instruction to run a workflow.

## Verified results

- 1 new generated ticket + 1 seeded historical ticket = 2 total.
- 1 duplicate escalation suppressed; 2 material ticket revisions; 10 immutable ticket version records including status/exception changes.
- 3 generated email drafts, all explicitly approved before local simulated delivery; 3 persisted simulated receipts; zero real deliveries.
- 5 resolver replies processed: scheduled, unable to patch, completed, exception requested and vulnerability persists.
- 2 scanner-confirmed synthetic closures, 1 partial assessment without closure and 1 subsequent scanner-confirmed reopening.
- 1 approved expiring exception; no acceptance is inferred from its request.
- Zero model calls or external communications. All original M2 rows and M3 sources are retained; verification adds synthetic scanner records rather than overwriting originals.

## Hypothetical SLA

Precedence for Critical: confirmed-known-exploitation policy trigger 24 hours, otherwise explicit verified technical exploitability 72 hours, otherwise 14 days. High: 30 days; Medium: 60 days; Low: 90 days. Calendar hours in UTC, anchored to each finding's earliest validated scanner observation; batch deadline is the earliest member deadline. New information can make an existing obligation immediately overdue; scans, scheduling and reminders never reset the clock.

The “actively exploited” urgency label uses verified KEV/explicit exploitation evidence as a **hypothetical prioritization trigger**, not proof of an active attack against the agency. EPSS alone never activates it or the technical-exploitability tier. Informational findings use the 90-day fallback; unknown severity requires review with no invented due date.

An approved exception temporarily pauses effective overdue until its specified expiry, while preserving the underlying due date/overdue state. It never closes a vulnerability. Expiry is evaluated from the supplied UTC clock even without a maintenance job. Scheduled/unable-to-patch replies grant no extension. All of this is illustrative policy, not a state mandate or CISA remediation deadline.

## Limits

This is a trusted local backend with named analyst decisions, not production authentication/RBAC. Reply interpretation recognizes explicit prefixes; unsupported free text requires review. Ambiguous routing, stale applicability and conflicting remediation identities require reconciliation. There is no real mailbox, ticketing integration, background scheduler, model invocation or dashboard. Full automated reset/replay management remains M5 work; this CLI preserves an immutable completed checkpoint.
