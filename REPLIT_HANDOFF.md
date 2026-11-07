# Replit implementation handoff

Build a portable, Replay-only demonstration of this existing Streamlit vulnerability-management application. Preserve its deterministic security and workflow rules. Do not replace it with a generic dashboard or silently remove validation to make it launch.

## Baseline and boundaries
Source is the accepted frozen November 7, 2026 v4 release (173-file runtime bundle), not a Git commit snapshot. The original repository's latest historical commit does not represent the accepted bundle. SOURCE_MANIFEST.json identifies copied source byte hashes. The unaccepted resolver-report candidate is deliberately excluded. This package makes safety/sanitization changes and is not byte-identical to the accepted running application.

No existing runtime state or accounting authority transfers. Never invent new allowance, seed a paid authorization, import old ledgers, obtain keys or enable provider calls. Package code blocks shared live execution and credential access. Those blocks must remain during this migration. Do not execute audit_tools live drivers. No external communications, public publishing, paid deployment or integration setup without separate approval.

## Phase 1: isolated portable Replay launch
1. Inspect the architecture and fixtures. Create a Linux dependency lock from the direct pins using Python 3.13, reporting any unavailable/incompatible versions instead of silently substituting them.
2. Implement an explicit `portable-replay` runtime mode with separate new state roots, synthetic-only state creation and no canonical-project or campaign-ledger dependency. Do not weaken the original existing-only validation. The current local-default initializes a campaign; simply launching `vulnmgmt.ui.main` is not an approved bootstrap.
3. Separate Replay application state initialization from paid campaign initialization and budget display. Use an inert unavailable-budget interface for Replay, not a fresh authorization ledger. Keep default mode Replay; stale Live settings and direct backend calls must fail before credential access/reservation/network.
4. Remove Windows Credential Manager setup from the portable UI. No environment-secret fallback. Keep genuine future live integration as a separate unimplemented capability.
5. Rebuild a new synthetic assessment from versioned fixture manifests. Do not recreate the old saved assessment or claim retained tickets/history. Handle unavailable historical dashboard data explicitly instead of fabricating prior results.
6. Implement a Streamlit launch on 0.0.0.0 and the platform-assigned PORT (fallback only if documented by host). Preserve XSRF/CORS protections and disable analytics. Confirm proxy/websocket behavior and environment isolation. Keep app private and access-controlled; analyst/resolver labels are not authentication or tenant isolation.
7. Demonstrate restart behavior on the selected hosting product. Workspace-local SQLite may be suitable for an explicitly disposable single-instance preview only after storage persistence is verified. Do not claim durable/multi-instance hosting on an ephemeral filesystem.

## Phase 2: durable PostgreSQL adaptation
This is NOT a DATABASE_URL substitution. `database.make_engine` hardcodes SQLite. Application catalogue, assessment/control state, workflow leases, budget code, schema fingerprints, triggers and snapshots use sqlite3 and SQLite semantics.

Create a reviewed persistence interface and new PostgreSQL migrations. Preserve frozen SQLite migration definitions; provide explicit version mapping and separate PostgreSQL schema/version fingerprints. Translate placeholders and SQL dialect, INSERT OR IGNORE/upserts, integer/boolean representation, row handling, UTC and JSON serialization, immutable audit triggers and foreign keys. Replace BEGIN IMMEDIATE with appropriate atomic transactions, row/advisory locking and serializable/retry handling. Demonstrate race-safe revision checks, grants (still disabled), ticket idempotency and lease ownership.

Design catalogue/assessment partitioning and generation rotation without assuming one file per assessment. Replace SQLite file copies/snapshots with transactionally consistent, auditable logical snapshots or provider-supported backups; restore must invalidate actionable approvals and retain audit history. No reset/deletion of arbitrary databases. Verify reconnect/restart, concurrent users, isolation, failover and backup/restore. Obtain separate approval before provisioning paid infrastructure or persistent credentials. Keep provider spending disabled throughout.

## Acceptance gates
- Source and fixture integrity, strict evidence quotations/references, unknown/failure provenance and no invented current patch/exploitation facts.
- Ingest overlapping synthetic Tenable/Defender inputs; deduplicate deterministically; preserve maximum severity and first-seen SLA clock.
- Exact revision-bound analyst approval; stale/double-click rejection; no real ticket/email delivery.
- Two distinct tickets/resolvers: report navigation and repeated actions affect only the intended ticket. Preserve data isolation.
- Owner closure claim enters Pending Verification. Only adequate subsequent scanner evidence reaches Verified Remediated. Missing findings alone do not close a vulnerability.
- Dashboard, queue, report and workflow state refresh coherently; Back/Close report does not close a ticket. Check 1280 and 1920 widths plus interrupted/repeated flows.
- All live entry paths reject before credentials, reservations or network, even with stale Live settings or supplied environment keys. Run tests with an outbound network deny guard.
- PostgreSQL-specific concurrent transaction, audit immutability, idempotency, approval binding, schema integrity, migration repeatability and backup/restore tests. The Windows SQLite suite is not PostgreSQL proof.
- Linux unit/integration tests plus real hosted browser acceptance, private-access check and restart/persistence check. Report exact passed/failed/not-run stages.

Deliver a reviewable diff, Linux dependency lock, new migration/rollback plan that preserves history, test results and a private preview only after approval. Do not claim migration complete until the actual hosted app and required persistence are verified.
