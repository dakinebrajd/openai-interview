# Migration readiness

Status: source package prepared; Replit application migration NOT complete. No GitHub upload, Replit agent execution, package install, deployment, provider call or credential read performed by package preparation.

Verified locally on existing Windows Python 3.13 environment: selected foundation and scanner-ingestion suite, 127 tests passed in 15.37 seconds; final combined suite including 12 migration safety cases passed 139 tests in 20.92 seconds on the final source (rerun after restoring original UTF-8 UI text) with test network guard. That is a focused SQLite suite, not full app/UI, Linux, Replit or PostgreSQL acceptance. Initial broader test selection failed collection due to omitted helper modules and was narrowed to self-contained tests; no broad-suite success is claimed.

Remaining blockers:
- New portable Replay runtime/bootstrap is not implemented. Default startup intentionally stops.
- Existing immutable-preview paths/origin/preprovisioned-state requirements cannot be reused in Replit. Local-default can create a campaign and must not be used as the portable bootstrap.
- Windows-only credential/security UI must be removed from the portable experience, never replaced by automatic secret discovery.
- PostgreSQL adapter/schema/transaction/snapshot migration unimplemented. SQLite use is spread across multiple modules.
- Linux dependencies have not been installed/resolved; Windows wheel lock was not reused.
- Hosted websocket/proxy behavior, private access, restart/persistence, concurrent use and browser acceptance not run.
- Full model-validation and two-ticket regression suites need a separately curated portable test dependency set; included tests are deliberately limited.

Security scan is a bounded pattern/filename audit, not a guarantee that every possible secret or personal datum is absent. No credential stores, environment values or databases were opened. Public-source body path-like strings were sanitized conservatively. Final archive contains only manifest-listed package files, never test-generated state.
