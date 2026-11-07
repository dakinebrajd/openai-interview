# Vulnerability-management demo: Replit migration input

This is a source-only migration starting point, not a working Replit deployment. Start with REPLIT_HANDOFF.md. `python app.py` intentionally stops with MIGRATION HOLD. No app database, saved assessment, spending ledger, credentials, Git history, private operational history or unaccepted report redesign is included.

## Contents
- `vulnmgmt/`: accepted frozen app modules, with three explicit package-only safety changes.
- `fixtures/`: synthetic scanner/workflow inputs and captured public research. Historical data is not current security advice.
- `audit_tools/`: source dependencies only, not authority to execute live workflows.
- `tests/`: foundation, scanner, and migration safety tests. This is not the entire original suite.
- `requirements.txt`: original direct dependency pins; Linux installation is not validated.
- `SOURCE_MANIFEST.json`: per-file provenance and original/package SHA-256.
- `PACKAGE_MANIFEST.json`: final distributable file hashes (excludes itself).
- `SECURITY_SCAN.json`, `READINESS.md`: audit scope and actual validation.

## Safe setup
Use Python 3.13, resolve `requirements.txt` in a new Linux environment, and produce a Linux dependency lock only after resolution and tests pass. The original Windows wheel lock is deliberately not shipped as a portable lock. No installation or dependency changes have been performed here.

`python -m pytest tests -q` runs the selected offline suite. `python app.py` is an intentional nonzero exit, not a web preview. Do not replace it with `streamlit run` until the portable Replay bootstrap and acceptance gates are implemented.

Only use synthetic data in this migration. Keep provider access, credential setup, real mail/tickets, publication and paid services disabled.
