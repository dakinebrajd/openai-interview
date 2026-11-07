# Baseline provenance and intentional differences

Accepted input: frozen November 7, 2026 v4 runtime code bundle, 173 pinned runtime files. This package copies selected source and fixtures from that bundle, not the dirty canonical checkout and not the unaccepted report redesign. Runtime app.py is replaced by a fail-closed migration placeholder. Original preview launcher and local Streamlit configuration are omitted because they require a specific local immutable runtime and existing state.

Source manifest labels tests/dependency pins separately: these came from the canonical project and are not part of the frozen bundle. No full prior test or browser acceptance claim transfers.

Package-only changes:
1. runtime_binding.py: default live_enabled=False; require_live unconditionally rejects.
2. credentials.py: OS credential access and for_operation reject without consulting a store.
3. live_ui_policy.py: hides live controls whenever live_enabled=False.
4. Two copies of captured public CISA sector-log4j fixture text contained Windows user-path-shaped strings. These were conservatively replaced with LOCAL_PATH_REMOVED. Content identities/references and affected package manifest file hashes were recomputed. No original input or prior evidence was changed. These sanitized capture variants need source/quotation validation before relying on that evidence.
5. New fail-closed entrypoint, setup metadata, documentation and migration safety tests.

Excluded: saved databases, accounting ledgers, snapshots, logs, screenshots, source-control history, virtual environments, secret stores, operational runbooks and local absolute paths. Synthetic/public fixtures retain their provenance and historical dates; they do not prove current applicability or current EPSS freshness.
