# Synthetic scanner scenario v1

This is a versioned hypothetical state agency dataset, not a production scanner export specification. All assets, owners, groups, installations, findings, severity ratings and scan times are synthetic. No real system was scanned.

- 30 assets: 8 Windows servers, 8 Linux servers, 8 workstations, 6 web applications.
- 6 synthetic owner identities and 4 resolver groups, using example.invalid addresses.
- 31 explicit software assessment instances (one asset has two same-product instances). Installed versions are deliberately unknown; the placeholder products do not establish actual CVE applicability.
- 36 Tenable-style rows and 43 Defender-style rows: 79 original occurrences, including 2 identical repeated rows, 10 cross-scanner overlaps and 6 quarantine cases.
- Expected result: 73 valid observations/links, 61 unique asset/component/CVE records, 12 consolidated duplicate links, 6 quarantined rows, 3 unresolved identity cases.
- Quarantine cases: missing CVE, malformed CVE, ambiguous shared hostname without scanner ID, unknown device, unknown component, malformed timestamp. No hostname-only matching is permitted, even for one candidate.

The synthetic formats differ deliberately. Tenable v1 uses findings/plugin_id/host_uuid/component_key/cve/severity/last_seen with numeric severity 0-4. Defender v1 uses value/findingId/deviceId/softwareKey/cveId/severity/detectedAt with Informational/Low/Medium/High/Critical. Unknown non-null ratings become unknown rank; missing/null severity is quarantined. Adapters require a synthetic=true, format version 1 envelope, tenant/scan ID and timezone-aware export time. Extra row fields are preserved; extra envelope fields are rejected. These are not validated integrations with Tenable APIs/exports or Microsoft Defender APIs/exports.

`cve_sources.json` records twelve real CVE identifiers, their CVE Program Services URLs, actual retrieval/attempt timestamps, assigner/publication metadata and the checked cveMetadata subset. All twelve were observed as PUBLISHED with matching IDs on 2026-11-03. Verification applies only to identifier publication. It provides no evidence of asset applicability, exploitation, sector targeting, patch availability or remediation equivalence. Related identifiers on a shared assessment component are analyst review candidates only, never confirmed shared actions. Unverified/missing catalog entries are visibly marked and never eligible for remediation claims.

`manifest.json` pins all five fixture file hashes and expected counts. `tenable_repeat.json` is an exact copy of tenable.json; another filename never creates another import. Byte-identical exports are no-ops. A changed export (including byte-level formatting) is a new immutable import under the current scanner/tenant/scan/export-hash identity; source-to-finding deduplication still consolidates its observations.

Offline regeneration from the checked source catalog:

```powershell
.\.venv\Scripts\python.exe -m vulnmgmt.fixture_builder
```

This does not refresh source retrieval times or contact any service. Source refresh is a separate read-only research action; changes require deliberate manifest regeneration and a new scenario version before use against an existing versioned database. Current generator/loader implement v1 only and reject manifest changes against seeded v1 data; they do not reset or silently upgrade an existing scenario.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m vulnmgmt.demo
```

This creates/uses ignored artifacts/m2-demo.sqlite3, imports both formats, attempts the repeat file, asserts the expected SQLite-derived summary and exports artifacts/m2/vulnerability_register.json, vulnerability_register.md and ingestion_summary.json. Re-running preserves the same counts. No files/databases are deleted. Pass --database and --output-dir to use a separate fresh demonstration location.
