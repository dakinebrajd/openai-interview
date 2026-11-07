# M3 evidence bundle v1

This is a **human-curated, source-backed replay**, not a recording of model execution. Zero live model calls were made. The network captures were real read-only retrievals; running replay loads those snapshots without performing current research.

The 25 source JSON files contain requested/final URLs, actual UTC retrieval timestamps, bounded retry/attempt history, response-body SHA-256, full UTF-8 body, source category, confidence and expiry. `manifest.json` pins each file and replay.json. The reference time is **2026-11-03T23:53:34.198526Z**, independent of M2's synthetic October observation clock. Replay must never imply these November snapshots were available in October.

## Source coverage

| Captures | Scope | Usable |
|---|---|---:|
| 12 CVE Program Services records | Matching published CNA affected-product/version records; structured assertions retained verbatim | 12 |
| CISA KEV and official cisagov mirror | Complete catalog/count checked; mirror is redundant, not independent corroboration | 2 |
| FIRST EPSS | Twelve dated score/percentile entries, distinct from exploitation evidence | 1 |
| Apache, OpenSSL, curl, two OpenSSH releases, Red Hat | Primary vendor pages/advisories | 6 |
| Two Microsoft MSRC pages | HTTP 200 JavaScript shells; **not usable patch guidance** | 0 |
| CISA AA22-174A | Documented Log4Shell exploitation; no curated state-government targeting conclusion | 1 |
| Official OpenAI SDK documentation | SDK architecture reference, not vulnerability evidence | 1 |

Thus 25 HTTP captures, **23 usable snapshots** (including the redundant catalog and SDK documentation), two unusable vendor shells. These are not 23 independent remediation advisories. Each source's exact URL/timestamp is in its JSON file and SQLite after ingestion. [OpenSSL advisory](https://openssl-library.org/news/secadv/20221101.txt), [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [FIRST EPSS API](https://api.first.org/data/v1/epss), [Apache security](https://logging.apache.org/security.html), and [curl advisory](https://curl.se/docs/CVE-2023-38545.html) are primary examples.

## Findings and boundaries

- All 12 M2 CVEs get dossiers with exact CNA affected data, cited vendor guidance when supported, KEV, EPSS, sector unknowns and review gaps.
- Seven dossiers have supported **historical CVE-specific** fix facts. These are not recommendations that old releases remain secure/supported today.
- Two conflicts: CVE-2021-44832's captured Apache table and CNA disagree on a fixed-version boundary; CVE-2023-38545's CNA interval is internally inconsistent with the curl vendor range. Retain both sources; no selected fix is asserted for either conflict.
- Three missing package-specific fix decisions: CVE-2023-23397, CVE-2021-34527 and CVE-2021-4034. No Microsoft KB or distribution build is invented.
- Captured KEV includes five identifiers; EPSS is available for twelve. A high EPSS score does not prove exploitation. No sector-specific targeting is verified. That does not mean targeting does not exist: sector research is incomplete, and the captured Log4j report does not establish state-government targeting.

## One deliberately synthetic applicability overlay

`replay.json` explicitly assumes that **LNX-SRV-005 / linux-assessment** represents upstream OpenSSL **3.0.6**. This is labeled `SYNTHETIC ASSUMPTION - NOT SCANNER EVIDENCE`, bound to component revision 0, and stored separately from the original component/scan records. No original installed version is changed.

The vendor advisory explicitly identifies both CVE-2022-3602 and CVE-2022-3786 as affecting 3.0.0–3.0.6 and instructs OpenSSL 3.0 users to upgrade to 3.0.7. The pipeline can therefore propose one asset-level, two-finding **historical demonstration batch**, pending analyst review. Its warning requires revalidating current supported releases before any real action. No patch is installed; no batch is approved; no finding changes status. The other 59 findings have unknown applicability. With `--no-assumptions`, all 61 remain unknown and no batch is proposed by that run.

Only the explicitly reviewed upstream OpenSSL rule is implemented for automatic version matching. Windows build rules, distribution backports, complex prerelease ranges and other products are review-required; the pipeline does not guess their semantics.

## Replay and freshness

```powershell
.\.venv\Scripts\python.exe -m vulnmgmt.enrichment_demo
.\.venv\Scripts\python.exe -m vulnmgmt.enrichment_demo --no-assumptions --output-dir artifacts/m3-no-assumptions
```

Source freshness is evaluated at the displayed historical reference time by default. `--as-of` permits a later explicit UTC time for stale-evidence demonstrations; times before bundle capture are rejected. KEV freshness checks both retrieval expiry and catalog date (one day); EPSS must have a current score date and unexpired retrieval (one day); other sources use 30 days from retrieval. These configurable-in-code defaults are illustrative, not agency policy. Stale/future inputs cannot support a new batch proposal. Old observations/facts remain visible with age flags; failed/missing feeds yield unknown, not false membership or zero probability.

Snapshot refresh is a separate online operation, e.g. `python -m vulnmgmt.research_sources --output-dir artifacts/m3-new-capture`. The fetcher enforces an HTTPS allowlist, validates redirect targets, limits response sizes and retries transient errors at most three times. It refuses to overwrite existing snapshots. Publication of a refreshed replay requires new versioning, explicit fact review and regenerated hashes; it must not relabel human curation as an AI response.

SDK agent definitions for roles 2, 3 and 4 exist with typed output schemas, but `--mode live` raises an explicit denial before DB/model activity. No API key is configured, no OpenAI requests are issued, and tracing is disabled for the offline definitions. Live model validation is deferred by user instruction.
