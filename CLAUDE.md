# tripline — notes for Claude Code

Sigma detection-as-code portfolio repo by John Denis Nyagah. 20 rules, tested against real and
synthetic logs, converted to Sentinel KQL and Splunk SPL, KQL executed in the Kusto emulator.

## Hard rules
- Pinned to the pySigma 1.x line (sigma-cli 3.1.0, pySigma 1.5.1) because pySigma-backend-kusto 1.0.1
  requires pysigma<2. Do not bump to pySigma 2 / sigma-cli 4 until the kusto backend supports it.
- ATT&CK v20 tags only; revoked IDs fail CI.
- One branch + one PR per change, never draft. John merges.
- Generated files (queries/, docs/results.md, coverage/) are never edited by hand.
- No malware, attack tooling or secrets in the repo or CI. No paid services.
- Every copied dataset file has a NOTICE entry with source, version and licence.
- Numbers in the README come only from docs/results.md.
- Ask John before changing rules, thresholds, datasets, README claims or anything in soc-triage.

## Current phase
Step 3 (KQL execution): Kusto emulator CI job, Sentinel table schemas, fixture ingestion,
tests/test_kql.py, hand-written KQL for rule 1.
Next: step 4 (sshd rules 2-3).

## Decisions
- 2026-11-04 — second backend is Splunk SPL; it converts all four sources and supports correlations — John
- 2026-11-04 — the 6 correlation rules get hand-written KQL, executed in the Kusto emulator — John
- 2026-11-04 — 20 rules, as listed in the build spec §5 — John
- 2026-11-04 — extras: only the soc-triage parity test; no SigmaHQ PR, no Atomic Red Team, no GitHub Pages — John
- 2026-11-04 — tripline mirrors soc-triage and cross-links to it; soc-triage does not consume Sigma — planning default
- 2026-11-04 — licences are MIT for code and DRL 1.1 for rules — planning default
- 2026-11-04 — all spec pins (incl. pySigma-backend-sqlite 2.0.0 and pySigma-validators-sigmahq 0.21.0) install together with pySigma 1.5.1 on Python 3.12; none dropped — Claude
- 2026-11-04 — pytest skips `-m kql` tests by default (addopts); the test-kql CI job selects them explicitly — Claude
- 2026-11-04 — `sigma check` is not in the step-0 lint job because rules/ is empty; it joins in step 1 with tests/sigma_check.yml — Claude
- 2026-11-04 — correlation path: pySigma-backend-sqlite 2.0.0 converts event_count, value_count and temporal_ordered itself (sliding windows over `timestamp`); boundary-tested in the spike, so no tripline/correlate.py — Claude
- 2026-11-04 — all 20 technique IDs in spec §5 resolve and are not revoked in the pinned v20.0 bundle; no corrections needed — Claude
- 2026-11-04 — ATT&CK v20.0 bundle pinned by attack-stix-data commit + sha256, downloaded and cached (.cache/attack), never committed — Claude
- 2026-11-04 — sshd events use Sentinel `Syslog` column names (HostName, ProcessName, ProcessID, SyslogMessage) plus parser-extracted SourceIp and User for group-by; only sshd lines are emitted (logsource service: sshd) — Claude
- 2026-11-04 — syslog lines have no year; the sshd parser assumes 2026 (the soc-triage samples' year), times are UTC — Claude
- 2026-11-04 — harness columns are TEXT COLLATE NOCASE because Sigma matching is case-insensitive and SQLite `=` is not — Claude
- 2026-11-04 — expectations may add `groups:` (exact set of group-by values that fire), because the sqlite backend emits one row per qualifying window and a row count alone can't show both IPs fired — Claude
- 2026-11-04 — `sigma check` disables tlptag/tlpv1_tag/tlpv2_tag (no TLP tags) and sigmahq_correlation_filename_prefix (conflicts with the lnx_sshd_*/aws_cloudtrail_* naming rule) — Claude
- 2026-11-04 — soc-triage sample_logs fixtures are labelled `synthetic: false` (non-synthetic TPs), although they are a hand-written scenario (RFC 5737 IPs) — John
- 2026-11-04 — Dependabot also ignores pySigma-backend-splunk >=3 and pySigma-backend-sqlite >=2.1: both require pySigma >=2 (Dependabot PR #2 tried them) — Claude
- 2026-11-04 — AWSCloudTrail RequestParameters/ResponseElements/AdditionalEventData are `string` (not dynamic as the spec assumed); nested Sigma fields become tostring(parse_json(<Column>).<path>) — Claude
- 2026-11-04 — CloudTrail KQL uses only pipelines/kusto_cloudtrail.yml, not azure_monitor, because azure_monitor rejects computed field expressions; a replace postprocessing step unquotes them and a template prepends the table — Claude
- 2026-11-04 — sshd KQL = kusto_syslog.yml (table Syslog + ProcessName =~ "sshd") + azure_monitor — Claude
- 2026-11-04 — SPL gets small tripline pipelines: sshd fields mapped to linux_secure names (_raw, src, user, process) + sourcetype; CloudTrail fields pass through + sourcetype aws:cloudtrail — Claude
- 2026-11-04 — generated SPL correlations use tumbling `bin _time span=10m`, unlike Sigma's sliding window; left as generated and documented in docs/conversion-notes.md — Claude
- 2026-11-04 — queries/ files hold the bare query (no header) so step 3 can run them as-is — Claude
- 2026-11-04 — KQL target for process_creation/process_access rules is option (c): a tripline pipeline to Microsoft's Sysmon parser function (`Sysmon | where EventID == 1/10 …`); README must say the parser has to be deployed — John
- 2026-11-04 — Kusto emulator used in GitHub CI after reading its licence (aka.ms/adx.emulator.license): it forbids production use, benchmark disclosure, redistribution and "commercial, non-profit, or revenue-generating activities", and grants use "on your devices … for internal business purposes"; nothing addresses CI. Reading: a personal portfolio's automated tests are within scope. Fallback if that changes: syntax-only check with Microsoft.Azure.Kusto.Language — John
- 2026-11-04 — emulator image pinned to kustainer-linux:2026.10.20.1451-2641-19d68ab-weeklyproduction (a weeklyproduction build >2 weeks old) — Claude
- 2026-11-04 — hand-written correlation KQL uses a self-join so the window slides like Sigma's, instead of bin(TimeGenerated, 10m) (tumbling) — Claude
- 2026-11-04 — emulator tables are created from the full Sentinel schemas (pySigma-backend-kusto's copy, matches Microsoft's reference); fixtures are mapped to columns by tripline/kusto.py independently of the conversion pipelines — Claude
