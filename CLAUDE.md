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
Step 9 (background corpora): Loghub OpenSSH, flaws.cloud CloudTrail, evtx-baseline Security and
Sysmon; hit counts per rule and corpus, investigated in the doc notes.
Next: step 10 (results table, Navigator layer, report job).

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
- 2026-11-04 — CI caches ~/.cache/pysigma with the ATT&CK bundle and retries `sigma check` once: pySigma tag validators download MITRE ATT&CK/D3FEND at runtime (30 s timeout) and a cold download timed out once — Claude
- 2026-11-04 — rule 2 is a chained correlation (event_count burst, generate: false -> temporal_ordered with Accepted password); window measured from the burst end, as the sqlite backend does; KQL matches that — Claude
- 2026-11-04 — rules using temporal_ordered (2 and 4) have no SPL: pySigma-backend-splunk 2.1.0 cannot convert them, and no hand-written SPL is added (it could not be executed in CI). Results table shows "SPL: n/a (backend unsupported)"; listed in convert.SPL_UNSUPPORTED — John
- 2026-11-04 — rule 3 matches `SyslogMessage|contains: 'Invalid user '` (not startswith) because Splunk's _raw includes the syslog prefix; distinct usernames are case-insensitive (NOCASE in SQLite, tolower in KQL) — Claude
- 2026-11-04 — metadata checker allows intermediate named correlations; every named document must be used and every reference must resolve to an earlier document — Claude
- 2026-11-04 — Stratus Red Team detonation logs pinned to v2.37.2 (commit 036d2ca; v2.38.0 was released the same day), copied unchanged from docs/detonation-logs/; they are bare JSON arrays, so the CloudTrail readers accept both `{"Records": [...]}` and `[...]` — Claude
- 2026-11-04 — Invictus aws_dataset (MIT, commit 4667aa9) files copied whole and unchanged (not extracted), including one real benign near-miss (non-admin AttachRolePolicy) — Claude
- 2026-11-04 — rule 6 matches only the AdministratorAccess managed policy (spec); soc-triage also counts IAMFullAccess/PowerUserAccess and PutUserPolicy — a known parity difference for step 12 — Claude
- 2026-11-04 — test_kql reads correlation group-by values from KQL output via the CloudTrail pipeline's field mapping (sourceIPAddress -> SourceIpAddress), so hand-written KQL uses real Sentinel column names — Claude
- 2026-11-04 — rule 10 tagged T1686.001 (defense-impairment) instead of the plan's T1530: weakening Block Public Access removes an access control rather than reading data; matches SigmaHQ — John
- 2026-11-04 — rule 8 is a single-event rule on CreateLoginProfile (the plan left this open): it covers existing users too, and a CreateUser->CreateLoginProfile sequence would lose SPL — Claude
- 2026-11-04 — rule 9 keeps the plan's logic (success and (MFAUsed No or Root)); federated console sessions logging MFAUsed No are documented as the main false positive, not filtered — Claude
- 2026-11-04 — CloudTrail parser renders JSON booleans as "true"/"false"; harness folds field names case-insensitively (real CloudTrail has maxResults and MaxResults in one file) — Claude
- 2026-11-04 — the KQL nested-field rewrite accepts single and doubled quotes (contains-lists are double-quoted by the backend); a test rejects any quoted parse_json/tostring in generated KQL — Claude
- 2026-11-04 — rule 10 has no real fixture (none in Stratus 2.37.2 or Invictus); it is synthetic-only and the results table will say so — Claude
- 2026-11-04 — Windows Security KQL needs pipelines/kusto_windows.yml (query_table SecurityEvent, Provider_Name -> EventSourceName): azure_monitor alone fails for 4720/1102, contrary to the plan's "works out of the box" — Claude
- 2026-11-04 — rule 12 base excludes 4625s with IpAddress "-", 127.0.0.1 or ::1 (no attributable source); threshold/window unchanged — Claude
- 2026-11-04 — Splunk attack_data used: PurpleSharp remote spray (rule 12) and a real 1102 (rule 14), Apache-2.0, LFS objects fetched at commit c8af10d and copied unchanged; datasets made with Atomic Red Team (4720 samples) deliberately not used — Claude
- 2026-11-04 — EVTX: parser reads .evtx through python-evtx, but no EVTX fixture is committed (no licence-compatible small EVTX among the §11 sources); EVTX gets exercised on Nextron evtx-baseline in step 9 — Claude
- 2026-11-04 — soc-triage's windows_security.xml is a benign near-miss for rule 12 (4 distinct accounts from 203.0.113.200, threshold is 5) — Claude
- 2026-11-04 — Sysmon KQL pipeline is pipelines/kusto_sysmon.yml (kusto_windows.yml already holds Windows Security); emulator table `Sysmon` uses the 100 columns of Microsoft's parser function — Claude
- 2026-11-04 — process-rule SPL uses pipelines/splunk_sysmon.yml (Sysmon source + EventCode 1/10) because splunk_windows adds nothing for process_creation/process_access — Claude
- 2026-11-04 — harness feeds Sysmon rules only the events of their category (EventID 1 or 10), matching the KQL/SPL conditions — Claude
- 2026-11-04 — rules without a real true positive after step 8: 10 (S3 Block Public Access), 16 (WMIC process call create; real benign only), 17 (certutil download), 19 (LSASS access); no small non-ART capture exists in the §11 sources — Claude
- 2026-11-04 — rule 18 (ClickFix) got a real TP after all: Splunk attack_data encoded_powershell/explorer_spawns (explorer -> padded, hidden, -enc PowerShell) — Claude
- 2026-11-04 — corpora: Loghub OpenSSH_2k (pinned commit), flaws.cloud tar member 00, evtx-baseline v0.8.5 win2022 Security.evtx + full Sysmon log; all sha256-verified, cached, never committed (tests/corpora/manifest.yml) — Claude
- 2026-11-04 — flaws subset is file 00 (chosen before running the rules: it holds the most rule-relevant events; files 04-15 hold none); a first-20k-records Sysmon subset was dropped because it held no event 1/10 — Claude
- 2026-11-04 — parsed corpus events are cached (gz JSON lines keyed by corpus + parser source hash): python-evtx needs ~20 min for the 222 MB Sysmon log, then CI reuses the cache — Claude
- 2026-11-04 — harness creates only the columns a rule references (real logs have hundreds of keys; SQLite caps tables at 2000 columns) — Claude
- 2026-11-04 — corpus findings fixed in parsers (not rules): sshd source IP without "port N" (older OpenSSH, Loghub), EVTX SystemTime rendered with a space by python-evtx, EVTX hex values zero-padded by python-evtx (hid every GrantedAccess match); KQL sshd IP regex updated to match — Claude
- 2026-11-04 — corpus hit counts are reported, not tuned: e.g. rule 19 hits snmp.exe (0x1410) on the benign baseline and rule 9 hits 35 routine root sign-ins on flaws; tuning needs John — Claude
