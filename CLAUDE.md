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
Step 1 (harness spike): sshd + CloudTrail parsers, SQLite harness, metadata checks with the
ATT&CK v20 bundle, rules 1 and 5 with fixtures. Next: step 2 (conversion to KQL/SPL).

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
- 2026-11-04 — soc-triage sample_logs are labelled `synthetic: true`: they are a hand-written scenario (RFC 5737 IPs, scripted story), not captured telemetry. Open question for John, see PR #3 — Claude
