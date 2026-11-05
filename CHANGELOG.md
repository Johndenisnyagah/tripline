# Changelog

All notable changes to this project are recorded here.

## [Unreleased]

### Added
- Results table (`docs/results.md`) and ATT&CK Navigator layer (`coverage/tripline-layer.json`)
  generated from test results by `python -m tripline.report`; CI `report` job; README link.
- Background corpora (Loghub OpenSSH, flaws.cloud CloudTrail, Nextron evtx-baseline Security and
  Sysmon): manifest with sha256, cached downloads and parsed events, `python -m tripline.corpora`,
  CI `corpora` job; hit counts investigated in the doc notes.

### Fixed
- sshd parser: source IP when the line has no "port N" (older OpenSSH).
- Windows parser: EVTX timestamps (python-evtx renders a space) and zero-padded hex values
  (python-evtx), which made `GrantedAccess` never match on EVTX input.
- Process rules 15-20 (encoded PowerShell, WMIC process call create, certutil download,
  ClickFix, LSASS access, shadow copy deletion) on the Sysmon parser function; Sysmon fixtures
  from Splunk attack_data; `Sysmon` table in the Kusto emulator. All 20 rules now tested.
- Windows parser (XML with or without `<Events>` wrapper, Splunk XmlWinEventLog, EVTX via
  python-evtx) and Windows Security rules 12-14 (password spraying, local account created,
  Security log cleared); Splunk attack_data fixtures; `SecurityEvent` in the Kusto emulator.
- CloudTrail rules 7-11: console brute force (event_count), IAM console password created,
  console login without MFA or as root, S3 Block Public Access weakened, EBS snapshot shared;
  Stratus/Invictus fixtures, hand-written KQL for rule 7, NOTICE-completeness test.
- CloudTrail rules `aws_cloudtrail_access_key_after_failed_console_login` (temporal_ordered) and
  `aws_cloudtrail_admin_policy_attached`; Stratus Red Team 2.37.2 and Invictus `aws_dataset`
  fixtures (real CloudTrail) for rules 4, 5 and 6; hand-written KQL for rule 4.
- sshd rules `lnx_sshd_brute_force_success` (chained correlation) and
  `lnx_sshd_invalid_user_enumeration` (value_count), with soc-triage and synthetic fixtures,
  hand-written KQL and doc notes.
- KQL execution: `test-kql` CI job runs generated and hand-written KQL in the Kusto
  emulator against the rule fixtures; hand-written KQL for `lnx_sshd_brute_force_password_guessing`.
- Conversion: Kusto pipelines (Syslog, AWSCloudTrail), Splunk pipelines (sshd, CloudTrail),
  `tripline.convert` with `--check` drift detection, generated `queries/`, `convert` CI job,
  `docs/conversion-notes.md` including the process-creation KQL target spike.
- Harness spike: sshd and CloudTrail parsers, SQLite test harness (correlations via
  pySigma-backend-sqlite), `expectations.yml` format, metadata checks with ATT&CK v20
  revoked-ID detection, `sigma check` config, `test-logic` CI job.
- Rules `lnx_sshd_brute_force_password_guessing` (correlation) and
  `aws_cloudtrail_logging_disabled`, with fixtures and doc notes.
- Scaffold: pinned toolchain in `pyproject.toml`, MIT and DRL 1.1 licences, NOTICE stub,
  CLAUDE.md, folder layout, `lint` CI job and Dependabot config.
