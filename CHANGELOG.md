# Changelog

All notable changes to this project are recorded here.

## [Unreleased]

### Added
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
