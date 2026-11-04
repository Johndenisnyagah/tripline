# Changelog

All notable changes to this project are recorded here.

## [Unreleased]

### Added
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
