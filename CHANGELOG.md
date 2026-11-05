# Changelog

All notable changes to this project are recorded here. The decisions behind them are in the
Decisions log in [CLAUDE.md](CLAUDE.md).

## [Unreleased]

### Added
- Documentation: full README with the results summary (copied from `docs/results.md` and
  checked by `tests/test_readme.py`), SECURITY.md, and a test that every rule doc note has all
  the sections in spec §8.
- Results table (`docs/results.md`) and ATT&CK Navigator layer (`coverage/tripline-layer.json`)
  generated from test results by `python -m tripline.report`; CI `report` job; README link to
  the layer in the hosted Navigator.
- Background corpora (Loghub OpenSSH, flaws.cloud CloudTrail, Nextron evtx-baseline Security and
  Sysmon): manifest with sha256, cached downloads and parsed events, `python -m tripline.corpora`,
  CI `corpora` job; hit counts investigated in the doc notes.
- Process rules 15-20 (encoded PowerShell, WMIC process call create, certutil download,
  ClickFix, LSASS access, shadow copy deletion) on Microsoft's Sysmon parser function; Sysmon
  fixtures from Splunk attack_data; `Sysmon` table in the Kusto emulator.
- Windows parser (XML with or without an `<Events>` wrapper, Splunk XmlWinEventLog, EVTX via
  python-evtx) and Windows Security rules 12-14 (password spraying, local account created,
  Security log cleared); Splunk attack_data fixtures; `SecurityEvent` in the Kusto emulator.
- CloudTrail rules 7-11: console brute force, IAM console password created, console login
  without MFA or as root, S3 Block Public Access weakened, EBS snapshot shared; Stratus Red Team
  and Invictus fixtures; hand-written KQL for rule 7; NOTICE-completeness test.
- CloudTrail rules 4 (access key after failed console login) and 6 (AdministratorAccess
  attached); Stratus Red Team 2.37.2 and Invictus `aws_dataset` fixtures for rules 4-6;
  hand-written KQL for rule 4.
- sshd rules 2 (success after brute force, chained correlation) and 3 (username enumeration),
  with soc-triage and synthetic fixtures, hand-written KQL and doc notes.
- KQL execution: `test-kql` CI job runs generated and hand-written KQL in the Kusto emulator
  against the rule fixtures; hand-written KQL for rule 1.
- Conversion: Kusto pipelines (Syslog, AWSCloudTrail, SecurityEvent, Sysmon), Splunk pipelines
  (sshd, CloudTrail, Sysmon), `tripline.convert` with `--check` drift detection, committed
  `queries/`, `convert` CI job, `docs/conversion-notes.md`.
- Harness: sshd and CloudTrail parsers, SQLite test harness (correlations via
  pySigma-backend-sqlite), `expectations.yml` format, metadata checks with ATT&CK v20
  revoked-ID detection, `sigma check` config, `test-logic` CI job; rules 1 and 5.
- Scaffold: pinned toolchain in `pyproject.toml`, MIT and DRL 1.1 licences, NOTICE, CLAUDE.md,
  folder layout, `lint` CI job and Dependabot config.

### Fixed
- sshd parser: source IP when the line has no `port N` (older OpenSSH, as in Loghub); the
  hand-written sshd KQL extracts it the same way.
- Windows parser: EVTX timestamps (python-evtx renders them with a space) and zero-padded hex
  values (python-evtx), which made Sysmon `GrantedAccess` never match on EVTX input.
- Splunk attack_data fixtures are stored byte-for-byte (`.gitattributes`), since one of them
  mixes CRLF and LF line endings.
- The CloudTrail KQL rewrite handles the doubled quotes the Kusto backend uses inside
  `contains` lists; a test rejects quoted field expressions in generated KQL.
