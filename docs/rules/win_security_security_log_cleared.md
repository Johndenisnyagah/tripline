# Windows Security Event Log Cleared

**Rule:** [`rules/windows/security/win_security_security_log_cleared.yml`](../../rules/windows/security/win_security_security_log_cleared.yml)

- **Goal:** catch an intruder wiping the Security log to remove evidence.
- **ATT&CK (v20):** T1685.005 Clear Windows Event Logs, tactic defense-impairment. It was
  T1070.001 until v19 revoked it.
- **How it works:** a single-event rule on EventID 1102 with `Provider_Name:
  Microsoft-Windows-Eventlog`. The Eventlog service writes 1102 into the Security log itself
  when that log is cleared, whether through `wevtutil cl`, Event Viewer or `Clear-EventLog`.
  The provider condition keeps out any other source that happens to use ID 1102.
- **Blind spots:**
  - Clearing other logs (System 104, Sysmon or PowerShell operational logs).
  - Stopping the Eventlog service (1100) or disabling auditing (4719) instead of clearing.
  - Deleting individual records with tools that patch the log file.
  - Clearing after forwarding has been cut, so the 1102 never reaches the SIEM.
- **False positives:**
  - Log collection agent rollouts that reset the local log.
  - Golden-image preparation.
  - `benign/other_logging_events.xml` (1100 service shutdown, 4719 audit policy change) must
    stay silent.
- **Validation:** `tests/fixtures/windows_security/win_security_security_log_cleared/`
  - `tp/soc-triage_windows_security.xml` (non-synthetic).
  - `tp/splunk-attack-data_windows_event_log_cleared.log`: Splunk attack_data, a real 1102
    from an Attack Range domain controller.
  - 1 synthetic benign file.
  - Results table: generated in a later step.
- **SigmaHQ relation:** derived from `win_security_audit_log_cleared.yml` (Florian Roth). It
  keeps the 1102 + provider selection and drops the legacy Windows 2003 event 517.
- **KQL:** generated, on `SecurityEvent`. `Provider_Name` maps to `EventSourceName` through
  `pipelines/kusto_windows.yml`.
