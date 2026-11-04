# LSASS Opened With Credential-Dumping Access Rights

**Rule:** [`rules/windows/process_access/proc_access_win_lsass_suspicious_access.yml`](../../rules/windows/process_access/proc_access_win_lsass_suspicious_access.yml)

- **Goal:** catch a process opening LSASS to read the credentials in its memory.
- **ATT&CK (v20):** T1003.001 LSASS Memory, tactic credential-access.
- **How it works:** Sysmon event 10 (process access) where `TargetImage` ends in `\lsass.exe`
  and `GrantedAccess` is one of the masks dumpers request:
  - `0x1010` / `0x1410`: VM_READ + query, as Mimikatz `sekurlsa` uses;
  - `0x1418`, `0x1438`, `0x143a`: CAR-2019-04-004;
  - full access: `0x1f0fff` … `0x1fffff`;
  - `0x40`: DUP_HANDLE, for handle duplication tricks.

  Windows' own processes (wininit, csrss, services, lsm, svchost in System32) and Defender's
  `MsMpEng.exe` are filtered out.
- **Blind spots:**
  - Dumping without a fresh handle on LSASS: duplicating an existing handle, `PssCaptureSnapshot`
    of a clone, or reading a crash dump.
  - Access masks not in the list.
  - Tools running under a filtered path (e.g. injected into `svchost.exe`).
  - Sysmon configurations that don't log event 10 for LSASS. Many do, but only with a filter.
- **False positives:**
  - Other EDR or antivirus agents. They must be added as filters per environment, since the
    shared rule only knows Defender.
  - Windows Error Reporting during an LSASS crash.
  - `benign/lsass_access_near_misses.xml` must stay silent: Defender and wininit with full
    access (filtered), svchost with `0x1000`, full access to notepad, and a process-creation
    event mentioning lsass (wrong category).
- **Validation:** `tests/fixtures/sysmon/proc_access_win_lsass_suspicious_access/`
  - **Synthetic only.** No small Sysmon event-10 capture of LSASS dumping was found outside
    Atomic Red Team datasets, which this project excludes. Splunk's mimikatz Sysmon file
    contains only the process start.
  - `tp/lsass_dumping_access.xml`: `0x1010` from an unknown binary, and full access from
    `rundll32` with `comsvcs.dll` in the call trace.
  - Results table: generated in a later step; it will mark this rule synthetic-only.
- **SigmaHQ relation:** derived from `proc_access_win_lsass_susp_access_flag.yml` (Florian Roth
  et al.). SigmaHQ matches hundreds of mask endings, filters every process under
  `Program Files` and `System32`, and leaves `0x1010`/`0x1410` to a separate rule. tripline
  uses an explicit, readable list including `0x1010`, and a narrow filter, so `rundll32` (in
  System32) dumping LSASS still fires.
- **KQL:** generated, on the `Sysmon` function (`EventID == 10`).
