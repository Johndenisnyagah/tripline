# Process Created Via WMIC Process Call Create

**Rule:** [`rules/windows/process_creation/proc_creation_win_wmic_process_call_create.yml`](../../rules/windows/process_creation/proc_creation_win_wmic_process_call_create.yml)

- **Goal:** catch WMIC used to launch a process, locally or on a remote host.
- **ATT&CK (v20):** T1047 Windows Management Instrumentation, tactic execution.
- **How it works:** the image is `wmic.exe` (or `OriginalFileName`), and the command line
  contains `process`, `call` and `create`. This covers `wmic process call create "…"` and
  `wmic /node:<host> process call create "…"` (remote execution). The new process is started
  by the WMI provider host (`WmiPrvSE.exe`), not by `wmic.exe`, which breaks the parent-child
  chain an analyst would follow.
- **Blind spots:**
  - WMI process creation without wmic.exe: PowerShell `Invoke-WmiMethod` or `Invoke-CimMethod`,
    or VBScript and .NET WMI calls. Splunk's `T1047/lateral_movement` dataset does exactly this.
  - `wmic.exe` is deprecated and missing from new Windows builds, so attackers move to those
    alternatives anyway.
- **False positives:**
  - Legacy deployment scripts that start installers remotely.
  - Real near-miss: `benign/splunk-attack-data_wmic_classes.log`, an infostealer running WMI
    *queries* (`wmic … get …`).
  - `benign/wmic_other_process_verbs.xml`: `process list` and `process … call terminate`.
- **Validation:** `tests/fixtures/sysmon/proc_creation_win_wmic_process_call_create/`
  - **No real true positive.** The TPs (`tp/wmic_process_call_create.xml`, local and `/node`)
    are synthetic, because no small, non-Atomic-Red-Team dataset with this command was found.
  - The real file is a benign near-miss.
  - Results table: generated in a later step.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  evtx-baseline Sysmon log (1,165 process creations): 0.
- **SigmaHQ relation:** derived from `proc_creation_win_wmic_process_creation.yml` (Michael
  Haag, Florian Roth, juju4, oscd.community). Same logic. tripline adds tests, fixtures and
  the documented blind spots.
- **KQL:** generated, on the `Sysmon` function (`EventID == 1`).
