# Shadow Copies Or Backup Catalog Deleted

**Rule:** [`rules/windows/process_creation/proc_creation_win_shadow_copy_deletion.yml`](../../rules/windows/process_creation/proc_creation_win_shadow_copy_deletion.yml)

- **Goal:** catch the step ransomware takes right before or during encryption: removing the
  local recovery points.
- **ATT&CK (v20):** T1490 Inhibit System Recovery, tactic impact.
- **How it works:** three alternatives, each pairing an image (or `OriginalFileName`) with
  command-line words:
  - `vssadmin.exe` with `delete` and `shadows`;
  - `wmic.exe` with `shadowcopy` and `delete`;
  - `wbadmin.exe` with `delete` and `catalog`.

  Matching the words rather than exact command lines covers `/all`, `/quiet`, `-quiet` and
  argument order.
- **Blind spots:**
  - PowerShell `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`, or CIM equivalents.
  - `vssadmin resize shadowstorage` to a tiny size, which silently purges copies.
  - Direct VSS COM calls from malware.
  - `bcdedit /set recoveryenabled no`.
- **False positives:**
  - Admins freeing disk space.
  - Backup software rebuilding a catalog.
  - `benign/shadow_copy_admin_tasks.xml` must stay silent: listing and creating shadow copies,
    `wbadmin get versions`, and `wmic shadowcopy list`.
- **Validation:** `tests/fixtures/sysmon/proc_creation_win_shadow_copy_deletion/`
  - `tp/splunk-attack-data_shadowcopy_del.log` (Splunk attack_data, real Sysmon, DarkSide
    style): PowerShell running `WMIC.exe shadowcopy delete`.
  - `tp/vssadmin_and_wbadmin_deletion.xml` (synthetic): the other two tools.
  - Results: this rule's row in [docs/results.md](../results.md).
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; current counts in
  [docs/results.md](../results.md)):
  evtx-baseline Sysmon log (1,165 process creations): 0.
- **SigmaHQ relation:** derived from `proc_creation_win_susp_shadow_copies_deletion.yml`
  (Florian Roth et al.).
  - SigmaHQ also matches PowerShell and `diskshadow`, and `vssadmin resize shadowstorage`.
  - tripline keeps the three tools in the plan, requires `catalog` for wbadmin without
    requiring `quiet`, and tags only T1490.
- **KQL:** generated, on the `Sysmon` function (`EventID == 1`).
