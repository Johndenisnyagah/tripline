# PowerShell Started With An Encoded Command

**Rule:** [`rules/windows/process_creation/proc_creation_win_powershell_encoded_command.yml`](../../rules/windows/process_creation/proc_creation_win_powershell_encoded_command.yml)

- **Goal:** catch PowerShell running a Base64-encoded script, which hides the real commands
  from anyone reading the process command line.
- **ATT&CK (v20):** T1059.001 PowerShell, tactic execution.
- **How it works:** the image is `powershell.exe` or `pwsh.exe` (or `OriginalFileName`, so a
  renamed copy still matches), and the command line contains `-EncodedCommand` or one of the
  prefixes PowerShell accepts for it (`-e`, `-en`, `-enc`, `-enco…`, `-ec`).
  - `windash` also matches `/enc` and Unicode dashes.
  - `' -enco'` would also match a cmdlet's `-Encoding` parameter, so `' -Encoding '` is
    filtered out.
- **Blind spots:**
  - Encoding passed another way: `-Command` with `[Convert]::FromBase64String`, or a script
    file.
  - PowerShell hosted inside another process (e.g. `System.Management.Automation` in a custom
    binary).
  - The flag written without the surrounding spaces the patterns expect, such as `"-enc"` in
    quotes or `-e:` with a colon. PowerShell accepts both.
- **False positives:**
  - Management agents (SCCM, RMM tools) that pass encoded scripts.
  - Admin scripts that encode to avoid quoting problems.
  - `benign/powershell_without_encoded_command.xml` must stay silent: `-File`, `-Encoding UTF8`,
    and "-enc" inside a cmd echo.
- **Validation:** `tests/fixtures/sysmon/proc_creation_win_powershell_encoded_command/`
  - `tp/splunk-attack-data_encoded_powershell_explorer_spawns.log` (Splunk attack_data, real
    Sysmon): exactly 2 matches. The bare `powershell.exe` and the Startup `.cmd` in the same
    file stay silent.
  - `tp/encoded_command_variants.xml` (synthetic): `-EncodedCommand` and `/e`.
  - Results: this rule's row in [docs/results.md](../results.md).
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; current counts in
  [docs/results.md](../results.md)):
  evtx-baseline Sysmon log (full, 1,165 process creations): 0. The baseline never starts PowerShell; most processes are .NET `mscorsvw.exe` compilations.
- **SigmaHQ relation:** derived from `proc_creation_win_powershell_encode.yml` (frack113).
  - Adds `windash` and an `OriginalFileName` match.
  - Drops the Azure guest-configuration filter, which is environment-specific.
- **KQL:** generated, on Microsoft's `Sysmon` parser function (`EventID == 1`).
