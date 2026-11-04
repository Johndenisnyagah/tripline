# ClickFix Command Pasted Into The Run Dialog

**Rule:** [`rules/windows/process_creation/proc_creation_win_clickfix_paste_and_run.yml`](../../rules/windows/process_creation/proc_creation_win_clickfix_paste_and_run.yml)

- **Goal:** catch a user being talked into pasting a command into Win+R ("ClickFix": fake
  CAPTCHAs and error pages that copy a command to the clipboard).
- **ATT&CK (v20):** T1204.004 Malicious Copy and Paste, tactic execution.
- **How it works:** commands run from the Run dialog get `explorer.exe` as their parent. The
  rule needs `explorer.exe` → `powershell`/`pwsh`/`mshta`/`cmd`, plus at least one lure trait:
  - a `#` comment (lures append text like "# I am not a robot - verification ID");
  - 20 or more spaces of padding, which pushes the real command out of the Run box's view;
  - a hidden window (`-w hidden`, `-windowstyle hidden`, `-w h`, matched with `windash`);
  - an `http(s)://` URL, as in `mshta https://…`.

  A user opening PowerShell or cmd from the Run dialog has none of these traits.
- **Blind spots:**
  - FileFix variants pasted into the Explorer address bar, which use a different parent
    chain.
  - Lures that launch other LOLBins (`rundll32`, `msiexec`, `curl`).
  - Payloads with none of the four traits.
  - Unicode space padding, which SigmaHQ's padding rule checks and this rule only matches for
    ASCII spaces.
- **False positives:**
  - Double-clicked shortcuts (`.lnk`) whose arguments include a URL or a hidden window, since
    these also have `explorer.exe` as their parent.
  - Power users typing URLs into the Run dialog.
  - Near-misses that must stay silent:
    - `benign/explorer_and_hidden_window_near_misses.xml`: plain PowerShell or cmd from
      explorer, notepad with "https" in a file name, and a hidden PowerShell started by cmd.
    - The real TP file also contains a bare `powershell.exe` and a Startup `.cmd` launched by
      explorer, which must not count.
- **Validation:** `tests/fixtures/sysmon/proc_creation_win_clickfix_paste_and_run/`
  - `tp/splunk-attack-data_encoded_powershell_explorer_spawns.log`: Splunk attack_data, real
    Sysmon from a manually generated ClickFix-style run, with 321 spaces of padding and
    `-WindowStyle hidden … -enc`. 2 matches.
  - `tp/run_dialog_lures.xml` (synthetic): `mshta https://…` and a cmd with a `#` lure comment.
  - The plan expected "synthetic if Splunk data isn't available"; a real sample was found.
  - Results table: generated in a later step.
- **SigmaHQ relation:** derived from two SigmaHQ rules.
  - `proc_creation_win_susp_clickfix_filefix_whitespace_padding.yml` (Swachchhanda Shrawan
    Poudel) and `proc_creation_win_susp_clickfix_filefix_execution.yml` (montysecurity,
    Swachchhanda Shrawan Poudel).
  - Those need a `#` *and* padding or lure keywords. tripline needs explorer plus a known shell
    plus *any one* lure trait, which is broader and noisier but covers lures without a comment.
- **KQL:** generated, on the `Sysmon` function (`EventID == 1`).
