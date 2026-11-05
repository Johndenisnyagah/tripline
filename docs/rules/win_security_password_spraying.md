# Windows Password Spraying From One Source

**Rule:** [`rules/windows/security/win_security_password_spraying.yml`](../../rules/windows/security/win_security_password_spraying.yml)

- **Goal:** catch one source trying a password against many Windows accounts, which stays
  under per-account lockout thresholds.
- **ATT&CK (v20):** T1110.003 Password Spraying, tactic credential-access.
- **How it works:** a base rule matches failed logons (4625) that have a source address. It
  excludes `IpAddress` values `-`, `127.0.0.1` and `::1`, because local and loopback failures
  can't be attributed to a source. A `value_count` correlation then fires when one `IpAddress`
  fails against 5 or more distinct `TargetUserName`s in a sliding 10-minute window.
  - Account names are compared case-insensitively.
  - Spraying is **variety**, not volume, which is what separates it from brute force: many
    failures for one account don't count.
- **Blind spots:**
  - Spraying spread over many source addresses.
  - Spraying slower than 5 accounts per 10 minutes.
  - Kerberos pre-authentication failures (4771) on domain controllers. They aren't 4625, so a
    Kerberos spray is invisible here.
  - Sprays run locally on a compromised host (`IpAddress: -`, logon type 2), as in Splunk's
    `purplesharp_valid_users_ntlm_xml` dataset.
- **False positives:**
  - Jump hosts, VPN or Citrix gateways that front many users.
  - Authenticated vulnerability scans with stale credentials.
  - Near-misses that must stay silent:
    - `benign/soc-triage_windows_security.xml`: real soc-triage data, 4 distinct accounts from
      one address, one below the threshold.
    - `benign/one_account_many_failures.xml`.
    - `benign/accounts_from_many_sources.xml`.
    - `benign/local_failures_no_source_address.xml`.
- **Validation:** `tests/fixtures/windows_security/win_security_password_spraying/`
  - `tp/splunk-attack-data_purplesharp_remote_spray_xml.log` (Splunk attack_data, PurpleSharp
    in Attack Range): 50 accounts from `10.0.1.15` in 50 seconds.
  - `tp/boundary_five_accounts.xml` (synthetic).
  - 4 benign files, listed above.
  - Results: this rule's row in [docs/results.md](../results.md).
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; current counts in
  [docs/results.md](../results.md)):
  evtx-baseline Windows Server 2022 Security log (22,085 events): 0. The baseline has no 4625 at all, so the zero says nothing about false positives.
- **SigmaHQ relation:** partial. SigmaHQ has no 4625 spraying correlation in
  `rules/windows/builtin/security`. tripline's rule is written from scratch, so it isn't marked
  `derived`.
- **KQL:** hand-written (`kql_manual/`) on `SecurityEvent`: a sliding-window self-join with
  `count_distinct(tolower(TargetUserName))`.
- **SPL:** generated, with `dc(TargetUserName)` in fixed 10-minute buckets (see
  `docs/conversion-notes.md`).
