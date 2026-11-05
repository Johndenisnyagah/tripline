# SSH Username Enumeration From One Source

**Rule:** [`rules/linux/sshd/lnx_sshd_invalid_user_enumeration.yml`](../../rules/linux/sshd/lnx_sshd_invalid_user_enumeration.yml)

- **Goal:** catch someone guessing *which accounts exist* over SSH, as opposed to guessing one
  account's password.
- **ATT&CK (v20):** two techniques.
  - **T1087 Account Discovery (tactic discovery).** soc-triage tags this rule T1087 because
    probing names like `oracle`, `postgres` and `jenkins` is a search for accounts that exist.
  - **T1110 Brute Force (tactic credential-access).** Every probe is also a login attempt with
    a password, so the same activity is brute-force behaviour.
  - Both tags are kept, and the Navigator layer credits both techniques. T1110 is the parent
    technique, not .001, because the attacker is varying usernames rather than guessing one
    account's password.
- **How it works:** a `value_count` correlation counts distinct `User` values in sshd lines
  containing `Invalid user `, per `SourceIp`, in a sliding 10-minute window, and fires at 3.
  - It counts *variety*, not volume: one username tried twenty times is password guessing
    (rule 1), not enumeration.
  - Usernames are compared case-insensitively, so `admin`, `Admin` and `ADMIN` count as one, as
    in soc-triage.
  - The rule matches with `contains`, not `startswith`. Splunk matches against the full `_raw`
    line, where `startswith` can never hit. `contains` also matches the companion
    `Failed password for invalid user X` line, but that line names the same user, so the
    distinct count is unchanged.
- **Blind spots:**
  - Fewer than 3 names per 10 minutes, or names spread across several source IPs.
  - Usernames that exist on the host: those produce `Failed password for <user>`, which rule 1
    covers instead.
  - sshd configurations that hide invalid-user lines.
- **False positives:**
  - An admin trying several account names on a new host.
  - Monitoring or configuration tools that probe a list of service accounts.
  - Near-misses that must stay silent:
    - `benign/same_invalid_user_retried.log`: one name retried in mixed case, plus one other.
    - `benign/invalid_users_from_many_sources.log`: 3 names from 3 IPs.
    - `benign/invalid_users_spread_out.log`: 3 names 6 minutes apart.
- **Validation:** `tests/fixtures/sshd/lnx_sshd_invalid_user_enumeration/`
  - `tp/soc-triage_auth.log` (soc-triage, non-synthetic): `203.0.113.5` probes admin, oracle
    and postgres, then later jenkins, gitlab and ansible.
  - `tp/boundary_three_invalid_users.log` (synthetic): exactly 3 names in 9m45s.
  - 3 benign near-misses (synthetic), listed above.
  - Results table: generated in a later step.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  Loghub OpenSSH 2k: 164 alert windows from 5 source IPs. Expected: internet scanners trying lists of account names (`187.141.143.180` probes 24 distinct names). The corpus also exposed a parser bug: this older OpenSSH logs `Invalid user X from <ip>` without `port N`, so the source IP was empty on those lines. With the parser and KQL fixed, the count rose from 96 to 164. `tp/older_openssh_without_port.log` now covers that format.
- **SigmaHQ relation:** original. SigmaHQ has no sshd username-enumeration correlation.
- **KQL:** hand-written (`kql_manual/`). The Kusto backend can't convert correlations, and
  `Syslog` has no source-IP or user column. The KQL uses `count_distinct(tolower(User))`.
- **SPL:** generated, using `dc(user)` in fixed 10-minute buckets. Splunk's `dc()` is
  case-sensitive, so `admin` and `Admin` would count as two there.
