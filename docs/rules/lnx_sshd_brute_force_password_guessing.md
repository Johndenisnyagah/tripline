# SSH Password Guessing From One Source

**Rule:** [`rules/linux/sshd/lnx_sshd_brute_force_password_guessing.yml`](../../rules/linux/sshd/lnx_sshd_brute_force_password_guessing.yml)

- **Goal:** catch online password guessing against SSH from a single source address.
- **ATT&CK (v20):** T1110.001 Password Guessing, tactic credential-access.
- **How it works:** a base rule matches every sshd `Failed password for …` line (valid and
  invalid users alike). An `event_count` correlation groups those by `SourceIp`, the address
  the parser extracts from `from <ip> port <n>`, and fires when 5 or more fall within a sliding
  10-minute window. Five-in-ten-minutes is the soc-triage threshold this rule mirrors. A user
  who mistypes a password rarely fails more than 2–3 times before getting it right or giving
  up, while a guessing tool makes several attempts a minute. The window slides, so 3 failures
  at 09:59 and 3 at 10:01 still count as 6.
- **Blind spots:**
  - Low-and-slow guessing below 5 per 10 minutes from one address.
  - Guessing spread across many source IPs (botnets, rotating proxies).
  - Key-based or keyboard-interactive attempts, which log differently.
  - Hosts where sshd's log level hides failures, or logs aren't forwarded.
- **False positives:**
  - A user or script retrying a stale password from one host.
  - Several users behind one NAT address. `benign/failures_from_many_sources.log` covers
    the opposite case: many sources with one failure each, which must not fire.
  - A user's typos, as in `benign/boundary_four_failures_then_success.log` (4 failures, then
    success).
- **Validation:** `tests/fixtures/sshd/lnx_sshd_brute_force_password_guessing/`
  - `tp/soc-triage_auth.log`: soc-triage sample (counted as non-synthetic). It
    has two bursts, and the test asserts that exactly `203.0.113.5` and
    `198.51.100.77` fire.
  - `tp/boundary_five_failures.log` (synthetic): exactly 5 failures in 9m57s. This is the
    lowest count that must fire.
  - `benign/boundary_four_failures_then_success.log`, `benign/slow_failures_outside_window.log`
    (5 failures, 3 minutes apart) and `benign/failures_from_many_sources.log` (synthetic): all
    must stay silent.
  - Results table: generated in a later step.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  Loghub OpenSSH 2k (internet-exposed lab server, about 4 hours): 450 alert windows from 9 source IPs. Expected: this is real password guessing. The top source, `183.62.140.253`, fails 286 times. The harness emits one row per qualifying window, so the 9 IPs, not the 450 rows, are what an analyst would triage.
- **SigmaHQ relation:** original. SigmaHQ has no sshd brute-force correlation rule.
- **KQL:** hand-written (`kql_manual/`, step 3). The Kusto backend can't convert correlation
  rules, and the `Syslog` table has no source-IP column, so the KQL extracts it from
  `SyslogMessage`.
