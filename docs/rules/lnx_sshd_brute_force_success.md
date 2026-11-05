# SSH Successful Password Login After Brute Force

**Rule:** [`rules/linux/sshd/lnx_sshd_brute_force_success.yml`](../../rules/linux/sshd/lnx_sshd_brute_force_success.yml)

- **Goal:** catch the moment password guessing over SSH *worked*: a successful login from an
  address that was just guessing.
- **ATT&CK (v20):** T1110.001 Password Guessing, tactic credential-access.
- **How it works:** a chained correlation in four documents:
  1. A base rule for `Failed password for …`.
  2. A base rule for `Accepted password for …`.
  3. An `event_count` correlation for a burst: 5 or more failures per `SourceIp` within 10
     minutes. It's marked `generate: false` because it's only a building block.
  4. A `temporal_ordered` correlation: a burst, then an accepted password, from the same
     `SourceIp` within 10 minutes.

  The threshold and window match rule 1 and soc-triage, so this rule can't fire on a burst too
  small to count as brute force. The order carries the meaning: success followed by typos is a
  normal user.
- **Timing detail:** the 10 minutes run from the end of the burst, meaning the failure that
  reached 5. soc-triage instead requires all 5 failures in the 10 minutes before the success.
  The two differ only at the edge: failures over minutes 0–2 and a success at minute 11 fire
  here but not in soc-triage. The hand-written KQL implements the same burst-end semantics as
  the Sigma rule.
- **Blind spots:**
  - Guessing below 5 per 10 minutes.
  - A pause of more than 10 minutes between the last failure and the login.
  - Logging in from a different IP than the one used for guessing.
  - Success by key or keyboard-interactive auth (only `Accepted password` is matched).
- **False positives:**
  - A user who fails 5 or more times and then gets it right. This is the boundary case;
    `benign/four_failures_then_success.log` stays one below it.
  - A shared NAT address. `benign/success_from_other_source.log` checks that a different
    source doesn't link up.
  - `benign/success_long_after_burst.log` (success 18 minutes later) and
    `benign/success_before_failures.log` (wrong order) cover timing and order.
- **Validation:** `tests/fixtures/sshd/lnx_sshd_brute_force_success/`
  - `tp/soc-triage_auth.log` (soc-triage, non-synthetic): only `203.0.113.5` fires (11
    failures, then `Accepted password for deploy`). `198.51.100.77` fails 7 times but never gets
    in.
  - `tp/boundary_five_failures_then_success.log` (synthetic): exactly 5 failures, then success.
  - 4 benign near-misses (synthetic), listed above.
  - Results table: generated in a later step.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  Loghub OpenSSH 2k: 0. The corpus has one `Accepted password` (user `fztu` from `119.137.62.142`), and that IP has no failed passwords.
- **SigmaHQ relation:** original. SigmaHQ has no sshd success-after-brute-force correlation.
- **KQL:** hand-written (`kql_manual/`). The Kusto backend can't convert correlations, and
  `Syslog` has no source-IP column.
- **SPL:** none, by decision. pySigma-backend-splunk 2.1.0 doesn't support `temporal_ordered`
  correlations (see `docs/conversion-notes.md`).
