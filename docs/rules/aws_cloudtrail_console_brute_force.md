# AWS Console Brute Force From One Source

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_console_brute_force.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_console_brute_force.yml)

- **Goal:** catch password guessing against the AWS management console.
- **ATT&CK (v20):** T1110 Brute Force, tactic credential-access.
- **How it works:** a base rule matches failed console sign-ins (`signin.amazonaws.com`,
  `ConsoleLogin`, `responseElements.ConsoleLogin: Failure`). An `event_count` correlation
  fires at 5 or more per `sourceIPAddress` in a sliding 10-minute window. The threshold and
  window are the same as the sshd rule and soc-triage, so one guessing pattern means the same
  thing on both surfaces.
- **Blind spots:**
  - Guessing below 5 per 10 minutes, or spread over many IPs.
  - SSO sign-ins through an identity provider, where the failures happen at the IdP, not in
    CloudTrail.
  - Root-user failures recorded in a different region's trail, if only one region is
    collected.
- **False positives:**
  - A user retrying a forgotten password.
  - NAT or VPN egress shared by many users.
  - Near-misses that must stay silent: `benign/four_failures_then_success.json`,
    `benign/slow_failures_outside_window.json` (3 minutes apart) and
    `benign/failures_from_many_sources.json`.
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_console_brute_force/`
  - `tp/soc-triage_cloudtrail.json` (non-synthetic): only `203.0.113.5` fires, with 6
    failures.
  - `tp/boundary_five_failures_in_nine_minutes.json` (synthetic).
  - 3 synthetic benign files, listed above.
  - Results table: generated in a later step.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  flaws.cloud file 00: 0. It's a real near-miss: `12.80.110.252` failed to sign in 5 times on 2018-02-26 between 18:45 and 19:04, but never 5 times within 10 minutes.
- **SigmaHQ relation:** derived from `aws_cloudtrail_console_login_failed_authentication.yml`
  (Ivan Saakov, Nasreddine Bencherchali). That rule alerts on every single failure. tripline
  counts failures per source over 10 minutes instead, so one typo doesn't alert. It also
  matches on `responseElements.ConsoleLogin: Failure` rather than the `errorMessage` text.
- **KQL:** hand-written (`kql_manual/`), a sliding-window self-join.
- **SPL:** generated, with fixed 10-minute buckets (see `docs/conversion-notes.md`).
