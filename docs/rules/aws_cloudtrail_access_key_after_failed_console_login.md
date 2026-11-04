# AWS Access Key Created After Failed Console Login

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_access_key_after_failed_console_login.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_access_key_after_failed_console_login.yml)

- **Goal:** catch the pivot from guessing to persistence: long-lived IAM credentials created
  from an address that just failed to sign in to the console.
- **ATT&CK (v20):** T1098.001 Additional Cloud Credentials, tactics persistence and
  privilege-escalation.
- **How it works:** a `temporal_ordered` correlation, grouped by `sourceIPAddress`, within 1
  hour:
  1. A `ConsoleLogin` on `signin.amazonaws.com` with `responseElements.ConsoleLogin: Failure`.
  2. Then a `CreateAccessKey` on `iam.amazonaws.com`.

  The window is 1 hour, not the 10 minutes used for brute force, because creating a key comes
  later in an intrusion than the guessing. soc-triage uses the same 1-hour window. Order
  matters: creating a key and then mistyping a password is routine admin work.
- **Blind spots:**
  - The attacker creates the key from a different IP than the failed sign-in (VPN hop, or a
    Lambda or EC2 role).
  - More than an hour passes between the two.
  - Persistence by other means: `CreateLoginProfile`, a new role, federation tokens.
  - Failures logged under a different event, such as SSO sign-ins through IAM Identity
    Center.
- **False positives:**
  - An admin who mistypes the console password and then rotates a key from the same office or
    VPN address.
  - Shared NAT egress addresses.
  - Near-misses that must stay silent: `benign/key_after_successful_login.json` (successful
    sign-in), `benign/key_before_failed_login.json` (wrong order),
    `benign/key_from_other_source.json` and `benign/key_61min_after_failed_login.json`.
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_access_key_after_failed_console_login/`
  - `tp/soc-triage_cloudtrail.json` (soc-triage, non-synthetic): only `203.0.113.5` fires (6
    failed sign-ins, then a key for `deploy` 5 minutes later).
  - `tp/boundary_key_59min_after_failed_login.json` (synthetic): just inside the window.
  - `benign/stratus-2.37.2_iam-create-admin-user.json` (Stratus Red Team 2.37.2, real
    detonation): `CreateAccessKey` with no failed sign-in before it, which must stay silent.
  - 4 synthetic benign near-misses, listed above.
  - Results table: generated in a later step.
- **SigmaHQ relation:** original. No SigmaHQ rule correlates a failed console sign-in with a
  later access key.
- **KQL:** hand-written (`kql_manual/`). The Kusto backend can't convert correlations.
  `ResponseElements` is a string column, so the outcome is read with `parse_json()`.
- **SPL:** none, by decision. pySigma-backend-splunk 2.1.0 doesn't support `temporal_ordered`
  (see `docs/conversion-notes.md`).
