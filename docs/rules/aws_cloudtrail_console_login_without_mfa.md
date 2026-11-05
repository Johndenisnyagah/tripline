# AWS Console Login Without MFA Or As Root

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_console_login_without_mfa.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_console_login_without_mfa.yml)

- **Goal:** catch console sessions where a stolen password alone was enough, and every
  interactive use of the root user.
- **ATT&CK (v20):** T1078.004 Cloud Accounts. Tactics initial-access, persistence,
  privilege-escalation and stealth (v20's name for the former defense-evasion tactic).
- **How it works:** a successful `ConsoleLogin` (`responseElements.ConsoleLogin: Success`)
  that fires on either of two branches:
  - `additionalEventData.MFAUsed: No`;
  - `userIdentity.type: Root`, whether or not MFA was used.
  - The root branch exists because a root session is worth a look on its own: the few tasks
    that need root are rare and should be planned.
- **Blind spots:**
  - Programmatic access with stolen access keys, which never produces `ConsoleLogin`.
  - Sessions started through `GetFederationToken` or a console URL built from STS
    credentials.
  - MFA fatigue: the attacker gets the victim to approve the prompt, so `MFAUsed` is `Yes`.
- **False positives:**
  - **Federated console sessions** (SAML, IAM Identity Center) log `MFAUsed: No`, because MFA
    happened at the identity provider. This is the biggest noise source in an SSO
    organisation. A per-environment filter on `userIdentity.type: AssumedRole` would remove
    it, but it isn't in the shared rule.
  - Planned root sign-ins.
  - Near-misses that must stay silent: `benign/invictus_20230710T1230Z_AvIajGd5rkz6vTy4.json`
    (a real sign-in *with* MFA) and `benign/near_miss_logins.json` (success with MFA, failed
    without MFA, failed root).
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_console_login_without_mfa/`
  - `tp/stratus-2.37.2_console-login-without-mfa.json` (Stratus Red Team 2.37.2).
  - `tp/invictus_20230710T1225Z_4iD2boYSOwmb6sWd.json` (Invictus).
  - `tp/root_login_with_mfa.json` (synthetic, root branch).
  - 2 benign files, listed above.
  - Results: this rule's row in [docs/results.md](../results.md).
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; current counts in
  [docs/results.md](../results.md)):
  flaws.cloud file 00: 36.
    - 35 are root console sign-ins, all *with* MFA. The root branch fires on every root sign-in by design, and the owner used root routinely; surfacing that is what the branch is for.
    - 1 is IAM user `piper` signing in without MFA.
    - Kept as is (John, 2026-11-05): every root console sign-in fires, with or without MFA, because routine root use is itself worth surfacing.
- **SigmaHQ relation:** derived from `aws_cloudtrail_console_login_success_without_mfa.yml`
  (Thuya@Hacktilizer, Ivan Saakov). It adds the root branch and an `eventSource` condition, and
  documents the federation false positive (SigmaHQ lists false positives as "Unlikely").
- **KQL:** generated, on `AWSCloudTrail`. `AdditionalEventData` and `ResponseElements` are read
  with `parse_json()`.
