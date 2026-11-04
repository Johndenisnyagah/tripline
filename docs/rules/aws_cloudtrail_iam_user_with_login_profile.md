# AWS IAM Console Password Created For User

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_iam_user_with_login_profile.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_iam_user_with_login_profile.yml)

- **Goal:** catch an IAM user being given a console password, the step that turns a created
  (or hijacked) IAM user into an interactive backdoor.
- **ATT&CK (v20):** T1136.003 Cloud Account, tactic persistence.
- **How it works:** a single-event rule on `CreateLoginProfile` from `iam.amazonaws.com`.
  - The plan left open whether to correlate `CreateUser` → `CreateLoginProfile`. A
    single-event rule was chosen: `CreateLoginProfile` on its own already means "this user can
    now sign in to the console".
  - Requiring `CreateUser` first would miss an attacker who adds a password to an *existing*,
    API-only user.
  - It would also make the rule a `temporal_ordered` correlation, which the Splunk backend
    can't convert.
- **Blind spots:**
  - `UpdateLoginProfile`, which resets an existing user's password (T1098, privilege
    escalation; Stratus `iam-update-user-login-profile`).
  - Console access through federation or IAM Identity Center users, which don't use login
    profiles.
  - Access keys alone (`CreateAccessKey`, rule 4).
- **False positives:**
  - Onboarding human users.
  - Identity tooling that provisions IAM users.
  - Near-misses that must stay silent: `benign/stratus-2.37.2_iam-update-user-login-profile.json`
    (real) and `benign/login_profile_other_calls.json` (`CreateUser`, `GetLoginProfile`,
    `DeleteLoginProfile`, `UpdateLoginProfile`).
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_iam_user_with_login_profile/`
  - `tp/stratus-2.37.2_iam-create-user-login-profile.json`: Stratus Red Team 2.37.2.
  - Two Invictus `aws_dataset` files (17 and 68 real records), one match each.
  - Results table: generated in a later step.
- **SigmaHQ relation:** partial. SigmaHQ's `aws_iam_s3browser_loginprofile_creation.yml`
  matches `CreateLoginProfile` only when the user agent is the S3 Browser tool. tripline's rule
  matches any client. Not marked `derived`, since the logic is not built from that rule.
- **KQL:** generated, on `AWSCloudTrail`.
