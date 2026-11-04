# AWS AdministratorAccess Policy Attached

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_admin_policy_attached.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_admin_policy_attached.yml)

- **Goal:** catch a principal being given full control of the AWS account.
- **ATT&CK (v20):** T1098.003 Additional Cloud Roles, tactics persistence and
  privilege-escalation.
- **How it works:** a single-event rule.
  - `eventSource: iam.amazonaws.com` with `AttachUserPolicy`, `AttachRolePolicy` or
    `AttachGroupPolicy`, where `requestParameters.policyArn` ends with `/AdministratorAccess`.
  - `endswith` rather than `contains` keeps AWS's narrower `AdministratorAccess-Amplify` and
    `AdministratorAccess-AWSElasticBeanstalk` policies out.
  - Denied attempts fire too.
- **Difference from soc-triage:** soc-triage's rule also treats `PowerUserAccess` and
  `IAMFullAccess` as admin-equivalent, and also covers inline `PutUserPolicy`. tripline follows
  the plan and matches only the `AdministratorAccess` managed policy. So soc-triage's sample
  `IAMFullAccess` attach fires there but not here; this is a known parity difference (step 12).
- **Blind spots:**
  - Admin rights through other paths: inline policies (`PutUserPolicy`, `PutRolePolicy`), a
    customer-managed policy with `"Action": "*"`, `IAMFullAccess` or `PowerUserAccess`.
  - Adding a user to an existing admin group (`AddUserToGroup`).
  - Changing a role's trust policy (`UpdateAssumeRolePolicy`).
- **False positives:**
  - Break-glass and bootstrap admins.
  - Account-vending pipelines.
  - Near-misses that must stay silent, in `benign/near_miss_policies.json`:
    `ReadOnlyAccess`, `AdministratorAccess-Amplify`, `DetachUserPolicy` of AdministratorAccess,
    `GetPolicy` and `ListAttachedUserPolicies`.
  - Real near-miss: `benign/invictus_20230710T1210Z_RBxlxVrF890sGHGg.json`, an
    `AttachRolePolicy` with a custom, non-admin policy.
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_admin_policy_attached/`
  - `tp/soc-triage_cloudtrail.json`: 1 match.
  - `tp/stratus-2.37.2_iam-create-admin-user.json` (Stratus Red Team 2.37.2 detonation): 1
    match.
  - `tp/invictus_20230710T1230Z_ZtUNbBkwAu98FPZb.json` (Invictus `aws_dataset`, 68 real
    records): 2 matches, a role and a user.
  - `tp/admin_attached_to_group.json` (synthetic, group variant): 1 match.
  - 2 benign files, listed above.
  - Results table: generated in a later step.
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; numbers from step 9):
  flaws.cloud file 00: 1. The account's root user attached AdministratorAccess to the IAM user `piper` while the owner was setting up the account. This is the documented false-positive class (deliberate admin grants).
- **SigmaHQ relation:** original. No SigmaHQ rule targets AdministratorAccess attachment
  specifically.
- **KQL:** generated, on `AWSCloudTrail`, using
  `tostring(parse_json(RequestParameters).policyArn) endswith "/AdministratorAccess"`.
