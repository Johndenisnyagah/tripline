# Windows Local User Account Created

**Rule:** [`rules/windows/security/win_security_local_account_created.yml`](../../rules/windows/security/win_security_local_account_created.yml)

- **Goal:** catch a new account being created on a workstation or member server: a classic
  way to keep access after the initial foothold.
- **ATT&CK (v20):** T1136.001 Local Account, tactic persistence.
- **How it works:** a single-event rule on EventID 4720 ("A user account was created") in the
  Security log.
  - On workstations and member servers that means a *local* account. In a domain-managed fleet
    those should almost never appear.
  - On domain controllers, 4720 logs every new *domain* account. Scoping the rule to non-DC
    hosts is a deployment decision, not part of the shared rule.
- **Blind spots:**
  - Enabling a disabled existing account (4722) or resetting its password (4724).
  - Adding an existing account to Administrators (4732), which soc-triage's sample does right
    after creating the account.
  - Accounts created with auditing off (account management not audited).
  - Domain accounts, which are only logged on the DC.
- **False positives:**
  - Domain controllers.
  - Endpoint management or privileged-access tools that create local accounts.
  - `benign/account_lifecycle_other_events.xml` must stay silent: 4722, 4724, 4738, 4726, and
    a computer account (4741).
- **Validation:** `tests/fixtures/windows_security/win_security_local_account_created/`
  - `tp/soc-triage_windows_security.xml` (non-synthetic): `Administrator` creates `svc-update`.
  - 1 synthetic benign file.
  - Splunk's `attack_data` 4720 samples were not used, because they were generated with Atomic
    Red Team, which this project excludes.
  - Results table: generated in a later step.
- **SigmaHQ relation:** derived from `win_security_user_creation.yml` (Patrick Bareiss). Same
  logic. tripline raises the level from low to medium and documents the domain-controller
  scoping and the 4732 follow-up as blind spots.
- **KQL:** generated, on `SecurityEvent` (`EventID == 4720`).
