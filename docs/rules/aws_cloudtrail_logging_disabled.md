# AWS CloudTrail Logging Stopped Or Reduced

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_logging_disabled.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_logging_disabled.yml)

- **Goal:** catch attempts to turn off or weaken the AWS audit trail before or during an
  intrusion.
- **ATT&CK (v20):** T1685.002 Disable or Modify Cloud Log, tactic defense-impairment. It was
  T1562.008 before v19 revoked the T1562 family.
- **How it works:** a single-event rule on `eventSource: cloudtrail.amazonaws.com` with
  `eventName` in `StopLogging`, `DeleteTrail`, `UpdateTrail` or `PutEventSelectors`. It
  ignores `errorCode` on purpose, so a denied attempt (`AccessDenied`) still fires: it means a
  credential is being pointed at the audit trail. Severity can be ranked on the outcome during
  triage.
- **Blind spots:**
  - Changes outside CloudTrail itself: deleting or locking the S3 bucket the trail writes to,
    an S3 lifecycle rule that expires logs, or KMS key policy changes that break log
    encryption.
  - Organisation-level trails changed from the management account, if that account's trail
    isn't collected.
  - `PutInsightSelectors` and CloudTrail Lake event data stores, which aren't covered.
- **False positives:**
  - Planned trail changes by administrators or infrastructure-as-code.
  - Account decommissioning.
  - `benign/trail_read_create_start.json` holds the near-misses that must not fire:
    read-only trail calls, `CreateTrail` and `StartLogging`.
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_logging_disabled/`
  - `tp/soc-triage_cloudtrail.json`: soc-triage sample (counted as non-synthetic).
    Exactly 1 match: the denied `StopLogging`.
  - `tp/trail_reconfigured_then_deleted.json` (synthetic): `PutEventSelectors`,
    `UpdateTrail`, `DeleteTrail`, giving 3 matches.
  - Stratus Red Team 2.37.2 detonation logs (real, non-synthetic), 1 match each:
    `tp/stratus-2.37.2_cloudtrail-stop.json` (`StopLogging`),
    `tp/stratus-2.37.2_cloudtrail-delete.json` (`DeleteTrail`) and
    `tp/stratus-2.37.2_cloudtrail-event-selectors.json` (`PutEventSelectors`). The last one is
    the case SigmaHQ's original rule misses.
  - Results: this rule's row in [docs/results.md](../results.md).
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; current counts in
  [docs/results.md](../results.md)):
  flaws.cloud file 00: 1. A CTF player using the leaked `Level6` credentials tried `UpdateTrail` and got `AccessDenied`. This is a real attempt; the rule fires on denied attempts by design.
- **SigmaHQ relation:** derived from `aws_cloudtrail_disable_logging.yml` ("AWS CloudTrail
  Important Change", vitaliy0x1). Differences:
  - Adds `PutEventSelectors`, which can silently stop logging write or management events
    while the trail stays "on".
  - States explicitly that denied attempts fire.
  - Status `experimental`, level `high` instead of `medium`, and documented blind spots.
- **KQL:** generated (single-event rule) on `AWSCloudTrail`.
