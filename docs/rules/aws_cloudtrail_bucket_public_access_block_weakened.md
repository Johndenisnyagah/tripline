# AWS S3 Bucket Block Public Access Weakened

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_bucket_public_access_block_weakened.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_bucket_public_access_block_weakened.yml)

- **Goal:** catch the safety catch being removed before a bucket is exposed to the internet.
- **ATT&CK (v20):** T1686.001 Cloud Firewall, tactic defense-impairment. The plan said T1530
  ("verify"). John chose T1686.001, because weakening Block Public Access removes a control
  that limits access to cloud resources (the v20 definition) rather than reading data
  (T1530, collection). SigmaHQ uses the same tag.
- **How it works:** on `s3.amazonaws.com`, the rule fires on either:
  - `DeleteBucketPublicAccessBlock`, which removes the protection entirely;
  - `PutBucketPublicAccessBlock` where any of `BlockPublicAcls`, `IgnorePublicAcls`,
    `BlockPublicPolicy` or `RestrictPublicBuckets` is `false`.

  A PUT replaces the whole configuration, so one `false` flag is a weakening.
- **Blind spots:**
  - The **account-level** setting (`PutPublicAccessBlock` on `s3control`), which overrides
    bucket settings.
  - Organisation SCPs.
  - Exposing data without touching the block, for example through presigned URLs or
    cross-account bucket policies.
  - Deny-only changes, and buckets created without a block.
- **False positives:**
  - Buckets meant to be public (static sites, public datasets).
  - Infrastructure-as-code applying a relaxed configuration.
  - `benign/public_access_block_enforced_and_read.json` (all flags true, plus a read) must stay
    silent.
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_bucket_public_access_block_weakened/`
  - **Synthetic only.** No real capture was available: Stratus Red Team 2.37.2 has no Block
    Public Access technique, and the Invictus dataset contains no such events.
  - `tp/block_public_policy_turned_off.json` (one flag false) and
    `tp/public_access_block_deleted.json`.
  - Results table: generated in a later step; it will mark this rule synthetic-only.
- **SigmaHQ relation:** derived from `aws_cloudtrail_bucket_block_public_access_weakened.yml`
  (Shoban Chiddarth). Differences:
  - Adds `DeleteBucketPublicAccessBlock`.
  - Drops the success-only `errorCode` filter: a denied attempt fires too, as in the other
    tripline CloudTrail rules.
- **Data detail:** CloudTrail logs the flags as JSON booleans. The rule compares them to
  `'false'` as text, which works in KQL (`tostring(...) =~ "false"`) and in Splunk. The parser
  turns booleans into `"true"`/`"false"` so the SQLite harness sees the same values.
- **KQL:** generated, on `AWSCloudTrail`, using `parse_json(RequestParameters)`.
