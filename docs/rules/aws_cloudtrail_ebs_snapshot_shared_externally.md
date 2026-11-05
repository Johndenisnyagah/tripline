# AWS EBS Snapshot Shared With Another Account

**Rule:** [`rules/aws/cloudtrail/aws_cloudtrail_ebs_snapshot_shared_externally.yml`](../../rules/aws/cloudtrail/aws_cloudtrail_ebs_snapshot_shared_externally.yml)

- **Goal:** catch a disk image leaving the account by being shared, not downloaded.
- **ATT&CK (v20):** T1537 Transfer Data to Cloud Account, tactic exfiltration.
- **How it works:** `ModifySnapshotAttribute` on `ec2.amazonaws.com` with `attributeType:
  CREATE_VOLUME_PERMISSION`, where `createVolumePermission.add.items` contains an account
  (`userId`) or the public group (`group: all`). Removing a permission doesn't fire.
- **Blind spots:**
  - Sharing an AMI (`ModifyImageAttribute`) or an RDS snapshot (`ModifyDBSnapshotAttribute`).
  - Copying a snapshot into an attacker-controlled KMS key or region first.
  - A share to an account that is "ours" but compromised; the rule can't tell accounts apart.
- **False positives:**
  - Sharing with your own backup or disaster-recovery account.
  - Account migrations.
  - Near-misses that must stay silent:
    - `benign/invictus_20230710T1215Z_YMDRJwtmC82bUwAo.json`: the real cleanup that removes
      the permission, plus AMI share events.
    - `benign/stratus-2.37.2_ec2-share-ami.json`: an AMI, not a snapshot.
    - `benign/snapshot_permission_removed_and_read.json`.
- **Validation:** `tests/fixtures/cloudtrail/aws_cloudtrail_ebs_snapshot_shared_externally/`
  - `tp/stratus-2.37.2_ec2-share-ebs-snapshot.json` (Stratus Red Team 2.37.2).
  - `tp/invictus_20230710T1220Z_ovtmbuX3ENJ119uH.json` (Invictus).
  - `tp/snapshot_made_public.json` (synthetic, `group: all`).
  - 3 benign files, listed above.
  - Results: this rule's row in [docs/results.md](../results.md).
- **Background corpora** (hits on unlabelled logs: not pass/fail, not a false-positive rate; current counts in
  [docs/results.md](../results.md)):
  flaws.cloud file 00: 18.
    - 3 are the root user making snapshots public on purpose (the flaws.cloud level built around a public snapshot).
    - 15 are CTF players using the leaked `backup` credentials, trying to share the snapshot with their own accounts or with `all`. All were denied (`Client.UnauthorizedOperation`). These are real exfiltration attempts, caught because the rule fires on denied attempts.
- **SigmaHQ relation:** derived from `aws_snapshot_backup_exfiltration.yml` (Darin Smith).
  That rule fires on every `ModifySnapshotAttribute`, removals included. tripline requires an
  `add`, which keeps the cleanup step silent.
- **Conversion detail:** `add.items` is a list. The rule matches the list as JSON text
  (`contains 'userId'` / `'group'`), which works in the harness and in KQL
  (`tostring(parse_json(RequestParameters).createVolumePermission.add.items) contains …`).
  The Splunk add-on extracts list elements as `…add.items{}.userId`, so the generated SPL
  (`…add.items IN ("*userId*", …)`) would likely need `spath` in Splunk. It's untested there.
- **KQL:** generated, on `AWSCloudTrail`.
