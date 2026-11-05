# Conversion notes

What broke when converting tripline's Sigma rules to KQL (Microsoft Sentinel) and SPL (Splunk),
and how each problem was handled. Versions: pySigma 1.5.1, pySigma-backend-kusto 1.0.1,
pySigma-backend-splunk 2.1.0. The generated queries are in `queries/`; `python -m tripline.convert`
rebuilds them, and CI fails if the committed files differ.

## Pipelines per log source

| Log source | KQL table | KQL pipelines | SPL pipelines |
|---|---|---|---|
| Linux sshd | `Syslog` | `pipelines/kusto_syslog.yml` + `azure_monitor` | `pipelines/splunk_sshd.yml` |
| AWS CloudTrail | `AWSCloudTrail` | `pipelines/kusto_cloudtrail.yml` only | `pipelines/splunk_cloudtrail.yml` |
| Windows Security | `SecurityEvent` | `pipelines/kusto_windows.yml` + `azure_monitor` | `splunk_windows` |
| Process creation / access | `Sysmon` (parser function) | `pipelines/kusto_sysmon.yml` | `pipelines/splunk_sysmon.yml` |

## CloudTrail → `AWSCloudTrail`

- **Nested fields are strings, not dynamic.** The spec assumed `RequestParameters` was a
  `dynamic` column. Microsoft's table reference (checked 2026-11-04) and the schema bundled with
  the backend both type `RequestParameters`, `ResponseElements`, `AdditionalEventData` and
  `ServiceEventDetails` as `string`. So `requestParameters.policyArn` has to become
  `tostring(parse_json(RequestParameters).policyArn)`.
- **`azure_monitor` rejects that mapping.** It checks every field against the literal
  `AWSCloudTrail` columns and fails with "Invalid SigmaDetectionItem field name". So CloudTrail
  rules use only tripline's pipeline, which sets the table itself.
- **The backend quotes expression field names.** Without `azure_monitor`, a mapped name like
  `parse_json(RequestParameters).policyArn` comes out as the string literal
  `'parse_json(RequestParameters).policyArn'`, which compares a constant and never matches. A
  `replace` postprocessing step rewrites it to `tostring(parse_json(...).x)`. A
  `simple_template` step prepends `AWSCloudTrail | where`. `tests/test_convert.py` pins the
  exact output, including inside a `not(...)`.
- **Doubled quotes inside `contains` lists.** For a list of `contains` values (rule 11), the
  backend quotes the field name twice (`''parse_json(...).add.items''`). The first version of
  the rewrite pattern only handled single quotes, so rule 11's KQL compared a string constant.
  The pattern now accepts one or two quotes, and `tests/test_convert.py` fails if any generated
  KQL still contains a quoted `parse_json(` or `tostring(`.
- **Booleans.** CloudTrail logs flags such as `BlockPublicAcls` as JSON `true`/`false`. Rules
  compare them to the text `'false'`. In KQL that becomes `tostring(...) =~ "false"`, which
  works because `tostring(false)` is `"false"`. The CloudTrail parser turns booleans into the
  same text, so the SQLite harness agrees (SQLite would otherwise store them as 0/1).
- **Lists.** Values such as `createVolumePermission.add.items` are JSON arrays. Rule 11
  matches them as JSON text (`contains 'userId'`), which works in the harness and in KQL. In
  Splunk the add-on extracts array elements as `…items{}.userId`, so the generated SPL
  `…add.items IN ("*userId*", …)` probably needs `spath` there. Untested, since there's no
  Splunk in CI.
- **Flat fields** map to Sentinel's columns: `eventName` → `EventName`, `sourceIPAddress` →
  `SourceIpAddress`, `userIdentity.type` → `UserIdentityType`, and so on (full list in
  `kusto_cloudtrail.yml`). Note the Sentinel spelling `UserIdentityPrincipalid` (lower-case *i*
  in "id").

## sshd → `Syslog`

- `kusto_syslog.yml` sets the table to `Syslog` and adds `ProcessName =~ "sshd"`.
  `azure_monitor` then validates fields and prepends the table.
- Rules match on `SyslogMessage|contains`. Keyword-only detections (no field) produce invalid
  KQL with this backend.
- `Syslog` has no source-IP or user column. The parser extracts `SourceIp` and `User` for the
  correlation `group-by`; the hand-written KQL extracts them from `SyslogMessage`.

## Windows Security → `SecurityEvent`

- **`azure_monitor` doesn't always pick the table.** It chose `SecurityEvent` by itself for
  4625, but failed for 4720 and 1102 with "Unable to determine table name from rule". The plan
  expected it to work out of the box. `pipelines/kusto_windows.yml` now sets `query_table:
  SecurityEvent` for every `service: security` rule.
- **`Provider_Name` has no `azure_monitor` mapping** and was rejected as an invalid field. In
  `SecurityEvent` the provider is the `EventSourceName` column, so `kusto_windows.yml` maps it.
- **Splunk:** `splunk_windows` turns `EventID` into `EventCode` and adds
  `source="WinEventLog:Security"`.
  - It leaves `Provider_Name` unmapped. The Splunk Add-on for Windows calls it `SourceName`, so
    rule 14's SPL needs that field renamed in a real Splunk.
  - Data indexed as `XmlWinEventLog:Security` (as in Splunk attack_data) needs the source
    adjusted.
  - Untested, since there's no Splunk in CI.

## Process creation / access → `Sysmon` function

- `pipelines/kusto_sysmon.yml` sets the table to `Sysmon`, adds `EventID == 1` (process_creation)
  or `EventID == 10` (process_access), and prepends `Sysmon | where` with a template. It doesn't
  use `azure_monitor`, because `Sysmon` is a saved function, not a table in its schema. Fields
  pass through unmapped, since Sysmon's names are Sigma's.
- In the emulator, `Sysmon` is a table with the 100 output columns of Microsoft's parser
  (`tripline/kusto.py`, `SYSMON_SCHEMA`).
- **Splunk:** `splunk_windows` (backend 2.1.0) adds **nothing** for these categories, so the
  SPL would have searched every event in the index. `pipelines/splunk_sysmon.yml` adds
  `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` and `EventCode=1`/`10`.
- **SPL operator precedence:** the generated SPL writes, for example,
  `Image IN (...) OR OriginalFileName IN (...) CommandLine="*-enc*" OR ...` without brackets.
  It's only correct because Splunk evaluates `OR` before the implicit `AND`.
  pySigma-backend-splunk 3.0.0 fixes cases where this widens queries, but 3.0 needs pySigma 2
  (see the Dependabot decision). Untested, since there's no Splunk in CI.
- **Harness:** a Sysmon fixture is a whole log (process, network, file events). The harness
  only feeds a rule the events of its category (event 1 or 10), as the KQL `EventID` condition
  and the Splunk `EventCode` do. A benign fixture for rule 19 checks this with a
  process-creation event that mentions lsass.

## Correlation rules

- The Kusto backend raises "Backend does not support correlation rules". Rules 1, 2, 3, 4, 7
  and 12 therefore get no generated KQL. Their KQL is hand-written in `kql_manual/` and
  executed in the Kusto emulator, and `convert.py` skips the KQL target for any file whose last document is a correlation.
- The Splunk backend converts correlations, but **with tumbling windows**:
  `bin _time span=10m | stats count by _time src | search event_count >= 5`. Sigma's
  `timespan` and the SQLite harness use **sliding** windows. A burst that straddles a bin edge
  (3 failures at 09:58–09:59 and 3 at 10:00–10:01) fires in the harness but not in this SPL.
  It's left as generated and documented here; changing the SPL by hand would defeat the drift
  check.

### Chained correlations (rule 2)

- Rule 2 chains an `event_count` burst (`generate: false`) into a `temporal_ordered` sequence.
  The sqlite backend converts the chain, and measures the sequence `timespan` from the burst's
  alert time, which is the failure that reached the threshold. So a success up to 10 minutes
  after the 5th failure fires, even if the first failure was earlier. The hand-written KQL
  implements the same rule, and the doc note explains the edge-case difference from soc-triage.
- **pySigma-backend-splunk 2.1.0 does not support `temporal_ordered`** ("Correlation type
  'temporal_ordered' is not supported by backend"). Rules 2 and 4 therefore get **no generated
  SPL**. `tripline/convert.py` lists them in `SPL_UNSUPPORTED` with the reason, so no other rule
  can lose its SPL silently. This contradicts the plan's assumption that all 20 rules get SPL.
  **Decision (John, 2026-11-04):** leave them without SPL rather than hand-write SPL that
  could never be executed in CI. The results table marks them "SPL: n/a (backend unsupported)".

## Splunk field names

- **sshd.** tripline's sshd fields follow Sentinel's `Syslog` table, which Splunk doesn't have.
  `splunk_sshd.yml` maps them to the Splunk Add-on for Unix and Linux (`linux_secure`):
  `SyslogMessage` → `_raw`, `SourceIp` → `src`, `User` → `user`, `ProcessName` → `process`. It
  also adds `sourcetype="linux_secure" process="sshd"`.
- **`startswith` on sshd messages.** Sentinel's `SyslogMessage` is only the message part
  (`Invalid user admin from …`), but Splunk's `_raw` is the whole line, with timestamp, host and
  `sshd[pid]:` prefix. A `startswith` maps to `_raw="Invalid user *"` and can never match there.
  sshd rules therefore use `contains`, and `tests/test_convert.py` fails if any sshd SPL anchors
  a `_raw` match without a leading `*`.
- **`dc()` is case-sensitive** in Splunk. Rule 3's SPL counts `admin` and `Admin` as two users,
  while the harness and the KQL count them as one.
- **CloudTrail.** The Splunk Add-on for AWS keeps CloudTrail's JSON names
  (`requestParameters.policyArn`), so fields pass through. `splunk_cloudtrail.yml` only adds
  `sourcetype="aws:cloudtrail"`.

## `windash`

`CommandLine|windash|contains: ' -enc '` expands to five dash variants (`-`, `/`, en dash, em
dash, horizontal bar) in both KQL and SPL. That is correct, but it makes the rule 15 query long.

## KQL target for process creation and process access (decided 2026-11-04)

Two test rules were converted with each option: encoded PowerShell (`process_creation`, using
`Image`, `OriginalFileName`, `ParentImage`, `CommandLine|windash`) and LSASS access
(`process_access`, using `TargetImage`, `GrantedAccess`).

| Option | process_creation | process_access (rule 19) | Fidelity |
|---|---|---|---|
| (a) `azure_monitor` → `SecurityEvent` 4688 | converts only if `OriginalFileName` is removed; adds **no `EventID == 4688` filter** | fails: no table | loses OriginalFileName and hashes; command line needs an audit policy |
| (b) `microsoft_xdr` → `DeviceProcessEvents` | converts cleanly | fails: no table (MDE has only `DeviceEvents` `OpenProcessApiCall`, without GrantedAccess) | good for process creation; needs MDE |
| (b2) `sentinel_asim` → `imProcessCreate` | fails: invalid field mapping in the pipeline | fails: no table | not usable with this backend version |
| (c) custom pipeline → Microsoft's Sysmon parser function | converts cleanly, `EventID == 1` added | converts cleanly, `EventID == 10` added | all Sysmon fields kept |

Option (c) relies on Microsoft's KQL parser in Azure-Sentinel
(`Parsers/Sysmon/Sysmon-AllVersions_Parser.txt` at `800b0bd`). It reads Sysmon from the `Event`
table and exposes Sysmon's own field names, which are also Sigma's names. Deployed as a saved
function named `Sysmon`, the generated KQL starts with `Sysmon | where EventID == 1 and …`. In
the emulator, `Sysmon` would be a plain table with the parser's columns.

**Recommendation: (c).** It is the only option that covers rule 19, keeps the Sysmon fields
the rules use, and matches the test data, which is Sysmon from Splunk attack_data.
Trade-off: the README must say that the process rules need the Sysmon parser function
deployed in Sentinel; they don't run against a default workspace.

**Decision (John, 2026-11-04): (c), Microsoft's Sysmon parser function.** Implemented as
`pipelines/kusto_sysmon.yml` (`kusto_windows.yml` holds the Windows Security pipeline).

## soc-triage parity

The CI `parity` job checks out soc-triage at the commit pinned in `tests/parity_map.yml`. It runs
soc-triage's own detection over its sample logs, read-only, through
`tests/parity/soc_triage_findings.py`. That script takes the same path as soc-triage's
`scripts/run_detection.py`: ingest through `POST /api/ingest`, read the stored events back, then
`run_rules`. `tests/test_parity.py` compares the result with tripline's rules on tripline's copies
of the same files, and also checks that the copies match.

- **What is compared.** soc-triage reports a finding under every entity it touches (`ip:`,
  `user:`, `host:`, `account:`, `principal:`). tripline's correlation rules group by source IP
  only, so correlation rules are compared on the set of IPs that fire. Single-event rules are
  compared on the set of matching events (by timestamp).
- **Seven pairs, six identical.** soc-triage's source-agnostic `brute_force_auth` is paired with
  both tripline rule 1 (sshd) and rule 7 (console sign-ins).
- **One known difference, listed in the map with its reason.** `admin_policy_attached` also
  fires on the 04:50:20 `IAMFullAccess` attachment. soc-triage counts IAMFullAccess and
  PowerUserAccess as admin; tripline's rule 6 matches AdministratorAccess only, as the build
  spec defines it.
- **Semantic differences the samples don't reach** (in the map as notes, not as differences):
  - Rule 2 measures its window from the 5th failure; soc-triage needs 5 failures in the
    10 minutes before the success.
  - Rule 4 needs a failed *console* sign-in; soc-triage accepts any authentication failure,
    sshd included.
  - soc-triage's brute force counts failures across sources per IP, while tripline counts per
    source.

  On these samples both sides fire for the same IPs anyway.
- **Not compared.** soc-triage's incident correlation (merging findings by shared entity and
  scoring severity by tactic count) has no tripline counterpart; see the README.
- **Dependencies.** soc-triage's `requirements.txt` uses `>=` ranges and lives in soc-triage, so
  the parity job installs whatever is newest. A future soc-triage dependency release could
  break the job without a tripline change; the job's `soc-findings` artifact shows what
  soc-triage produced.
