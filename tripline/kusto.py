"""Run tripline's KQL in the Kusto emulator (Azure Data Explorer "kustainer").

The emulator listens on http://localhost:8080 with no auth and a default database
`NetDefaultDB`. Tables are created with the real Sentinel column schemas (taken from the
schema copy bundled with pySigma-backend-kusto, which matches Microsoft's table reference),
so a query that names a wrong column fails here as it would in Sentinel.

Fixture events are mapped to Sentinel columns *independently* of the conversion pipelines:
the mapping below mimics what Sentinel's connectors write, so a wrong pipeline field mapping
shows up as a failing test instead of agreeing with itself.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
from pathlib import Path

import requests
import yaml
from sigma.pipelines.azuremonitor.tables import AZURE_MONITOR_TABLES

from tripline.parsers import cloudtrail, sshd, windows

REPO_ROOT = Path(__file__).resolve().parent.parent
KUSTO_URL = os.environ.get("TRIPLINE_KUSTO_URL", "http://localhost:8080")
DATABASE = "NetDefaultDB"

# Sentinel table per fixture source.
SOURCE_TABLE = {
    "sshd": "Syslog",
    "cloudtrail": "AWSCloudTrail",
    "windows_security": "SecurityEvent",
    "sysmon": "Sysmon",
}

_KUSTO_TYPES = {
    "string": "string",
    "datetime": "datetime",
    "int": "int",
    "long": "long",
    "real": "real",
    "bool": "bool",
    "boolean": "bool",
    "dynamic": "dynamic",
    "guid": "guid",
}


#: Columns of Microsoft's Sysmon parser function (Azure-Sentinel
#: Parsers/Sysmon/Sysmon-AllVersions_Parser.txt @ 800b0bd): TimeGenerated and EventID come from
#: the Event table, every Sysmon field is a string. The emulator gets a table of this shape
#: named `Sysmon`, standing in for the saved function.
SYSMON_SCHEMA: dict[str, str] = {
    "TimeGenerated": "datetime",
    "Source": "string",
    "EventLog": "string",
    "Computer": "string",
    "EventLevel": "string",
    "EventLevelName": "string",
    "EventID": "int",
    "UserName": "string",
    "RenderedDescription": "string",
    "MG": "string",
    "ManagementGroupName": "string",
    "_ResourceId": "string",
    "UtcTime": "string",
    "ID": "string",
    "Description": "string",
    "RuleName": "string",
    "ProcessGuid": "string",
    "ProcessId": "string",
    "Image": "string",
    "FileVersion": "string",
    "Product": "string",
    "Company": "string",
    "OriginalFileName": "string",
    "CommandLine": "string",
    "CurrentDirectory": "string",
    "User": "string",
    "LogonGuid": "string",
    "LogonId": "string",
    "TerminalSessionId": "string",
    "IntegrityLevel": "string",
    "Hashes": "string",
    "ParentProcessGuid": "string",
    "ParentProcessId": "string",
    "ParentImage": "string",
    "ParentCommandLine": "string",
    "ParentUser": "string",
    "TargetFilename": "string",
    "CreationUtcTime": "string",
    "PreviousCreationUtcTime": "string",
    "Protocol": "string",
    "Initiated": "string",
    "SourceIsIpv6": "string",
    "SourceIp": "string",
    "SourceHostname": "string",
    "SourcePort": "string",
    "SourcePortName": "string",
    "DestinationIsIpv6": "string",
    "DestinationIp": "string",
    "DestinationHostname": "string",
    "DestinationPort": "string",
    "DestinationPortName": "string",
    "State": "string",
    "Version": "string",
    "SchemaVersion": "string",
    "ImageLoaded": "string",
    "Signed": "string",
    "Signature": "string",
    "SignatureStatus": "string",
    "SourceProcessGuid": "string",
    "SourceProcessId": "string",
    "SourceImage": "string",
    "TargetProcessGuid": "string",
    "TargetProcessId": "string",
    "TargetImage": "string",
    "NewThreadId": "string",
    "StartAddress": "string",
    "StartModule": "string",
    "StartFunction": "string",
    "SourceUser": "string",
    "TargetUser": "string",
    "Device": "string",
    "SourceProcessGUID": "string",
    "SourceThreadId": "string",
    "TargetProcessGUID": "string",
    "GrantedAccess": "string",
    "CallTrace": "string",
    "EventType": "string",
    "TargetObject": "string",
    "Details": "string",
    "NewName": "string",
    "Hash": "string",
    "Contents": "string",
    "Configuration": "string",
    "ConfigurationFileHash": "string",
    "PipeName": "string",
    "Operation": "string",
    "EventNamespace": "string",
    "Name": "string",
    "Query": "string",
    "Type": "string",
    "Destination": "string",
    "Consumer": "string",
    "Filter": "string",
    "QueryName": "string",
    "QueryStatus": "string",
    "QueryResults": "string",
    "IsExecutable": "string",
    "Archived": "string",
    "Session": "string",
    "ClientInfo": "string",
}


class KustoError(RuntimeError):
    pass


def _post(endpoint: str, csl: str) -> dict:
    response = requests.post(
        f"{KUSTO_URL}/v1/rest/{endpoint}",
        json={"db": DATABASE, "csl": csl},
        timeout=120,
    )
    if response.status_code != 200:
        raise KustoError(f"{endpoint} failed ({response.status_code}): {response.text[:2000]}")
    return response.json()


def command(csl: str) -> dict:
    return _post("mgmt", csl)


def query(csl: str) -> list[dict]:
    """Run a query; return the rows of the primary result table as dicts."""
    tables = _post("query", csl)["Tables"]
    primary = tables[0]
    columns = [c["ColumnName"] for c in primary["Columns"]]
    return [dict(zip(columns, row, strict=True)) for row in primary["Rows"]]


def wait_until_ready(timeout: float = 300) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            command(".show version")
            return
        except (requests.RequestException, KustoError) as exc:
            last_error = exc
            time.sleep(5)
    raise KustoError(f"emulator not ready after {timeout}s: {last_error}")


def table_schema(table: str) -> dict[str, str]:
    if table == "Sysmon":
        return dict(SYSMON_SCHEMA)
    return {
        column: _KUSTO_TYPES[spec["data_type"].lower()]
        for column, spec in AZURE_MONITOR_TABLES[table].items()
    }


def create_tables() -> None:
    for table in SOURCE_TABLE.values():
        columns = ", ".join(f"['{c}']:{t}" for c, t in table_schema(table).items())
        command(f".create-merge table ['{table}'] ({columns})")


def ingest(table: str, rows: list[dict]) -> None:
    """Replace the table's contents with `rows` (missing columns stay empty)."""
    command(f".clear table ['{table}'] data")
    if not rows:
        return
    columns = list(table_schema(table))
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for row in rows:
        writer.writerow(["" if row.get(c) is None else _csv_value(row[c]) for c in columns])
    command(f".ingest inline into table ['{table}'] <|\n{buffer.getvalue()}")


def _csv_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# --- fixture events -> Sentinel rows -----------------------------------------


def syslog_row(event: dict) -> dict:
    return {
        "TimeGenerated": event["timestamp"],
        "EventTime": event["timestamp"],
        "Computer": event["HostName"],
        "HostName": event["HostName"],
        "Facility": "auth",
        "SeverityLevel": "info",
        "ProcessName": event["ProcessName"],
        "ProcessID": event["ProcessID"],
        "SyslogMessage": event["SyslogMessage"],
        "SourceSystem": "Linux",
        "Type": "Syslog",
    }


def _json_or_none(value) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"))


def cloudtrail_row(record: dict) -> dict:
    """One raw CloudTrail record -> AWSCloudTrail columns (as the AWS S3 connector fills them)."""
    identity = record.get("userIdentity") or {}
    session = identity.get("sessionContext") or {}
    issuer = session.get("sessionIssuer") or {}
    attributes = session.get("attributes") or {}
    mfa = attributes.get("mfaAuthenticated")
    return {
        "TimeGenerated": record["eventTime"],
        "EventVersion": record.get("eventVersion"),
        "EventSource": record.get("eventSource"),
        "EventName": record.get("eventName"),
        "EventTypeName": record.get("eventType"),
        "AWSRegion": record.get("awsRegion"),
        "SourceIpAddress": record.get("sourceIPAddress"),
        "UserAgent": record.get("userAgent"),
        "ErrorCode": record.get("errorCode"),
        "ErrorMessage": record.get("errorMessage"),
        "AwsEventId": record.get("eventID"),
        "AwsRequestId": record.get("requestID"),
        "ReadOnly": record.get("readOnly"),
        "ManagementEvent": record.get("managementEvent"),
        "RecipientAccountId": record.get("recipientAccountId"),
        "SharedEventId": record.get("sharedEventID"),
        "VpcEndpointId": record.get("vpcEndpointId"),
        "UserIdentityType": identity.get("type"),
        "UserIdentityArn": identity.get("arn"),
        "UserIdentityAccountId": identity.get("accountId"),
        "UserIdentityPrincipalid": identity.get("principalId"),
        "UserIdentityAccessKeyId": identity.get("accessKeyId"),
        "UserIdentityUserName": identity.get("userName"),
        "UserIdentityInvokedBy": identity.get("invokedBy"),
        "SessionIssuerType": issuer.get("type"),
        "SessionIssuerArn": issuer.get("arn"),
        "SessionIssuerUserName": issuer.get("userName"),
        "SessionIssuerAccountId": issuer.get("accountId"),
        "SessionIssuerPrincipalId": issuer.get("principalId"),
        "SessionMfaAuthenticated": None if mfa is None else str(mfa).lower() == "true",
        "SessionCreationDate": attributes.get("creationDate"),
        "RequestParameters": _json_or_none(record.get("requestParameters")),
        "ResponseElements": _json_or_none(record.get("responseElements")),
        "AdditionalEventData": _json_or_none(record.get("additionalEventData")),
        "ServiceEventDetails": _json_or_none(record.get("serviceEventDetails")),
        "Resources": _json_or_none(record.get("resources")),
        "Category": record.get("eventCategory"),
        "Type": "AWSCloudTrail",
    }


#: Windows System fields whose SecurityEvent column has a different name.
_SECURITY_EVENT_RENAMES = {"Provider_Name": "EventSourceName", "EventRecordID": "EventRecordId"}


def security_event_row(event: dict) -> dict:
    """One parsed Windows Security event -> SecurityEvent columns (as the AMA connector fills them).

    EventData fields whose name is also a SecurityEvent column (TargetUserName, IpAddress,
    LogonType, ...) are copied; int columns get ints, and non-numeric values ("-") become null.
    """
    schema = table_schema("SecurityEvent")
    row: dict = {
        "TimeGenerated": event["timestamp"],
        "SourceSystem": "OpsManager",
        "Type": "SecurityEvent",
    }
    for key, value in event.items():
        column = _SECURITY_EVENT_RENAMES.get(key, key)
        if column not in schema or column in row or value is None:
            continue
        if schema[column] in ("int", "long"):
            text = str(value).strip()
            if not text.lstrip("-").isdigit():
                continue  # e.g. "-" for an unset KeyLength: leave the int column empty
            value = int(text)
        row[column] = value
    if event.get("TargetUserName") and event.get("TargetDomainName"):
        row["TargetAccount"] = event["TargetDomainName"] + "\\" + event["TargetUserName"]
    return row


def sysmon_row(event: dict) -> dict:
    """One parsed Sysmon event -> a row of the Sysmon parser function's output."""
    row: dict = {
        "TimeGenerated": event["timestamp"],
        "Source": event.get("Provider_Name"),
        "EventLog": event.get("Channel"),
        "EventID": int(event["EventID"]),
    }
    for key, value in event.items():
        if key in SYSMON_SCHEMA and key not in row and value is not None:
            row[key] = value
    return row


def fixture_rows(source: str, path: Path) -> list[dict]:
    if source == "sshd":
        return [syslog_row(e) for e in sshd.parse_file(path)]
    if source == "cloudtrail":
        # Raw records, not the flattened parser output: the connector keeps nested JSON.
        return [cloudtrail_row(r) for r in cloudtrail.load_records(path)]
    if source == "windows_security":
        return [security_event_row(e) for e in windows.parse_file(path)]
    if source == "sysmon":
        return [sysmon_row(e) for e in windows.parse_file(path)]
    raise ValueError(f"no Sentinel table mapping for source {source!r}")


def sentinel_column(source: str, sigma_field: str) -> str:
    """The Sentinel column a Sigma field lands in (for reading group-by values from KQL output).

    CloudTrail uses the field mapping in pipelines/kusto_cloudtrail.yml; sshd group-by fields
    (SourceIp, User) keep their names because the hand-written KQL extracts them under those.
    """
    if source != "cloudtrail":
        return sigma_field
    pipeline = yaml.safe_load((REPO_ROOT / "pipelines" / "kusto_cloudtrail.yml").read_text("utf-8"))
    for item in pipeline["transformations"]:
        if item.get("type") == "field_name_mapping":
            return item["mapping"].get(sigma_field, sigma_field)
    return sigma_field


# --- which KQL runs for a rule -----------------------------------------------


def kql_for_rule(rule_id: str) -> tuple[str, str]:
    """Return (kind, query) where kind is 'generated' or 'hand-written'."""
    generated = REPO_ROOT / "queries" / "kql" / f"{rule_id}.kql"
    manual = REPO_ROOT / "kql_manual" / f"{rule_id}.kql"
    if generated.exists() and manual.exists():
        raise ValueError(f"{rule_id} has both generated and hand-written KQL")
    if generated.exists():
        return "generated", generated.read_text(encoding="utf-8")
    if manual.exists():
        return "hand-written", manual.read_text(encoding="utf-8")
    raise FileNotFoundError(f"no KQL for {rule_id} in queries/kql/ or kql_manual/")
