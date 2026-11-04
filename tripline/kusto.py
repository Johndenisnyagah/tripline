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
from sigma.pipelines.azuremonitor.tables import AZURE_MONITOR_TABLES

from tripline.parsers import sshd

REPO_ROOT = Path(__file__).resolve().parent.parent
KUSTO_URL = os.environ.get("TRIPLINE_KUSTO_URL", "http://localhost:8080")
DATABASE = "NetDefaultDB"

# Sentinel table per fixture source.
SOURCE_TABLE = {"sshd": "Syslog", "cloudtrail": "AWSCloudTrail"}

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


def fixture_rows(source: str, path: Path) -> list[dict]:
    if source == "sshd":
        return [syslog_row(e) for e in sshd.parse_file(path)]
    if source == "cloudtrail":
        # Raw records, not the flattened parser output: the connector keeps nested JSON.
        records = json.loads(path.read_text(encoding="utf-8"))["Records"]
        return [cloudtrail_row(r) for r in records]
    raise ValueError(f"no Sentinel table mapping for source {source!r}")


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
