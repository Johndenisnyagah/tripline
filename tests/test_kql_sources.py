"""Offline checks for the KQL test setup (no emulator needed)."""

import json

import pytest
import yaml

from tripline import kusto
from tripline.metadata import rule_files

RULES = rule_files()


@pytest.mark.parametrize("path", RULES, ids=[p.stem for p in RULES])
def test_every_rule_has_exactly_one_kql(path) -> None:
    kind, _ = kusto.kql_for_rule(path.stem)
    docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    expected = "hand-written" if "correlation" in docs[-1] else "generated"
    assert kind == expected


def test_hand_written_kql_has_header() -> None:
    for path in sorted((kusto.REPO_ROOT / "kql_manual").glob("*.kql")):
        header = path.read_text(encoding="utf-8").splitlines()[:6]
        assert any(path.stem in line for line in header), f"{path.name}: header must name rule"
        assert any(line.startswith("// Why hand-written:") for line in header), path.name


def test_cloudtrail_row_uses_sentinel_columns() -> None:
    record = {
        "eventTime": "2026-08-02T04:59:20Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "sourceIPAddress": "203.0.113.5",
        "errorCode": "AccessDenied",
        "readOnly": False,
        "userIdentity": {"type": "IAMUser", "userName": "deploy", "principalId": "AIDA1"},
        "requestParameters": {"name": "org-trail"},
        "responseElements": None,
    }
    row = kusto.cloudtrail_row(record)
    schema = kusto.table_schema("AWSCloudTrail")
    assert set(row) <= set(schema), set(row) - set(schema)
    assert row["EventName"] == "StopLogging"
    assert row["SourceIpAddress"] == "203.0.113.5"
    assert row["UserIdentityPrincipalid"] == "AIDA1"
    assert row["ReadOnly"] is False
    assert json.loads(row["RequestParameters"]) == {"name": "org-trail"}
    assert row["ResponseElements"] is None


def test_syslog_row_uses_sentinel_columns() -> None:
    event = {
        "timestamp": "2026-08-02T04:41:07Z",
        "HostName": "webserver01",
        "ProcessName": "sshd",
        "ProcessID": "3311",
        "SyslogMessage": "Failed password for root from 203.0.113.5 port 44102 ssh2",
    }
    row = kusto.syslog_row(event)
    assert set(row) <= set(kusto.table_schema("Syslog"))
