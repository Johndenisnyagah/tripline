"""Conversion: committed queries/ match the rules, drift is detected, pipelines map fields."""

import shutil
from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

from tripline.convert import QUERIES_DIR, _pipeline, drift, generate

NESTED_RULE = """
title: Nested CloudTrail Fields
id: 0b0e7d4e-2f39-4a43-9d0e-6b8b8c1f2a10
status: experimental
logsource: {product: aws, service: cloudtrail}
detection:
    selection:
        eventName: AttachUserPolicy
        requestParameters.policyArn|endswith: /AdministratorAccess
        userIdentity.type: Root
    filter:
        additionalEventData.MFAUsed: 'Yes'
    condition: selection and not filter
"""


def test_committed_queries_up_to_date() -> None:
    problems = drift()
    assert not problems, "\n".join(problems) + "\nRun `python -m tripline.convert`."


def test_hand_edit_is_detected(tmp_path: Path) -> None:
    copy = tmp_path / "queries"
    shutil.copytree(QUERIES_DIR, copy)
    assert drift(copy) == []
    edited = copy / "kql" / "aws_cloudtrail_logging_disabled.kql"
    edited.write_text(edited.read_text(encoding="utf-8") + "| take 10\n", encoding="utf-8")
    assert drift(copy) == [f"differs from generated: queries/kql/{edited.name}"]


def test_stale_and_missing_files_are_detected(tmp_path: Path) -> None:
    copy = tmp_path / "queries"
    shutil.copytree(QUERIES_DIR, copy)
    (copy / "spl" / "lnx_sshd_brute_force_password_guessing.spl").unlink()
    (copy / "kql" / "removed_rule.kql").write_text("x\n", encoding="utf-8")
    assert sorted(drift(copy)) == [
        "missing: queries/spl/lnx_sshd_brute_force_password_guessing.spl",
        "stale (no rule): queries/kql/removed_rule.kql",
    ]


def test_correlation_rules_get_spl_but_no_generated_kql() -> None:
    files = generate()
    assert Path("spl/lnx_sshd_brute_force_password_guessing.spl") in files
    assert Path("kql/lnx_sshd_brute_force_password_guessing.kql") not in files


def test_cloudtrail_kql_targets_awscloudtrail() -> None:
    kql = generate()[Path("kql/aws_cloudtrail_logging_disabled.kql")]
    assert kql.startswith("AWSCloudTrail\n| where ")
    assert 'EventSource =~ "cloudtrail.amazonaws.com"' in kql


def test_cloudtrail_nested_fields_become_parse_json() -> None:
    backend = KustoBackend(_pipeline(("kusto_cloudtrail.yml",)))
    (kql,) = backend.convert(SigmaCollection.from_yaml(NESTED_RULE))
    assert kql == (
        "AWSCloudTrail\n"
        '| where (EventName =~ "AttachUserPolicy" and '
        'tostring(parse_json(RequestParameters).policyArn) endswith "/AdministratorAccess" and '
        'UserIdentityType =~ "Root") and '
        '(not(tostring(parse_json(AdditionalEventData).MFAUsed) =~ "Yes"))'
    )


def test_cloudtrail_spl_passes_fields_through() -> None:
    (spl,) = SplunkBackend(_pipeline(("splunk_cloudtrail.yml",))).convert(
        SigmaCollection.from_yaml(NESTED_RULE)
    )
    assert spl.startswith('sourcetype="aws:cloudtrail" eventName="AttachUserPolicy"')
    assert 'requestParameters.policyArn="*/AdministratorAccess"' in spl
