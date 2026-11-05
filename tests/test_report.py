"""Results table and Navigator layer: statuses come from test results, output is stable."""

import json

import pytest

from tripline import report
from tripline.harness import all_cases
from tripline.layer import COLORS, build_layer

CASES = all_cases()


def _kql(passed: bool = True, skip: str | None = None) -> dict:
    return {
        c.test_id: {"kql": "x", "passed": passed, "matches": 0} for c in CASES if c.test_id != skip
    }


@pytest.fixture(scope="module")
def results() -> list[report.RuleResult]:
    return report.collect(_kql(), None)


def test_one_row_per_rule(results) -> None:
    assert len(results) == len({c.rule_id for c in CASES}) == 20


def test_status_follows_real_true_positives(results) -> None:
    by_id = {r.rule_id: r for r in results}
    # Rules whose true positives are all synthetic (see the Decisions log).
    synthetic_only = {
        "aws_cloudtrail_bucket_public_access_block_weakened",
        "proc_creation_win_wmic_process_call_create",
        "proc_creation_win_certutil_download",
        "proc_access_win_lsass_suspicious_access",
    }
    assert {r for r, v in by_id.items() if v.status == report.SYNTHETIC_ONLY} == synthetic_only
    assert all(v.status == report.VALIDATED for r, v in by_id.items() if r not in synthetic_only)


def test_failed_or_missing_kql_case_makes_rule_failing() -> None:
    case = CASES[0]
    failed = {case.test_id: {"kql": "x", "passed": False, "matches": 0}}
    rows = report.collect({**_kql(), **failed}, None)
    assert next(r for r in rows if r.rule_id == case.rule_id).status == report.FAILING
    missing = report.collect(_kql(skip=case.test_id), None)
    row = next(r for r in missing if r.rule_id == case.rule_id)
    assert row.status == report.FAILING and any("not run" in f for f in row.failures)


def test_layer_format_and_colours(results) -> None:
    layer = build_layer(results)
    assert layer["versions"] == {"attack": "20", "navigator": "5.3.2", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    scored = {t["techniqueID"]: t for t in layer["techniques"] if "score" in t}
    assert scored["T1110.001"]["score"] == 2  # rules 1 and 2
    assert scored["T1110.001"]["color"] == COLORS["validated"]
    assert scored["T1686.001"]["color"] == COLORS["synthetic-only"]
    assert all("tactic" not in t for t in layer["techniques"])
    parents = {t["techniqueID"] for t in layer["techniques"] if "score" not in t}
    assert "T1003" in parents  # T1003.001 is tagged, its parent is shown expanded


def test_failing_rule_turns_its_technique_red(results) -> None:
    rule = next(r for r in results if "T1490" in r.techniques)
    rule.failures.append("forced")
    try:
        technique = next(
            t for t in build_layer(results)["techniques"] if t["techniqueID"] == "T1490"
        )
        assert technique["color"] == COLORS["failing"]
    finally:
        rule.failures.remove("forced")


def test_output_is_stable() -> None:
    hits = {"corpora": {}, "hits": {}}
    first = report.outputs(_kql(), hits)
    second = report.outputs(_kql(), hits)
    assert first == second
    markdown = first[report.RESULTS_MD]
    assert "Do not edit by hand" in markdown and "**20 rules:**" in markdown
    json.loads(first[report.LAYER_JSON])
