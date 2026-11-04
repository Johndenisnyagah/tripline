"""Sigma rule logic against fixtures: one test per expectations.yml entry.

Each rule is converted with pySigma-backend-sqlite (correlations included) and run
over its parsed fixture in an in-memory SQLite table. See tripline/harness.py.
"""

import pytest

from tripline.harness import Case, all_cases, run_case

CASES = all_cases()


def test_cases_exist() -> None:
    assert CASES, "no expectations.yml found under tests/fixtures/"


@pytest.mark.parametrize("case", CASES, ids=[c.test_id for c in CASES])
def test_rule_on_fixture(case: Case) -> None:
    assert case.kind in ("tp", "benign"), f"fixture must live in tp/ or benign/: {case.file}"
    if case.kind == "benign":
        assert case.expect == {"matches": 0}, "benign fixtures must expect matches: 0"
    failure = case.check(run_case(case))
    assert failure is None, f"{case.test_id} ({case.origin}): {failure}"
