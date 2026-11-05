"""KQL executed in the Kusto emulator against the same fixtures and expectations as test_rules.py.

Runs only in the CI `test-kql` job (`pytest -m kql`), which starts the emulator as a service
container. Locally: `docker run -e ACCEPT_EULA=Y -p 8080:8080 <image>` then `pytest -m kql`.

Single-event rules run their generated query (queries/kql/); correlation rules run their
hand-written query (kql_manual/). For correlation rules the `groups` expectation is checked
against the output columns named by the rule's group-by fields.
"""

import json
import os
from pathlib import Path

import pytest
import yaml

from tripline import kusto
from tripline.harness import Case, all_cases, rule_path

pytestmark = pytest.mark.kql

CASES = all_cases()
#: Per-case outcomes, written to $TRIPLINE_KQL_RESULTS for the report job (docs/results.md).
RESULTS: dict[str, dict] = {}


@pytest.fixture(scope="module", autouse=True)
def emulator():
    kusto.wait_until_ready()
    kusto.create_tables()
    yield
    out = os.environ.get("TRIPLINE_KQL_RESULTS")
    if out:
        Path(out).write_text(json.dumps(RESULTS, indent=2, sort_keys=True) + "\n", "utf-8")


def group_by_fields(rule_id: str) -> list[str]:
    docs = [d for d in yaml.safe_load_all(rule_path(rule_id).read_text(encoding="utf-8")) if d]
    return (docs[-1].get("correlation") or {}).get("group-by") or []


@pytest.mark.parametrize("case", CASES, ids=[c.test_id for c in CASES])
def test_kql_on_fixture(case: Case) -> None:
    kind, kql = kusto.kql_for_rule(case.rule_id)
    kusto.ingest(kusto.SOURCE_TABLE[case.source], kusto.fixture_rows(case.source, case.path))
    rows = kusto.query(kql)

    columns = [kusto.sentinel_column(case.source, f) for f in group_by_fields(case.rule_id)]
    groups = {"|".join(str(row[c]) for c in columns) for row in rows} if columns else set()
    failure = case.check_counts(len(rows), groups)
    RESULTS[case.test_id] = {"kql": kind, "passed": failure is None, "matches": len(rows)}
    assert failure is None, f"{case.test_id} ({kind} KQL): {failure}\nrows: {rows[:5]}"
