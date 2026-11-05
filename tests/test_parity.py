"""soc-triage parity: tripline's rules 1-7 vs soc-triage's six detections on shared samples.

Needs soc-triage's findings, produced in the CI `parity` job:
    python tests/parity/soc_triage_findings.py <soc-triage checkout> > soc-findings.json
    TRIPLINE_SOC_FINDINGS=soc-findings.json TRIPLINE_SOC_TRIAGE=<checkout> pytest -m parity

The offline tests at the bottom (map shape) run everywhere.
"""

import json
import os
from pathlib import Path

import pytest
import yaml

from tripline.harness import FIXTURES_DIR, PARSERS, alert_groups, rule_path, run_rule

ROOT = Path(__file__).parent.parent
MAP = yaml.safe_load((ROOT / "tests" / "parity_map.yml").read_text(encoding="utf-8"))
PAIRS = MAP["pairs"]
SOURCE_OF_SAMPLE = {
    "auth.log": ("sshd", "syslog_sshd"),
    "cloudtrail.json": ("cloudtrail", "aws_cloudtrail"),
}
SOC_RULES = {
    "brute_force_auth",
    "brute_force_success",
    "invalid_user_enumeration",
    "access_key_after_suspicious_auth",
    "cloud_logging_disabled",
    "admin_policy_attached",
}


def _pair_id(pair: dict) -> str:
    return f"{pair['soc_rule']}~{pair['tripline_rule']}"


def tripline_fixture(pair: dict) -> Path:
    source, _ = SOURCE_OF_SAMPLE[pair["sample"]]
    return FIXTURES_DIR / source / pair["tripline_rule"] / "tp" / f"soc-triage_{pair['sample']}"


def tripline_set(pair: dict) -> set[str]:
    source, _ = SOURCE_OF_SAMPLE[pair["sample"]]
    rows = run_rule(rule_path(pair["tripline_rule"]), list(PARSERS[source](tripline_fixture(pair))))
    if pair["compare"] == "ips":
        return alert_groups(rows)
    return {row["timestamp"] for row in rows}


def soc_set(pair: dict, findings: list[dict]) -> set[str]:
    _, soc_source = SOURCE_OF_SAMPLE[pair["sample"]]
    relevant = [
        f for f in findings if f["rule_id"] == pair["soc_rule"] and soc_source in f["source_types"]
    ]
    if pair["compare"] == "ips":
        return {
            f["entity_key"].removeprefix("ip:")
            for f in relevant
            if f["entity_key"].startswith("ip:")
        }
    return {ts for f in relevant for ts, _ip, source in f["evidence"] if source == soc_source}


# --- live comparison (CI parity job) ---------------------------------------------

needs_soc = pytest.mark.skipif(
    not os.environ.get("TRIPLINE_SOC_FINDINGS"),
    reason="needs TRIPLINE_SOC_FINDINGS (CI parity job)",
)


@pytest.fixture(scope="module")
def soc_findings() -> list[dict]:
    return json.loads(Path(os.environ["TRIPLINE_SOC_FINDINGS"]).read_text(encoding="utf-8"))[
        "findings"
    ]


@pytest.mark.parity
@needs_soc
@pytest.mark.parametrize("pair", PAIRS, ids=[_pair_id(p) for p in PAIRS])
def test_parity(pair: dict, soc_findings: list[dict]) -> None:
    soc, ours = soc_set(pair, soc_findings), tripline_set(pair)
    assert soc or ours, f"{_pair_id(pair)}: neither side fired; the pair tests nothing"
    expected = pair.get("expected_difference", {})
    assert sorted(soc - ours) == sorted(expected.get("soc_only", [])), (
        f"{_pair_id(pair)}: soc-triage only {sorted(soc - ours)}"
    )
    assert sorted(ours - soc) == sorted(expected.get("tripline_only", [])), (
        f"{_pair_id(pair)}: tripline only {sorted(ours - soc)}"
    )


@pytest.mark.parity
@needs_soc
@pytest.mark.parametrize("pair", PAIRS, ids=[_pair_id(p) for p in PAIRS])
def test_fixture_is_soc_triage_sample(pair: dict) -> None:
    """tripline's copy is the same file soc-triage ran on (modulo line endings)."""
    checkout = Path(os.environ["TRIPLINE_SOC_TRIAGE"])
    upstream = (checkout / "sample_logs" / pair["sample"]).read_bytes().replace(b"\r\n", b"\n")
    ours = tripline_fixture(pair).read_bytes().replace(b"\r\n", b"\n")
    assert ours == upstream


# --- offline: the map itself -------------------------------------------------------


def test_map_covers_every_soc_triage_detection() -> None:
    assert {p["soc_rule"] for p in PAIRS} == SOC_RULES
    assert MAP["soc_triage"]["commit"] and len(MAP["soc_triage"]["commit"]) == 40


@pytest.mark.parametrize("pair", PAIRS, ids=[_pair_id(p) for p in PAIRS])
def test_map_entry(pair: dict) -> None:
    assert rule_path(pair["tripline_rule"]).exists()
    assert pair["compare"] in ("ips", "events")
    assert tripline_fixture(pair).exists(), tripline_fixture(pair)
    if "expected_difference" in pair:
        assert pair.get("reason"), "every known difference needs a reason"
