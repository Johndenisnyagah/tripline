"""README numbers come only from docs/results.md (CLAUDE.md hard rule); links resolve."""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
RESULTS = (ROOT / "docs" / "results.md").read_text(encoding="utf-8")


def _results_summary() -> str:
    """The rule-count line and the totals block at the top of docs/results.md."""
    start = RESULTS.index("**")
    end = RESULTS.index("- **validated**")
    return RESULTS[start:end].strip()


def _readme_summary() -> str:
    match = re.search(
        r"<!-- results-summary:start -->\n(.*?)\n<!-- results-summary:end -->", README, re.S
    )
    assert match, "README needs the results-summary block"
    return match.group(1).strip()


def _readme_rules() -> dict[int, str]:
    rows = re.findall(r"^\| (\d+) \| \[[^\]]+\]\(docs/rules/(\w+)\.md\)", README, re.M)
    return {int(number): rule_id for number, rule_id in rows}


def test_summary_block_is_copied_from_results() -> None:
    assert _readme_summary() == _results_summary(), (
        "README summary differs from docs/results.md; copy the block from the generated file"
    )


def test_rule_table_lists_every_rule_once() -> None:
    rules = _readme_rules()
    on_disk = {p.stem for p in (ROOT / "rules").rglob("*.yml")}
    assert sorted(rules) == list(range(1, 21))
    assert set(rules.values()) == on_disk


def test_synthetic_only_rules_named_in_readme_match_results() -> None:
    sentence = re.search(r"Rules ([\d, and]+) have synthetic true positives only", README)
    assert sentence, "README must name the synthetic-only rules"
    named = {int(n) for n in re.findall(r"\d+", sentence.group(1))}
    rules = _readme_rules()
    synthetic_only = {
        rule_id
        for rule_id in rules.values()
        if re.search(rf"\[{rule_id}\]\(rules/{rule_id}\.md\) \|[^\n]*\| synthetic-only \|", RESULTS)
    }
    assert {rules[n] for n in named} == synthetic_only


def test_relative_links_resolve() -> None:
    for target in re.findall(r"\]\((?!https?://|#)([^)#]+)\)", README):
        assert (ROOT / target).exists(), f"README links to missing {target}"
