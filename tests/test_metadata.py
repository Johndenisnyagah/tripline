"""Rule metadata: required fields, conventions, ATT&CK v20 tags, fixtures and docs."""

from pathlib import Path

import pytest

from tripline.metadata import check_rule_file, check_uniqueness, rule_files

RULES = rule_files()


def test_rules_exist() -> None:
    assert RULES, "no rules found under rules/"


@pytest.mark.parametrize("path", RULES, ids=[p.stem for p in RULES])
def test_rule_metadata(path: Path) -> None:
    problems = check_rule_file(path)
    assert not problems, "\n".join(problems)


def test_ids_and_filenames_unique() -> None:
    problems = check_uniqueness(RULES)
    assert not problems, "\n".join(problems)


# --- the checker itself must catch bad rules ---------------------------------

GOOD_RULE = (
    Path(__file__).parent.parent / "rules/aws/cloudtrail/aws_cloudtrail_logging_disabled.yml"
)


def _mutated(tmp_path: Path, old: str, new: str) -> Path:
    text = GOOD_RULE.read_text(encoding="utf-8")
    assert old in text
    path = tmp_path / GOOD_RULE.name
    path.write_text(text.replace(old, new), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("attack.t1685.002", "attack.t1562.008", "T1562.008 is revoked"),
        ("attack.t1685.002", "attack.t1070.001", "T1070.001 is revoked"),
        ("attack.t1685.002", "attack.t9999", "T9999 does not exist"),
        ("attack.defense-impairment", "attack.defense-evasion", "not a v20 tactic"),
        ("status: experimental", "status: test", "status must be experimental"),
        ("description: |\n    Detects", "description: |\n    Finds", "must start with 'Detects'"),
    ],
)
def test_checker_rejects(tmp_path: Path, old: str, new: str, expected: str) -> None:
    problems = check_rule_file(_mutated(tmp_path, old, new))
    assert any(expected in p for p in problems), problems
