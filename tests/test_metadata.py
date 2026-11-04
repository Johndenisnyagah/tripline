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


def test_checker_rejects_dangling_correlation_reference(tmp_path: Path) -> None:
    rule = Path(__file__).parent.parent / "rules/linux/sshd/lnx_sshd_brute_force_success.yml"
    text = rule.read_text(encoding="utf-8")
    broken = text.replace("        - lnx_sshd_bfs_failure_burst\n", "        - lnx_sshd_typo\n")
    assert broken != text
    path = tmp_path / rule.name
    path.write_text(broken, encoding="utf-8")
    problems = check_rule_file(path)
    assert any("'lnx_sshd_typo' before it is defined" in p for p in problems), problems
    assert any("not used by any correlation" in p for p in problems), problems


def test_every_copied_fixture_is_in_notice() -> None:
    """Spec §11: every copied dataset file has a NOTICE entry (path, source, version, licence)."""
    from tripline.harness import FIXTURES_DIR, all_cases

    notice = (Path(__file__).parent.parent / "NOTICE").read_text(encoding="utf-8")
    missing = [
        case.path.relative_to(FIXTURES_DIR.parent.parent).as_posix()
        for case in all_cases()
        if case.origin != "synthetic"
        and case.path.relative_to(FIXTURES_DIR.parent.parent).as_posix() not in notice
    ]
    assert not missing, "copied fixtures missing from NOTICE:\n" + "\n".join(missing)


def test_synthetic_flag_matches_origin() -> None:
    from tripline.harness import all_cases

    wrong = [c.test_id for c in all_cases() if c.synthetic != (c.origin == "synthetic")]
    assert not wrong, f"synthetic flag disagrees with origin: {wrong}"
