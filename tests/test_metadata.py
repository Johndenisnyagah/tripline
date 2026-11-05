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


#: sha256 of third-party files whose bytes git must not normalise (see .gitattributes, NOTICE).
PINNED_SHA256 = {
    "tests/fixtures/windows_security/win_security_password_spraying/tp/"
    "splunk-attack-data_purplesharp_remote_spray_xml.log": (
        "92ab741ca691f9b7308cc684864bee0b0bff1bb1e01440c4ab874a3afa3f4307"
    ),
    "tests/fixtures/windows_security/win_security_security_log_cleared/tp/"
    "splunk-attack-data_windows_event_log_cleared.log": (
        "fd483a9c03b1cf5b10b4cc8b1500abd782da334647e93db61edee7f7040dce87"
    ),
    "tests/fixtures/sysmon/proc_creation_win_powershell_encoded_command/tp/"
    "splunk-attack-data_encoded_powershell_explorer_spawns.log": (
        "9200692ad74037b5234fe6f7da733d3e416b0ea8bb7f6d8ebb5bd16fc39b8b22"
    ),
    "tests/fixtures/sysmon/proc_creation_win_clickfix_paste_and_run/tp/"
    "splunk-attack-data_encoded_powershell_explorer_spawns.log": (
        "9200692ad74037b5234fe6f7da733d3e416b0ea8bb7f6d8ebb5bd16fc39b8b22"
    ),
    "tests/fixtures/sysmon/proc_creation_win_wmic_process_call_create/benign/"
    "splunk-attack-data_wmic_classes.log": (
        "4d4894fe9a4d6bc11315788d0cd4f83e5865a7fbb7be9c2441eedd451fe4f8e5"
    ),
    "tests/fixtures/sysmon/proc_creation_win_shadow_copy_deletion/tp/"
    "splunk-attack-data_shadowcopy_del.log": (
        "b943f1ca687118745fae96c11af10a07f8d91f7b34d6c24757579ee55ad539b7"
    ),
}


@pytest.mark.parametrize("relpath", PINNED_SHA256)
def test_copied_file_is_byte_identical_to_upstream(relpath: str) -> None:
    import hashlib

    data = (Path(__file__).parent.parent / relpath).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED_SHA256[relpath]


#: Sections every doc note has (spec §8: shortened Palantir ADS format).
DOC_NOTE_SECTIONS = (
    "**Goal:**",
    "**ATT&CK (v20):**",
    "**How it works:**",
    "**Blind spots:**",
    "**False positives:**",
    "**Validation:**",
    "**Background corpora**",
    "**SigmaHQ relation:**",
    "**KQL:**",
)


@pytest.mark.parametrize("path", RULES, ids=[p.stem for p in RULES])
def test_doc_note_is_complete(path: Path) -> None:
    note = (Path(__file__).parent.parent / "docs" / "rules" / f"{path.stem}.md").read_text(
        encoding="utf-8"
    )
    missing = [s for s in DOC_NOTE_SECTIONS if s not in note]
    assert not missing, f"docs/rules/{path.stem}.md lacks {missing}"
    assert "later step" not in note
