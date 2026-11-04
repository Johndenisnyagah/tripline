"""Metadata checks for tripline rules (beyond what `sigma check` covers).

`check_rule_file` returns a list of problems for one rule file; an empty list means
the file passes. Kept as plain functions so a test can feed it a deliberately broken
rule (e.g. a revoked ATT&CK ID) and assert that it is caught.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import yaml

from tripline.attack import AttackIndex, load_index

REPO_ROOT = Path(__file__).resolve().parent.parent

FILENAME_PREFIXES = (
    "lnx_sshd_",
    "aws_cloudtrail_",
    "win_security_",
    "proc_creation_win_",
    "proc_access_win_",
)
AUTHOR = "John Denis Nyagah"
REQUIRED = ("title", "id", "status", "description", "author", "date", "level")
TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
# GitHub links must pin a commit, not a moving branch.
GITHUB_BRANCH_LINK = re.compile(r"github\.com/[^/]+/[^/]+/(?:blob|tree)/(?![0-9a-f]{40}/)")


def load_documents(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def _check_tags(doc: dict, index: AttackIndex) -> list[str]:
    problems = []
    for tag in doc.get("tags") or []:
        if not tag.startswith("attack."):
            continue
        name = tag.removeprefix("attack.")
        technique = TECHNIQUE_TAG.match(tag)
        if technique:
            tid = technique.group(1).upper()
            found = index.techniques.get(tid)
            if found is None:
                problems.append(f"tag {tag}: {tid} does not exist in ATT&CK v20")
            elif found.revoked:
                problems.append(f"tag {tag}: {tid} is revoked in ATT&CK v20")
            elif found.deprecated:
                problems.append(f"tag {tag}: {tid} is deprecated in ATT&CK v20")
        elif re.fullmatch(r"[a-z]+(?:-[a-z]+)*", name):
            if name not in index.tactics:
                problems.append(f"tag {tag}: not a v20 tactic shortname")
        elif not re.fullmatch(r"[gs]\d{4}", name):
            problems.append(f"tag {tag}: unrecognised attack tag")
    return problems


def check_rule_file(path: Path, index: AttackIndex | None = None) -> list[str]:
    index = index or load_index()
    problems: list[str] = []
    stem = path.stem
    if not stem.startswith(FILENAME_PREFIXES):
        problems.append(f"filename must start with one of {FILENAME_PREFIXES}")
    if not 10 <= len(path.name) <= 90:
        problems.append(f"filename length {len(path.name)} outside 10-90")

    docs = load_documents(path)
    if not docs:
        return [*problems, "file contains no YAML documents"]
    # The last document is the one that alerts: the single rule, or the correlation.
    *bases, main = docs
    base_names = set()
    for base in bases:
        if "correlation" in base or "name" not in base:
            problems.append("only the last document may be a correlation; bases need `name`")
        base_names.add(base.get("name"))
    if bases:
        referenced = set((main.get("correlation") or {}).get("rules") or [])
        if referenced != base_names:
            problems.append(f"correlation rules {referenced} != base rule names {base_names}")

    for doc in docs:
        title = doc.get("title", "<untitled>")
        missing = [f for f in REQUIRED if f not in doc]
        if missing:
            problems.append(f"{title}: missing {missing}")
        if doc.get("status") != "experimental":
            problems.append(f"{title}: status must be experimental")
        if doc.get("author") != AUTHOR:
            problems.append(f"{title}: author must be {AUTHOR!r}")
        if not str(doc.get("description", "")).startswith("Detects"):
            problems.append(f"{title}: description must start with 'Detects'")
        try:
            if uuid.UUID(str(doc.get("id"))).version != 4:
                problems.append(f"{title}: id is not a UUIDv4")
        except ValueError:
            problems.append(f"{title}: id is not a UUID")
        if not doc.get("falsepositives"):
            problems.append(f"{title}: falsepositives must not be empty")
        for ref in doc.get("references") or []:
            if "attack.mitre.org" in ref:
                problems.append(f"{title}: no attack.mitre.org references (tags carry ATT&CK)")
            if GITHUB_BRANCH_LINK.search(ref):
                problems.append(f"{title}: GitHub reference is not a commit permalink: {ref}")
        problems.extend(f"{title}: {p}" for p in _check_tags(doc, index))

    if not any(TECHNIQUE_TAG.match(t) for t in main.get("tags") or []):
        problems.append("alerting rule has no attack.tXXXX technique tag")

    rule_id = stem
    expectations = list((REPO_ROOT / "tests" / "fixtures").glob(f"*/{rule_id}/expectations.yml"))
    if len(expectations) != 1:
        problems.append(f"expected one tests/fixtures/*/{rule_id}/expectations.yml")
    else:
        data = yaml.safe_load(expectations[0].read_text(encoding="utf-8"))
        if data.get("rule_id") != rule_id:
            problems.append(f"expectations rule_id {data.get('rule_id')!r} != {rule_id!r}")
        files = [t["file"] for t in data.get("tests", [])]
        for kind in ("tp", "benign"):
            if not any(f.startswith(f"{kind}/") for f in files):
                problems.append(f"expectations need at least one {kind}/ test")
        for f in files:
            if not (expectations[0].parent / f).is_file():
                problems.append(f"expectations reference missing fixture {f}")

    if not (REPO_ROOT / "docs" / "rules" / f"{rule_id}.md").is_file():
        problems.append(f"missing docs/rules/{rule_id}.md")
    return problems


def rule_files() -> list[Path]:
    return sorted((REPO_ROOT / "rules").rglob("*.yml"))


def check_uniqueness(paths: list[Path]) -> list[str]:
    problems = []
    seen_ids: dict[str, Path] = {}
    seen_names: dict[str, Path] = {}
    for path in paths:
        if path.name in seen_names:
            problems.append(f"duplicate filename {path.name}: {seen_names[path.name]}, {path}")
        seen_names[path.name] = path
        for doc in load_documents(path):
            rid = str(doc.get("id"))
            if rid in seen_ids:
                problems.append(f"duplicate id {rid}: {seen_ids[rid]}, {path}")
            seen_ids[rid] = path
    return problems
