"""Run a Sigma rule against parsed fixture events in an in-memory SQLite table.

The rule is converted with pySigma-backend-sqlite, which also converts Sigma
correlation rules (event_count, value_count, temporal_ordered) into SQL with
sliding windows over the `timestamp` column. A rule file that holds a base rule and
its correlation converts to the correlation query only, so the number of rows
returned is the number of alerts the rule raises.

Every column is TEXT COLLATE NOCASE because Sigma string matching is
case-insensitive; SQLite's `=` is not, by default.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from tripline.parsers import cloudtrail, sshd, windows

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

PARSERS: dict[str, Callable[[Path], Iterator[dict]]] = {
    "sshd": sshd.parse_file,
    "cloudtrail": cloudtrail.parse_file,
    "windows_security": windows.parse_file,
}


def rule_path(rule_id: str) -> Path:
    matches = list(RULES_DIR.rglob(f"{rule_id}.yml"))
    if len(matches) != 1:
        raise FileNotFoundError(f"expected one rule file for {rule_id!r}, found {matches}")
    return matches[0]


def _fields(item) -> Iterator[str]:
    """Yield every field name a detection (or nested detection item) refers to."""
    if getattr(item, "field", None):
        yield item.field
    for child in getattr(item, "detection_items", []):
        yield from _fields(child)


def rule_fields(collection: SigmaCollection) -> set[str]:
    fields: set[str] = set()
    for rule in collection.rules:
        if isinstance(rule, SigmaRule):
            for detection in rule.detection.detections.values():
                fields.update(_fields(detection))
        elif isinstance(rule, SigmaCorrelationRule):
            fields.update(rule.group_by or [])
            fieldref = rule.condition.fieldref
            if isinstance(fieldref, str):
                fields.add(fieldref)
            elif fieldref:  # pySigma allows a list of fields for value_count
                fields.update(fieldref)
    return fields


@cache
def _converted(path: Path) -> tuple[tuple[str, ...], frozenset[str]]:
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    queries = sqliteBackend().convert(collection)
    return tuple(queries), frozenset(rule_fields(collection))


def _fold_case(event: dict) -> dict:
    """Key the event by lower-cased field name, keeping the first non-empty value.

    Real CloudTrail can carry the same parameter in two spellings (maxResults / MaxResults);
    SQLite would reject them as duplicate columns.
    """
    folded: dict = {}
    for key, value in event.items():
        if folded.get(key.lower()) is None:
            folded[key.lower()] = value
    return folded


def run_rule(path: Path, events: Iterable[dict]) -> list[sqlite3.Row]:
    """Return every row (match or correlation alert) the rule produces on the events."""
    queries, fields = _converted(path)
    events = [_fold_case(e) for e in events]
    # SQLite column names are case-insensitive: one column per case-folded name.
    columns: dict[str, str] = {}
    for name in sorted({"timestamp", *fields, *(k for e in events for k in e)}):
        columns.setdefault(name.lower(), name)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    column_sql = ", ".join(f'"{c}" TEXT COLLATE NOCASE' for c in columns.values())
    db.execute(f"CREATE TABLE logs ({column_sql})")
    placeholders = ", ".join("?" for _ in columns)
    quoted = ", ".join(f'"{c}"' for c in columns.values())
    db.executemany(
        f"INSERT INTO logs ({quoted}) VALUES ({placeholders})",
        [[e.get(key) for key in columns] for e in events],
    )
    rows: list[sqlite3.Row] = []
    for query in queries:
        rows.extend(db.execute(query).fetchall())
    db.close()
    return rows


# --- expectations ------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One entry of a rule's expectations.yml."""

    source: str
    rule_id: str
    file: str
    origin: str
    synthetic: bool
    expect: dict

    @property
    def kind(self) -> str:  # "tp" or "benign"
        return self.file.split("/", 1)[0]

    @property
    def path(self) -> Path:
        return FIXTURES_DIR / self.source / self.rule_id / self.file

    @property
    def test_id(self) -> str:
        return f"{self.rule_id}:{self.file}"

    def events(self) -> list[dict]:
        return list(PARSERS[self.source](self.path))

    def check(self, rows: list[sqlite3.Row]) -> str | None:
        """Return None if the rule's output meets the expectation, else a failure message.

        `matches` / `min_matches` count result rows. For correlations the sqlite backend
        emits one row per qualifying window, so a burst of 8 failures yields several rows;
        `groups` pins down *which* group-by values fired (exact set).
        """
        return self.check_counts(len(rows), alert_groups(rows))

    def check_counts(self, matches: int, groups: set[str]) -> str | None:
        """Shared by the SQLite harness and the Kusto emulator tests."""
        if "matches" in self.expect and matches != self.expect["matches"]:
            return f"expected exactly {self.expect['matches']} matches, got {matches}"
        if "min_matches" in self.expect and matches < self.expect["min_matches"]:
            return f"expected at least {self.expect['min_matches']} matches, got {matches}"
        if "groups" in self.expect:
            fired = sorted(groups)
            if fired != sorted(self.expect["groups"]):
                return f"expected groups {sorted(self.expect['groups'])}, fired for {fired}"
        return None


def alert_groups(rows: list[sqlite3.Row]) -> set[str]:
    """Group-by values of correlation alerts, joined with '|' for multi-field group-by."""
    groups = set()
    for row in rows:
        # sqlite3.Row: `in row` tests values, so .keys() is needed. Single-event rows have none.
        if "group_keys" not in row.keys():  # noqa: SIM118
            continue
        keys = json.loads(row["group_keys"])
        groups.add("|".join(str(v) for v in keys.values()))
    return groups


def expectation_files() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*/*/expectations.yml"))


def load_cases(path: Path) -> list[Case]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    source = path.parent.parent.name
    return [
        Case(
            source=source,
            rule_id=data["rule_id"],
            file=t["file"],
            origin=t["origin"],
            synthetic=bool(t["synthetic"]),
            expect=t["expect"],
        )
        for t in data["tests"]
    ]


def all_cases() -> list[Case]:
    return [case for path in expectation_files() for case in load_cases(path)]


def run_case(case: Case) -> list[sqlite3.Row]:
    return run_rule(rule_path(case.rule_id), case.events())
