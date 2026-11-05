"""Run every rule over the background corpora in tests/corpora/manifest.yml.

    python -m tripline.corpora                 # writes .cache/corpus-hits.json, prints a table
    python -m tripline.corpora --out hits.json

Each corpus is downloaded once into the cache (keyed by sha256, verified), the archive member
is extracted (and gunzipped), and every rule whose fixtures use the same log source is run
over it with the SQLite harness. The counts are hits on an unlabelled corpus: not pass/fail,
and not a false-positive rate.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

import yaml

from tripline.harness import PARSERS, all_cases, events_for_rule, rule_path, run_rule

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "tests" / "corpora" / "manifest.yml"
#: Group-by values listed per rule and corpus (the full count is always reported).
MAX_GROUPS_LISTED = 20


def cache_dir() -> Path:
    root = Path(os.environ.get("TRIPLINE_CACHE", REPO_ROOT / ".cache"))
    path = root / "corpora"
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_manifest(path: Path = MANIFEST) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["corpora"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(entry: dict) -> Path:
    """The verified download for a manifest entry (fetched once, cached by sha256)."""
    target = cache_dir() / entry["sha256"] / Path(entry["url"].split("?")[0]).name
    if target.exists() and _sha256(target) == entry["sha256"]:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(entry["url"], headers={"User-Agent": "tripline-corpora"})
    with urllib.request.urlopen(request, timeout=600) as response, tmp.open("wb") as out:  # noqa: S310
        shutil.copyfileobj(response, out)
    actual = _sha256(tmp)
    if actual != entry["sha256"]:
        tmp.unlink()
        raise RuntimeError(f"{entry['id']}: sha256 mismatch: {actual} != {entry['sha256']}")
    tmp.replace(target)
    return target


def materialise(entry: dict) -> Path:
    """The file to parse: the download itself, or its archive member (gunzipped)."""
    archive = download(entry)
    member = entry.get("member")
    if not member:
        return archive
    out_dir = archive.parent / "extracted"
    extracted = out_dir / member
    final = extracted.with_suffix("") if member.endswith(".gz") else extracted
    if final.exists():
        return final
    with tarfile.open(archive) as tar:
        tar.extract(member, out_dir, filter="data")
    if member.endswith(".gz"):
        with gzip.open(extracted, "rb") as src, final.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        extracted.unlink()
    return final


def _parsed_cache(entry: dict, path: Path) -> Path:
    """Where the parsed events of a corpus are cached.

    Keyed by the corpus, the record cap and the parser's source code, so a parser change
    re-parses. Parsing the 222 MB Sysmon EVTX with python-evtx takes ~15 minutes; after that,
    CI reads the cached events in seconds.
    """
    parser_source = Path(sys.modules[PARSERS[entry["source"]].__module__].__file__).read_bytes()
    key = hashlib.sha256(parser_source + str(entry.get("max_records")).encode()).hexdigest()[:16]
    return path.parent / f"{path.name}.{key}.events.jsonl.gz"


def corpus_events(entry: dict) -> list[dict]:
    path = materialise(entry)
    cached = _parsed_cache(entry, path)
    if cached.exists():
        with gzip.open(cached, "rt", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]
    parse = PARSERS[entry["source"]]
    if entry.get("max_records"):
        events = list(parse(path, max_records=entry["max_records"]))
    else:
        events = list(parse(path))
    tmp = cached.with_suffix(".part")
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    tmp.replace(cached)
    return events


def rules_by_source() -> dict[str, list[str]]:
    sources: dict[str, set[str]] = {}
    for case in all_cases():
        sources.setdefault(case.source, set()).add(case.rule_id)
    return {source: sorted(rules) for source, rules in sources.items()}


def _groups(rows) -> list[str]:
    groups = set()
    for row in rows:
        if "group_keys" in row.keys():  # noqa: SIM118 (sqlite3.Row)
            groups.add("|".join(str(v) for v in json.loads(row["group_keys"]).values()))
    return sorted(groups)


def run(manifest: list[dict] | None = None) -> dict:
    manifest = manifest if manifest is not None else load_manifest()
    rules = rules_by_source()
    result: dict = {"corpora": {}, "hits": {}}
    for entry in manifest:
        events = corpus_events(entry)
        result["corpora"][entry["id"]] = {
            "source": entry["source"],
            "label": entry["label"],
            "events": len(events),
            "sha256": entry["sha256"],
            "member": entry.get("member"),
            "max_records": entry.get("max_records"),
        }
        for rule_id in rules.get(entry["source"], []):
            seen = events_for_rule(entry["source"], rule_id, events)
            rows = run_rule(rule_path(rule_id), seen)
            groups = _groups(rows)
            result["hits"].setdefault(rule_id, {})[entry["id"]] = {
                # Events the rule could look at (Sysmon: only its category's EventID).
                "events_seen": len(seen),
                "matches": len(rows),
                "group_count": len(groups),
                "groups": groups[:MAX_GROUPS_LISTED],
            }
    return result


def table(result: dict) -> str:
    lines = ["| Rule | Corpus | Events seen | Hits | Groups |", "|---|---|---|---|---|"]
    for rule_id in sorted(result["hits"]):
        for corpus_id, hit in result["hits"][rule_id].items():
            groups = hit["group_count"] or ""
            lines.append(
                f"| {rule_id} | {corpus_id} | {hit['events_seen']} | {hit['matches']} | {groups} |"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=cache_dir().parent / "corpus-hits.json")
    args = parser.parse_args(argv)
    result = run()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(table(result))
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
