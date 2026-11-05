"""Build docs/results.md and coverage/tripline-layer.json from test results.

    python -m tripline.report --kql-results kql-results.json --corpus-hits corpus-hits.json
    python -m tripline.report ... --check     # exit 1 if the committed files are stale

Every number comes from a run, never from rule tags:
- logic tests: each expectations.yml case is run live through the SQLite harness;
- KQL: per-case outcomes written by the CI test-kql job (Kusto emulator);
- corpus hits: the CI corpora job's corpus-hits.json.
The output holds no timestamps or commit ids, so it is stable while the inputs are.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tripline import kusto
from tripline.attack import ATTACK_VERSION, load_index
from tripline.convert import SPL_UNSUPPORTED
from tripline.harness import Case, all_cases, rule_path, run_case
from tripline.layer import build_layer

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_MD = REPO_ROOT / "docs" / "results.md"
LAYER_JSON = REPO_ROOT / "coverage" / "tripline-layer.json"

SOURCE_NAMES = {
    "sshd": "Linux sshd",
    "cloudtrail": "AWS CloudTrail",
    "windows_security": "Windows Security",
    "sysmon": "Sysmon",
}
#: Order of rows in the table: by source, then rule id.
SOURCE_ORDER = list(SOURCE_NAMES)

VALIDATED = "validated"
SYNTHETIC_ONLY = "synthetic-only"
FAILING = "failing"


@dataclass
class RuleResult:
    rule_id: str
    title: str
    source: str
    techniques: list[str]
    tp_passed: int = 0
    tp_total: int = 0
    benign_passed: int = 0
    benign_total: int = 0
    non_synthetic_tp: bool = False
    kql_kind: str = ""
    kql_passed: int | None = None  # None: no KQL results given
    kql_total: int = 0
    spl: str = ""
    corpus: list[dict] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.failures:
            return FAILING
        return VALIDATED if self.non_synthetic_tp else SYNTHETIC_ONLY


def _rule_docs(rule_id: str) -> list[dict]:
    text = rule_path(rule_id).read_text(encoding="utf-8")
    return [d for d in yaml.safe_load_all(text) if d]


def _techniques(doc: dict) -> list[str]:
    return [
        t.removeprefix("attack.").upper()
        for t in doc.get("tags") or []
        if t.startswith("attack.t") and t[len("attack.t") :][:1].isdigit()
    ]


def collect(kql_results: dict | None, corpus_hits: dict | None) -> list[RuleResult]:
    cases: dict[str, list[Case]] = {}
    for case in all_cases():
        cases.setdefault(case.rule_id, []).append(case)

    results = []
    for rule_id, rule_cases in cases.items():
        main = _rule_docs(rule_id)[-1]
        kind, _ = kusto.kql_for_rule(rule_id)
        result = RuleResult(
            rule_id=rule_id,
            title=main["title"],
            source=rule_cases[0].source,
            techniques=_techniques(main),
            kql_kind=kind,
            spl="n/a (backend unsupported)" if rule_id in SPL_UNSUPPORTED else "generated",
        )
        for case in rule_cases:
            failure = case.check(run_case(case))
            passed = failure is None
            if case.kind == "tp":
                result.tp_total += 1
                result.tp_passed += passed
                result.non_synthetic_tp |= not case.synthetic
            else:
                result.benign_total += 1
                result.benign_passed += passed
            if failure:
                result.failures.append(f"logic {case.test_id}: {failure}")
            if kql_results is not None:
                outcome = kql_results.get(case.test_id)
                result.kql_total += 1
                result.kql_passed = (result.kql_passed or 0) + bool(outcome and outcome["passed"])
                if not outcome:
                    result.failures.append(f"KQL {case.test_id}: not run")
                elif not outcome["passed"]:
                    result.failures.append(f"KQL {case.test_id}: failed")
        if corpus_hits is not None:
            for corpus_id, hit in sorted(corpus_hits["hits"].get(rule_id, {}).items()):
                result.corpus.append({"corpus": corpus_id, **hit})
        results.append(result)
    return sorted(results, key=lambda r: (SOURCE_ORDER.index(r.source), r.rule_id))


# --- docs/results.md -----------------------------------------------------------


def _kql_cell(r: RuleResult) -> str:
    if r.kql_passed is None:
        return f"{r.kql_kind}, not run"
    return f"{r.kql_kind}, {r.kql_passed}/{r.kql_total} pass"


def _corpus_cell(r: RuleResult, corpora: dict) -> str:
    if not r.corpus:
        return "not run"
    parts = []
    for hit in r.corpus:
        label = hit["corpus"]
        text = f"{hit['matches']}"
        if hit["group_count"]:
            text += f" ({hit['group_count']} sources)"
        seen = hit["events_seen"]
        parts.append(f"{text} of {seen:,} events, `{label}`")
    return "<br>".join(parts)


def render_markdown(results: list[RuleResult], corpus_hits: dict | None) -> str:
    index = load_index()
    corpora = (corpus_hits or {}).get("corpora", {})
    counts = {s: sum(r.status == s for r in results) for s in (VALIDATED, SYNTHETIC_ONLY, FAILING)}
    lines = [
        "# Results",
        "",
        "<!-- Generated by `python -m tripline.report`. Do not edit by hand. -->",
        "",
        f"**{len(results)} rules:** {counts[VALIDATED]} validated, "
        f"{counts[SYNTHETIC_ONLY]} synthetic-only, {counts[FAILING]} failing.",
        "",
        "- **validated**: every true-positive and benign test passes (SQLite harness and, where",
        "  run, KQL in the Kusto emulator) and at least one true positive is a real log, not",
        "  synthetic.",
        "- **synthetic-only**: every test passes, but every true positive is synthetic.",
        "- **failing**: at least one test fails.",
        "",
        "| Rule | Technique (ATT&CK v" + ATTACK_VERSION.split(".")[0] + ") | Source | Status "
        "| TP tests | Benign tests | Real TP | KQL | SPL | Hits on unlabelled corpus |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        techniques = "<br>".join(
            f"{t} {index.techniques[t].name}" if t in index.techniques else t for t in r.techniques
        )
        lines.append(
            f"| [{r.rule_id}](rules/{r.rule_id}.md) | {techniques} | {SOURCE_NAMES[r.source]} "
            f"| {r.status} | {r.tp_passed}/{r.tp_total} | {r.benign_passed}/{r.benign_total} "
            f"| {'Y' if r.non_synthetic_tp else 'N'} | {_kql_cell(r)} | {r.spl} "
            f"| {_corpus_cell(r, corpora)} |"
        )
    lines += [
        "",
        "## Reading the columns",
        "",
        "- **TP / Benign tests**: fixtures from `tests/fixtures/`, run through the SQLite harness",
        "  (`pySigma-backend-sqlite`, correlations included).",
        "- **Real TP**: Y if at least one true-positive fixture is a real log (soc-triage, Stratus",
        "  Red Team, Invictus, Splunk attack_data); see each rule's `expectations.yml` and NOTICE.",
        "- **KQL**: *generated* queries (`queries/kql/`) or *hand-written* ones",
        "  (`kql_manual/`, for correlation rules), executed against the same fixtures in the",
        "  Kusto emulator. The",
        "  process rules query Microsoft's `Sysmon` parser function, which must be deployed in",
        "  Sentinel.",
        "- **SPL**: generated by `pySigma-backend-splunk`; not executed (no Splunk in CI).",
        "  *n/a*: the backend cannot convert `temporal_ordered` correlations.",
        "- **Hits on unlabelled corpus**: matches (alert windows for correlation rules, with the",
        "  number of distinct sources) when the rule runs over a real background log that is not",
        "  labelled. This is not pass/fail and **not a false-positive rate**; two of the corpora",
        "  contain attack traffic. The cause of every hit is written up in the rule's doc note.",
        "",
        "## Corpora",
        "",
        "| Corpus | Source | Label | Events |",
        "|---|---|---|---|",
    ]
    for corpus_id, c in sorted(corpora.items()):
        lines.append(
            f"| `{corpus_id}` | {SOURCE_NAMES[c['source']]} | {c['label']} | {c['events']:,} |"
        )
    if not corpora:
        lines.append("| not run | | | |")
    failures = [f for r in results for f in r.failures]
    if failures:
        lines += ["", "## Failures", ""] + [f"- {f}" for f in failures]
    return "\n".join(lines) + "\n"


# --- CLI -----------------------------------------------------------------------


def _load(path: Path | None) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def outputs(kql_results: dict | None, corpus_hits: dict | None) -> dict[Path, str]:
    results = collect(kql_results, corpus_hits)
    layer = build_layer(results)
    return {
        RESULTS_MD: render_markdown(results, corpus_hits),
        LAYER_JSON: json.dumps(layer, indent=2, sort_keys=False) + "\n",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--kql-results", type=Path, help="test-kql job's kql-results.json")
    parser.add_argument("--corpus-hits", type=Path, help="corpora job's corpus-hits.json")
    parser.add_argument("--check", action="store_true", help="fail if committed files differ")
    parser.add_argument("--out-dir", type=Path, help="write copies here instead of the repo")
    args = parser.parse_args(argv)

    generated = outputs(_load(args.kql_results), _load(args.corpus_hits))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(generated[RESULTS_MD])

    stale = [
        p.relative_to(REPO_ROOT).as_posix()
        for p, content in generated.items()
        if not p.exists() or p.read_text(encoding="utf-8") != content
    ]
    if args.out_dir:
        for path, content in generated.items():
            target = args.out_dir / path.relative_to(REPO_ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
    if args.check:
        for path in stale:
            print(f"stale: {path} (regenerate with python -m tripline.report)", file=sys.stderr)
        return 1 if stale else 0
    if not args.out_dir:
        for path, content in generated.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    print(f"{'stale' if stale else 'up to date'}: {', '.join(stale) or 'results.md, layer'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
