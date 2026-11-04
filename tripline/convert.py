"""Regenerate queries/kql/ and queries/spl/ from rules/.

    python -m tripline.convert           # write queries/
    python -m tripline.convert --check   # exit 1 if committed queries/ differ (drift)

KQL is generated only for single-event rules. The Kusto backend cannot convert Sigma
correlation rules, so those get hand-written KQL in kql_manual/ instead. SPL is generated
for every rule the Splunk backend can convert (see SPL_UNSUPPORTED).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.processing.pipeline import ProcessingPipeline

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
PIPELINES_DIR = REPO_ROOT / "pipelines"
QUERIES_DIR = REPO_ROOT / "queries"


def _yaml_pipeline(name: str) -> ProcessingPipeline:
    return ProcessingPipeline.from_yaml((PIPELINES_DIR / name).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Target:
    """Which pipelines convert a rule from one log source, per backend."""

    kql: tuple[str, ...]  # YAML pipelines in pipelines/
    kql_azure_monitor: bool  # also apply pySigma's azure_monitor pipeline
    spl: tuple[str, ...]


TARGETS: dict[tuple[str | None, str | None, str | None], Target] = {
    # (product, service, category)
    ("linux", "sshd", None): Target(
        kql=("kusto_syslog.yml",), kql_azure_monitor=True, spl=("splunk_sshd.yml",)
    ),
    ("aws", "cloudtrail", None): Target(
        kql=("kusto_cloudtrail.yml",), kql_azure_monitor=False, spl=("splunk_cloudtrail.yml",)
    ),
}


#: Rules the Splunk backend cannot convert, with the reason. Listed explicitly so that a rule
#: never loses its SPL silently: any other conversion error fails `python -m tripline.convert`.
SPL_UNSUPPORTED: dict[str, str] = {
    "lnx_sshd_brute_force_success": (
        "pySigma-backend-splunk 2.1.0 does not support temporal_ordered correlations"
    ),
}


def _logsource_key(docs: list[dict]) -> tuple[str | None, str | None, str | None]:
    ls = next(d["logsource"] for d in docs if "logsource" in d)
    return ls.get("product"), ls.get("service"), ls.get("category")


def _pipeline(names: tuple[str, ...], azure_monitor: bool = False) -> ProcessingPipeline:
    pipeline = ProcessingPipeline()
    for name in names:
        pipeline += _yaml_pipeline(name)
    if azure_monitor:
        pipeline += azure_monitor_pipeline()
    return pipeline


def convert_rule(path: Path) -> dict[str, str]:
    """Return {"kql": query, "spl": query} for one rule file (kql omitted for correlations)."""
    text = path.read_text(encoding="utf-8")
    docs = [d for d in yaml.safe_load_all(text) if d]
    target = TARGETS[_logsource_key(docs)]
    is_correlation = "correlation" in docs[-1]

    out: dict[str, str] = {}
    if path.stem not in SPL_UNSUPPORTED:
        spl = SplunkBackend(_pipeline(target.spl)).convert(SigmaCollection.from_yaml(text))
        out["spl"] = "\n\n".join(spl)
    if not is_correlation:
        backend = KustoBackend(_pipeline(target.kql, target.kql_azure_monitor))
        out["kql"] = "\n\n".join(backend.convert(SigmaCollection.from_yaml(text)))
    return out


def generate() -> dict[Path, str]:
    """All generated files, as {path relative to queries/: content}."""
    files: dict[Path, str] = {}
    for path in sorted(RULES_DIR.rglob("*.yml")):
        for lang, query in convert_rule(path).items():
            files[Path(lang) / f"{path.stem}.{lang}"] = query.rstrip("\n") + "\n"
    return files


def _existing(queries_dir: Path) -> dict[Path, str]:
    return {
        p.relative_to(queries_dir): p.read_text(encoding="utf-8")
        for lang in ("kql", "spl")
        for p in sorted((queries_dir / lang).glob(f"*.{lang}"))
    }


def drift(queries_dir: Path = QUERIES_DIR) -> list[str]:
    """Differences between generated output and what is in queries_dir."""
    expected, actual = generate(), _existing(queries_dir)
    problems = [f"missing: queries/{p.as_posix()}" for p in expected if p not in actual]
    problems += [f"stale (no rule): queries/{p.as_posix()}" for p in actual if p not in expected]
    problems += [
        f"differs from generated: queries/{p.as_posix()}"
        for p in expected
        if p in actual and actual[p] != expected[p]
    ]
    return problems


def write(queries_dir: Path = QUERIES_DIR) -> None:
    expected = generate()
    for path in _existing(queries_dir):
        if path not in expected:
            (queries_dir / path).unlink()
    for path, content in expected.items():
        target = queries_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if queries/ is out of date")
    args = parser.parse_args(argv)
    if args.check:
        problems = drift()
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            print("Run `python -m tripline.convert` and commit queries/.", file=sys.stderr)
            return 1
        print("queries/ is up to date")
        return 0
    write()
    print(f"wrote {len(generate())} files to queries/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
