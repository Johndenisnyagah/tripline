"""ATT&CK Enterprise v20.0 lookups from the pinned STIX bundle.

The bundle (~55 MB) is downloaded once, verified by sha256 and cached under
`.cache/attack/` (or $TRIPLINE_CACHE). A compact index of technique IDs and tactic
shortnames is cached next to it so later runs skip the 55 MB JSON parse.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from dataclasses import dataclass
from functools import cache
from pathlib import Path

ATTACK_VERSION = "20.0"
STIX_COMMIT = "c2494b29dd268c46a5d0ea0990553e4327cd2253"
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{STIX_COMMIT}/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
STIX_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"

REPO_ROOT = Path(__file__).resolve().parent.parent


def cache_dir() -> Path:
    root = Path(os.environ.get("TRIPLINE_CACHE", REPO_ROOT / ".cache"))
    path = root / "attack"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    revoked: bool
    deprecated: bool

    @property
    def usable(self) -> bool:
        return not (self.revoked or self.deprecated)


@dataclass(frozen=True)
class AttackIndex:
    techniques: dict[str, Technique]
    tactics: frozenset[str]  # v20 shortnames, e.g. "stealth", "defense-impairment"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bundle_path() -> Path:
    path = cache_dir() / f"enterprise-attack-{ATTACK_VERSION}.json"
    if not path.exists() or _sha256(path) != STIX_SHA256:
        tmp = path.with_suffix(".part")
        urllib.request.urlretrieve(STIX_URL, tmp)  # noqa: S310 (fixed https URL)
        actual = _sha256(tmp)
        if actual != STIX_SHA256:
            tmp.unlink()
            raise RuntimeError(f"ATT&CK bundle sha256 mismatch: {actual} != {STIX_SHA256}")
        tmp.replace(path)
    return path


def _build_index(bundle: Path) -> dict:
    data = json.loads(bundle.read_text(encoding="utf-8"))
    techniques: dict[str, dict] = {}
    tactics: list[str] = []
    for obj in data["objects"]:
        refs = [
            r["external_id"]
            for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack"
        ]
        if obj["type"] == "attack-pattern" and refs:
            techniques[refs[0]] = {
                "name": obj.get("name", ""),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            }
        elif obj["type"] == "x-mitre-tactic":
            tactics.append(obj["x_mitre_shortname"])
    return {"sha256": STIX_SHA256, "techniques": techniques, "tactics": sorted(tactics)}


@cache
def load_index() -> AttackIndex:
    index_path = cache_dir() / f"index-{ATTACK_VERSION}.json"
    raw = None
    if index_path.exists():
        raw = json.loads(index_path.read_text(encoding="utf-8"))
        if raw.get("sha256") != STIX_SHA256:
            raw = None
    if raw is None:
        raw = _build_index(_bundle_path())
        index_path.write_text(json.dumps(raw), encoding="utf-8")
    return AttackIndex(
        techniques={tid: Technique(id=tid, **t) for tid, t in raw["techniques"].items()},
        tactics=frozenset(raw["tactics"]),
    )
