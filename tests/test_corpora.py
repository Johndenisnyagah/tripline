"""Corpus machinery (offline): manifest shape, download verification, extraction, caching.

The real corpora run in the CI `corpora` job (`python -m tripline.corpora`), not here.
"""

import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

import pytest

from tripline import corpora
from tripline.harness import PARSERS

MANIFEST = corpora.load_manifest()


@pytest.mark.parametrize("entry", MANIFEST, ids=[e["id"] for e in MANIFEST])
def test_manifest_entry(entry: dict) -> None:
    for field in ("id", "source", "label", "url", "sha256", "licence", "description"):
        assert entry.get(field), f"{entry.get('id')}: missing {field}"
    assert entry["source"] in PARSERS
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    assert entry["url"].startswith("https://")
    # Pinned: a GitHub raw URL names a commit, a release URL names a tag.
    if "raw.githubusercontent.com" in entry["url"]:
        assert re.search(r"/[0-9a-f]{40}/", entry["url"]), entry["url"]
    if "/releases/download/" in entry["url"]:
        assert re.search(r"/releases/download/v[\d.]+/", entry["url"]), entry["url"]


def test_manifest_ids_unique_and_every_source_covered() -> None:
    ids = [e["id"] for e in MANIFEST]
    assert len(ids) == len(set(ids))
    covered = {e["source"] for e in MANIFEST}
    assert covered == set(corpora.rules_by_source()), "every rule source needs a corpus"


def _local_corpus(tmp_path: Path) -> dict:
    record = {
        "eventTime": "2017-02-12T21:13:42Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "sourceIPAddress": "192.0.2.10",
    }
    payload = gzip.compress(json.dumps({"Records": [record]}).encode())
    archive = tmp_path / "src" / "logs.tar"
    archive.parent.mkdir()
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("logs/part00.json.gz")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return {
        "id": "local-test",
        "source": "cloudtrail",
        "label": "test",
        "url": archive.as_uri(),
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "member": "logs/part00.json.gz",
    }


def test_download_extract_parse_and_cache(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TRIPLINE_CACHE", str(tmp_path / "cache"))
    entry = _local_corpus(tmp_path)
    events = corpora.corpus_events(entry)
    assert [e["eventName"] for e in events] == ["StopLogging"]
    cached = list((tmp_path / "cache" / "corpora").rglob("*.events.jsonl.gz"))
    assert len(cached) == 1
    # Second call reads the parsed cache, even with the source archive gone.
    (tmp_path / "src" / "logs.tar").unlink()
    assert corpora.corpus_events(entry) == events

    result = corpora.run([entry])
    hit = result["hits"]["aws_cloudtrail_logging_disabled"]["local-test"]
    assert (hit["events_seen"], hit["matches"]) == (1, 1)


def test_sha256_mismatch_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TRIPLINE_CACHE", str(tmp_path / "cache"))
    entry = _local_corpus(tmp_path) | {"sha256": "0" * 64}
    with pytest.raises(RuntimeError, match="sha256 mismatch"):
        corpora.download(entry)
