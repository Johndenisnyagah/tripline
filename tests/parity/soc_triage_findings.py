"""Run soc-triage's own detection over its sample logs and print the findings as JSON.

Runs with soc-triage's Python environment, not tripline's:

    python tests/parity/soc_triage_findings.py <soc-triage checkout> > soc-findings.json

It takes the same path as soc-triage's `backend/scripts/run_detection.py`, read-only: upload
each sample through the real `POST /api/ingest` (format detection, parsing and dedup), read
the stored events back with `Event.to_normalized()`, and run `run_rules`. soc-triage itself is
not modified; this file only imports it. The script prints findings instead of soc-triage's
text report, so the parity test can compare them with tripline's results.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

#: The samples tripline also uses as fixtures, and the year their syslog lines describe
#: (run_detection.py pins the same year).
SAMPLE_FILES = ("auth.log", "cloudtrail.json")
SAMPLE_LOG_YEAR = 2026


def main(checkout: Path) -> None:
    backend = checkout / "backend"
    sys.path.insert(0, str(backend))
    tmp = Path(tempfile.mkdtemp(prefix="tripline-parity-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{(tmp / 'parity.db').as_posix()}"

    from app.database import SessionLocal
    from app.detection.engine import run_rules
    from app.main import app
    from app.models import Event
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        for name in SAMPLE_FILES:
            path = checkout / "sample_logs" / name
            response = client.post(
                "/api/ingest",
                files={"file": (name, path.read_bytes(), "text/plain")},
                data={"default_year": str(SAMPLE_LOG_YEAR)},
            )
            if response.status_code != 201:
                sys.exit(f"ingest of {name} failed: {response.status_code} {response.text}")

    with SessionLocal() as session:
        events = [row.to_normalized() for row in session.query(Event).order_by(Event.timestamp)]

    findings = []
    for finding in run_rules(events).findings:
        evidence = [e for e in finding.evidence if e.timestamp]
        findings.append(
            {
                "rule_id": finding.rule_id,
                "entity_key": finding.entity_key,
                "technique": finding.technique,
                "source_types": sorted({str(e.source_type) for e in finding.evidence}),
                "evidence": sorted(
                    {
                        (
                            e.timestamp.isoformat().replace("+00:00", "Z"),
                            e.source_ip or "",
                            str(e.source_type),
                        )
                        for e in evidence
                    }
                ),
            }
        )
    json.dump({"events": len(events), "findings": findings}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
