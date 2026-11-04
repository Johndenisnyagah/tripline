"""Parse CloudTrail JSON into flat events with dotted keys.

Accepts both native shapes: a CloudTrail log file (`{"Records": [...]}`) and a bare JSON
array of records (how Stratus Red Team publishes its detonation logs).

Nested objects become dotted keys (`requestParameters.name`,
`responseElements.ConsoleLogin`), which is how Sigma rules for CloudTrail name
nested fields. Lists are kept as JSON text. JSON booleans become "true"/"false" (how
Sentinel's tostring() and Splunk render them), so a Sigma value 'false' matches in SQLite,
which would otherwise store them as 0/1. `eventTime` is copied to `timestamp` for the
correlation windows.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path


def flatten(obj: dict, prefix: str = "") -> dict:
    flat: dict = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{name}."))
        elif isinstance(value, list):
            flat[name] = json.dumps(value, sort_keys=True)
        elif isinstance(value, bool):
            flat[name] = "true" if value else "false"
        else:
            flat[name] = value
    return flat


def load_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["Records"] if isinstance(data, dict) else data


def parse_file(path: Path) -> Iterator[dict]:
    for record in load_records(path):
        event = flatten(record)
        event["timestamp"] = record["eventTime"]
        yield event
