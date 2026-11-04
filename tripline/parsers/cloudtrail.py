"""Parse CloudTrail `{"Records": [...]}` JSON into flat events with dotted keys.

Nested objects become dotted keys (`requestParameters.name`,
`responseElements.ConsoleLogin`), which is how Sigma rules for CloudTrail name
nested fields. Lists are kept as JSON text. `eventTime` is copied to `timestamp`
for the correlation windows.
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
        else:
            flat[name] = value
    return flat


def parse_file(path: Path) -> Iterator[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    for record in data["Records"]:
        event = flatten(record)
        event["timestamp"] = record["eventTime"]
        yield event
