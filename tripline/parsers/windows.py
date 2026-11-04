"""Parse Windows event logs (XML or EVTX) into flat events with Sigma field names.

Accepted inputs, all in their native form:
- an XML file with an `<Events>` wrapper (soc-triage, wevtutil exports);
- concatenated `<Event>` elements, one or several lines each (Splunk XmlWinEventLog exports,
  e.g. Splunk attack_data);
- `.evtx` binary logs, read with python-evtx.

Each event becomes a dict with the System fields Sigma uses (`EventID`, `Channel`,
`Computer`, `Provider_Name`), plus every `EventData/Data[@Name]` value. For events that carry
`UserData` instead (e.g. 1102 "log cleared"), the leaf elements are used, keyed by local tag
name (`SubjectUserName`). `timestamp` comes from `TimeCreated/@SystemTime`.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

_EVENT_BLOCK = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    return next((c for c in parent if _local(c.tag) == name), None)


def _timestamp(system_time: str) -> str:
    """'2022-09-08T21:56:17.382220600Z' -> '2022-09-08T21:56:17.382220Z' (microseconds)."""
    match = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", system_time)
    if not match:
        raise ValueError(f"unexpected SystemTime {system_time!r}")
    base, fraction = match.groups()
    return f"{base}.{(fraction or '0')[:6].ljust(6, '0')}Z"


def parse_event_xml(xml: str) -> dict:
    event = ET.fromstring(xml)
    system = _child(event, "System")
    flat: dict = {}

    provider = _child(system, "Provider")
    if provider is not None:
        flat["Provider_Name"] = provider.get("Name")
    for name in ("EventID", "Channel", "Computer", "EventRecordID", "Level", "Task"):
        node = _child(system, name)
        if node is not None and node.text is not None:
            flat[name] = node.text.strip()
    created = _child(system, "TimeCreated")
    flat["timestamp"] = _timestamp(created.get("SystemTime"))

    event_data = _child(event, "EventData")
    if event_data is not None:
        for data in event_data:
            name = data.get("Name")
            if name:
                flat[name] = data.text
    user_data = _child(event, "UserData")
    if user_data is not None:
        for node in user_data.iter():
            if len(node) == 0 and node is not user_data:
                flat.setdefault(_local(node.tag), node.text)
    return flat


def _xml_blocks(path: Path) -> Iterator[str]:
    if path.suffix.lower() == ".evtx":
        from Evtx.Evtx import Evtx

        with Evtx(str(path)) as log:
            for record in log.records():
                yield record.xml()
        return
    text = path.read_text(encoding="utf-8-sig")
    yield from _EVENT_BLOCK.findall(text)


def parse_file(path: Path) -> Iterator[dict]:
    for block in _xml_blocks(path):
        yield parse_event_xml(block)
