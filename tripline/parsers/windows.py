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
from itertools import islice
from pathlib import Path

_EVENT_BLOCK = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    return next((c for c in parent if _local(c.tag) == name), None)


def _timestamp(system_time: str) -> str:
    """'2022-09-08T21:56:17.382220600Z' -> '2022-09-08T21:56:17.382220Z' (microseconds).

    python-evtx renders EVTX times as '2022-04-04 13:07:04.036406+00:00' (space, offset);
    exported XML uses 'T' and 'Z'. Both are UTC.
    """
    match = re.match(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d+))?", system_time)
    if not match:
        raise ValueError(f"unexpected SystemTime {system_time!r}")
    date, clock, fraction = match.groups()
    return f"{date}T{clock}.{(fraction or '0')[:6].ljust(6, '0')}Z"


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


_PADDED_HEX = re.compile(r"^0x0+([0-9a-fA-F]+)$")


def normalise_evtx_values(event: dict) -> dict:
    """Undo python-evtx's hex rendering so values match what Windows (and Sentinel/Splunk) show.

    python-evtx renders HexInt32 fields zero-padded to 8 digits ("0x001fffff", "0x00001410");
    Windows renders them without padding ("0x1fffff", "0x1410"). Without this, Sysmon's
    GrantedAccess in an EVTX file never equals the values rules compare against.
    """
    for key, value in event.items():
        if isinstance(value, str) and len(value) == 10 and (match := _PADDED_HEX.match(value)):
            event[key] = "0x" + match.group(1)
    return event


def parse_file(path: Path, max_records: int | None = None) -> Iterator[dict]:
    """Parse every event, or only the first `max_records` (a fixed subset of a large log)."""
    evtx = path.suffix.lower() == ".evtx"
    for block in islice(_xml_blocks(path), max_records):
        event = parse_event_xml(block)
        yield normalise_evtx_values(event) if evtx else event
