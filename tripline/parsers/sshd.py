"""Parse sshd lines from a syslog auth.log into flat events.

Output fields follow Microsoft Sentinel's `Syslog` table (HostName, ProcessName,
ProcessID, SyslogMessage) so the same Sigma field names work in the SQLite harness
and in KQL. Two fields are extracted from the message because Syslog has no column
for them and the correlation rules group by them: SourceIp and User.

Only sshd lines are emitted: the rules' logsource is `service: sshd`, which the
KQL pipeline turns into `ProcessName =~ "sshd"`. CRON and systemd lines are skipped.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

# Syslog lines carry no year. The soc-triage samples describe 2026.
DEFAULT_YEAR = 2026

_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<proc>[\w.-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
_SOURCE_IP = re.compile(r" from (?P<ip>[0-9A-Fa-f.:]+) port \d+")
_USER = re.compile(
    r"^(?:(?:Failed|Accepted|Postponed|Partial) \S+ for (?:invalid user )?|Invalid user )"
    r"(?P<user>\S+) from "
)


def parse_line(line: str, year: int = DEFAULT_YEAR) -> dict | None:
    match = _HEADER.match(line.rstrip("\r\n"))
    if not match or match["proc"] != "sshd":
        return None
    ts = datetime.strptime(f"{year} {match['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    msg = match["msg"]
    ip = _SOURCE_IP.search(msg)
    user = _USER.match(msg)
    return {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "HostName": match["host"],
        "ProcessName": match["proc"],
        "ProcessID": match["pid"],
        "SyslogMessage": msg,
        "SourceIp": ip["ip"] if ip else None,
        "User": user["user"] if user else None,
    }


def parse_file(path: Path, year: int = DEFAULT_YEAR) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            event = parse_line(line, year)
            if event is not None:
                yield event
