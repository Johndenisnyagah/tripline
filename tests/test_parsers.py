"""Parser unit tests: raw lines and records to flat events."""

import json

from tripline.parsers import cloudtrail, sshd


def test_sshd_failed_password_invalid_user() -> None:
    event = sshd.parse_line(
        "Aug  2 04:43:13 webserver01 sshd[3321]: Failed password for invalid user admin "
        "from 203.0.113.5 port 44210 ssh2"
    )
    assert event == {
        "timestamp": "2026-08-02T04:43:13Z",
        "HostName": "webserver01",
        "ProcessName": "sshd",
        "ProcessID": "3321",
        "SyslogMessage": "Failed password for invalid user admin from 203.0.113.5 port 44210 ssh2",
        "SourceIp": "203.0.113.5",
        "User": "admin",
    }


def test_sshd_invalid_user_and_accepted() -> None:
    invalid = sshd.parse_line(
        "Aug  2 04:43:12 webserver01 sshd[3321]: Invalid user admin from 203.0.113.5 port 44210"
    )
    assert (invalid["User"], invalid["SourceIp"]) == ("admin", "203.0.113.5")
    accepted = sshd.parse_line(
        "Aug  2 04:48:41 webserver01 sshd[3340]: Accepted password for deploy "
        "from 203.0.113.5 port 44301 ssh2"
    )
    assert (accepted["User"], accepted["SourceIp"]) == ("deploy", "203.0.113.5")


def test_sshd_skips_other_processes_and_session_lines_have_no_ip() -> None:
    assert (
        sshd.parse_line(
            "Aug  2 03:14:01 webserver01 CRON[2841]: pam_unix(cron:session): session opened"
        )
        is None
    )
    session = sshd.parse_line(
        "Aug  2 04:48:41 webserver01 sshd[3340]: pam_unix(sshd:session): session opened for user"
        " deploy by (uid=0)"
    )
    assert session["SourceIp"] is None and session["User"] is None


def test_cloudtrail_flattens_nested_fields(tmp_path) -> None:
    path = tmp_path / "ct.json"
    record = {
        "eventTime": "2026-08-02T04:45:30Z",
        "eventName": "ConsoleLogin",
        "responseElements": {"ConsoleLogin": "Failure"},
        "additionalEventData": {"MFAUsed": "No"},
        "resources": [{"ARN": "arn:aws:iam::111122223333:user/x"}],
    }
    path.write_text(json.dumps({"Records": [record]}), encoding="utf-8")
    (event,) = cloudtrail.parse_file(path)
    assert event["timestamp"] == "2026-08-02T04:45:30Z"
    assert event["responseElements.ConsoleLogin"] == "Failure"
    assert event["additionalEventData.MFAUsed"] == "No"
    assert json.loads(event["resources"]) == [{"ARN": "arn:aws:iam::111122223333:user/x"}]
