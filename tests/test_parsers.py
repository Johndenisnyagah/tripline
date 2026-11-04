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


def test_cloudtrail_booleans_become_text(tmp_path) -> None:
    path = tmp_path / "ct.json"
    record = {
        "eventTime": "2026-11-03T10:00:00Z",
        "readOnly": False,
        "requestParameters": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}},
    }
    path.write_text(json.dumps([record]), encoding="utf-8")  # bare array, as Stratus ships
    (event,) = cloudtrail.parse_file(path)
    assert event["readOnly"] == "false"
    assert event["requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls"] == "false"


WIN_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
WIN_4625 = (
    f"<Event xmlns='{WIN_NS}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
    "<EventID>4625</EventID><TimeCreated SystemTime='2022-09-08T21:56:17.382220600Z'/>"
    "<Channel>Security</Channel><Computer>dc01.example.local</Computer></System>"
    "<EventData><Data Name='TargetUserName'>MONROE_YATES</Data>"
    "<Data Name='IpAddress'>10.0.1.15</Data><Data Name='LogonType'>3</Data></EventData></Event>"
)
WIN_1102 = (
    f"<Event xmlns='{WIN_NS}'><System><Provider Name='Microsoft-Windows-Eventlog'/>"
    "<EventID>1102</EventID><TimeCreated SystemTime='2024-07-22T16:25:54.9Z'/>"
    "<Channel>Security</Channel><Computer>dc01</Computer></System><UserData>"
    "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
    "<SubjectUserName>Administrator</SubjectUserName></LogFileCleared></UserData></Event>"
)


def test_windows_eventdata_fields() -> None:
    from tripline.parsers import windows

    event = windows.parse_event_xml(WIN_4625)
    assert event["EventID"] == "4625"
    assert event["Provider_Name"] == "Microsoft-Windows-Security-Auditing"
    assert event["timestamp"] == "2022-09-08T21:56:17.382220Z"
    assert (event["TargetUserName"], event["IpAddress"], event["LogonType"]) == (
        "MONROE_YATES",
        "10.0.1.15",
        "3",
    )


def test_windows_userdata_fields() -> None:
    from tripline.parsers import windows

    event = windows.parse_event_xml(WIN_1102)
    assert event["EventID"] == "1102"
    assert event["Provider_Name"] == "Microsoft-Windows-Eventlog"
    assert event["SubjectUserName"] == "Administrator"
    assert event["timestamp"] == "2024-07-22T16:25:54.900000Z"


def test_windows_file_shapes(tmp_path) -> None:
    from tripline.parsers import windows

    wrapped = tmp_path / "wrapped.xml"
    wrapped.write_text(f'<?xml version="1.0"?>\n<Events>\n{WIN_4625}\n{WIN_1102}\n</Events>\n')
    # Splunk XmlWinEventLog: concatenated events, one of them split across lines.
    splunk = tmp_path / "windows-security.log"
    splunk.write_text(WIN_4625 + "\n" + WIN_1102.replace("<UserData>", "\n<UserData>\n") + "\n")
    for path in (wrapped, splunk):
        assert [e["EventID"] for e in windows.parse_file(path)] == ["4625", "1102"]
