"""One Windows Sigma example, proved from scrubbed native Security exports.

Donor 0014240 added eight examples. Only privileged password guessing can be
decided from fields Watchpost stores: EventID 4625, TargetUserName, and IpAddress.
These exports are omitted because their discriminators do not survive:

- exchange_exploit_request.yml: IIS paths, not a Security export. T1190 stays mapped-only.
- external_rdp_logon.yml: logon type 10 or port 3389. Neither is stored.
- external_smb_connection.yml: network_connection plus port 445. No Security event
  stores that pair. These fixtures do not establish T1048.
- local_admin_network_logon.yml: logon type 3. LogonType is not stored.
- password_spray_unknown_user.yml: substatus 0xC0000064, and a count. One failure
  is not a spray. SubStatus is not stored.
- port_scan_tool.yml: process name or command line on a process start.
- security_log_tampering.yml: rendered 1102 text or a clearing command.

A 4688 is ingested below. Its command line stays in the raw record and is not a
detection field, so there is no execution example. A shell name in arbitrary text
would not validate one.
"""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from watchpost import engine, sigma
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload
from watchpost.rules import DEFAULT_RULES

WINDOWS = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "windows"
EXAMPLE = "privileged_password_guessing.yml"
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
LOGSOURCE_WARNING = "logsource is informational only: the rule runs on every stored event"
OMITTED = (
    "exchange_exploit_request.yml",
    "external_rdp_logon.yml",
    "external_smb_connection.yml",
    "local_admin_network_logon.yml",
    "password_spray_unknown_user.yml",
    "port_scan_tool.yml",
    "security_log_tampering.yml",
)

# label, event id, timestamp, EventData pairs. LogonType and IpPort are present on purpose.
_RECORDS = [
    ("remote-4624", 4624, "2026-09-14T15:00:00.0000000Z", (
        ("TargetUserName", "jsmith"), ("IpAddress", "203.0.113.8"),
        ("LogonType", "10"), ("IpPort", "49721"),
    )),
    ("local-4624", 4624, "2026-09-14T15:01:00.0000000Z", (
        ("TargetUserName", "Administrator"), ("IpAddress", "10.2.3.4"),
        ("LogonType", "2"), ("IpPort", "0"),
    )),
    ("fail-external", 4625, "2026-09-14T15:02:00.0000000Z", (
        ("TargetUserName", "Administrator"), ("IpAddress", "203.0.113.44"),
        ("LogonType", "3"), ("IpPort", "445"),
        ("Status", "0xC000006D"), ("SubStatus", "0xC000006A"),
    )),
    ("fail-internal", 4625, "2026-09-14T15:03:00.0000000Z", (
        ("TargetUserName", "Administrator"), ("IpAddress", "10.2.3.4"),
        ("LogonType", "3"), ("IpPort", "445"), ("SubStatus", "0xC000006A"),
    )),
    ("missing-ip", 4625, "2026-09-14T15:04:00.0000000Z", (
        ("TargetUserName", "Administrator"), ("LogonType", "3"), ("IpPort", "49721"),
    )),
    ("dash-ip", 4625, "2026-09-14T15:05:00.0000000Z", (
        ("TargetUserName", "Administrator"), ("IpAddress", "-"),
        ("LogonType", "10"), ("IpPort", "3389"),
    )),
    ("near-name", 4625, "2026-09-14T15:06:00.0000000Z", (
        ("TargetUserName", "admin1"), ("IpAddress", "203.0.113.45"),
        ("LogonType", "3"), ("IpPort", "445"),
    )),
    ("missing-user", 4624, "2026-09-14T15:07:00.0000000Z", (
        ("LogonType", "2"), ("IpPort", "49722"),
    )),
    ("process-4688", 4688, "2026-09-14T15:08:00.0000000Z", (
        ("SubjectUserName", "ada"),
        ("NewProcessName", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        ("CommandLine", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command Get-Date"),
        ("ParentProcessName", r"C:\Windows\System32\cmd.exe"),
    )),
]

_STORED = {
    "remote-4624": ("auth_success", "jsmith", "203.0.113.8"),
    "local-4624": ("auth_success", "Administrator", "10.2.3.4"),
    "fail-external": ("auth_failure", "Administrator", "203.0.113.44"),
    "fail-internal": ("auth_failure", "Administrator", "10.2.3.4"),
    "missing-ip": ("auth_failure", "Administrator", None),
    "dash-ip": ("auth_failure", "Administrator", None),
    "near-name": ("auth_failure", "admin1", "203.0.113.45"),
    "missing-user": ("auth_success", None, None),
    "process-4688": ("process_start", None, None),
}


def _native(event_id, when, fields):
    return {
        "Event": {
            "System": {
                "EventID": {"#text": str(event_id)},
                "TimeCreated": {"SystemTime": when},
                "Computer": "dc01.example",
                "Channel": "Security",
            },
            "EventData": {"Data": [{"Name": name, "#text": value} for name, value in fields]},
        }
    }


class WindowsSigmaPackTests(unittest.TestCase):
    def test_only_the_supported_example_is_shipped(self):
        names = sorted(path.name for path in WINDOWS.glob("*.yml"))
        self.assertEqual(names, [EXAMPLE])
        for name in OMITTED:
            self.assertFalse((WINDOWS / name).exists(), name)

    def test_external_privileged_failure_is_the_only_accepted_event(self):
        rule = sigma.compile_rule((WINDOWS / EXAMPLE).read_text())
        self.assertEqual(rule["rule_id"], "sigma_windows_privileged_password_guessing")
        self.assertEqual(rule["sigma_id"], "769f3a96-3cdd-4e27-90db-fb0b13d13ff4")
        self.assertEqual(rule["severity"], "high")
        self.assertEqual(rule["logsource"]["product"], "windows")
        self.assertEqual(tuple(item["id"] for item in rule["techniques"]), ("T1110.001",))
        self.assertIn(LOGSOURCE_WARNING, rule["warnings"])

        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        stored_rules = {row["id"] for row in conn.execute("SELECT id FROM rules")}
        self.assertEqual(stored_rules, {item["id"] for item in DEFAULT_RULES})
        self.assertNotIn(rule["rule_id"], stored_rules)

        payload = json.dumps([_native(event_id, when, fields) for _, event_id, when, fields in _RECORDS])
        events, rejections = parse_payload(payload, "json", "win-dc", year=2026, now=NOW)
        self.assertEqual(rejections, [])
        self.assertEqual(len(events), len(_RECORDS))
        result = engine.ingest(conn, events, rejections, "win-dc", "json", "tester")
        self.assertEqual(result["detection"]["status"], "ok", result["detection"])
        self.assertEqual(result["detection"]["alerts_created"], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)

        rows = conn.execute(
            "SELECT id, event_type, user, src_ip, dest_port, message, host, source, raw "
            "FROM events ORDER BY id"
        ).fetchall()
        self.assertEqual(len(rows), len(_RECORDS))
        by_label = {}
        for (label, _, _, _), row in zip(_RECORDS, rows):
            by_label[label] = row
            self.assertEqual(
                (row["event_type"], row["user"], row["src_ip"]), _STORED[label], label)
            self.assertIsNone(row["dest_port"], label)
            self.assertIsNone(row["message"], label)
            self.assertEqual(row["host"], "dc01.example")
            self.assertEqual(row["source"], "Security")
            self.assertNotIn("Logon Type", row["raw"])

        external = by_label["fail-external"]
        self.assertIn('{"#text": "3", "Name": "LogonType"}', external["raw"])
        self.assertIn('{"#text": "445", "Name": "IpPort"}', external["raw"])
        self.assertIn("0xC000006A", external["raw"])
        started = by_label["process-4688"]
        self.assertIn("powershell.exe", started["raw"])
        self.assertIn("CommandLine", started["raw"])
        self.assertNotIn("powershell", started["message"] or "")

        max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        projected, history, _ = engine.scan_events(conn, [], max_id)
        self.assertEqual(history, [])
        self.assertEqual([event["id"] for event in projected], [row["id"] for row in rows])
        for event in projected:
            self.assertIsNone(event["dest_port"])
            self.assertIsNone(event["message"])
            self.assertNotIn("LogonType", event)
            self.assertNotIn("IpPort", event)

        findings = sigma.run(projected, rule["params"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["group_key"], "203.0.113.44")
        self.assertEqual(findings[0]["event_ids"], [external["id"]])
        self.assertEqual(
            findings[0]["title"],
            "Windows Privileged Password Guessing: 1 matching event(s) for 203.0.113.44",
        )
        accepted = {label for label, row in by_label.items() if row["id"] in findings[0]["event_ids"]}
        self.assertEqual(accepted, {"fail-external"})
