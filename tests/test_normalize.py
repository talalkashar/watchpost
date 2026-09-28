import json
import unittest
from datetime import datetime, timezone

from watchpost.diagnostics import redact
from watchpost.normalize import (EventError, normalize_authlog_line, normalize_record, normalize_weblog_line,
                                 parse_payload)

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class NormalizeRecordTests(unittest.TestCase):
    def test_aliases_and_defaults(self):
        e = normalize_record({"@timestamp": "2026-09-15T10:00:00Z", "type": "login_failed",
                              "username": "alice", "source_ip": "203.0.113.9"}, "api", NOW)
        self.assertEqual(e["ts"], "2026-09-15T10:00:00.000Z")
        self.assertEqual(e["event_type"], "auth_failure")
        self.assertEqual(e["outcome"], "failure")
        self.assertEqual(e["severity"], "low")
        self.assertEqual(e["user"], "alice")
        self.assertEqual(e["src_ip"], "203.0.113.9")
        self.assertEqual(e["source"], "api")

    def test_windows_event_ids(self):
        e = normalize_record({"TimeCreated": "2026-09-15 10:00:00", "EventID": 4625,
                              "TargetUserName": "bob", "IpAddress": "10.0.0.5", "Computer": "dc01"}, "win", NOW)
        self.assertEqual((e["event_type"], e["host"], e["user"]), ("auth_failure", "dc01", "bob"))
        self.assertEqual(normalize_record({"ts": 1789_000_000, "EventID": "4624"}, "win", NOW)["event_type"],
                         "auth_success")

    def test_ecs_nested_fields(self):
        e = normalize_record({"ts": "2026-09-15T10:00:00Z", "event_type": "auth_success",
                              "user": {"name": "carol"}, "source": {"ip": "10.1.1.1"}}, "ecs", NOW)
        self.assertEqual((e["user"], e["src_ip"], e["source"]), ("carol", "10.1.1.1", "ecs"))

    def test_unknown_type_becomes_other(self):
        self.assertEqual(normalize_record({"ts": "2026-09-15T10:00:00Z", "type": "weird"}, "x", NOW)["event_type"],
                         "other")

    def test_rejections(self):
        cases = [
            ({}, "missing timestamp"),
            ({"ts": "yesterday"}, "unparseable timestamp"),
            ({"ts": "2026-09-20T00:00:00Z"}, "future"),
            ({"ts": "1990-01-01T00:00:00Z"}, "before year 2000"),
            ({"ts": "2026-09-15T10:00:00Z", "src_ip": "999.1.1.1"}, "src_ip"),
            ({"ts": "2026-09-15T10:00:00Z", "severity": "urgent"}, "severity"),
            ({"ts": "2026-09-15T10:00:00Z", "source": "bad source!"}, "source"),
        ]
        for record, fragment in cases:
            with self.subTest(record=record):
                with self.assertRaisesRegex(EventError, fragment):
                    normalize_record(record, "api", NOW)
        with self.assertRaises(EventError):
            normalize_record(["not", "an", "object"], "api", NOW)

    def test_control_characters_and_lengths(self):
        e = normalize_record({"ts": "2026-09-15T10:00:00Z", "user": "ev\x00il\x1b[31m", "message": "x" * 5000},
                             "api", NOW)
        self.assertNotIn("\x00", e["user"])
        self.assertNotIn("\x1b", e["user"])
        self.assertEqual(len(e["message"]), 2000)

    def test_secrets_redacted_from_message_and_raw(self):
        e = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": "login password=hunter2 ok",
                              "password": "hunter2"}, "api", NOW)
        self.assertNotIn("hunter2", e["message"])
        self.assertNotIn("hunter2", e["raw"])


class AuthlogTests(unittest.TestCase):
    def test_failed_and_accepted(self):
        f = normalize_authlog_line(
            "Sep 15 10:00:01 web01 sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 5 ssh2",
            "authlog", now=NOW)
        self.assertEqual((f["event_type"], f["user"], f["src_ip"], f["host"]),
                         ("auth_failure", "admin", "203.0.113.5", "web01"))
        self.assertEqual(f["ts"], "2026-09-15T10:00:01.000Z")
        a = normalize_authlog_line(
            "2026-09-15T10:05:00+00:00 web01 sshd[9]: Accepted publickey for alice from 10.0.0.5 port 1 ssh2",
            "authlog", now=NOW)
        self.assertEqual((a["event_type"], a["user"]), ("auth_success", "alice"))

    def test_year_rollover(self):
        # A December line read in January belongs to the previous year.
        e = normalize_authlog_line("Dec 31 23:59:00 h sshd[1]: Invalid user x from 192.0.2.1 port 1", "a",
                                   now=datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc))
        self.assertTrue(e["ts"].startswith("2026-12-31"))

    def test_non_ssh_line_is_other(self):
        e = normalize_authlog_line("Sep 15 10:00:01 web01 CRON[5]: pam_unix(cron:session): session opened",
                                   "a", now=NOW)
        self.assertEqual(e["event_type"], "other")

    def test_garbage_line_rejected(self):
        with self.assertRaises(EventError):
            normalize_authlog_line("hello world", "a", now=NOW)


class PayloadTests(unittest.TestCase):
    def test_mixed_valid_and_invalid_reports_positions(self):
        text = '{"ts":"2026-09-15T10:00:00Z","type":"login"}\nnot json\n{"ts":"bad"}\n'
        events, rejections = parse_payload(text, "jsonl", "x", now=NOW)
        self.assertEqual(len(events), 1)
        self.assertEqual([r["index"] for r in rejections], [2, 3])
        self.assertNotIn("not json", str(rejections))  # content is never echoed back

    def test_csv(self):
        text = "timestamp,event_type,user,src_ip\n2026-09-15T10:00:00Z,auth_failure,bob,10.0.0.1\n,,,\n"
        events, rejections = parse_payload(text, "csv", "csv", now=NOW)
        self.assertEqual(len(events), 1)
        self.assertEqual(rejections[0]["index"], 3)

    def test_auto_detect(self):
        self.assertEqual(len(parse_payload('[{"ts":"2026-09-15T10:00:00Z"}]', "auto", "x", now=NOW)[0]), 1)
        self.assertEqual(len(parse_payload(
            "Sep 15 10:00:01 h sshd[1]: Invalid user x from 192.0.2.1 port 1\n", "auto", "x", now=NOW)[0]), 1)
        with self.assertRaises(EventError):
            parse_payload("just words", "auto", "x", now=NOW)

    def test_invalid_json_and_limits(self):
        with self.assertRaisesRegex(EventError, "invalid JSON"):
            parse_payload("[{", "json", "x", now=NOW)
        with self.assertRaisesRegex(EventError, "limit"):
            parse_payload('[{"ts":1},{"ts":2},{"ts":3}]', "json", "x", now=NOW, max_events=2)
        with self.assertRaisesRegex(EventError, "unsupported"):
            parse_payload("x", "xml", "x", now=NOW)


class WebLogTests(unittest.TestCase):
    LINE = '203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "GET {path} HTTP/1.1" {status} 162 "-" "{agent}"'

    def parse(self, path="/", status=200, agent="Mozilla/5.0"):
        return normalize_weblog_line(self.LINE.format(path=path, status=status, agent=agent), "nginx", now=NOW)

    def test_request_fields(self):
        e = self.parse("/app/dashboard")
        self.assertEqual((e["event_type"], e["src_ip"], e["bytes"], e["outcome"]),
                         ("web_request", "203.0.113.80", 162, "success"))
        self.assertEqual(e["ts"], "2026-09-15T10:00:00.000Z")
        self.assertTrue(e["message"].startswith("GET /app/dashboard -> 200"))

    def test_scan_patterns(self):
        for path in ["/.env", "/wp-login.php", "/blog/.git/config", "/index.php?id=1%27%20or%20%271%27=%271",
                     "/q?s=1+UNION+SELECT+password", "/../../etc/passwd"]:
            with self.subTest(path=path):
                self.assertEqual(self.parse(path, 404)["event_type"], "web_scan")
        self.assertEqual(self.parse("/", 200, agent="sqlmap/1.7")["event_type"], "web_scan")
        self.assertEqual(self.parse("/api/orders", 502)["event_type"], "web_error")
        self.assertEqual(self.parse("/missing", 404)["event_type"], "web_request")

    def test_detect_and_reject(self):
        text = self.LINE.format(path="/.env", status=404, agent="x") + "\nnot a log line\n"
        events, rejections = parse_payload(text, "auto", "nginx", now=NOW)
        self.assertEqual(len(events), 1)
        self.assertEqual(rejections[0]["index"], 2)


class FirewallAndHostTests(unittest.TestCase):
    def test_firewall_csv(self):
        text = ("timestamp,action,src_ip,dest_ip,dest_port,bytes\n"
                "2026-09-15T10:00:00Z,deny,198.51.100.140,10.0.0.10,3389,0\n"
                "2026-09-15T10:00:01Z,ACCEPT,10.0.1.20,198.51.100.200,443,600000000\n"
                "2026-09-15T10:00:02Z,deny,198.51.100.140,10.0.0.10,99999,0\n")
        events, rejections = parse_payload(text, "csv", "fw", now=NOW)
        self.assertEqual([(e["event_type"], e["dest_port"]) for e in events], [("fw_deny", 3389), ("fw_allow", 443)])
        self.assertEqual(events[1]["bytes"], 600000000)
        self.assertIn("dest_port", rejections[0]["reason"])

    def test_syslog_firewall_vpn_and_host_lines(self):
        cases = [
            ("Sep 15 10:00:00 fw01 kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.141 DST=10.0.0.10 LEN=44 "
             "PROTO=TCP SPT=4000 DPT=3306 WINDOW=1024", ("fw_deny", None, "198.51.100.141")),
            ("Sep 15 10:00:00 vpn01 openvpn[8]: 203.0.113.150:51234 [erin] Peer Connection Initiated with x",
             ("vpn_login", "erin", "203.0.113.150")),
            ("Sep 15 10:00:00 web01 sudo:    frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash",
             ("privilege_escalation", "frank", None)),
            ("Sep 15 10:00:00 web01 su: (to root) frank on pts/0", ("privilege_escalation", "frank", None)),
            ("Sep 15 10:00:00 web01 useradd[9]: new user: name=svc-backup2, UID=1002", ("user_created", "svc-backup2", None)),
            ('Sep 15 10:00:00 web01 audit[5]: type=SYSCALL syscall=59 exe="/usr/bin/curl" AUID="frank"',
             ("process_start", "frank", None)),
            ('Sep 15 10:00:00 web01 audit[5]: type=PATH item=0 name="/etc/shadow" nametype=NORMAL',
             ("file_access", None, None)),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                e = normalize_authlog_line(line, "host", now=NOW)
                self.assertEqual((e["event_type"], e["user"], e["src_ip"]), expected)
        fw = normalize_authlog_line(cases[0][0], "host", now=NOW)
        self.assertEqual((fw["dest_ip"], fw["dest_port"], fw["host"]), ("10.0.0.10", 3306, "fw01"))

    def test_windows_runas_and_file_access(self):
        self.assertEqual(normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4648}, "w", NOW)["event_type"],
                         "privilege_escalation")
        self.assertEqual(normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4663}, "w", NOW)["event_type"],
                         "file_access")

    def test_new_types_accepted_directly(self):
        for event_type in ["web_scan", "fw_deny", "vpn_login", "cloud_iam_change", "privilege_escalation"]:
            e = normalize_record({"ts": "2026-09-15T10:00:00Z", "event_type": event_type}, "api", NOW)
            self.assertEqual(e["event_type"], event_type)
        with self.assertRaisesRegex(EventError, "bytes"):
            normalize_record({"ts": "2026-09-15T10:00:00Z", "bytes": -5}, "api", NOW)
        with self.assertRaisesRegex(EventError, "dest_port"):
            normalize_record({"ts": "2026-09-15T10:00:00Z", "dest_port": True}, "api", NOW)


class CloudTrailTests(unittest.TestCase):
    def record(self, name, source, **extra):
        return {"eventTime": "2026-09-15T10:00:00Z", "eventName": name, "eventSource": source,
                "sourceIPAddress": "203.0.113.150", "recipientAccountId": "123456789012",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/svc-deploy-tmp"}, **extra}

    def test_mapping(self):
        text = json.dumps({"Records": [
            self.record("CreateAccessKey", "iam.amazonaws.com"),
            self.record("GetObject", "s3.amazonaws.com", additionalEventData={"bytesTransferredOut": 5000}),
            self.record("ListUsers", "iam.amazonaws.com"),
            self.record("GetObject", "s3.amazonaws.com", sourceIPAddress="s3.amazonaws.com", errorCode="AccessDenied"),
        ]})
        events, rejections = parse_payload(text, "auto", "cloud", now=NOW)
        self.assertEqual(rejections, [])
        self.assertEqual([e["event_type"] for e in events],
                         ["cloud_iam_change", "cloud_data_access", "cloud_api_call", "cloud_data_access"])
        self.assertEqual({e["user"] for e in events}, {"svc-deploy-tmp"})
        self.assertEqual(events[1]["bytes"], 5000)
        self.assertEqual((events[3]["src_ip"], events[3]["outcome"]), (None, "failure"))
        self.assertIn("eventName", events[0]["raw"])


class SampleFileTests(unittest.TestCase):
    def test_every_sample_parses_with_one_rejection(self):
        from pathlib import Path
        samples = Path(__file__).resolve().parent.parent / "samples"
        expected = {"nginx_access.log": "web_scan", "firewall.csv": "fw_deny", "cloudtrail.json": "cloud_iam_change",
                    "linux_host.log": "privilege_escalation"}
        for name, event_type in expected.items():
            with self.subTest(sample=name):
                events, rejections = parse_payload((samples / name).read_text(), "auto", "sample", year=2026, now=NOW)
                self.assertEqual(len(rejections), 1)
                self.assertIn(event_type, {e["event_type"] for e in events})


class RedactionTests(unittest.TestCase):
    def test_patterns(self):
        for text in ["password=abc123", "Authorization: Bearer abcdefghijklmnop",
                     'body {"password": "abc123"}', "token wp_abcdefghijklmnopqrstuvwxyz", "api_key: abc123"]:
            with self.subTest(text=text):
                out = redact(text)
                self.assertIn("REDACTED", out)
                self.assertNotIn("abc123", out)
                self.assertNotIn("abcdefghijklmnop", out)


if __name__ == "__main__":
    unittest.main()
