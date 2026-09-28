import unittest
from datetime import datetime, timezone

from watchpost.diagnostics import redact
from watchpost.normalize import EventError, normalize_authlog_line, normalize_record, parse_payload

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
