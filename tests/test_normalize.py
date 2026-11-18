import inspect
import json
import re
import unittest
from datetime import datetime, timezone

from watchpost.db import connect, init_schema
from watchpost.diagnostics import record_error, redact
from watchpost.normalize import (EventError, MAX_LEN, classify_web_request, normalize_authlog_line,
                                 normalize_record, normalize_weblog_line, parse_payload)
from watchpost import normalize

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

    def test_event_types_fold_ascii_letters_only(self):
        # Network_Connection, Account_Lockout, and Block stay catalog types. A Kelvin sign does not.
        cases = (
            ("Network_Connection", "network_connection"),
            ("NETWORK_CONNECTION", "network_connection"),
            ("Network Connection", "network_connection"),
            ("Account_Lockout", "account_lockout"),
            ("account-lockout", "account_lockout"),
            ("Block", "fw_deny"),
            ("BLOCK", "fw_deny"),
            ("LOGIN-FAILED", "auth_failure"),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                event = normalize_record(
                    {"ts": "2026-09-15T10:00:00Z", "event_type": raw, "message": "labelled synthetic"},
                    "api", NOW)
                self.assertEqual(event["event_type"], expected)
        self.assertEqual(
            normalize_record({"ts": "2026-09-15T10:00:00Z", "action": "Block"}, "api", NOW)["event_type"],
            "fw_deny")
        kelvin_net = "networ\u212a_connection"
        kelvin_block = "bloc\u212a"
        for raw in (kelvin_net, kelvin_block):
            with self.subTest(raw=raw):
                event = normalize_record(
                    {"ts": "2026-09-15T10:00:00Z", "type": raw, "message": raw}, "api", NOW)
                self.assertEqual(event["event_type"], "other")
                self.assertEqual(json.loads(event["raw"])["type"], raw)
                self.assertEqual(event["message"], raw)
        self.assertNotEqual(
            normalize_record({"ts": "2026-09-15T10:00:00Z", "event_type": kelvin_net}, "api", NOW)["event_type"],
            "network_connection")
        self.assertNotEqual(
            normalize_record({"ts": "2026-09-15T10:00:00Z", "event_type": kelvin_block}, "api", NOW)["event_type"],
            "fw_deny")
        source = inspect.getsource(normalize.normalize_type)
        self.assertNotIn(".lower(", source)
        self.assertNotIn(".casefold(", source)
        for text in (self._docs("API.md"), self._docs("REFERENCE.md")):
            self.assertIn("`Network_Connection` is `network_connection`", text)
            self.assertIn("`Account_Lockout` is `account_lockout`", text)
            self.assertIn("`Block` is `fw_deny`", text)
            self.assertIn("`networ\u212a_connection` and `bloc\u212a` stay `other`", text)
        reference = self._docs("REFERENCE.md")
        self.assertIn("`networ\u212a_connection` stays `other` and is not `network_connection`", reference)
        self.assertIn("`bloc\u212a` stays `other` and is not `fw_deny`", reference)

    @staticmethod
    def _docs(name):
        from pathlib import Path
        return (Path(__file__).resolve().parent.parent / "docs" / name).read_text()

    def test_severity_folds_ascii_letters_only(self):
        # HIGH stays high. A dotted capital I is not rewritten into high.
        cases = (
            ("HIGH", "high"),
            ("High", "high"),
            ("  CRITICAL  ", "critical"),
            ("Low", "low"),
            ("MEDIUM", "medium"),
            ("Info", "info"),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                event = normalize_record(
                    {"ts": "2026-09-15T10:00:00Z", "severity": raw, "message": "labelled synthetic"},
                    "api", NOW)
                self.assertEqual(event["severity"], expected)
        self.assertEqual(
            normalize_record({"ts": "2026-09-15T10:00:00Z", "level": "HIGH"}, "api", NOW)["severity"],
            "high")
        dotted = "H\u0130GH"
        with self.assertRaises(EventError) as caught:
            normalize_record({"ts": "2026-09-15T10:00:00Z", "severity": dotted}, "api", NOW)
        message = str(caught.exception)
        self.assertEqual(message, "severity must be one of info, low, medium, high, critical")
        self.assertNotIn("\u0307", message)
        self.assertNotIn("h\u0130gh", message)
        self.assertNotIn("severity 'high'", message)
        events, rejections = parse_payload(
            '{"ts":"2026-09-15T10:00:00Z","severity":"HIGH"}\n'
            '{"ts":"2026-09-15T10:00:00Z","severity":"H\u0130GH"}\n',
            "jsonl", "api", now=NOW)
        self.assertEqual([event["severity"] for event in events], ["high"])
        self.assertEqual(rejections[0]["reason"], message)
        self.assertNotIn("\u0307", rejections[0]["reason"])
        source = inspect.getsource(normalize.normalize_record)
        self.assertNotIn(".lower(", source)
        self.assertNotIn(".casefold(", source)
        for text in (self._docs("API.md"), self._docs("REFERENCE.md")):
            self.assertIn("`HIGH` is `high`", text)
            self.assertIn("`H\u0130GH` stays the severity error and is not `high`", text)

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

    def test_scan_folds_ascii_letters_only(self):
        # UNION SELECT and /.ENV stay scans. Dotless i, dotted I, and Kelvin do not become those words.
        scans = ("union select", "UNION SELECT", "UNION ALL SELECT", "/.env", "/.ENV", "/.GIT",
                 "/blog/.GIT/config", "SLEEP(1)", "Or 1=1", "<SCRIPT", "${JNDI:",
                 "/q?s=1%20UNION%20SELECT%20password")
        for path in scans:
            with self.subTest(path=path):
                self.assertEqual(classify_web_request(path, 200), "web_scan", path)
        self.assertEqual(self.parse("/.ENV", 404)["event_type"], "web_scan")
        self.assertEqual(self.parse("/q?s=1+UNION+SELECT+password", 200)["event_type"], "web_scan")
        lookalikes = ("unıon select", "UNİON SELECT", "benchmarK(", "ınformation_schema", "/.gİt")
        for path in lookalikes:
            with self.subTest(path=path):
                self.assertEqual(classify_web_request(path, 200), "web_request", path)
                self.assertEqual(classify_web_request(path, 500), "web_error", path)
        self.assertEqual(self.parse("/.gİt", 404)["event_type"], "web_request")
        self.assertEqual(self.parse("/.gİt", 502)["event_type"], "web_error")
        self.assertEqual(self.parse("/q?s=benchmarK(", 200)["event_type"], "web_request")
        self.assertNotEqual(classify_web_request("/.gİt", 200), classify_web_request("/.git", 200))
        source = inspect.getsource(classify_web_request)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("re.I", source)
        self.assertNotIn("IGNORECASE", source)
        self.assertFalse(normalize._SCAN_PATTERN.flags & re.IGNORECASE)
        api = (self._docs("API.md"))
        reference = self._docs("REFERENCE.md")
        for text in (api, reference):
            self.assertIn("`UNION SELECT` and `/.ENV` are `web_scan`", text)
            self.assertIn("`unıon select` and `/.gİt` are not", text)
        self.assertIn("`/.gİt` is not `/.git`", reference)

    def test_scanner_agent_folds_ascii_letters_only(self):
        # Nikto and sqlmap stay scans. A Kelvin sign in the name does not become nikto.
        scans = ("Nikto/2.1", "NIKTO", "sqlmap/1.7", "SQLMAP", "nmap", "Nmap", "Masscan")
        for agent in scans:
            with self.subTest(agent=agent):
                self.assertEqual(classify_web_request("/", 200, agent), "web_scan", agent)
        nikto = self.parse("/", 200, agent="Nikto/2.1")
        self.assertEqual(nikto["event_type"], "web_scan")
        self.assertIn("ua=Nikto/2.1", nikto["message"])
        sqlmap = self.parse("/", 200, agent="sqlmap/1.7")
        self.assertEqual(sqlmap["event_type"], "web_scan")
        lookalike = "ni\u212ato"
        self.assertEqual(classify_web_request("/", 200, lookalike), "web_request")
        self.assertEqual(classify_web_request("/", 500, lookalike), "web_error")
        self.assertEqual(self.parse("/", 404, agent=lookalike)["event_type"], "web_request")
        errored = self.parse("/", 502, agent=lookalike)
        self.assertEqual(errored["event_type"], "web_error")
        self.assertIn("ua=" + lookalike, errored["message"])
        self.assertNotEqual(
            classify_web_request("/", 200, lookalike),
            classify_web_request("/", 200, "nikto"))
        self.assertEqual(classify_web_request("/", 200, "Mozilla/5.0"), "web_request")
        self.assertEqual(classify_web_request("/.env", 200, lookalike), "web_scan")
        self.assertFalse(normalize._SCANNER_AGENT.flags & re.IGNORECASE)
        assignment = next(line for line in inspect.getsource(normalize).splitlines()
                          if "_SCANNER_AGENT" in line)
        self.assertNotIn("re.I", assignment)
        self.assertNotIn("IGNORECASE", assignment)
        source = inspect.getsource(classify_web_request)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("re.I", source)
        self.assertNotIn("IGNORECASE", source)
        for text in (self._docs("API.md"), self._docs("REFERENCE.md")):
            self.assertIn("`Nikto` and `sqlmap` are `web_scan`", text)
            self.assertIn("`ni\u212ato` is not", text)
        self.assertIn("`ni\u212ato` is not `nikto`", self._docs("REFERENCE.md"))

    @staticmethod
    def _docs(name):
        from pathlib import Path
        return (Path(__file__).resolve().parent.parent / "docs" / name).read_text()

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

    def test_json_escaped_quote_does_not_leave_the_rest_of_the_secret(self):
        # The value is a\"supersecret. Stopping at the first quote would keep supersecret.
        text = '{"password": "a\\"supersecret", "user": "alice"}'
        self.assertEqual(redact(text), '{"password": "[REDACTED]", "user": "alice"}')
        self.assertEqual(redact('{"password" : "a\\"b\\"c"}'), '{"password" : "[REDACTED]"}')
        self.assertEqual(redact('{"password": ""}'), '{"password": "[REDACTED]"}')
        for key in ("passwd", "secret", "token", "api_key", "Password"):
            with self.subTest(key=key):
                raw = '{"%s": "a\\"supersecret"}' % key
                self.assertNotIn("supersecret", redact(raw))
                self.assertIn('"[REDACTED]"', redact(raw))

    def test_json_keys_use_the_same_secret_names_as_key_value(self):
        # Quoted JSON only named password, passwd, secret, token, and api_key.
        # api-key, authorization, and session stayed in the message and the error log.
        secret = "supersecret"
        keys = ("pwd", "api-key", "apikey", "api_key", "authorization", "cookie", "session",
                "API-KEY", "Session")
        for key in keys:
            with self.subTest(key=key):
                raw = '{"%s": "a\\"%s", "user": "alice"}' % (key, secret)
                out = redact(raw)
                self.assertNotIn(secret, out)
                self.assertEqual(out, '{"%s": "[REDACTED]", "user": "alice"}' % key)
        self.assertIn(secret, redact('{"session_id": "%s"}' % secret))
        self.assertEqual(redact("session_id=%s" % secret), "session_id=%s" % secret)

    def test_token_and_key_names_are_redacted(self):
        # access_token, refresh_token, id_token, client_secret, and private_key
        # stayed in the message. token and secret do not cover those names.
        secret = "supersecret"
        keys = ("access_token", "refresh_token", "id_token", "client_secret", "private_key",
                "Access_Token", "PRIVATE_KEY")
        for key in keys:
            with self.subTest(key=key):
                raw = '{"%s": "a\\"%s", "user": "alice"}' % (key, secret)
                out = redact(raw)
                self.assertNotIn(secret, out)
                self.assertEqual(out, '{"%s": "[REDACTED]", "user": "alice"}' % key)
                self.assertEqual(redact("%s=%s" % (key, secret)), "%s=[REDACTED]" % key)
                self.assertEqual(redact('%s: "%s"' % (key, secret)), "%s: [REDACTED]" % key)
        self.assertIn(secret, redact('{"session_id": "a\\"%s"}' % secret))
        self.assertEqual(redact("session_id=%s" % secret), "session_id=%s" % secret)

        message = ('{"access_token": "a\\"%s", "refresh_token": "%s", '
                   '"id_token": "%s", "client_secret": "%s", "private_key": "%s", '
                   '"session_id": "keep-%s", "user": "alice"}') % (
                       secret, secret, secret, secret, secret, secret)
        event = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": message}, "api", NOW)
        self.assertNotIn('"a\\"%s"' % secret, event["message"])
        self.assertIn("[REDACTED]", event["message"])
        self.assertIn('"session_id": "keep-%s"' % secret, event["message"])
        self.assertIn('"user": "alice"', event["message"])
        for key in ("access_token", "refresh_token", "id_token", "client_secret", "private_key"):
            self.assertIn('"%s": "[REDACTED]"' % key, event["message"])

        top = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": "line",
                                "access_token": secret, "client_secret": secret,
                                "private_key": secret, "session_id": secret}, "api", NOW)
        self.assertIn('"access_token": "[REDACTED]"', top["raw"])
        self.assertIn('"client_secret": "[REDACTED]"', top["raw"])
        self.assertIn('"private_key": "[REDACTED]"', top["raw"])
        self.assertIn('"session_id": "%s"' % secret, top["raw"])

        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        stored = record_error(conn, "ingest", message)
        self.assertNotIn("a\\\"%s" % secret, stored)
        self.assertIn("keep-%s" % secret, stored)
        logged = conn.execute("SELECT message FROM error_log").fetchone()[0]
        self.assertNotIn("a\\\"%s" % secret, logged)
        self.assertIn("[REDACTED]", logged)
        self.assertIn("keep-%s" % secret, logged)

        message = ('{"api-key": "%s", "authorization": "Bearer %s", '
                   '"session": "a\\"%s", "user": "alice"}') % (secret, secret, secret)
        event = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": message}, "api", NOW)
        self.assertNotIn(secret, event["message"])
        self.assertIn('"user": "alice"', event["message"])
        # A top-level key is real JSON in the stored raw record.
        top = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": "line",
                                "api-key": secret, "authorization": secret, "session": secret},
                               "api", NOW)
        self.assertNotIn(secret, top["raw"])
        self.assertIn('"api-key": "[REDACTED]"', top["raw"])
        self.assertIn('"authorization": "[REDACTED]"', top["raw"])
        self.assertIn('"session": "[REDACTED]"', top["raw"])

        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        stored = record_error(conn, "ingest", message)
        self.assertNotIn(secret, stored)
        logged = conn.execute("SELECT message FROM error_log").fetchone()[0]
        self.assertNotIn(secret, logged)
        self.assertIn("[REDACTED]", logged)

    def test_escaped_json_secret_is_redacted_in_the_stored_message(self):
        secret = '{"password": "a\\"supersecret"}'
        event = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": secret}, "api", NOW)
        self.assertEqual(event["message"], '{"password": "[REDACTED]"}')
        self.assertNotIn("supersecret", event["message"])

    def test_quoted_secret_is_redacted_before_the_message_and_raw_cuts(self):
        # The JSON value pattern needs the closing quote. Cutting first keeps the secret.
        secret = "SUPERSECRET"
        value = 'a\\"' + secret + ("p" * 40)
        opener = '{"password": "'
        pad = MAX_LEN["message"] - len(opener) - len('a\\"') - len(secret)
        message = ("n" * pad) + opener + value + '"}'
        cut = message[:MAX_LEN["message"]]
        self.assertIn(secret, cut)
        self.assertIn(secret, redact(cut))
        self.assertNotIn(secret, redact(message))
        event = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": message}, "api", NOW)
        self.assertNotIn(secret, event["message"])
        self.assertLessEqual(len(event["message"]), MAX_LEN["message"])
        self.assertIn("[REDACTED]", event["message"])

        # A top-level password whose closer sits past the raw limit.
        raw_value = 'a"' + secret + ("p" * 80)
        record = {"ts": "2026-09-15T10:00:00Z", "note": "n" * 3900, "password": raw_value}
        raw = json.dumps(record, default=str, sort_keys=True)
        raw_cut = raw[:MAX_LEN["raw"]]
        self.assertGreater(len(raw), MAX_LEN["raw"])
        self.assertIn(secret, raw_cut)
        self.assertIn(secret, redact(raw_cut))
        self.assertNotIn(secret, redact(raw))
        event = normalize_record(record, "api", NOW)
        self.assertNotIn(secret, event["raw"])
        self.assertLessEqual(len(event["raw"]), MAX_LEN["raw"])
        self.assertIn("[REDACTED]", event["raw"])


if __name__ == "__main__":
    unittest.main()
