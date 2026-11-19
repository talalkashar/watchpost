import json
import unittest
from datetime import datetime, timezone

from watchpost import engine
from watchpost.db import connect, init_schema
from watchpost.diagnostics import record_error, redact
from watchpost.ecs import to_ecs
from watchpost.normalize import (EventError, MAX_LEN, normalize_authlog_line, normalize_record,
                                 normalize_weblog_line, parse_payload)

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
        # Quoted JSON only named password, passwd, sample, token, and api_key.
        # api-key, authorization, and session stayed in the message and the error log.
        sample = "hunter2value"
        keys = ("pwd", "api-key", "apikey", "api_key", "authorization", "cookie", "session",
                "API-KEY", "Session")
        for key in keys:
            with self.subTest(key=key):
                raw = '{"%s": "a\\"%s", "user": "alice"}' % (key, sample)
                out = redact(raw)
                self.assertNotIn(sample, out)
                self.assertEqual(out, '{"%s": "[REDACTED]", "user": "alice"}' % key)
        self.assertIn(sample, redact('{"session_id": "%s"}' % sample))
        self.assertEqual(redact("session_id=%s" % sample), "session_id=%s" % sample)

    def test_token_and_key_names_are_redacted(self):
        # access_token, refresh_token, id_token, client_secret, and private_key
        # stayed in the message. token and sample do not cover those names.
        sample = "hunter2value"
        keys = ("access_token", "refresh_token", "id_token", "client_secret", "private_key",
                "Access_Token", "PRIVATE_KEY")
        for key in keys:
            with self.subTest(key=key):
                raw = '{"%s": "a\\"%s", "user": "alice"}' % (key, sample)
                out = redact(raw)
                self.assertNotIn(sample, out)
                self.assertEqual(out, '{"%s": "[REDACTED]", "user": "alice"}' % key)
                self.assertEqual(redact("%s=%s" % (key, sample)), "%s=[REDACTED]" % key)
                self.assertEqual(redact('%s: "%s"' % (key, sample)), "%s: [REDACTED]" % key)
        self.assertIn(sample, redact('{"session_id": "a\\"%s"}' % sample))
        self.assertEqual(redact("session_id=%s" % sample), "session_id=%s" % sample)

        message = ('{"access_token": "a\\"%s", "refresh_token": "%s", '
                   '"id_token": "%s", "client_secret": "%s", "private_key": "%s", '
                   '"session_id": "keep-%s", "user": "alice"}') % (
                       sample, sample, sample, sample, sample, sample)
        event = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": message}, "api", NOW)
        self.assertNotIn('"a\\"%s"' % sample, event["message"])
        self.assertIn("[REDACTED]", event["message"])
        self.assertIn('"session_id": "keep-%s"' % sample, event["message"])
        self.assertIn('"user": "alice"', event["message"])
        for key in ("access_token", "refresh_token", "id_token", "client_secret", "private_key"):
            self.assertIn('"%s": "[REDACTED]"' % key, event["message"])

        top = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": "line",
                                "access_token": sample, "client_secret": sample,
                                "private_key": sample, "session_id": sample}, "api", NOW)
        self.assertIn('"access_token": "[REDACTED]"', top["raw"])
        self.assertIn('"client_secret": "[REDACTED]"', top["raw"])
        self.assertIn('"private_key": "[REDACTED]"', top["raw"])
        self.assertIn('"session_id": "%s"' % sample, top["raw"])

        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        stored = record_error(conn, "ingest", message)
        self.assertNotIn("a\\\"%s" % sample, stored)
        self.assertIn("keep-%s" % sample, stored)
        logged = conn.execute("SELECT message FROM error_log").fetchone()[0]
        self.assertNotIn("a\\\"%s" % sample, logged)
        self.assertIn("[REDACTED]", logged)
        self.assertIn("keep-%s" % sample, logged)

        message = ('{"api-key": "%s", "authorization": "Bearer %s", '
                   '"session": "a\\"%s", "user": "alice"}') % (sample, sample, sample)
        event = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": message}, "api", NOW)
        self.assertNotIn(sample, event["message"])
        self.assertIn('"user": "alice"', event["message"])
        # A top-level key is real JSON in the stored raw record.
        top = normalize_record({"ts": "2026-09-15T10:00:00Z", "message": "line",
                                "api-key": sample, "authorization": sample, "session": sample},
                               "api", NOW)
        self.assertNotIn(sample, top["raw"])
        self.assertIn('"api-key": "[REDACTED]"', top["raw"])
        self.assertIn('"authorization": "[REDACTED]"', top["raw"])
        self.assertIn('"session": "[REDACTED]"', top["raw"])

        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        stored = record_error(conn, "ingest", message)
        self.assertNotIn(sample, stored)
        logged = conn.execute("SELECT message FROM error_log").fetchone()[0]
        self.assertNotIn(sample, logged)
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


class CoverageTests(unittest.TestCase):
    def test_windows_shapes_and_status(self):
        nested = normalize_record({
            "Event": {"System": {
                "EventID": {"#text": "4625"},
                "TimeCreated": {"SystemTime": "2026-09-15T10:00:00.0000000Z"},
                "Computer": "dc01", "Channel": "Security"},
                "EventData": {"Data": [
                    {"Name": "TargetUserName", "#text": "bob"},
                    {"Name": "IpAddress", "#text": "10.0.0.8"}]}}}, "win", NOW)
        self.assertEqual((nested["event_type"], nested["user"], nested["src_ip"], nested["host"], nested["source"]),
                         ("auth_failure", "bob", "10.0.0.8", "dc01", "Security"))
        self.assertEqual(nested["ts"], "2026-09-15T10:00:00.000Z")
        self.assertNotIn("EventID", nested)
        beat = normalize_record({
            "@timestamp": "2026-09-15T10:00:00Z",
            "winlog": {"event_id": 4625, "computer_name": "dc02", "channel": "Security",
                       "event_data": {"TargetUserName": "carol", "IpAddress": "10.0.0.9"}}}, "win", NOW)
        self.assertEqual((beat["event_type"], beat["user"], beat["host"], beat["src_ip"]),
                         ("auth_failure", "carol", "dc02", "10.0.0.9"))
        self.assertEqual(normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": {"#text": 4625},
                                           "TargetUserName": "bob"}, "win", NOW)["event_type"], "auth_failure")
        self.assertEqual(normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4771}, "win", NOW)["event_type"],
                         "auth_failure")
        ok = normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4776, "Status": "0x0"}, "win", NOW)
        bad = normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4776, "Status": "0xC000006A"}, "win", NOW)
        guessed = normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4776}, "win", NOW)
        garbled = normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 4776, "Status": "0xZZZZ"}, "win", NOW)
        self.assertEqual((ok["event_type"], bad["event_type"], guessed["event_type"], garbled["event_type"]),
                         ("auth_success", "auth_failure", "other", "other"))
        self.assertIsNone(garbled["outcome"])
        for status in ("²", "9" * 5000):
            with self.subTest(status=status[:10]):
                rows, rejected = parse_payload(json.dumps([
                    {"EventID": 4776, "Status": status}, {"EventID": 4624}
                ]), "json", "win", now=NOW)
                self.assertEqual(rejected, [])
                self.assertEqual([row["event_type"] for row in rows], ["other", "auth_success"])
        deny = normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 5157, "SourceAddress": "198.51.100.10",
                                 "DestAddress": "10.0.0.5", "DestPort": 3389}, "win", NOW)
        allow = normalize_record({"ts": "2026-09-15T10:00:00Z", "EventID": 5156}, "win", NOW)
        self.assertEqual((deny["event_type"], deny["src_ip"], deny["dest_ip"], deny["dest_port"]),
                         ("fw_deny", "198.51.100.10", "10.0.0.5", 3389))
        self.assertEqual(allow["event_type"], "fw_allow")

    def test_user_domain_is_split_and_the_stored_name_stays(self):
        corp = to_ecs({"user": "CORP\\bob", "event_type": "auth_success"})
        self.assertEqual(corp["user"], {"name": "CORP\\bob", "domain": "CORP"})
        upn = to_ecs({"user": "bob@corp", "event_type": "auth_success"})
        self.assertEqual(upn["user"]["name"], "bob@corp")
        self.assertEqual(upn["user"]["domain"], "corp")
        self.assertEqual(to_ecs({"user": "alice", "event_type": "auth_success"})["user"], {"name": "alice"})

    def test_authlog_fallbacks(self):
        cases = [
            ("Sep 15 10:00:01 web01 sshd[1]: Failed none for alice from 203.0.113.5 port 22 ssh2",
             ("auth_failure", "alice", "203.0.113.5", "failure")),
            ("Sep 15 10:00:01 web01 sshd[1]: Connection closed by authenticating user root 203.0.113.5 port 22 [preauth]",
             ("other", "root", "203.0.113.5", None)),
            ("Sep 15 10:00:01 web01 sshd[1]: Connection closed by 203.0.113.9 port 22 [preauth]",
             ("other", None, "203.0.113.9", None)),
            ("Sep 15 10:00:01 web01 sshd[1]: error: maximum authentication attempts exceeded for invalid user admin from 203.0.113.8 port 22 ssh2 [preauth]",
             ("auth_failure", "admin", "203.0.113.8", "failure")),
            ("Sep 15 10:00:01 web01 sshd[1]: Disconnected from user alice 10.0.0.5 port 22",
             ("other", None, None, None)),
            ("Sep 15 10:00:01 web01 sshd[1]: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice",
             ("auth_failure", "alice", None, "failure")),
            ("Sep 15 10:00:01 web01 sshd[1]: pam_faillock(sshd:auth): Consecutive login failures for user alice account temporarily locked",
             ("account_lockout", "alice", None, None)),
            ("Sep 15 10:00:01 web01 sudo: frank is not in the sudoers file. This incident will be reported.",
             ("privilege_escalation", "frank", None, "failure")),
            ("Sep 15 10:00:01 web01 sudo: frank : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash",
             ("privilege_escalation", "frank", None, "failure")),
            ("Sep 15 10:00:01 web01 sshd[1]: Failed password for root from gateway.example port 22 ssh2",
             ("auth_failure", "root", None, "failure")),
            ("Sep 15 10:00:01 web01 sshd[1]: Failed password for root from 2001:db8::10 port 22 ssh2",
             ("auth_failure", "root", "2001:db8::10", "failure")),
            ("<34>Sep 15 10:00:01 web01 sshd[123]: Failed password for root from 203.0.113.5 port 22 ssh2",
             ("auth_failure", "root", "203.0.113.5", "failure")),
            ("<34>1 2026-09-15T10:00:01.000Z web01 sshd 123 - - Failed password for root from 203.0.113.5 port 22 ssh2",
             ("auth_failure", "root", "203.0.113.5", "failure")),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                event = normalize_authlog_line(line, "authlog", now=NOW)
                self.assertEqual((event["event_type"], event["user"], event["src_ip"], event["outcome"]), expected)

    def test_firewall_syslog_formats(self):
        iptables = normalize_authlog_line(
            "Sep 15 10:00:00 fw01 kernel: IPTABLES DROPPED: IN=eth0 OUT= MAC= SRC=198.51.100.10 DST=10.0.0.5 "
            "LEN=40 PROTO=TCP SPT=40000 DPT=22", "fw", now=NOW)
        self.assertEqual((iptables["event_type"], iptables["src_ip"], iptables["dest_ip"], iptables["dest_port"]),
                         ("fw_deny", "198.51.100.10", "10.0.0.5", 22))
        asa = normalize_authlog_line(
            "Sep 15 10:00:00 asa01 %ASA-4-106023: Deny tcp src outside:198.51.100.10/40000 "
            "dst inside:10.0.0.10/3389 by access-group \"outside_in\"", "fw", now=NOW)
        self.assertEqual((asa["event_type"], asa["src_ip"], asa["dest_ip"], asa["dest_port"], asa["host"]),
                         ("fw_deny", "198.51.100.10", "10.0.0.10", 3389, "asa01"))
        acl = normalize_authlog_line(
            "Sep 15 10:00:00 asa01 %ASA-6-106100: access-list outside_in permitted tcp "
            "outside/198.51.100.10(40000) -> inside/10.0.0.10(443)", "fw", now=NOW)
        self.assertEqual((acl["event_type"], acl["dest_port"]), ("fw_allow", 443))
        forti = normalize_authlog_line(
            "Sep 15 10:00:00 fw01 date=2026-09-15 time=10:00:00 devname=\"fw01\" devid=FG100 type=traffic "
            "subtype=forward level=warning vd=root srcip=198.51.100.10 srcport=40000 srcintf=wan "
            "dstip=10.0.0.5 dstport=3389 dstintf=lan action=deny policyid=1 proto=6 sentbyte=60", "fw", now=NOW)
        self.assertEqual((forti["event_type"], forti["src_ip"], forti["dest_ip"], forti["dest_port"], forti["bytes"]),
                         ("fw_deny", "198.51.100.10", "10.0.0.5", 3389, 60))
        pfsense = normalize_authlog_line(
            "Sep 15 10:00:00 fw01 filterlog[123]: 5,,,1000000103,em0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,52,"
            "198.51.100.10,10.0.0.5,40000,22,0,S,1024,,", "fw", now=NOW)
        self.assertEqual((pfsense["event_type"], pfsense["src_ip"], pfsense["dest_ip"], pfsense["dest_port"]),
                         ("fw_deny", "198.51.100.10", "10.0.0.5", 22))

    def test_weblog_vhost_iis_and_apache(self):
        vhost = normalize_weblog_line(
            'example.com:8443 203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "GET /app HTTP/1.1" 200 162 "-" "Mozilla/5.0"',
            "nginx", now=NOW)
        self.assertEqual((vhost["host"], vhost["src_ip"], vhost["event_type"], vhost["bytes"]),
                         ("example.com", "203.0.113.80", "web_request", 162))
        empty = normalize_weblog_line(
            '203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "-" 400 0 "-" "-"', "nginx", now=NOW)
        self.assertEqual((empty["event_type"], empty["outcome"], empty["src_ip"]),
                         ("web_request", "failure", "203.0.113.80"))
        encoded = normalize_weblog_line(
            '203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "GET /%252e%252e%252fetc%252fpasswd HTTP/1.1" 404 0 "-" "x"',
            "nginx", now=NOW)
        self.assertEqual(encoded["event_type"], "web_scan")
        scan = normalize_weblog_line(
            '203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "GET /wp-config.php HTTP/1.1" 404 0 "-" "x"',
            "nginx", now=NOW)
        self.assertEqual(scan["event_type"], "web_scan")
        apache = ('[Tue Sep 15 10:00:00 2026] [authz_core:error] [pid 123] [client 203.0.113.9:51234] '
                  'AH01630: client denied by server configuration: /var/www/html/.env')
        event = normalize_weblog_line(apache, "apache", now=NOW)
        self.assertEqual((event["event_type"], event["src_ip"], event["ts"]),
                         ("web_scan", "203.0.113.9", "2026-09-15T10:00:00.000Z"))
        events, rejections = parse_payload(apache + "\n", "auto", "apache", now=NOW)
        self.assertEqual(len(events), 1)
        self.assertEqual(rejections, [])
        iis = (
            "#Software: Microsoft Internet Information Services 10.0\n"
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
            "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n"
            "2026-09-15 10:00:00 10.0.0.5 GET /wp-config.php - 443 alice 203.0.113.80 Mozilla/5.0 - 404 0 0 15\n"
        )
        events, rejections = parse_payload(iis, "auto", "iis", now=NOW)
        self.assertEqual([item["reason"] for item in rejections], ["log header directive", "log header directive"])
        self.assertEqual(len(events), 1)
        row = events[0]
        self.assertEqual((row["event_type"], row["src_ip"], row["dest_ip"], row["dest_port"], row["user"]),
                         ("web_scan", "203.0.113.80", "10.0.0.5", 443, "alice"))
        self.assertEqual(row["ts"], "2026-09-15T10:00:00.000Z")
        self.assertIsNone(row["host"])
        with self.assertRaisesRegex(EventError, "no #Fields"):
            normalize_weblog_line("2026-09-15 10:00:00 10.0.0.5 GET /only", "iis", now=NOW)

    def test_preauth_close_is_not_a_failed_password(self):
        # Ten real failures meet the seeded thresholds. Ten pre-auth closes from another
        # IP, one Windows failure, and a garbled status must not add a rule hit.
        stamp = "Sep 15 10:00:01"
        failed = f"{stamp} web01 sshd[9]: Failed password for alice from 203.0.113.5 port 22 ssh2"
        closed = f"{stamp} web01 sshd[9]: Connection closed by 203.0.113.50 port 22 [preauth]"
        named = (f"{stamp} web01 sshd[9]: Connection closed by authenticating user root "
                 "203.0.113.50 port 22 [preauth]")
        firewall = (f"{stamp} fw01 kernel: IPTABLES DROPPED: IN=eth0 OUT= MAC= SRC=198.51.100.10 "
                    "DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40000 DPT=22")
        bad_line = (f"Xxx 15 10:00:01 web01 sshd[9]: Failed password for secretuser "
                    "from 203.0.113.99 port 22 ssh2")
        auth_text = "\n".join([failed] * 10 + [closed] * 10 + [named, firewall, bad_line]) + "\n"
        auth_events, auth_rej = parse_payload(auth_text, "authlog", "authlog", now=NOW)
        self.assertEqual(len(auth_events), 22)
        self.assertEqual(auth_rej, [{"index": 23, "reason": "unparseable timestamp"}])
        self.assertNotIn("secretuser", json.dumps(auth_rej))
        failures = [event for event in auth_events if event["user"] == "alice"]
        self.assertEqual(len(failures), 10)
        self.assertTrue(all(event["event_type"] == "auth_failure" and event["outcome"] == "failure"
                            and event["src_ip"] == "203.0.113.5" for event in failures))
        closes = [event for event in auth_events if event["src_ip"] == "203.0.113.50"]
        self.assertEqual(len(closes), 11)
        self.assertTrue(all(event["event_type"] == "other" and event["outcome"] is None for event in closes))
        self.assertEqual(next(event["user"] for event in closes if event["user"]), "root")
        denied = next(event for event in auth_events if event["event_type"] == "fw_deny")
        self.assertEqual((denied["src_ip"], denied["dest_ip"], denied["dest_port"]),
                         ("198.51.100.10", "10.0.0.5", 22))

        windows = [
            {"ts": "2026-09-15T10:00:01Z", "EventID": 4776, "Status": "0x0",
             "TargetUserName": "bob", "IpAddress": "10.1.1.1"},
            {"ts": "2026-09-15T10:00:01Z", "EventID": 4776, "Status": "0xC000006A",
             "TargetUserName": "carol", "IpAddress": "10.1.1.2"},
            {"ts": "2026-09-15T10:00:01Z", "EventID": 4776, "Status": "0xZZZZ",
             "TargetUserName": "dave", "IpAddress": "10.1.1.3"},
            {"EventID": 4625, "TargetUserName": "erin", "message": "SECRET-SIBLING"},
            {"Event": {"System": {
                "EventID": {"#text": "4624"},
                "TimeCreated": {"SystemTime": "2026-09-15T10:00:01.0000000Z"},
                "Computer": "dc01", "Channel": "Security"},
                "EventData": {"Data": [
                    {"Name": "TargetUserName", "#text": "dave2"},
                    {"Name": "IpAddress", "#text": "10.1.1.9"}]}}},
        ]
        win_events, win_rej = parse_payload(json.dumps(windows), "json", "win", now=NOW)
        self.assertEqual(len(win_events), 4)
        self.assertEqual(win_rej, [{"index": 4, "reason": "missing timestamp"}])
        self.assertNotIn("SECRET-SIBLING", json.dumps(win_rej))
        self.assertNotIn("erin", json.dumps(win_rej))
        by_user = {event["user"]: event for event in win_events}
        self.assertEqual((by_user["bob"]["event_type"], by_user["bob"]["outcome"], by_user["bob"]["src_ip"]),
                         ("auth_success", "success", "10.1.1.1"))
        self.assertEqual((by_user["carol"]["event_type"], by_user["carol"]["outcome"], by_user["carol"]["src_ip"]),
                         ("auth_failure", "failure", "10.1.1.2"))
        self.assertEqual((by_user["dave"]["event_type"], by_user["dave"]["outcome"]), ("other", None))
        self.assertEqual((by_user["dave2"]["event_type"], by_user["dave2"]["host"], by_user["dave2"]["src_ip"]),
                         ("auth_success", "dc01", "10.1.1.9"))

        iis = (
            "#Software: Microsoft Internet Information Services 10.0\n"
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
            "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n"
            "2026-09-15 10:00:01 10.0.0.5 GET /wp-config.php - 443 mallory 203.0.113.80 Mozilla/5.0 - 404 0 0 15\n"
            "2026-09-15 10:00:01 10.0.0.5 GET /index.html - 443 mallory 203.0.113.81 Mozilla/5.0 - ZZZ 0 0 15\n"
        )
        iis_events, iis_rej = parse_payload(iis, "weblog", "iis", now=NOW)
        self.assertEqual(len(iis_events), 1)
        self.assertEqual((iis_events[0]["event_type"], iis_events[0]["user"], iis_events[0]["src_ip"]),
                         ("web_scan", "mallory", "203.0.113.80"))
        self.assertEqual([item["reason"] for item in iis_rej],
                         ["log header directive", "log header directive", "IIS line does not match #Fields"])

        accepted = auth_events + win_events + iis_events
        rejections = auth_rej + win_rej + iis_rej
        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        engine.seed_rules(conn)
        result = engine.ingest(conn, accepted, rejections, "mixed", "auto", "test")
        self.assertEqual((result["received"], result["accepted"], result["rejected"]),
                         (len(accepted) + len(rejections), len(accepted), len(rejections)))
        batch = dict(conn.execute(
            "SELECT received, accepted, rejected, errors FROM ingest_batches").fetchone())
        self.assertEqual((batch["received"], batch["accepted"], batch["rejected"]),
                         (result["received"], result["accepted"], 5))
        stored_reasons = json.loads(batch["errors"])
        self.assertNotIn("secretuser", json.dumps(stored_reasons))
        self.assertNotIn("SECRET-SIBLING", json.dumps(stored_reasons))
        self.assertNotIn("erin", json.dumps(stored_reasons))
        rows = [dict(row) for row in conn.execute(
            "SELECT event_type, outcome, user, src_ip FROM events")]
        self.assertEqual(len(rows), len(accepted))
        stored_fail = next(row for row in rows if row["user"] == "alice")
        stored_ok = next(row for row in rows if row["user"] == "bob")
        stored_close = next(row for row in rows if row["src_ip"] == "203.0.113.50" and row["user"] is None)
        fail_ecs = to_ecs(stored_fail)
        ok_ecs = to_ecs(stored_ok)
        close_ecs = to_ecs(stored_close)
        self.assertEqual(fail_ecs["event"]["category"], ["authentication"])
        self.assertEqual(fail_ecs["event"]["type"], ["start"])
        self.assertEqual(fail_ecs["event"]["outcome"], "failure")
        self.assertEqual(ok_ecs["event"]["category"], ["authentication"])
        self.assertEqual(ok_ecs["event"]["outcome"], "success")
        self.assertNotIn("category", close_ecs["event"])
        self.assertNotIn("outcome", close_ecs["event"])
        self.assertEqual(close_ecs["event"]["action"], "other")
        hits = {(row["rule_id"], row["group_key"]) for row in conn.execute(
            "SELECT rule_id, group_key FROM alerts")}
        self.assertEqual(hits, {("brute_force_ip", "203.0.113.5"), ("account_repeated_failures", "alice")})
        self.assertEqual(result["detection"]["alerts_created"], 2)


if __name__ == "__main__":
    unittest.main()
