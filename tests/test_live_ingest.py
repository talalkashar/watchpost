import importlib.util
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from tests.helpers import ServerTestCase
from watchpost import health, syslog_listener
from watchpost.config import Config
from watchpost.db import connect
from watchpost.health import run_health_checks
from watchpost.normalize import EventError
from watchpost.server import App
from watchpost.syslog_listener import SyslogListener, frame_to_event, parse_frame, read_tcp_frame

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("shipper", ROOT / "scripts" / "shipper.py")
shipper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shipper)


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    return predicate()


class SyslogParsingTests(unittest.TestCase):
    def test_rfc5424_sshd_failure_uses_auth_parser(self):
        event = frame_to_event("<38>1 2026-09-28T10:00:01.12+02:00 web01 sshd 812 - - "
                               "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2")
        self.assertEqual((event["host"], event["event_type"], event["user"], event["src_ip"]),
                         ("web01", "auth_failure", "admin", "203.0.113.9"))
        self.assertEqual(event["ts"], "2026-09-28T08:00:01.120Z")
        self.assertEqual(event["source"], "syslog")

    def test_rfc3164_accepted_login(self):
        event = frame_to_event("<86>Sep 28 10:00:02 bastion01 sshd[99]: Accepted publickey for alice "
                               "from 198.51.100.7 port 22 ssh2")
        self.assertEqual((event["host"], event["event_type"], event["user"]), ("bastion01", "auth_success", "alice"))

    def test_generic_fallback_takes_severity_from_pri_and_redacts(self):
        event = frame_to_event("<11>Sep 28 10:00:03 web01 nginx: upstream timed out password=hunter2")
        self.assertEqual((event["event_type"], event["severity"]), ("syslog", "high"))  # PRI 11 = user.err
        self.assertEqual(event["message"], "nginx: upstream timed out password=[REDACTED]")
        self.assertNotIn("hunter2", event["raw"])

    def test_pri_severity_mapping(self):
        for pri, severity in [(8, "critical"), (10, "critical"), (12, "medium"), (13, "low"), (14, "info")]:
            self.assertEqual(frame_to_event(f"<{pri}>Sep 28 10:00:00 h1 app: x")["severity"], severity)

    def test_missing_hostname_and_header_fall_back_to_peer(self):
        event = frame_to_event("<30>Sep 28 10:00:04 systemd[1]: Started Session 5.", peer_ip="192.0.2.1")
        self.assertEqual((event["host"], event["message"]), ("192.0.2.1", "systemd: Started Session 5."))
        event = frame_to_event("no header at all", peer_ip="192.0.2.2")
        self.assertEqual((event["host"], event["event_type"], event["severity"]), ("192.0.2.2", "syslog", "low"))

    def test_rfc5424_structured_data_bom_and_nil_values(self):
        parsed = parse_frame('<165>1 2026-09-28T10:00:05Z - app - ID47 [ex@32473 iut="3" x="a\\]b"] ﻿Hello')
        self.assertEqual((parsed["format"], parsed["host"], parsed["app"], parsed["msg"], parsed["facility"],
                          parsed["level"]), ("rfc5424", None, "app", "Hello", 20, 5))

    def test_bad_timestamp_is_rejected(self):
        with self.assertRaises(EventError):
            frame_to_event("<13>1 2126-09-28T10:00:05Z host app - - - from the future")

    def test_tcp_framing_octet_counting_and_newlines(self):
        import io
        msg = b"<13>1 2026-09-28T10:00:00Z h a - - - one\nstill one"
        stream = io.BufferedReader(io.BytesIO(b"%d " % len(msg) + msg + b"<13>two\n<13>three\n"))
        self.assertEqual(read_tcp_frame(stream), msg)
        self.assertEqual(read_tcp_frame(stream), b"<13>two\n")
        self.assertEqual(read_tcp_frame(stream), b"<13>three\n")
        self.assertIsNone(read_tcp_frame(stream))

    def test_oversized_tcp_line_is_truncated_not_merged(self):
        import io
        stream = io.BufferedReader(io.BytesIO(b"<13>" + b"x" * 100 + b"\n<13>next\n"))
        self.assertEqual(len(read_tcp_frame(stream, max_bytes=20)), 21)
        self.assertEqual(read_tcp_frame(stream, max_bytes=20), b"<13>next\n")


class SyslogListenerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        App(Config.from_env(db_path=self.db_path, admin_password="admin-test-password-1",
                            analyst_password="analyst-test-password-1"))
        self.listeners = []

    def tearDown(self):
        for listener in self.listeners:
            listener.stop()
        self.assertNotIn("syslog", health._COMPONENT_CHECKS)
        self.tmp.cleanup()

    def listener(self, **kw):
        kw.setdefault("port", 0)
        listener = SyslogListener(self.db_path, flush_interval=0.1, **kw)
        self.listeners.append(listener)
        return listener

    def rows(self, sql="SELECT * FROM events ORDER BY id"):
        conn = connect(self.db_path)
        try:
            return [dict(r) for r in conn.execute(sql)]
        finally:
            conn.close()

    def health(self):
        report = run_health_checks(lambda: connect(self.db_path), self.db_path)
        return {c["name"]: c for c in report["checks"]}

    def test_udp_and_tcp_frames_land_as_events(self):
        listener = self.listener()
        self.assertTrue(listener.start())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(b"<38>Sep 28 10:00:01 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
                       ("127.0.0.1", listener.udp_port))
        framed = b"<14>1 2026-09-28T10:00:02Z db01 cron 7 - - job finished"
        with socket.create_connection(("127.0.0.1", listener.tcp_port)) as tcp:
            tcp.sendall(b"<86>Sep 28 10:00:03 web02 sshd[2]: Accepted password for bob from 198.51.100.4 port 2\n"
                        + b"%d " % len(framed) + framed)
        events = wait_for(lambda: len(self.rows()) == 3 and self.rows())
        self.assertTrue(events, "frames did not reach the database")
        by_host = {e["host"]: e for e in events}
        self.assertEqual(by_host["web01"]["event_type"], "auth_failure")
        self.assertEqual(by_host["web02"]["event_type"], "auth_success")
        self.assertEqual((by_host["db01"]["event_type"], by_host["db01"]["message"]), ("syslog", "cron: job finished"))
        self.assertTrue(all(e["source"] == "syslog" and e["synthetic"] == 0 for e in events))
        batches = self.rows("SELECT * FROM ingest_batches")
        self.assertTrue(batches and all(b["submitted_by"] == "syslog-listener" for b in batches))
        check = self.health()["syslog"]
        self.assertEqual(check["status"], "ok")
        self.assertEqual(check["details"]["events_ingested"], 3)

    def test_rejected_frames_are_counted_not_stored(self):
        listener = self.listener(tcp=False)
        listener.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(b"<13>1 2126-01-01T00:00:00Z h a - - - future", ("127.0.0.1", listener.udp_port))
        self.assertTrue(wait_for(lambda: listener.stats["rejected"] == 1))
        self.assertEqual(self.rows(), [])

    def test_bind_failure_reports_failing_health_without_raising(self):
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen()
            listener = self.listener(port=busy.getsockname()[1], udp=False)
            self.assertFalse(listener.start())
        check = self.health()["syslog"]
        self.assertEqual(check["status"], "failing")
        self.assertIn("could not bind", check["message"])
        self.assertTrue(self.rows("SELECT * FROM error_log WHERE component = 'syslog'"))

    def test_allow_list_denies_other_peers(self):
        listener = self.listener(allow="192.0.2.0/24")
        listener.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(b"<13>hello", ("127.0.0.1", listener.udp_port))
        with socket.create_connection(("127.0.0.1", listener.tcp_port)) as tcp:
            tcp.sendall(b"<13>hello\n")
        self.assertTrue(wait_for(lambda: listener.stats["denied"] == 2))
        listener.flush()
        self.assertEqual(self.rows(), [])

    def test_invalid_allow_list_fails_closed(self):
        listener = self.listener(allow="not-an-ip")
        self.assertFalse(listener.start())
        self.assertIsNone(listener.udp_server)
        self.assertEqual(self.health()["syslog"]["status"], "failing")

    def test_start_if_enabled_follows_config(self):
        config = Config.from_env(db_path=self.db_path, syslog_enabled=False)
        app = type("FakeApp", (), {"config": config})()
        self.assertIsNone(syslog_listener.start_if_enabled(app))
        app.config = Config.from_env(db_path=self.db_path, syslog_enabled=True, syslog_port=0)
        listener = syslog_listener.start_if_enabled(app)
        self.listeners.append(listener)
        self.assertIsNotNone(listener.udp_port)
        self.assertEqual(self.health()["syslog"]["status"], "ok")

    def test_env_configuration(self):
        env = {"SIEM_SYSLOG": "1", "SIEM_SYSLOG_BIND": "::1", "SIEM_SYSLOG_PORT": "6514",
               "SIEM_SYSLOG_ALLOW": "10.0.0.0/8"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            config = Config.from_env()
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual((config.syslog_enabled, config.syslog_bind, config.syslog_port, config.syslog_allow),
                         (True, "::1", 6514, "10.0.0.0/8"))
        self.assertFalse(Config.from_env().syslog_enabled)


class SyslogHealthApiTests(ServerTestCase):
    def test_listener_appears_in_health_endpoints(self):
        listener = SyslogListener(self.db_path, port=0, flush_interval=0.1)
        listener.start()
        try:
            status, data, _ = self.client().get("/api/health")
            self.assertEqual((status, data["checks"].get("syslog")), (200, "ok"))
            status, data, _ = self.client("analyst").get("/api/health/details")
            check = next(c for c in data["checks"] if c["name"] == "syslog")
            self.assertEqual(check["details"]["udp_port"], listener.udp_port)
        finally:
            listener.stop()
        status, data, _ = self.client().get("/api/health")
        self.assertNotIn("syslog", data["checks"])


# --- Shipper -------------------------------------------------------------------------

class FakeIngest:
    """Records ingest requests and answers with a scripted list of statuses (last one repeats)."""

    def __init__(self, statuses=(201,)):
        self.statuses, self.requests = list(statuses), []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                fake.requests.append({"path": urlparse(self.path).path,
                                      "query": {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()},
                                      "auth": self.headers.get("Authorization"), "body": body})
                status = fake.statuses.pop(0) if len(fake.statuses) > 1 else fake.statuses[0]
                lines = body.count(b"\n")
                payload = json.dumps({"accepted": lines if status < 300 else 0,
                                      "rejected": 0 if status < 300 else lines}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ShipperTests(unittest.TestCase):
    TOKEN = "wp_test-token-value-0123456789"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.log = self.dir / "auth.log"
        self.state = self.dir / "state" / "positions.json"
        self.sleeps = []
        self.fakes = []

    def tearDown(self):
        for fake in self.fakes:
            fake.close()
        self.tmp.cleanup()

    def fake(self, statuses=(201,)):
        fake = FakeIngest(statuses)
        self.fakes.append(fake)
        return fake

    def make(self, url, from_start=True):
        tail = shipper.Shipper(url, self.TOKEN, [(str(self.log), "authlog", "box-auth")], self.state,
                               from_start=from_start, sleep=self.sleeps.append)
        self.addCleanup(tail.close)
        return tail

    def append(self, text, path=None):
        with open(path or self.log, "ab") as handle:
            handle.write(text.encode())

    def test_ships_complete_lines_and_resumes_from_position_file(self):
        fake = self.fake()
        self.append("line 1\nline 2\n\nline 3\npartial")
        self.assertEqual(self.make(fake.url).ship_once(), 3)
        request = fake.requests[0]
        self.assertEqual(request["path"], "/api/ingest/upload")
        self.assertEqual(request["query"], {"format": "authlog", "source": "box-auth"})
        self.assertEqual(request["auth"], f"Bearer {self.TOKEN}")
        self.assertEqual(request["body"], b"line 1\nline 2\nline 3\n")
        saved = json.loads(self.state.read_text())[str(self.log)]
        self.assertEqual(saved, {"inode": os.stat(self.log).st_ino, "offset": len(b"line 1\nline 2\n\nline 3\n")})

        self.append(" done\nline 4\n")
        restarted = self.make(fake.url)  # a new process reads the position file
        self.assertEqual(restarted.ship_once(), 2)
        self.assertEqual(fake.requests[1]["body"], b"partial done\nline 4\n")
        self.assertEqual(restarted.ship_once(), 0)
        self.assertEqual(len(fake.requests), 2)

    def test_batches_respect_line_limit(self):
        fake = self.fake()
        self.append("".join(f"l{i}\n" for i in range(7)))
        tail = self.make(fake.url)
        tail.batch_lines = 3
        self.assertEqual(tail.ship_once(), 7)
        self.assertEqual([r["body"].count(b"\n") for r in fake.requests], [3, 3, 1])

    def test_backoff_retries_same_batch_until_accepted(self):
        fake = self.fake([503, 500, 201])
        self.append("a\nb\n")
        tail = self.make(fake.url)
        self.assertEqual(tail.ship_once(), 2)
        self.assertEqual(len(fake.requests), 3)
        self.assertTrue(all(r["body"] == b"a\nb\n" for r in fake.requests))
        self.assertEqual(len(self.sleeps), 2)
        self.assertLess(self.sleeps[0], self.sleeps[1] + 1)  # doubles, with jitter
        self.assertEqual(tail.stats["retries"], 2)

    def test_network_failure_keeps_position_and_gives_up_after_max_retries(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            dead_url = f"http://127.0.0.1:{s.getsockname()[1]}"
        self.append("a\n")
        with self.assertRaises(shipper.FatalError):
            self.make(dead_url).ship_once(max_retries=2)
        self.assertEqual(len(self.sleeps), 2)
        self.assertFalse(self.state.exists())  # nothing committed; the batch is resent next time

    def test_invalid_batch_is_skipped_so_the_file_keeps_moving(self):
        fake = self.fake([422, 201])
        self.append("garbage\n")
        tail = self.make(fake.url)
        tail.ship_once()
        self.append("good\n")
        tail.ship_once()
        self.assertEqual([r["body"] for r in fake.requests], [b"garbage\n", b"good\n"])
        self.assertEqual(tail.stats["skipped_batches"], 1)

    def test_follows_rotation_after_draining_old_file(self):
        fake = self.fake()
        self.append("old 1\n")
        tail = self.make(fake.url)
        tail.ship_once()
        self.append("old 2\n")
        os.rename(self.log, self.dir / "auth.log.1")
        self.append("old 3\n", self.dir / "auth.log.1")  # writer still has the old file open
        self.append("new 1\n")
        tail.ship_once()
        self.assertEqual(b"".join(r["body"] for r in fake.requests), b"old 1\nold 2\nold 3\nnew 1\n")
        self.assertEqual(json.loads(self.state.read_text())[str(self.log)]["inode"], os.stat(self.log).st_ino)

    def test_handles_truncation_in_place(self):
        fake = self.fake()
        self.append("first line that is long\n")
        tail = self.make(fake.url)
        tail.ship_once()
        self.log.write_bytes(b"")  # copytruncate
        tail.ship_once()
        self.append("after\n")
        tail.ship_once()
        self.assertEqual([r["body"] for r in fake.requests], [b"first line that is long\n", b"after\n"])
        self.assertEqual(json.loads(self.state.read_text())[str(self.log)]["offset"], 6)

    def test_new_file_starts_at_end_unless_from_start(self):
        fake = self.fake()
        self.append("history\n")
        tail = self.make(fake.url, from_start=False)
        self.assertEqual(tail.ship_once(), 0)
        self.append("live\n")
        tail.ship_once()
        self.assertEqual([r["body"] for r in fake.requests], [b"live\n"])

    def test_missing_file_is_picked_up_when_it_appears(self):
        fake = self.fake()
        tail = self.make(fake.url, from_start=False)
        self.assertEqual(tail.ship_once(), 0)
        self.append("appeared\n")
        self.assertEqual(tail.ship_once(), 1)

    def test_url_and_token_safety(self):
        with self.assertRaises(shipper.FatalError):
            shipper.check_url("http://siem.example.com", allow_insecure=False)
        shipper.check_url("http://127.0.0.1:8080", allow_insecure=False)
        shipper.check_url("https://siem.example.com", allow_insecure=False)
        shipper.check_url("http://siem.example.com", allow_insecure=True)
        old = os.environ.pop("WATCHPOST_TOKEN", None)
        try:
            self.assertEqual(shipper.main(["--url", "http://127.0.0.1:1", "--file", str(self.log), "--once"]), 2)
        finally:
            if old is not None:
                os.environ["WATCHPOST_TOKEN"] = old

    def test_file_spec_parsing(self):
        self.assertEqual(shipper.parse_file_spec("/var/log/auth.log", hostname="box"),
                         ("/var/log/auth.log", "auto", "box-auth"))
        self.assertEqual(shipper.parse_file_spec("/var/log/nginx/access.log:nginx:web 01", hostname="box"),
                         ("/var/log/nginx/access.log", "nginx", "web-01"))


class ShipperEndToEndTests(ServerTestCase):
    def test_shipper_cli_delivers_auth_log_to_a_real_server(self):
        admin = self.client("admin")
        status, token, _ = admin.post("/api/tokens", {"name": "shipper"})
        self.assertEqual(status, 201)
        log_path = Path(self.tmp.name) / "auth.log"
        log_path.write_text(
            "Sep 28 10:00:01 web01 sshd[10]: Failed password for root from 203.0.113.50 port 5000 ssh2\n"
            "Sep 28 10:00:05 web01 sshd[10]: Accepted password for alice from 198.51.100.20 port 5001 ssh2\n")
        token_file = Path(self.tmp.name) / "token"
        token_file.write_text(token["token"] + "\n")
        state = Path(self.tmp.name) / "pos.json"
        code = shipper.main(["--url", self.base, "--file", f"{log_path}:authlog:web01-auth", "--state", str(state),
                             "--token-file", str(token_file), "--from-start", "--year", "2026", "--once",
                             "--max-retries", "0"])
        self.assertEqual(code, 0)
        status, data, _ = self.client("analyst").get("/api/events?source=web01-auth")
        self.assertEqual(data["total"], 2)
        self.assertEqual({e["event_type"] for e in data["events"]}, {"auth_failure", "auth_success"})
        self.assertEqual(json.loads(state.read_text())[str(log_path)]["offset"], log_path.stat().st_size)


if __name__ == "__main__":
    unittest.main()
