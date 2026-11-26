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
from watchpost.diagnostics import redact
from watchpost.health import run_health_checks
from watchpost.normalize import MAX_LEN, EventError, parse_payload
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

    def test_generic_message_redacts_before_the_length_cut(self):
        secret = "SUPERSECRET"
        value = 'a\\"' + secret + ("p" * 40)
        opener = '{"password": "'
        prefix = "nginx: "
        pad = MAX_LEN["message"] - len(prefix) - len(opener) - len('a\\"') - len(secret)
        body = ("n" * pad) + opener + value + '"}'
        combined = prefix + body
        self.assertIn(secret, redact(combined[:MAX_LEN["message"]]))
        event = frame_to_event(f"<11>Sep 28 10:00:03 web01 {combined}")
        self.assertNotIn(secret, event["message"])
        self.assertNotIn(secret, event["raw"])
        self.assertLessEqual(len(event["message"]), MAX_LEN["message"])
        self.assertIn("[REDACTED]", event["message"])

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

    def test_nginx_access_line_gets_web_event_type(self):
        scan = frame_to_event('<190>Sep 28 10:00:02 web01 nginx: 203.0.113.5 - - [28/Sep/2026:10:00:02 +0000] '
                              '"GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"', "127.0.0.1")
        self.assertEqual((scan["event_type"], scan["host"], scan["src_ip"], scan["source"]),
                         ("web_scan", "web01", "203.0.113.5", "syslog"))
        self.assertEqual(scan["ts"], "2026-09-28T10:00:02.000Z")
        self.assertTrue(scan["raw"].startswith("<190>"))
        ok = frame_to_event('<190>1 2026-09-28T10:00:03Z web01 nginx - - - 198.51.100.7 - - '
                            '[28/Sep/2026:10:00:03 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"')
        self.assertEqual((ok["event_type"], ok["bytes"]), ("web_request", 612))
        error = frame_to_event('<187>Sep 28 10:00:04 web01 nginx: 198.51.100.7 - - [28/Sep/2026:10:00:04 +0000] '
                               '"POST /api HTTP/1.1" 502 0 "-" "-"')
        self.assertEqual(error["event_type"], "web_error")

    def test_firewall_deny_line_gets_fw_event_type(self):
        event = frame_to_event("<4>Sep 28 10:00:01 fw01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00 "
                               "SRC=203.0.113.9 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40000 DPT=22 WINDOW=1024")
        self.assertEqual((event["event_type"], event["host"], event["src_ip"], event["dest_ip"], event["dest_port"]),
                         ("fw_deny", "fw01", "203.0.113.9", "192.0.2.10", 22))
        allow = frame_to_event("<6>1 2026-09-28T10:00:05Z fw01 kernel - - - [UFW ALLOW] IN=eth0 OUT= "
                               "SRC=198.51.100.3 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40001 DPT=443")
        self.assertEqual(allow["event_type"], "fw_allow")

    def test_fortigate_without_reliable_zone_keeps_the_envelope_time(self):
        frame = ('<189>1 2026-09-28T08:15:00-04:00 relay FortiGate - - - date=2026-09-27 time=23:58:00 '
                 'devname="FG100" logid="13" type="traffic" action="deny" srcip=192.0.2.2 dstip=192.0.2.3')
        for zone in ("", ' tz="EST"', ' tz="+1260"', ' tz="+2400"', ' tz="-0000"'):
            with self.subTest(zone=zone):
                event = frame_to_event(frame + zone)
                self.assertEqual((event["host"], event["event_type"], event["ts"]),
                                 ("FG100", "fw_deny", "2026-09-28T12:15:00.000Z"))

    def test_relayed_cisco_id_in_message_reaches_live_and_upload(self):
        for device in ("ASA", "FTD"):
            frame = (f"<164>1 2026-09-28T11:00:00Z asa01 - - - - %{device}-4-106023: Deny tcp "
                     "src outside:203.0.113.9/40000 dst inside:192.0.2.10/3389")
            uploaded, rejected = parse_payload(frame, "auto", "upload")
            self.assertEqual(rejected, [])
            self.assertEqual(len(uploaded), 1)
            for path, event in (("live", frame_to_event(frame)), ("upload", uploaded[0])):
                with self.subTest(device=device, path=path):
                    self.assertEqual((event["event_type"], event["src_ip"], event["dest_ip"], event["dest_port"]),
                                     ("fw_deny", "203.0.113.9", "192.0.2.10", 3389))

    def test_fortigate_login_respects_syslog_sender_on_live_and_upload(self):
        payload = ('date=2026-09-28 time=10:00:00 tz="+0000" devname="FG100" logid="0100032002" '
                   'type="event" action="login" status="failed" user="admin" srcip=192.0.2.5')
        for app, prefix in (("reporter", "archived example: "), ("reporter", ""), ("syslog", ""),
                            ("-", "archived example: "), ("-", ""), ("FortiGate", "")):
            frame = f"<13>1 2026-09-28T11:00:00Z app01 {app} - - - {prefix}{payload}"
            uploaded, rejected = parse_payload(frame, "auto", "upload")
            self.assertEqual(rejected, [])
            self.assertEqual(len(uploaded), 1)
            for generic, event in (("syslog", frame_to_event(frame)), ("other", uploaded[0])):
                with self.subTest(app=app, prefix=prefix, generic=generic):
                    expected = (generic, "app01", "2026-09-28T11:00:00.000Z", None, None)
                    if app in ("-", "FortiGate") and not prefix:
                        expected = ("auth_failure", "FG100", "2026-09-28T10:00:00.000Z", "admin", "192.0.2.5")
                    self.assertEqual((event["event_type"], event["host"], event["ts"], event["user"], event["src_ip"]),
                                     expected)

    def test_ordinary_application_quoting_an_asa_message_stays_generic(self):
        payload = "%ASA-4-106023: Deny tcp src outside:192.0.2.5/1234 dst inside:192.0.2.6/443"
        for prefix in ("", "logged example: "):
            frame = "<13>1 2026-09-28T10:00:00Z relay reporter - - - " + prefix + payload
            self.assertEqual(frame_to_event(frame)["event_type"], "syslog")

    def test_firewall_appliance_frames(self):
        # FortiGate sends no syslog header: the device name and time come from its own fields.
        deny = frame_to_event('<189>date=2026-09-28 time=12:00:01 devname="FG100" logid="0000000013" type="traffic" '
                              'subtype="forward" tz="+0200" srcip=203.0.113.9 srcport=40000 dstip=192.0.2.10 '
                              'dstport=22 action="deny" sentbyte=0 rcvdbyte=0', "192.0.2.254")
        self.assertEqual((deny["event_type"], deny["host"], deny["ts"], deny["src_ip"], deny["dest_port"]),
                         ("fw_deny", "FG100", "2026-09-28T10:00:01.000Z", "203.0.113.9", 22))
        closed = frame_to_event('<189>date=2026-09-28 time=12:00:02 devname="FG100" logid="0000000013" '
                                'type="traffic" tz="+0000" srcip=10.0.3.15 dstip=198.51.100.99 dstport=443 action="close" '
                                'user="carol" sentbyte=1800000000 rcvdbyte=4000', "192.0.2.254")
        self.assertEqual((closed["event_type"], closed["user"], closed["bytes"], closed["ts"]),
                         ("fw_allow", "carol", 1800000000, "2026-09-28T12:00:02.000Z"))
        login = frame_to_event('<185>date=2026-09-28 time=12:00:03 devname="FG100" logid="0100032002" type="event" '
                               'subtype="system" logdesc="Admin login failed" user="admin" srcip=203.0.113.9 '
                               'action="login" status="failed"', "192.0.2.254")
        self.assertEqual((login["event_type"], login["user"], login["src_ip"]), ("auth_failure", "admin", "203.0.113.9"))
        # Palo Alto: the default comma-separated TRAFFIC log, with a quoted rule name that contains a comma.
        allow = frame_to_event('<14>Sep 28 10:00:13 pa01 1,2026/09/28 10:00:13,007000001234,TRAFFIC,end,2049,'
                               '2026/09/28 10:00:13,10.0.3.15,198.51.100.99,192.0.2.1,198.51.100.99,"allow, web",'
                               'corp\\dave,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-fwd,'
                               '2026/09/28 10:00:13,4321,1,52000,443,61000,443,0x400053,tcp,allow,1250000900,'
                               '1250000000,900,9000,2026/09/28 09:50:00,600,any')
        self.assertEqual((allow["event_type"], allow["host"], allow["user"], allow["dest_port"], allow["bytes"]),
                         ("fw_allow", "pa01", "corp\\dave", 443, 1250000000))
        drop = frame_to_event("<14>Sep 28 10:00:12 pa01 1,2026/09/28 10:00:12,007000001234,TRAFFIC,drop,2049,"
                              "2026/09/28 10:00:12,203.0.113.9,192.0.2.10,0.0.0.0,0.0.0.0,block-inbound,,,"
                              "not-applicable,vsys1,untrust,trust,ethernet1/1,,log-fwd,2026/09/28 10:00:12,0,1,"
                              "40003,8080,0,0,0x0,tcp,drop,74,74,0,1,2026/09/28 10:00:11,0,any")
        self.assertEqual((drop["event_type"], drop["src_ip"], drop["dest_port"]), ("fw_deny", "203.0.113.9", 8080))
        # Cisco ASA: the message ID is the syslog tag, with or without a header in front of it.
        for frame, host in (('<164>Sep 28 10:00:04 asa01 %ASA-4-106023: Deny tcp src outside:203.0.113.9/40000 dst '
                             'inside:192.0.2.10/3389 by access-group "outside_in" [0x0, 0x0]', "asa01"),
                            ('<164>%ASA-4-106023: Deny tcp src outside:203.0.113.9/40000 dst inside:192.0.2.10/3389 '
                             'by access-group "outside_in" [0x0, 0x0]', "192.0.2.254")):
            asa = frame_to_event(frame, "192.0.2.254")
            self.assertEqual((asa["event_type"], asa["host"], asa["dest_port"]), ("fw_deny", host, 3389))

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
        # The flush commits rows before it bumps the counter, so wait for the counter too.
        check = wait_for(lambda: (c := self.health()["syslog"])["details"]["events_ingested"] == 3 and c)
        self.assertTrue(check, "events_ingested never reached 3")
        self.assertEqual(check["status"], "ok")

    def test_nginx_and_firewall_frames_land_with_specific_types(self):
        listener = self.listener()
        self.assertTrue(listener.start())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(b'<190>Sep 28 10:00:02 web01 nginx: 203.0.113.5 - - [28/Sep/2026:10:00:02 +0000] '
                       b'"GET /wp-login.php HTTP/1.1" 404 153 "-" "curl/8.0"', ("127.0.0.1", listener.udp_port))
        with socket.create_connection(("127.0.0.1", listener.tcp_port)) as tcp:
            tcp.sendall(b"<4>Sep 28 10:00:01 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 "
                        b"DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024\n")
        events = wait_for(lambda: len(self.rows()) == 2 and self.rows())
        self.assertTrue(events, "frames did not reach the database")
        by_host = {e["host"]: e for e in events}
        self.assertEqual((by_host["web01"]["event_type"], by_host["web01"]["src_ip"]), ("web_scan", "203.0.113.5"))
        self.assertEqual((by_host["fw01"]["event_type"], by_host["fw01"]["dest_port"]), ("fw_deny", 3389))
        self.assertNotIn("syslog", {e["event_type"] for e in events})

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
                if 300 <= status < 400:
                    self.send_header("Location", "/moved")
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

    def test_redirect_preserves_unsent_position(self):
        redirect = self.fake((302,))
        self.append("old line\n")
        tail = self.make(redirect.url, from_start=False)
        self.append("new line\n")
        with self.assertRaisesRegex(shipper.FatalError, "configure the final endpoint"):
            tail.ship_once(max_retries=0)
        tail.close()
        self.assertEqual([r["body"] for r in redirect.requests], [b"new line\n"])

        endpoint = self.fake()
        restarted = self.make(endpoint.url, from_start=False)
        self.assertEqual(restarted.ship_once(), 1)
        self.assertEqual(self.make(endpoint.url, from_start=False).ship_once(), 0)
        self.assertEqual([r["body"] for r in endpoint.requests], [b"new line\n"])

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

    def test_shipper_cli_delivers_nginx_access_log_as_web_events(self):
        admin = self.client("admin")
        status, token, _ = admin.post("/api/tokens", {"name": "shipper"})
        self.assertEqual(status, 201)
        log_path = Path(self.tmp.name) / "access.log"
        log_path.write_text(
            '203.0.113.60 - - [28/Sep/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"\n'
            '198.51.100.21 - - [28/Sep/2026:10:00:02 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"\n')
        token_file = Path(self.tmp.name) / "token"
        token_file.write_text(token["token"] + "\n")
        for fmt in ("weblog", "auto"):
            source = f"web01-{fmt}"
            code = shipper.main(["--url", self.base, "--file", f"{log_path}:{fmt}:{source}",
                                 "--state", str(Path(self.tmp.name) / f"pos-{fmt}.json"),
                                 "--token-file", str(token_file), "--from-start", "--once", "--max-retries", "0"])
            self.assertEqual(code, 0)
            status, data, _ = self.client("analyst").get(f"/api/events?source={source}")
            self.assertEqual({e["event_type"] for e in data["events"]}, {"web_scan", "web_request"}, fmt)


if __name__ == "__main__":
    unittest.main()
