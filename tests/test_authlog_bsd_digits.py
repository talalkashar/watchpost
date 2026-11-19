"""Authlog BSD day, clock, firewall port, and OpenVPN address accept ASCII digits only.

Sep 28 12:00:00 stays day 28. A day of ２８ is not rewritten to day 28. A clock
of １２:００:００ is the existing syslog-format error, not an HTTP 500 from
strptime. int("２８") is 28, and int is not called for those two refusals.
The format error is raised before strptime. DPT=443 stores port 443.
DPT=４４３ does not store port 443.
OpenVPN 203.0.113.10 stays vpn_login. A fullwidth quad is not stored as
that address. The patterns are [0-9], not \\d.
"""

import inspect
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import normalize
from watchpost.db import connect
from watchpost.normalize import EventError, normalize_authlog_line

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
LIVE = Path(__file__).resolve().parent.parent / "docs" / "LIVE_INGEST.md"
NOW = datetime(2026, 9, 28, 13, 0, tzinfo=timezone.utc)
FORMAT_ERROR = "line is not in syslog format"
DAY = "\uff12\uff18"  # ２８
CLOCK = "\uff11\uff12:\uff10\uff10:\uff10\uff10"  # １２:００:００
PORT = "\uff14\uff14\uff13"  # ４４３
QUAD = "\uff12\uff10\uff13.\uff10.\uff11\uff11\uff13.\uff11\uff10"  # ２０３.０.１１３.１０
ASCII_IP = "203.0.113.10"
GOOD = (f"Sep 28 12:00:00 web01 sshd[1]: Failed password for alice "
        f"from {ASCII_IP} port 22 ssh2")
WIDE_DAY = GOOD.replace("Sep 28 ", f"Sep {DAY} ", 1)
WIDE_CLOCK = GOOD.replace("12:00:00", CLOCK, 1)
FW = ("Sep 28 12:00:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= "
      "SRC=203.0.113.9 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40000 DPT=443 WINDOW=1024")
WIDE_FW = FW.replace("DPT=443", f"DPT={PORT}", 1)
VPN = (f"Sep 28 12:00:00 vpn01 openvpn[8]: {ASCII_IP}:51234 [erin] "
       "Peer Connection Initiated with x")
WIDE_VPN = VPN.replace(ASCII_IP, QUAD, 1)
DOC_LINES = (
    "The BSD day and clock are ASCII digits.",
    "`Sep 28 12:00:00` stays day 28.",
    "A day of `２８` is `line is not in syslog format` and is not rewritten to day 28.",
    "A clock of `１２:００:００` is that same refusal and is not an HTTP 500.",
    "`DPT=443` stores port 443.",
    "`DPT=４４３` does not store port 443.",
    "OpenVPN `203.0.113.10` stays `vpn_login`.",
    "A fullwidth quad is not stored as that address.",
)


class AuthlogBsdDigitTests(unittest.TestCase):
    def test_ascii_day_stays_day_28(self):
        event = normalize_authlog_line(GOOD, "auth", now=NOW)
        self.assertEqual(event["ts"], "2026-09-28T12:00:00.000Z")
        self.assertEqual(event["event_type"], "auth_failure")
        self.assertEqual(event["user"], "alice")
        self.assertEqual(event["src_ip"], ASCII_IP)
        self.assertEqual(int(DAY), 28)
        self.assertEqual(int(PORT), 443)

    def test_fullwidth_day_and_clock_are_the_format_error(self):
        for line in (WIDE_DAY, WIDE_CLOCK):
            with self.subTest(line=line):
                with self.assertRaises(EventError) as caught:
                    normalize_authlog_line(line, "auth", now=NOW)
                self.assertEqual(str(caught.exception), FORMAT_ERROR)
        kept = normalize_authlog_line(GOOD, "auth", now=NOW)
        self.assertEqual(kept["ts"], "2026-09-28T12:00:00.000Z")
        self.assertNotIn(DAY, kept["ts"])
        self.assertNotIn(CLOCK, kept["ts"])

    def test_pattern_is_ascii_digits_and_int_and_strptime_are_not_called(self):
        pattern = normalize._SYSLOG_PREFIX.pattern
        bsd = pattern.split("(?P<bsd>")[1].split(")", 1)[0]
        self.assertIn("[0-9]{1,2}", bsd)
        self.assertIn("[0-9]{2}:[0-9]{2}:[0-9]{2}", bsd)
        self.assertNotIn("\\d", bsd)
        source = inspect.getsource(normalize_authlog_line)
        match_at = source.index("_SYSLOG_PREFIX.match")
        int_at = source.index("int(")
        stamp_at = source.index("strptime(")
        self.assertLess(match_at, int_at)
        self.assertLess(int_at, stamp_at)
        # The format error returns before either call. The stamp call stays after int.
        self.assertLess(source.index(FORMAT_ERROR), int_at)
        calls = []
        real_int = int

        def spy_int(value, *args):
            calls.append(value)
            return real_int(value, *args)

        normalize.int = spy_int
        try:
            for line in (WIDE_DAY, WIDE_CLOCK):
                with self.assertRaises(EventError) as caught:
                    normalize_authlog_line(line, "auth", now=NOW)
                self.assertEqual(str(caught.exception), FORMAT_ERROR)
            self.assertEqual(calls, [])
        finally:
            del normalize.int
        event = normalize_authlog_line(GOOD, "auth", now=NOW)
        self.assertEqual(event["ts"], "2026-09-28T12:00:00.000Z")

    def test_firewall_port_and_openvpn_address_stay_ascii(self):
        fw = next(item for item in normalize._SSH_PATTERNS if item[1] == "firewall")[0]
        vpn = next(item for item in normalize._SSH_PATTERNS if item[1] == "vpn_login")[0]
        self.assertIn("DPT=(?P<dpt>[0-9]+)", fw.pattern)
        self.assertNotIn("\\d", fw.pattern)
        self.assertIn("(?P<ip>[0-9]{1,3}(?:\\.[0-9]{1,3}){3})", vpn.pattern)
        self.assertNotIn("\\d", vpn.pattern)
        blocked = normalize_authlog_line(FW, "fw", now=NOW)
        self.assertEqual((blocked["event_type"], blocked["dest_port"], blocked["src_ip"]),
                         ("fw_deny", 443, "203.0.113.9"))
        wide_port = normalize_authlog_line(WIDE_FW, "fw", now=NOW)
        self.assertEqual(wide_port["event_type"], "fw_deny")
        self.assertIsNone(wide_port["dest_port"])
        self.assertNotEqual(wide_port["dest_port"], 443)
        self.assertEqual(wide_port["src_ip"], "203.0.113.9")
        session = normalize_authlog_line(VPN, "vpn", now=NOW)
        self.assertEqual((session["event_type"], session["user"], session["src_ip"]),
                         ("vpn_login", "erin", ASCII_IP))
        wide_quad = normalize_authlog_line(WIDE_VPN, "vpn", now=NOW)
        self.assertNotEqual(wide_quad["event_type"], "vpn_login")
        self.assertIsNone(wide_quad["src_ip"])
        self.assertNotEqual(wide_quad["src_ip"], ASCII_IP)
        self.assertNotIn(ASCII_IP, wide_quad["message"])

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text(), LIVE.read_text()):
            for line in DOC_LINES:
                self.assertIn(line, text)


class AuthlogBsdDigitApiTests(ServerTestCase):
    def _upload(self, client, line):
        return client.post(
            "/api/ingest/upload?format=authlog&source=auth&synthetic=true",
            raw=(line + "\n").encode(),
            headers={"Content-Type": "text/plain"})

    def test_fullwidth_day_and_clock_store_nothing_and_are_not_http_500(self):
        client = self.client("analyst")
        for line in (WIDE_DAY, WIDE_CLOCK):
            status, body, headers = self._upload(client, line)
            self.assertEqual(status, 422, body)
            self.assertNotEqual(status, 500)
            self.assertEqual(body["accepted"], 0)
            self.assertEqual(body["rejected"], 1)
            self.assertEqual(body["rejections"][0]["reason"], FORMAT_ERROR)
            self.assertEqual(headers["Cache-Control"], "no-store")

        status, page, _ = client.get("/api/events")
        self.assertEqual(status, 200, page)
        self.assertEqual(page["total"], 0)
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

        status, stored, headers = self._upload(client, GOOD)
        self.assertEqual(status, 201, stored)
        self.assertEqual(stored["accepted"], 1)
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, page, _ = client.get("/api/events")
        self.assertEqual(page["total"], 1)
        event = page["events"][0]
        self.assertEqual(event["ts"], "2026-09-28T12:00:00.000Z")
        self.assertEqual(event["event_type"], "auth_failure")
        self.assertEqual(event["user"], "alice")
        self.assertEqual(event["src_ip"], ASCII_IP)
        self.assertEqual(event["synthetic"], 1)
        self.assertTrue(event["source"].startswith("demo:"))

        status, again, _ = self._upload(client, WIDE_CLOCK)
        self.assertEqual(status, 422, again)
        self.assertEqual(again["rejections"][0]["reason"], FORMAT_ERROR)
        status, still, _ = client.get("/api/events")
        self.assertEqual(still["total"], 1)
        self.assertEqual(still["events"][0]["ts"], "2026-09-28T12:00:00.000Z")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def test_fullwidth_port_and_address_are_not_the_ascii_values(self):
        client = self.client("analyst")
        status, body, _ = self._upload(client, WIDE_FW)
        self.assertEqual(status, 201, body)
        self.assertNotEqual(status, 500)
        status, page, _ = client.get("/api/events")
        self.assertEqual(page["total"], 1)
        wide = page["events"][0]
        self.assertEqual(wide["event_type"], "fw_deny")
        self.assertIsNone(wide["dest_port"])
        self.assertNotEqual(wide["dest_port"], 443)
        self.assertEqual(wide["src_ip"], "203.0.113.9")

        status, body, _ = self._upload(client, WIDE_VPN)
        self.assertEqual(status, 201, body)
        status, page, _ = client.get("/api/events")
        self.assertEqual(page["total"], 2)
        quad = next(row for row in page["events"] if QUAD.split(".")[0] in row["message"])
        self.assertNotEqual(quad["event_type"], "vpn_login")
        self.assertIsNone(quad["src_ip"])
        self.assertNotEqual(quad["src_ip"], ASCII_IP)

        status, body, _ = self._upload(client, FW)
        self.assertEqual(status, 201, body)
        status, page, _ = client.get("/api/events")
        blocked = next(row for row in page["events"] if row["dest_port"] == 443)
        self.assertEqual(blocked["event_type"], "fw_deny")
        self.assertEqual(blocked["dest_ip"], "192.0.2.10")

        status, body, _ = self._upload(client, VPN)
        self.assertEqual(status, 201, body)
        status, page, _ = client.get("/api/events")
        session = next(row for row in page["events"] if row["event_type"] == "vpn_login")
        self.assertEqual(session["src_ip"], ASCII_IP)
        self.assertEqual(session["user"], "erin")
        self.assertEqual(session["synthetic"], 1)
        self.assertTrue(session["source"].startswith("demo:"))
        ports = [row["dest_port"] for row in page["events"]]
        self.assertEqual(ports.count(443), 1)
