"""Syslog PRI accepts ASCII digits only.

<13> stays priority 13, so an unlabeled line stays severity low. <4> is
priority 4 and that unlabeled line is medium. <４> is not priority 4 and
does not change that severity. int("４") is 4, and int is not called for
the fullwidth frame. The pattern is [0-9], not \\d. The <= 191 check stays
for ASCII digits. A normal RFC 5424 or RFC 3164 frame still parses.
"""

import inspect
import unittest
from datetime import datetime, timezone
from pathlib import Path

from watchpost import syslog_listener
from watchpost.syslog_listener import (
    PRI_SEVERITY, _PRI, frame_to_event, parse_frame,
)

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
LIVE = Path(__file__).resolve().parent.parent / "docs" / "LIVE_INGEST.md"
NOW = datetime(2026, 9, 28, 10, 0, tzinfo=timezone.utc)
FULLWIDTH_FOUR = "\uff14"  # ４
NOTICE = "<13>Sep 28 10:00:03 web01 app: plain notice"
WARN = "<4>Sep 28 10:00:03 web01 app: disk warning"
WIDE = f"<{FULLWIDTH_FOUR}>Sep 28 10:00:03 web01 app: disk warning"
RFC5424 = ("<38>1 2026-09-28T10:00:01.12+02:00 web01 sshd 812 - - "
           "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2")
RFC3164 = ("<86>Sep 28 10:00:02 bastion01 sshd[99]: Accepted publickey for alice "
           "from 198.51.100.7 port 22 ssh2")


class SyslogPriDigitTests(unittest.TestCase):
    def test_ascii_pri_stays_and_sets_unlabeled_severity(self):
        notice = parse_frame(NOTICE)
        self.assertEqual((notice["pri"], notice["level"], notice["format"]), (13, 5, "rfc3164"))
        event = frame_to_event(NOTICE, now=NOW)
        self.assertEqual((event["event_type"], event["severity"], event["host"]),
                         ("syslog", "low", "web01"))
        self.assertEqual(event["message"], "app: plain notice")
        warning = parse_frame(WARN)
        self.assertEqual((warning["pri"], warning["level"]), (4, 4))
        event = frame_to_event(WARN, now=NOW)
        self.assertEqual(event["severity"], PRI_SEVERITY[4])
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(int(FULLWIDTH_FOUR), 4)

    def test_fullwidth_pri_is_not_priority_4(self):
        parsed = parse_frame(WIDE)
        self.assertEqual(parsed["pri"], 13)
        self.assertNotEqual(parsed["pri"], 4)
        self.assertEqual(parsed["level"], 5)
        self.assertEqual(parsed["format"], "raw")
        event = frame_to_event(WIDE, peer_ip="192.0.2.9", now=NOW)
        self.assertEqual(event["event_type"], "syslog")
        self.assertEqual(event["severity"], "low")
        self.assertNotEqual(event["severity"], PRI_SEVERITY[4])
        self.assertNotEqual(event["severity"], "medium")
        self.assertIn(FULLWIDTH_FOUR, event["message"])
        later = frame_to_event(NOTICE, now=NOW)
        self.assertEqual((later["severity"], later["message"]), ("low", "app: plain notice"))
        warning = frame_to_event(WARN, now=NOW)
        self.assertEqual(warning["severity"], "medium")

    def test_pri_above_191_stays_the_default(self):
        kept = parse_frame("<191>Sep 28 10:00:03 h1 app: edge")
        self.assertEqual((kept["pri"], kept["level"]), (191, 7))
        self.assertEqual(frame_to_event("<191>Sep 28 10:00:03 h1 app: edge", now=NOW)["severity"], "info")
        dropped = parse_frame("<192>Sep 28 10:00:03 h1 app: over")
        self.assertEqual(dropped["pri"], 13)
        self.assertEqual(frame_to_event("<192>Sep 28 10:00:03 h1 app: over", now=NOW)["severity"], "low")

    def test_pattern_is_ascii_digits_and_int_is_not_called(self):
        self.assertIn("[0-9]{1,3}", _PRI.pattern)
        self.assertNotIn(r"\d", _PRI.pattern)
        source = inspect.getsource(parse_frame)
        self.assertLess(source.index("_PRI.match"), source.index("int("))
        self.assertIn("<= 191", source)
        calls = []
        real = int

        def spy(value, *args):
            calls.append(value)
            return real(value, *args)

        syslog_listener.int = spy
        try:
            parsed = parse_frame(WIDE)
            self.assertEqual(calls, [])
            self.assertEqual(parsed["pri"], 13)
            event = frame_to_event(WIDE, now=NOW)
            self.assertEqual(calls, [])
            self.assertEqual(event["severity"], "low")
        finally:
            del syslog_listener.int
        self.assertEqual(parse_frame(NOTICE)["pri"], 13)
        self.assertEqual(frame_to_event(WARN, now=NOW)["severity"], "medium")

    def test_rfc5424_and_rfc3164_still_parse(self):
        failure = frame_to_event(RFC5424, now=NOW)
        self.assertEqual((failure["host"], failure["event_type"], failure["user"], failure["src_ip"]),
                         ("web01", "auth_failure", "admin", "203.0.113.9"))
        self.assertEqual(failure["ts"], "2026-09-28T08:00:01.120Z")
        success = frame_to_event(RFC3164, now=NOW)
        self.assertEqual((success["host"], success["event_type"], success["user"]),
                         ("bastion01", "auth_success", "alice"))
        self.assertEqual(parse_frame(RFC5424)["format"], "rfc5424")
        self.assertEqual(parse_frame(RFC3164)["format"], "rfc3164")

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("The PRI value is one to three ASCII digits", text)
            self.assertIn("`<13>` stays priority 13", text)
            self.assertIn("`<４>` is not priority 4", text)
            self.assertIn("is not `medium`", text)
            self.assertIn("A normal RFC 5424 frame and a normal RFC 3164 frame still parse", text)
        live = LIVE.read_text()
        self.assertIn("PRI is one to three ASCII digits", live)
        self.assertIn("`<13>` stays priority 13", live)
        self.assertIn("`<４>` is not priority 4", live)
