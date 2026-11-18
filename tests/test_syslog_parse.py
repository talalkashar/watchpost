"""RFC 3164/5424 parsing and RFC 6587 framing: malformed, oversize, and canary frames."""

import io
import unittest
from datetime import datetime, timezone

from watchpost.normalize import MAX_LEN, EventError
from watchpost.syslog_listener import frame_to_event, parse_frame, read_tcp_frame

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def frames(data, max_bytes=16 * 1024):
    stream = io.BufferedReader(io.BytesIO(data))
    out = []
    while True:
        frame = read_tcp_frame(stream, max_bytes=max_bytes)
        if frame is None:
            break
        out.append(frame)
    return out


class SyslogParseTests(unittest.TestCase):
    def test_rfc5424_non_numeric_procid_still_parses_auth_failure(self):
        frame = ("<38>1 2026-09-28T10:00:01.12+02:00 web01 sshd abc - - "
                 "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2")
        parsed = parse_frame(frame)
        self.assertEqual(parsed["procid"], "abc")
        self.assertEqual(parsed["format"], "rfc5424")
        event = frame_to_event(frame, now=NOW)
        self.assertEqual((event["event_type"], event["user"], event["src_ip"], event["ts"]),
                         ("auth_failure", "admin", "203.0.113.9", "2026-09-28T08:00:01.120Z"))

    def test_rfc3164_non_numeric_pid_still_parses_auth_success(self):
        frame = ("<86>Sep 28 10:00:02 bastion01 sshd[sshd]: Accepted publickey for alice "
                 "from 198.51.100.7 port 22 ssh2")
        self.assertEqual(parse_frame(frame)["procid"], "sshd")
        event = frame_to_event(frame, now=NOW)
        self.assertEqual((event["host"], event["event_type"], event["user"], event["ts"]),
                         ("bastion01", "auth_success", "alice", "2026-09-28T10:00:02.000Z"))

    def test_bsd_fraction_year_and_december_rollover(self):
        fraction = frame_to_event("<13>Sep 28 10:00:01.123 web01 app: hi", now=NOW)
        self.assertEqual((fraction["host"], fraction["ts"]), ("web01", "2026-09-28T10:00:01.123Z"))
        one_digit = frame_to_event("<13>Sep 28 10:00:01.5 web01 app: hi", now=NOW)
        self.assertEqual(one_digit["ts"], "2026-09-28T10:00:01.500Z")
        comma = frame_to_event("<13>Sep 28 10:00:01,5 web01 app: hi", now=NOW)
        self.assertEqual(comma["ts"], "2026-09-28T10:00:01.500Z")
        year = frame_to_event("<13>Sep 28 2024 10:00:01 web01 app: hi", now=NOW)
        self.assertEqual((year["host"], year["ts"]), ("web01", "2024-09-28T10:00:01.000Z"))
        rolled = frame_to_event("<13>Dec 28 10:00:01.5 web01 app: hi", now=NOW)
        self.assertEqual(rolled["ts"], "2025-12-28T10:00:01.500Z")
        classic = frame_to_event("<13>Dec 28 10:00:01 web01 app: hi", now=NOW)
        self.assertEqual(classic["ts"], "2025-12-28T10:00:01.000Z")

    def test_cisco_sequence_is_skipped_and_host_kept(self):
        frame = "<13>123: Sep 28 10:00:01 h %ASA-6-302013: Built"
        parsed = parse_frame(frame)
        self.assertEqual((parsed["format"], parsed["host"], parsed["ts"]), ("rfc3164", "h", "Sep 28 10:00:01"))
        event = frame_to_event(frame, now=NOW)
        self.assertEqual((event["host"], event["event_type"]), ("h", "syslog"))

    def test_bad_pri_is_consumed_and_defaults(self):
        for frame in ("<192>Sep 28 10:00:01 h app: m", "<999>Sep 28 10:00:01 h app: m",
                      "<>Sep 28 10:00:01 h app: m", "<99999>Sep 28 10:00:01 h app: m"):
            parsed = parse_frame(frame)
            self.assertEqual((parsed["format"], parsed["host"], parsed["pri"], parsed["level"]),
                             ("rfc3164", "h", 13, 5), frame)
            event = frame_to_event(frame, now=NOW)
            self.assertEqual((event["host"], event["severity"]), ("h", "low"), frame)
        raw = parse_frame("<not-pri>Sep 28 10:00:01 h app: m")
        self.assertEqual(raw["format"], "raw")
        self.assertIn("<not-pri>", raw["msg"])

    def test_leading_bom_and_whitespace_still_see_pri(self):
        for frame in ("\ufeff<13>Sep 28 10:00:01 web01 app: hi",
                      " \t<13>Sep 28 10:00:01 web01 app: hi"):
            parsed = parse_frame(frame)
            self.assertEqual((parsed["format"], parsed["host"], parsed["pri"]), ("rfc3164", "web01", 13), frame)

    def test_lenient_5424_keeps_header_when_structured_data_is_broken(self):
        unclosed = parse_frame('<165>1 2026-09-28T10:00:05Z web01 app - ID47 [ex@32473 iut="3"')
        self.assertEqual((unclosed["format"], unclosed["host"], unclosed["app"]), ("rfc5424", "web01", "app"))
        missing_space = parse_frame('<165>1 2026-09-28T10:00:05Z web01 app - ID47 [id@1 a="b"]tail')
        self.assertEqual((missing_space["format"], missing_space["host"], missing_space["msg"]),
                         ("rfc5424", "web01", "tail"))
        spaced = parse_frame('<165>1 2026-09-28T10:00:05Z web01 app - ID47 [id@1 a="b" ] tail')
        self.assertEqual(spaced["msg"], "tail")
        no_sd = parse_frame("<165>1 2026-09-28T10:00:05Z web01 app proc msgid hello there")
        self.assertEqual((no_sd["format"], no_sd["host"], no_sd["msg"]), ("rfc5424", "web01", "hello there"))
        garbage = parse_frame("1 hello there friend from home and more")
        self.assertEqual(garbage["format"], "raw")
        event = frame_to_event("1 hello there friend from home and more", peer_ip="192.0.2.9", now=NOW)
        self.assertEqual((event["event_type"], event["host"], event["severity"]), ("syslog", "192.0.2.9", "low"))

    def test_impossible_bsd_dates_are_event_errors(self):
        for frame in ("<13>Sep 32 10:00:01 h app: m", "<13>Xxx 28 10:00:01 h app: m",
                      "<13>Sep 28 25:00:01 h app: m"):
            with self.assertRaises(EventError) as caught:
                frame_to_event(frame, now=NOW)
            self.assertIn("unparseable timestamp", str(caught.exception))

    def test_future_iso_timestamp_is_still_rejected(self):
        with self.assertRaises(EventError) as caught:
            frame_to_event("<13>1 2126-09-28T10:00:05Z host app - - - from the future", now=NOW)
        self.assertIn("future", str(caught.exception))

    def test_oversize_frame_is_bounded(self):
        frame = "<13>Sep 28 10:00:01 h app: " + ("A" * 100000)
        event = frame_to_event(frame, now=NOW)
        self.assertEqual(event["host"], "h")
        self.assertLessEqual(len(event["message"]), MAX_LEN["message"])
        self.assertLessEqual(len(event["raw"]), MAX_LEN["raw"])
        parsed = parse_frame(frame)
        self.assertEqual(parsed["host"], "h")
        self.assertLess(len(parsed["msg"]), 16 * 1024)

    def test_bytes_and_non_strings_do_not_crash_the_parser(self):
        parsed = parse_frame(b"<13>Sep 28 10:00:01 h app: caf\xff")
        self.assertEqual(parsed["host"], "h")
        self.assertIn("caf", parsed["msg"])
        event = frame_to_event(b"<13>Sep 28 10:00:01 h app: caf\xff", now=NOW)
        self.assertEqual(event["host"], "h")
        self.assertEqual(parse_frame(None)["format"], "raw")
        self.assertEqual(parse_frame(None)["pri"], 13)
        self.assertEqual(parse_frame(123)["msg"], "")
        with self.assertRaises(EventError):
            frame_to_event(None)
        with self.assertRaises(EventError):
            frame_to_event(123)

    def test_empty_and_bare_pri_stay_generic_events(self):
        for frame in ("", "<13>"):
            event = frame_to_event(frame, now=NOW)
            self.assertEqual(event["event_type"], "syslog", frame)

    def test_double_space_day_and_pri_ends(self):
        parsed = parse_frame("<13>Sep  8 10:00:01 h app: m")
        self.assertEqual((parsed["format"], parsed["host"]), ("rfc3164", "h"))
        self.assertEqual(parse_frame("<0>Sep 28 10:00:01 h app: m")["level"], 0)
        self.assertEqual(frame_to_event("<0>Sep 28 10:00:01 h app: m", now=NOW)["severity"], "critical")
        self.assertEqual(parse_frame("<191>Sep 28 10:00:01 h app: m")["level"], 7)
        self.assertEqual(frame_to_event("<191>Sep 28 10:00:01 h app: m", now=NOW)["severity"], "info")

    def test_strict_5424_sd_bom_and_nil_still_win(self):
        parsed = parse_frame('<165>1 2026-09-28T10:00:05Z - app - ID47 [ex@32473 iut="3" x="a\\]b"] \ufeffHello')
        self.assertEqual((parsed["format"], parsed["host"], parsed["app"], parsed["msg"], parsed["facility"],
                          parsed["level"]), ("rfc5424", None, "app", "Hello", 20, 5))

    def test_known_auth_lines_still_classify(self):
        failure = frame_to_event("<38>1 2026-09-28T10:00:01.12+02:00 web01 sshd 812 - - "
                                 "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2")
        self.assertEqual((failure["host"], failure["event_type"], failure["ts"]),
                         ("web01", "auth_failure", "2026-09-28T08:00:01.120Z"))
        success = frame_to_event("<86>Sep 28 10:00:02 bastion01 sshd[99]: Accepted publickey for alice "
                                 "from 198.51.100.7 port 22 ssh2", now=NOW)
        self.assertEqual((success["host"], success["event_type"], success["user"]),
                         ("bastion01", "auth_success", "alice"))

    def test_tcp_nul_and_false_octet_frames_stay_split(self):
        self.assertEqual(frames(b"12\n<13>two\n"), [b"12\n", b"<13>two\n"])
        self.assertEqual(frames(b"<13>one\x00<13>two\n"), [b"<13>one\x00", b"<13>two\n"])
        self.assertEqual(frames(b"5\x00<13>two\n"), [b"5\x00", b"<13>two\n"])
        body = b"<13>hi"
        self.assertEqual(frames(b"<13>one\x00%d %s" % (len(body), body)), [b"<13>one\x00", body])
        self.assertEqual(frames(b"12x not octet\n"), [b"12x not octet\n"])
        self.assertEqual(frames(b"1234567 extra digits\n"), [b"1234567 extra digits\n"])
        self.assertEqual(frames(b"0 \n<13>next\n"), [b"", b"\n", b"<13>next\n"])

    def test_tcp_oversize_octet_and_newline_do_not_merge(self):
        octet = frames(b"30 " + b"A" * 30 + b"<13>next\n", max_bytes=10)
        self.assertEqual(len(octet[0]), 10)
        self.assertEqual(octet[1], b"<13>next\n")
        newline = frames(b"<13>" + b"x" * 100 + b"\n<13>next\n", max_bytes=20)
        self.assertEqual(len(newline[0]), 21)
        self.assertEqual(newline[1], b"<13>next\n")
        msg = b"<13>one\nstill one"
        self.assertEqual(frames(b"%d " % len(msg) + msg + b"<13>two\n"), [msg, b"<13>two\n"])

    def test_comma_fraction_iso_timestamp(self):
        event = frame_to_event("<13>1 2026-09-28T10:00:01,5Z web01 app - - - hi", now=NOW)
        self.assertEqual((event["host"], event["ts"]), ("web01", "2026-09-28T10:00:01.500Z"))


if __name__ == "__main__":
    unittest.main()
