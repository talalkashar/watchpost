import unittest
from datetime import datetime, timedelta, timezone

from watchpost.db import iso
from watchpost.normalize import (EventError, MAX_BYTES, detect_format, normalize_type, parse_int,
                                 parse_ip, parse_timestamp)

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class ParseTimestampEdges(unittest.TestCase):
    def test_future_bound_is_inclusive_through_one_day(self):
        self.assertEqual(parse_timestamp(iso(NOW + timedelta(days=1)), NOW), "2026-09-17T12:00:00.000Z")
        with self.assertRaisesRegex(EventError, "future"):
            parse_timestamp(iso(NOW + timedelta(days=1, seconds=1)), NOW)

    def test_year_2000_is_inclusive(self):
        self.assertEqual(parse_timestamp("2000-01-01T00:00:00Z", NOW), "2000-01-01T00:00:00.000Z")
        with self.assertRaisesRegex(EventError, "before year 2000"):
            parse_timestamp("1999-12-31T23:59:59Z", NOW)

    def test_naive_and_offset_instants_are_utc(self):
        self.assertEqual(parse_timestamp("2026-09-15T10:00:00", NOW), "2026-09-15T10:00:00.000Z")
        self.assertEqual(parse_timestamp("2026-09-15T12:00:00+02:00", NOW), "2026-09-15T10:00:00.000Z")

    def test_milliseconds_match_seconds(self):
        seconds = parse_timestamp(1_789_000_000, NOW)
        self.assertEqual(seconds, "2026-09-10T00:26:40.000Z")
        self.assertEqual(parse_timestamp(1_789_000_000_000, NOW), seconds)
        self.assertEqual(parse_timestamp(1_789_000_000.0, NOW), seconds)

    def test_empty_and_malformed(self):
        for value in (None, ""):
            with self.subTest(value=value):
                with self.assertRaisesRegex(EventError, "missing timestamp"):
                    parse_timestamp(value, NOW)
        for value in ("   ", True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(EventError, "unparseable"):
                    parse_timestamp(value, NOW)

    @unittest.expectedFailure
    def test_year_gate_uses_the_utc_instant(self):
        # parse_timestamp checks dt.year on the offset wall clock, then iso() stores UTC.
        # 2000-01-01 00:30+02:00 is 1999-12-31 22:30 UTC and is accepted.
        # 1999-12-31 23:00-02:00 is 2000-01-01 01:00 UTC and is rejected.
        with self.assertRaisesRegex(EventError, "before year 2000"):
            parse_timestamp("2000-01-01T00:30:00+02:00", NOW)
        self.assertEqual(parse_timestamp("1999-12-31T23:00:00-02:00", NOW), "2000-01-01T01:00:00.000Z")


class ParseIpEdges(unittest.TestCase):
    def test_empty_values_are_absent(self):
        for value in (None, "", "-", "  "):
            with self.subTest(value=value):
                self.assertIsNone(parse_ip(value, "src_ip"))

    def test_ipv6_is_compressed_and_lowercased(self):
        self.assertEqual(parse_ip("2001:DB8:0:0:0:0:0:1", "src_ip"), "2001:db8::1")
        self.assertEqual(parse_ip("  2001:DB8::1  ", "dest_ip"), "2001:db8::1")

    def test_malformed(self):
        with self.assertRaisesRegex(EventError, "dest_ip is not a valid IP address"):
            parse_ip("2001:db8::gg", "dest_ip")


class ParseIntEdges(unittest.TestCase):
    def test_empty_values_are_absent(self):
        for value in (None, "", "-", "  "):
            with self.subTest(value=value):
                self.assertIsNone(parse_int(value, "bytes", MAX_BYTES))

    def test_bounds_are_inclusive(self):
        self.assertEqual(parse_int(0, "dest_port", 65535), 0)
        self.assertEqual(parse_int("  65535  ", "dest_port", 65535), 65535)
        self.assertEqual(parse_int(MAX_BYTES, "bytes", MAX_BYTES), MAX_BYTES)
        with self.assertRaisesRegex(EventError, "dest_port must be between 0 and 65535"):
            parse_int(65536, "dest_port", 65535)
        with self.assertRaisesRegex(EventError, "bytes must be between 0 and"):
            parse_int(MAX_BYTES + 1, "bytes", MAX_BYTES)

    def test_malformed(self):
        with self.assertRaisesRegex(EventError, "dest_port must be an integer"):
            parse_int("12.5", "dest_port", 65535)


class NormalizeTypeEdges(unittest.TestCase):
    def test_windows_id_wins_over_a_conflicting_type(self):
        self.assertEqual(normalize_type({"EventID": 4625, "event_type": "auth_success"}), "auth_failure")
        self.assertEqual(normalize_type({"event_id": "4740", "type": "login"}), "account_lockout")

    def test_unknown_or_malformed_id_falls_through(self):
        self.assertEqual(normalize_type({"EventID": 9999, "type": "login-failure"}), "auth_failure")
        self.assertEqual(normalize_type({"EventID": "nope", "action": "deny"}), "fw_deny")
        # A list is not an id. int() fails and the type alias is used.
        self.assertEqual(normalize_type({"EventID": [4625], "type": "vpn"}), "vpn_login")

    def test_spacing_case_and_empty(self):
        self.assertEqual(normalize_type({"type": "Failed Login"}), "auth_failure")
        self.assertEqual(normalize_type({"event_type": "FW-DENY"}), "fw_deny")
        self.assertEqual(normalize_type({}), "other")
        self.assertEqual(normalize_type({"type": "   "}), "other")
        self.assertEqual(normalize_type({"type": "-"}), "other")


class DetectFormatEdges(unittest.TestCase):
    def test_empty(self):
        for text in ("", "   ", "\n\n"):
            with self.subTest(text=repr(text)):
                with self.assertRaisesRegex(EventError, "could not detect format"):
                    detect_format(text)

    def test_json_versus_jsonl(self):
        self.assertEqual(detect_format('{"a": 1}\n'), "json")
        self.assertEqual(detect_format('{"a": 1}\n{"a": 2}\n'), "jsonl")
        self.assertEqual(detect_format('  [\n{"a": 1}\n]\n'), "json")

    def test_syslog_and_weblog_win_over_a_comma(self):
        syslog = "Sep 15 10:00:01 web01 sshd[1]: Failed password for user,admin from 10.0.0.1"
        weblog = ('203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 162 '
                  '"-" "Mozilla/5.0 (Windows, x64)"')
        self.assertEqual(detect_format(syslog), "authlog")
        self.assertEqual(detect_format(weblog), "weblog")
        self.assertEqual(detect_format("timestamp,user\n2026-09-15T10:00:00Z,alice\n"), "csv")


if __name__ == "__main__":
    unittest.main()
