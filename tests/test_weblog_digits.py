"""Combined access-log status and size accept ASCII digits only.

A normal 500 line stays parsed and is web_error. A status of ５００ or a size
of １６２ is the existing combined-format error and stores nothing. int() of
those digits is 500 and 162, and int() is not called for the two refusals.
Neither refusal is an HTTP 500.
"""

import inspect
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import normalize
from watchpost.db import connect
from watchpost.normalize import EventError, normalize_weblog_line, parse_payload

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NOW = datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc)
FORMAT_ERROR = "line is not in combined access log format"
FULLWIDTH_STATUS = "\uff15\uff10\uff10"  # ５００
FULLWIDTH_SIZE = "\uff11\uff16\uff12"  # １６２
HEAD = '203.0.113.80 - alice [15/Sep/2026:10:00:00 +0000] "GET /api/orders HTTP/1.1" '
TAIL = ' "-" "Mozilla/5.0"'
GOOD = HEAD + "500 162" + TAIL
WIDE_STATUS = HEAD + FULLWIDTH_STATUS + " 162" + TAIL
WIDE_SIZE = HEAD + "200 " + FULLWIDTH_SIZE + TAIL


class WebLogDigitTests(unittest.TestCase):
    def test_ascii_500_stays_a_web_error(self):
        event = normalize_weblog_line(GOOD, "nginx", now=NOW)
        self.assertEqual(event["event_type"], "web_error")
        self.assertEqual(event["bytes"], 162)
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["src_ip"], "203.0.113.80")
        self.assertEqual(event["user"], "alice")
        self.assertIn("GET /api/orders -> 500", event["message"])
        self.assertEqual(int(FULLWIDTH_STATUS), 500)
        self.assertEqual(int(FULLWIDTH_SIZE), 162)

    def test_fullwidth_status_and_size_are_the_format_error(self):
        for line in (WIDE_STATUS, WIDE_SIZE):
            with self.subTest(line=line):
                with self.assertRaises(EventError) as caught:
                    normalize_weblog_line(line, "nginx", now=NOW)
                self.assertEqual(str(caught.exception), FORMAT_ERROR)
        events, rejections = parse_payload(
            GOOD + "\n" + WIDE_STATUS + "\n" + WIDE_SIZE + "\n", "weblog", "nginx", now=NOW)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "web_error")
        self.assertEqual(events[0]["bytes"], 162)
        self.assertEqual(
            [row["reason"] for row in rejections], [FORMAT_ERROR, FORMAT_ERROR])
        self.assertNotIn(FULLWIDTH_STATUS, events[0]["message"])
        self.assertNotIn("-> 200", events[0]["message"])

    def test_pattern_is_ascii_digits_and_int_is_not_called(self):
        pattern = normalize._WEBLOG.pattern
        self.assertIn("[0-9]{3}", pattern)
        self.assertIn("[0-9]+", pattern)
        self.assertNotIn(r"\d", pattern)
        source = inspect.getsource(normalize_weblog_line)
        self.assertLess(source.index("_WEBLOG.match"), source.index("int("))
        calls = []
        real = int

        def spy(value, *args):
            calls.append(value)
            return real(value, *args)

        normalize.int = spy
        try:
            for line in (WIDE_STATUS, WIDE_SIZE):
                with self.assertRaises(EventError):
                    normalize_weblog_line(line, "nginx", now=NOW)
            self.assertEqual(calls, [])
        finally:
            del normalize.int
        event = normalize_weblog_line(GOOD, "nginx", now=NOW)
        self.assertEqual(event["event_type"], "web_error")
        self.assertEqual(event["bytes"], 162)

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("The status and the size are ASCII digits", text)
            self.assertIn("`500` stays a 5xx `web_error`", text)
            self.assertIn(
                "A status of `５００` or a size of `１６２` is "
                "`line is not in combined access log format`", text)
            self.assertIn("`５００` is not status 500", text)
            self.assertIn("That refusal is not an HTTP 500", text)


class WebLogDigitApiTests(ServerTestCase):
    def _upload(self, client, line):
        return client.post(
            "/api/ingest/upload?format=weblog&source=nginx&synthetic=true",
            raw=(line + "\n").encode(),
            headers={"Content-Type": "text/plain"})

    def test_fullwidth_lines_store_nothing_and_are_not_http_500(self):
        client = self.client("analyst")
        for line in (WIDE_STATUS, WIDE_SIZE):
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
        self.assertEqual(event["event_type"], "web_error")
        self.assertEqual(event["bytes"], 162)
        self.assertEqual(event["user"], "alice")
        self.assertTrue(event["source"].startswith("demo:"))
        self.assertEqual(event["synthetic"], 1)
        self.assertIn("-> 500", event["message"])

        status, again, _ = self._upload(client, WIDE_STATUS)
        self.assertEqual(status, 422, again)
        self.assertEqual(again["rejections"][0]["reason"], FORMAT_ERROR)
        status, still, _ = client.get("/api/events")
        self.assertEqual(still["total"], 1)
        self.assertEqual(still["events"][0]["event_type"], "web_error")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
