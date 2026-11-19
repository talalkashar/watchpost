"""Hunt last: accepts ASCII digits only.

last:24h and last:24H stay 24 hours. last:４h and last:24４h are the existing
last error, not 4 hours or 244 hours. int() runs only after the number is
ASCII digits. last:24İ stays that error. Neither refusal is a 500.
"""

import inspect
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema, iso

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
LAST_ERROR = "last must be a number with m, h or d, such as 15m, 24h or 7d (at most 365d)"
FULLWIDTH_FOUR = "\uff14"  # ４
MIXED = "24\uff14"  # 24４


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = (
        (iso(NOW - timedelta(minutes=1)), "recent"),
        (iso(NOW - timedelta(hours=3)), "inside"),
        (iso(NOW - timedelta(hours=24)), "edge"),
        (iso(NOW - timedelta(days=2)), "day"),
        (iso(NOW - timedelta(days=366)), "old"),
    )
    for ts, user in rows:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message,"
            " synthetic) VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", "web01", "auth_success", "info", user, "[SYNTHETIC] login"))
    return conn


class HuntLastDigitTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, query):
        page = hunt.run(self.conn, {"q": query}, now=NOW)
        return sorted(event["user"] for event in page["events"])

    def test_ascii_twenty_four_hours_stays_twenty_four(self):
        day = hunt.compile_query("last:24h", now=NOW)
        for query in ("last:24h", "last:24H"):
            with self.subTest(query=query):
                where, args = hunt.compile_query(query, now=NOW)
                self.assertEqual((where, args), day)
                self.assertEqual(args, ["2026-10-06T12:00:00.000Z"])
                self.assertNotIn("24", where[0])
        self.assertEqual(self.users("last:24h"), ["edge", "inside", "recent"])
        self.assertNotIn("day", self.users("last:24h"))
        self.assertEqual(self.users("last:4h"), ["inside", "recent"])
        self.assertEqual(self.users("last:244h"), ["day", "edge", "inside", "recent"])

    def test_non_ascii_digits_stay_the_existing_error(self):
        for value in (FULLWIDTH_FOUR + "h", MIXED + "h", "24\u0130"):
            query = "last:" + value
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(query, now=NOW)
                self.assertEqual(str(caught.exception), LAST_ERROR)
                self.assertEqual(caught.exception.status, 400)
        self.assertEqual(self.users("last:24h"), ["edge", "inside", "recent"])
        self.assertEqual(self.users("last:4h"), ["inside", "recent"])
        self.assertEqual(self.users("last:244h"), ["day", "edge", "inside", "recent"])

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(hunt._term_sql)
        self.assertIn("isascii()", source)
        self.assertIn("isdigit()", source)
        self.assertLess(source.index("isascii()"), source.index("int("))
        self.assertNotIn(r"\d", hunt._LAST.pattern)
        self.assertIn("[0-9]", hunt._LAST.pattern)
        calls = []
        real = int

        def spy(value, *args):
            calls.append(value)
            return real(value, *args)

        hunt.int = spy
        try:
            for value in (FULLWIDTH_FOUR + "h", MIXED + "h"):
                with self.assertRaises(hunt.HuntError):
                    hunt.compile_query("last:" + value, now=NOW)
            self.assertEqual(calls, [])
            hunt.compile_query("last:24h", now=NOW)
            self.assertEqual(calls, ["24"])
        finally:
            del hunt.int


class HuntLastDigitApiTests(ServerTestCase):
    def test_hunt_rejects_non_ascii_last_numbers(self):
        client = self.client("analyst")
        now = datetime.now(timezone.utc)
        rows = (
            (iso(now - timedelta(minutes=1)), "recent"),
            (iso(now - timedelta(hours=3)), "inside"),
            (iso(now - timedelta(days=2)), "day"),
        )
        for ts, user in rows:
            status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [{
                "ts": ts, "type": "login", "user": user, "message": "[SYNTHETIC] login",
            }]})
            self.assertEqual(status, 201, body)

        def users(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return sorted(event["user"] for event in data["events"])

        self.assertEqual(users("last:24h"), ["inside", "recent"])
        self.assertEqual(users("last:24H"), ["inside", "recent"])
        self.assertNotIn("day", users("last:24h"))
        self.assertEqual(users("last:4h"), ["inside", "recent"])

        for value in (FULLWIDTH_FOUR + "h", MIXED + "h", "24\u0130"):
            query = "last:" + value
            with self.subTest(query=query):
                status, data, headers = client.get("/api/hunt?q=" + quote(query))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], LAST_ERROR)
                self.assertNotIn("events", data)
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(users("last:24h"), ["inside", "recent"])
        self.assertEqual(users("last:4h"), ["inside", "recent"])
        self.assertEqual(users("last:244h"), ["day", "inside", "recent"])

    def test_docs_name_the_ascii_digits(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        last_row = next(line for line in REFERENCE.read_text().splitlines()
                        if line.startswith("| `last:`"))
        for text in (hunt_row, last_row):
            self.assertIn("ASCII digits only", text)
            self.assertIn("`last:24h`", text)
            self.assertIn("24H", text)
            self.assertIn("\uff14h", text)
            self.assertIn("24\uff14h", text)
            self.assertIn("not 4 hours", text)
            self.assertIn("244 hours", text)
            self.assertIn("not a 500", text)
            self.assertIn("24\u0130", text)
        self.assertIn(LAST_ERROR, hunt_row)
