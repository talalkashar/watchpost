"""Hunt last: folds the unit on ASCII letters only.

last:24H is 24 hours, last:15M is 15 minutes, and last:7D is 7 days.
last:24İ, last:24, and a window past 365 days stay the existing 400.
The maximum stays 365 days.
"""

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


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = (
        (iso(NOW - timedelta(minutes=1)), "recent"),
        (iso(NOW - timedelta(hours=24)), "edge"),
        (iso(NOW - timedelta(days=2)), "day"),
        (iso(NOW - timedelta(days=366)), "old"),
    )
    for ts, user in rows:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, ts, "lab", "web01", "auth_success", "info", user, "[SYNTHETIC] login", 1))
    return conn


class HuntLastTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, query):
        page = hunt.run(self.conn, {"q": query}, now=NOW)
        return sorted(event["user"] for event in page["events"])

    def test_units_fold_ascii_case(self):
        day = hunt.compile_query("last:24h", now=NOW)
        for query, expected in (
            ("last:24H", day),
            ("last:24h", day),
            ("last:15M", (["ts >= ?"], ["2026-10-07T11:45:00.000Z"])),
            ("last:15m", (["ts >= ?"], ["2026-10-07T11:45:00.000Z"])),
            ("last:7D", (["ts >= ?"], ["2026-09-30T12:00:00.000Z"])),
            ("last:7d", (["ts >= ?"], ["2026-09-30T12:00:00.000Z"])),
            ("last:365D", (["ts >= ?"], ["2025-10-07T12:00:00.000Z"])),
        ):
            with self.subTest(query=query):
                where, args = hunt.compile_query(query, now=NOW)
                self.assertEqual((where, args), expected)
                self.assertNotIn("lower(", where[0])
        self.assertEqual(hunt.explain("last:24H", now=NOW)[0]["text"],
                         "time >= 2026-10-06T12:00:00.000Z (last 24H)")
        self.assertEqual(self.users("last:24H"), ["edge", "recent"])
        self.assertEqual(self.users("last:15M"), ["recent"])
        self.assertEqual(self.users("last:7D"), ["day", "edge", "recent"])
        self.assertEqual(self.users("last:365D"), ["day", "edge", "recent"])
        self.assertNotIn("old", self.users("last:365d"))

    def test_bad_units_stay_the_existing_error(self):
        for query in ("last:24\u0130", "last:24", "last:366D", "last:400d", "last:0H"):
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(query, now=NOW)
                self.assertEqual(str(caught.exception), LAST_ERROR)
                self.assertEqual(caught.exception.status, 400)
        self.assertEqual(self.users("last:7d"), ["day", "edge", "recent"])


class HuntLastApiTests(ServerTestCase):
    def test_hunt_accepts_the_folded_units(self):
        client = self.client("analyst")
        now = datetime.now(timezone.utc)
        rows = (
            (iso(now - timedelta(minutes=1)), "recent"),
            (iso(now - timedelta(hours=2)), "hours"),
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

        self.assertEqual(users("last:15M"), ["recent"])
        self.assertEqual(users("last:24H"), ["hours", "recent"])
        self.assertEqual(users("last:7D"), ["day", "hours", "recent"])

        for query in ("last:24\u0130", "last:24", "last:366D"):
            with self.subTest(query=query):
                status, data, headers = client.get("/api/hunt?q=" + quote(query))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], LAST_ERROR)
                self.assertEqual(headers["Cache-Control"], "no-store")

    def test_docs_name_the_unit_fold(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        self.assertIn("24H", hunt_row)
        self.assertIn("15M", hunt_row)
        self.assertIn("7D", hunt_row)
        self.assertIn(LAST_ERROR, hunt_row)
        self.assertIn("365 days", hunt_row)
        last_row = next(line for line in REFERENCE.read_text().splitlines()
                        if line.startswith("| `last:`"))
        self.assertIn("24H", last_row)
        self.assertIn("15M", last_row)
        self.assertIn("7D", last_row)
        self.assertIn("24\u0130", last_row)
