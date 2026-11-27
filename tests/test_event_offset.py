"""offset above 10000 is refused on event search and hunt.

SQLite OFFSET visits every skipped row. since_id remains the way to walk newer events.
"""

import unittest

from tests.helpers import ServerTestCase
from watchpost import hunt, queries
from watchpost.db import connect, init_schema


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for n, host in enumerate(("web01", "db01")):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", host, "process_start", "low", "erin", "[SYNTHETIC] offset",))
    return conn


class EventOffsetTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_offset_above_10000_names_the_maximum(self):
        for params in ({"offset": "10001"}, {"offset": "10000000"}):
            with self.subTest(params=params):
                with self.assertRaises(queries.QueryError) as caught:
                    queries.search_events(self.conn, params)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn("10000", str(caught.exception))
                self.assertIn("offset", str(caught.exception))

        page = queries.search_events(self.conn, {"offset": "10000", "limit": "1"})
        self.assertEqual((page["offset"], page["events"], page["total"]), (10000, [], 2))

    def test_since_id_still_walks_newer_events(self):
        first_id = self.conn.execute("SELECT MIN(id) FROM events").fetchone()[0]
        newer = queries.search_events(self.conn, {"since_id": str(first_id), "offset": "0"})
        self.assertEqual([row["host"] for row in newer["events"]], ["db01"])
        self.assertEqual(newer["total"], 1)

    def test_hunt_refuses_the_same_offset_on_a_page_and_a_stage(self):
        for params in ({"q": "host:web01", "offset": "10001"},
                       {"q": "| stats count", "offset": "10000000"}):
            with self.subTest(params=params):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.run(self.conn, params)
                self.assertIn("10000", str(caught.exception))

        page = hunt.run(self.conn, {"q": "", "offset": "10000"})
        self.assertEqual((page["offset"], page["total"]), (10000, 2))
        counted = hunt.run(self.conn, {"q": "| stats count", "offset": "10000"})
        self.assertEqual(counted["rows"], [[2]])


class EventOffsetApiTests(ServerTestCase):
    def test_events_and_hunt_return_400_naming_the_maximum(self):
        client = self.client("viewer")
        paths = (
            "/api/events?offset=10001",
            "/api/hunt?q=&offset=10001",
            "/api/hunt?q=%7C%20stats%20count&offset=10000000",
        )
        for path in paths:
            with self.subTest(path=path):
                status, data, headers = client.get(path)
                self.assertEqual(status, 400)
                self.assertIn("10000", data["error"])
                self.assertIn("offset", data["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, _ = client.get("/api/events?offset=10000")
        self.assertEqual(status, 200, data)
        self.assertEqual(data["offset"], 10000)

        status, data, _ = client.get("/api/events?since_id=0")
        self.assertEqual(status, 200, data)
        self.assertIn("events", data)
