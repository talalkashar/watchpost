"""Event search q longer than 200 characters is refused.

A silent slice matched messages that did not contain the rest of the needle.
"""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import queries
from watchpost.db import connect, init_schema

PREFIX = "A" * 200
LONGER = PREFIX + "Z"
API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    ts = "2026-10-07T11:00:00.000Z"
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "process_start", "low", "erin", f"[SYNTHETIC] {PREFIX}"),
    )
    return conn


class SearchQLimitTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_q_above_200_names_the_maximum_and_is_not_sliced(self):
        with self.assertRaises(queries.QueryError) as caught:
            queries.search_events(self.conn, {"q": LONGER})
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("200", str(caught.exception))
        self.assertIn("q", str(caught.exception))

        # The stored message is only the first 200 characters. A slice would have returned it.
        page = queries.search_events(self.conn, {"q": PREFIX})
        self.assertEqual(page["total"], 1)
        self.assertNotIn("Z", page["events"][0]["message"])

    def test_q_of_200_matches_the_full_needle(self):
        page = queries.search_events(self.conn, {"q": PREFIX})
        self.assertEqual(page["total"], 1)
        self.assertIn(PREFIX, page["events"][0]["message"])
        self.assertEqual(queries.search_events(self.conn, {"q": "B" * 200})["total"], 0)
        self.assertEqual(queries.search_events(self.conn, {})["total"], 1)


class SearchQLimitApiTests(ServerTestCase):
    def test_events_return_400_naming_the_maximum(self):
        client = self.client("viewer")
        status, data, headers = client.get("/api/events?q=" + LONGER)
        self.assertEqual(status, 400)
        self.assertIn("200", data["error"])
        self.assertIn("q", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, _ = client.get("/api/events?q=" + PREFIX)
        self.assertEqual(status, 200, data)
        self.assertEqual(data["total"], 0)

    def test_api_docs_name_the_maximum(self):
        text = API.read_text()
        self.assertIn("at most 200 characters", text)
        self.assertIn("A longer value is 400 naming that maximum", text)
