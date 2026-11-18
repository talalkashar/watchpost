"""The dashboard recent list says how many events the cap dropped.

The rows stay the newest 60 by ts, then id. An older event with a higher id
is the one left out. The same timestamp keeps the higher ids. A list that
fits, including an empty table, returns recent_events_omitted 0. events_total
stays the full count.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import RECENT_LIMIT, dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
NEW = "2026-09-01T00:00:00.000Z"
OLD = "2026-01-01T00:00:00.000Z"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, ts=NEW, message="[SYNTHETIC] dashboard recent"):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", "alice", message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


class DashboardRecentOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def recent(self):
        body = dashboard(self.conn)
        return body["recent_events_omitted"], [row["id"] for row in body["recent_events"]], body["events_total"]

    def test_an_older_event_with_a_higher_id_is_the_one_past_the_cap(self):
        kept = [add_event(self.conn) for _ in range(RECENT_LIMIT)]
        older = add_event(self.conn, ts=OLD)
        omitted, ids, total = self.recent()
        self.assertEqual(omitted, 1)
        self.assertEqual(total, RECENT_LIMIT + 1)
        self.assertEqual(ids, list(reversed(kept)))
        self.assertNotIn(older, ids)
        self.assertGreater(older, kept[-1])
        self.assertEqual(self.conn.execute("SELECT message FROM events WHERE id = ?", (ids[0],)).fetchone()[0],
                         "[SYNTHETIC] dashboard recent")
        self.assertNotIn("raw", dashboard(self.conn)["recent_events"][0])

    def test_the_same_timestamp_keeps_the_higher_ids(self):
        ids = [add_event(self.conn, ts=OLD) for _ in range(RECENT_LIMIT + 1)]
        omitted, shown, total = self.recent()
        self.assertEqual(omitted, 1)
        self.assertEqual(total, RECENT_LIMIT + 1)
        self.assertEqual(shown, list(reversed(ids[1:])))
        self.assertNotIn(ids[0], shown)

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        self.assertEqual(self.recent(), (0, [], 0))
        one = add_event(self.conn)
        self.assertEqual(self.recent(), (0, [one], 1))
        self.conn.execute("DELETE FROM events")
        exact = [add_event(self.conn) for _ in range(RECENT_LIMIT)]
        omitted, ids, total = self.recent()
        self.assertEqual(omitted, 0)
        self.assertEqual(total, RECENT_LIMIT)
        self.assertEqual(ids, list(reversed(exact)))

    def test_the_docs_name_recent_events_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`recent_events` (the newest 60 by `ts`, then `id`, no `raw`). "
            "`recent_events_omitted` is how many stored events were past that cap"
            " (0 when there are 60 or fewer)",
            api)
        self.assertIn("`events_total` stays the full count", api)


class DashboardRecentOmittedApiTests(ServerTestCase):
    def test_the_dashboard_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for _ in range(RECENT_LIMIT):
                add_event(db)
            older = add_event(db, ts=OLD)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["recent_events_omitted"], 1)
        self.assertEqual(body["events_total"], RECENT_LIMIT + 1)
        self.assertEqual(len(body["recent_events"]), RECENT_LIMIT)
        self.assertNotIn(older, {row["id"] for row in body["recent_events"]})
        self.assertEqual(body["recent_events"][0]["message"], "[SYNTHETIC] dashboard recent")
        self.assertEqual(body["recent_events"][0]["synthetic"], 1)
        self.assertNotIn("raw", body["recent_events"][0])

    def test_an_empty_dashboard_and_a_rejected_request(self):
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["recent_events"], [])
        self.assertEqual(body["recent_events_omitted"], 0)
        self.assertEqual(body["events_total"], 0)
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("recent_events_omitted", denied)
