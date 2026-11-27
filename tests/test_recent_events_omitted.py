"""Entity detail says how many events the 50-row cap dropped.

The rows stay the newest 50 by ts, then id. A shorter entity returns recent_events_omitted 0.
event_count stays the full count of matching events.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.entities import RECENT_EVENTS_LIMIT, get_entity

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes, user="alice", message="[SYNTHETIC] recent cap"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", user, message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


class RecentEventsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_an_older_event_with_a_higher_id_is_the_one_past_the_cap(self):
        # Later time, then one earlier row. ts wins, so the higher id is the omitted event.
        kept = [add_event(self.conn, minutes=10) for _ in range(RECENT_EVENTS_LIMIT)]
        older = add_event(self.conn, minutes=0)
        other = add_event(self.conn, minutes=0, user="bob")

        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual([row["id"] for row in detail["recent_events"]], list(reversed(kept)))
        self.assertEqual(detail["recent_events_omitted"], 1)
        self.assertEqual(detail["event_count"], RECENT_EVENTS_LIMIT + 1)
        self.assertNotIn(older, {row["id"] for row in detail["recent_events"]})
        self.assertNotIn(other, {row["id"] for row in detail["recent_events"]})
        self.assertEqual(detail["recent_events"][0]["message"], "[SYNTHETIC] recent cap")
        self.assertEqual(detail["recent_events"][0]["synthetic"], 1)

    def test_the_same_timestamp_keeps_the_higher_ids(self):
        ids = [add_event(self.conn, minutes=0) for _ in range(RECENT_EVENTS_LIMIT + 1)]
        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual([row["id"] for row in detail["recent_events"]], list(reversed(ids[1:])))
        self.assertEqual(detail["recent_events_omitted"], 1)
        self.assertNotIn(ids[0], {row["id"] for row in detail["recent_events"]})

    def test_a_short_entity_and_an_exact_cap_omit_nothing(self):
        one = add_event(self.conn, minutes=0, user="one")
        exact = [add_event(self.conn, minutes=1, user="exact") for _ in range(RECENT_EVENTS_LIMIT)]

        short = get_entity(self.conn, "user", "one")
        self.assertEqual([row["id"] for row in short["recent_events"]], [one])
        self.assertEqual(short["recent_events_omitted"], 0)
        self.assertEqual(short["event_count"], 1)

        filled = get_entity(self.conn, "user", "exact")
        self.assertEqual(len(filled["recent_events"]), RECENT_EVENTS_LIMIT)
        self.assertEqual(filled["recent_events_omitted"], 0)
        self.assertEqual(filled["event_count"], RECENT_EVENTS_LIMIT)
        self.assertEqual([row["id"] for row in filled["recent_events"]], list(reversed(exact)))

        empty = get_entity(self.conn, "user", "nobody")
        self.assertEqual(empty["recent_events"], [])
        self.assertEqual(empty["recent_events_omitted"], 0)
        self.assertEqual(empty["event_count"], 0)

    def test_the_api_docs_name_the_cap_and_the_omitted_count(self):
        text = API.read_text()
        self.assertIn(
            "`recent_events` (the newest 50 matching events by `ts`, then `id`), `recent_events_omitted`"
            " (how many matching events were past that cap; 0 when the entity has 50 or fewer;"
            " `event_count` stays the full count)",
            text)


class RecentEventsOmittedApiTests(ServerTestCase):
    def test_entity_detail_reports_the_dropped_row(self):
        conn = connect(self.db_path)
        try:
            kept = [add_event(conn, minutes=10) for _ in range(RECENT_EVENTS_LIMIT)]
            older = add_event(conn, minutes=0)
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get("/api/entities/user/alice")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["recent_events"]], list(reversed(kept)))
        self.assertEqual(detail["recent_events_omitted"], 1)
        self.assertEqual(detail["event_count"], RECENT_EVENTS_LIMIT + 1)
        self.assertNotIn(older, {row["id"] for row in detail["recent_events"]})
        self.assertEqual(detail["recent_events"][0]["message"], "[SYNTHETIC] recent cap")
        self.assertEqual(detail["recent_events"][0]["synthetic"], 1)
