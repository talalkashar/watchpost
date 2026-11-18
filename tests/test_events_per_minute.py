"""Dashboard events_per_minute is 60 ingest-time buckets ending now.

A minute with events and a minute with none stay in order. The count is
ingested_at, not event ts. The current minute is the last bucket. An event
ingested 61 minutes ago is not a bucket and is not a count. Empty minutes are 0.
"""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
# 30 seconds into the minute, so the truncated current minute is 12:00.
FROZEN = datetime(2026, 9, 15, 12, 0, 30, tzinfo=timezone.utc)
OLD_TS = "2026-09-15T08:00:00.000Z"
DOC = (
    "`events_per_minute` (60 one-minute buckets ending at the current minute, "
    "filled with 0 when that minute has no events. The count is ingest time "
    "`ingested_at`, not event time `ts`. An event ingested in the current minute "
    "is the last bucket. An event ingested 61 minutes ago is not a bucket and "
    "is not a count)"
)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def bucket(offset):
    """Bucket label offset minutes from the truncated current minute."""
    base = FROZEN.replace(second=0, microsecond=0) + timedelta(minutes=offset)
    return iso(base)[:16] + ":00Z"


def at(offset, seconds=0):
    base = FROZEN.replace(second=0, microsecond=0) + timedelta(minutes=offset, seconds=seconds)
    return iso(base)


def add_event(conn, ingested_at, ts, user):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ingested_at, "lab", "web01", "auth", "low", user, "[SYNTHETIC] events per minute"))


def load_window(conn):
    # Old event time, ingested in the current minute: two rows, last bucket.
    add_event(conn, at(0, 10), OLD_TS, "synth-current-a")
    add_event(conn, at(0, 40), OLD_TS, "synth-current-b")
    # A busy minute, then the next minute stays empty.
    add_event(conn, at(-30, 5), OLD_TS, "synth-busy")
    # First bucket of the window (59 minutes before the current minute).
    add_event(conn, at(-59, 15), OLD_TS, "synth-edge")
    # Recent event time, ingested 61 minutes ago: not a bucket and not a count.
    add_event(conn, at(-61, 0), at(0, 20), "synth-old-ingest")


class EventsPerMinuteTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def per_minute(self):
        with patch("watchpost.queries.utcnow", return_value=FROZEN):
            return dashboard(self.conn)["events_per_minute"]

    def test_empty_table_is_sixty_zeros_ending_at_the_current_minute(self):
        rows = self.per_minute()
        self.assertEqual(len(rows), 60)
        self.assertEqual([row["count"] for row in rows], [0] * 60)
        self.assertEqual(rows[0]["minute"], bucket(-59))
        self.assertEqual(rows[-1]["minute"], bucket(0))

    def test_ingest_time_keeps_order_and_drops_the_sixty_first_minute(self):
        load_window(self.conn)
        rows = self.per_minute()
        self.assertEqual(len(rows), 60)
        minutes = [row["minute"] for row in rows]
        self.assertEqual(minutes, [bucket(-59 + i) for i in range(60)])
        by = {row["minute"]: row["count"] for row in rows}
        self.assertEqual(by[bucket(0)], 2)
        self.assertEqual(by[bucket(-30)], 1)
        self.assertEqual(by[bucket(-29)], 0)
        self.assertEqual(by[bucket(-59)], 1)
        self.assertEqual(sum(by.values()), 4)
        self.assertNotIn(bucket(-61), by)
        self.assertLess(minutes.index(bucket(-30)), minutes.index(bucket(-29)))
        self.assertLess(minutes.index(bucket(-29)), minutes.index(bucket(0)))

    def test_the_docs_name_ingest_time_buckets(self):
        self.assertIn(DOC, API.read_text())


class EventsPerMinuteApiTests(ServerTestCase):
    def test_the_dashboard_counts_ingest_time(self):
        with sqlite3.connect(self.db_path) as db:
            load_window(db)
        viewer = self.client("viewer")
        with patch("watchpost.queries.utcnow", return_value=FROZEN):
            status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        rows = body["events_per_minute"]
        self.assertEqual([row["minute"] for row in rows], [bucket(-59 + i) for i in range(60)])
        by = {row["minute"]: row["count"] for row in rows}
        self.assertEqual(by[bucket(0)], 2)
        self.assertEqual(by[bucket(-30)], 1)
        self.assertEqual(by[bucket(-29)], 0)
        self.assertEqual(sum(by.values()), 4)
        self.assertEqual(body["events_total"], 5)
        self.assertEqual(body["synthetic_events"], 5)
        users = {row["user"] for row in body["recent_events"]}
        self.assertIn("synth-old-ingest", users)
        self.assertNotIn(bucket(-61), by)

    def test_an_empty_dashboard_and_a_rejected_request(self):
        viewer = self.client("viewer")
        with patch("watchpost.queries.utcnow", return_value=FROZEN):
            status, body, _ = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        rows = body["events_per_minute"]
        self.assertEqual(len(rows), 60)
        self.assertEqual([row["count"] for row in rows], [0] * 60)
        self.assertEqual(rows[-1]["minute"], bucket(0))
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("events_per_minute", denied)
