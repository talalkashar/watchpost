"""activity_last_24h_of_data is 24 clock hours anchored on the newest event ts.

The newest hour is the last bucket. A hour with no events stays 0 in that
place. The count is ts, not ingested_at. An event 25 hours before that newest
hour is not a bucket and is not a count. An empty table is []. failures counts
auth_failure only.
"""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import metrics

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
# Newest event is 12:30, so the last bucket is 12:00 and the window ends at 13:00.
NEWEST = datetime(2026, 9, 15, 12, 30, tzinfo=timezone.utc)
END = NEWEST.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
START = END - timedelta(hours=24)
DOC = (
    "24 hourly buckets anchored on the newest event `ts`, filled with 0, "
    "not the `hours` window. An event in the newest hour is the last bucket. "
    "An hour with no events stays 0 in that place. The count is `ts`, not "
    "`ingested_at`. An event 25 hours before that newest hour is not a bucket "
    "and is not a count. An empty events table is `[]`. `failures` counts "
    "`auth_failure` only."
)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def stamp(moment):
    return iso(moment)


def hour_label(moment):
    base = moment.replace(minute=0, second=0, microsecond=0)
    return iso(base)[:13] + ":00Z"


def add_event(conn, ts, event_type, user, ingested_at=None):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user,"
        " message, synthetic) VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ingested_at or ts, "lab", "web01", event_type, "low", user,
         "[SYNTHETIC] activity histogram"))


def load_window(conn):
    # First bucket: exactly the window start, an auth failure.
    add_event(conn, stamp(START), "auth_failure", "synth-edge")
    # Hour 10:00 has one success. The next hour, 11:00, stays empty.
    add_event(conn, stamp(END - timedelta(hours=2, minutes=45)), "auth_success", "synth-quiet")
    # Newest hour. Event time counts; an old ingest time still counts.
    add_event(conn, stamp(NEWEST), "auth_failure", "synth-newest",
              ingested_at=stamp(NEWEST - timedelta(days=10)))
    add_event(conn, stamp(NEWEST - timedelta(minutes=10)), "auth_success", "synth-ok")
    # Same hour, catalog spelling only. Auth_Failure is an event, not a failure.
    add_event(conn, stamp(NEWEST - timedelta(minutes=5)), "Auth_Failure", "synth-case")
    # 25 hours before the newest hour (12:00). Ingested in that hour, still out.
    before = NEWEST.replace(minute=0) - timedelta(hours=25) + timedelta(minutes=15)
    add_event(conn, stamp(before), "auth_failure", "synth-old", ingested_at=stamp(NEWEST))
    # Exactly 24 hours before the newest timestamp, still the hour before the window.
    add_event(conn, stamp(NEWEST - timedelta(hours=24)), "auth_failure", "synth-roll")


class ActivityHistogramTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_empty_table_is_an_empty_list(self):
        self.assertEqual(metrics(self.conn)["activity_last_24h_of_data"], [])

    def test_event_time_fills_zeros_and_drops_the_hour_before_the_window(self):
        load_window(self.conn)
        rows = metrics(self.conn)["activity_last_24h_of_data"]
        self.assertEqual(len(rows), 24)
        labels = [row["hour"] for row in rows]
        self.assertEqual(labels, [hour_label(START + timedelta(hours=i)) for i in range(24)])
        self.assertEqual(rows[-1]["hour"], hour_label(NEWEST))
        by = {row["hour"]: row for row in rows}
        edge = hour_label(START)
        self.assertEqual(by[edge], {"hour": edge, "events": 1, "failures": 1})
        quiet = hour_label(END - timedelta(hours=3))
        gap = hour_label(END - timedelta(hours=2))
        self.assertEqual(by[quiet], {"hour": quiet, "events": 1, "failures": 0})
        self.assertEqual(by[gap], {"hour": gap, "events": 0, "failures": 0})
        self.assertLess(labels.index(quiet), labels.index(gap))
        self.assertLess(labels.index(gap), labels.index(hour_label(NEWEST)))
        self.assertEqual(by[hour_label(NEWEST)], {
            "hour": hour_label(NEWEST), "events": 3, "failures": 1})
        self.assertEqual(sum(row["events"] for row in rows), 5)
        self.assertEqual(sum(row["failures"] for row in rows), 2)
        old = hour_label(NEWEST.replace(minute=0) - timedelta(hours=25))
        self.assertNotIn(old, by)
        narrow = metrics(self.conn, hours=1)["activity_last_24h_of_data"]
        wide = metrics(self.conn, hours=72)["activity_last_24h_of_data"]
        self.assertEqual(narrow, rows)
        self.assertEqual(wide, rows)

    def test_the_count_query_uses_event_time_and_auth_failure_only(self):
        load_window(self.conn)
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append((sql, args))
            return real_execute(sql, args)

        self.conn.execute = execute
        metrics(self.conn)
        activity = [sql for sql, _args in captured if "substr(ts, 1, 13)" in sql]
        self.assertEqual(len(activity), 1)
        self.assertIn("SUM(event_type = 'auth_failure') AS failures", activity[0])
        self.assertIn("WHERE ts >= ? AND ts < ?", activity[0])
        self.assertIn("GROUP BY hour", activity[0])
        self.assertNotIn("ingested_at", activity[0])

    def test_the_docs_name_the_hourly_buckets(self):
        self.assertIn(DOC, API.read_text())


class ActivityHistogramApiTests(ServerTestCase):
    def test_the_metrics_endpoint_counts_event_time(self):
        with sqlite3.connect(self.db_path) as db:
            load_window(db)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/metrics?hours=1")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        rows = body["activity_last_24h_of_data"]
        self.assertEqual([row["hour"] for row in rows],
                         [hour_label(START + timedelta(hours=i)) for i in range(24)])
        by = {row["hour"]: row for row in rows}
        self.assertEqual(by[hour_label(NEWEST)]["events"], 3)
        self.assertEqual(by[hour_label(NEWEST)]["failures"], 1)
        self.assertEqual(by[hour_label(END - timedelta(hours=2))]["events"], 0)
        self.assertEqual(sum(row["events"] for row in rows), 5)
        self.assertEqual(body["events_total"], 7)
        self.assertEqual(body["window_scope"]["newest_event_24h"], ["activity_last_24h_of_data"])
        wide = viewer.get("/api/metrics?hours=72")[1]["activity_last_24h_of_data"]
        self.assertEqual(wide, rows)

    def test_an_empty_metrics_payload_and_a_rejected_request(self):
        status, body, _headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["activity_last_24h_of_data"], [])
        status, denied, _headers = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("activity_last_24h_of_data", denied)
