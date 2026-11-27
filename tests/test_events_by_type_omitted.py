"""Metrics events_by_type says how many event types the cap of 100 dropped.

The rows stay the types with the most events, then event_type. A quieter type
is the one left out. Equal counts keep the earlier event_type. A type with no
events is not a row and is not omitted. hours does not filter the list, and
the window note still says this field counts every stored event.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import EVENTS_BY_TYPE_LIMIT, METRICS_WINDOW_NOTE, metrics

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
TS = "2026-09-15T12:00:00.000Z"
QUIET = "zzz_quiet"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_events(conn, event_type, n=1):
    conn.executemany(
        "INSERT INTO events(ts, ingested_at, source, event_type, severity, message, synthetic)"
        " VALUES (?,?,?,?,?,?,1)",
        [(TS, TS, "test", event_type, "low", "synthetic labeled") for _ in range(n)])


class EventsByTypeOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def body(self, hours=24):
        return metrics(self.conn, hours=hours)

    def test_a_quieter_type_is_the_one_past_the_cap(self):
        kept = [f"type_{i:03d}" for i in range(EVENTS_BY_TYPE_LIMIT)]
        for event_type in kept:
            add_events(self.conn, event_type, n=2)
        add_events(self.conn, QUIET, n=1)
        body = self.body()
        types = [row["event_type"] for row in body["events_by_type"]]
        self.assertEqual(body["events_by_type_omitted"], 1)
        self.assertEqual(types, kept)
        self.assertNotIn(QUIET, types)
        self.assertNotIn("auth_success", types)
        self.assertTrue(all(row["count"] == 2 for row in body["events_by_type"]))
        self.assertEqual(body["events_total"], EVENTS_BY_TYPE_LIMIT * 2 + 1)
        self.assertEqual(body["window_scope"]["note"], METRICS_WINDOW_NOTE)
        self.assertIn("events_by_type", body["window_scope"]["all_stored_events"])

    def test_equal_counts_keep_the_earlier_event_type(self):
        kept = [f"type_{i:03d}" for i in range(EVENTS_BY_TYPE_LIMIT)]
        for event_type in kept:
            add_events(self.conn, event_type, n=1)
        add_events(self.conn, QUIET, n=1)
        body = self.body()
        types = [row["event_type"] for row in body["events_by_type"]]
        self.assertEqual(body["events_by_type_omitted"], 1)
        self.assertEqual(types, kept)
        self.assertNotIn(QUIET, types)
        self.assertTrue(all(row["count"] == 1 for row in body["events_by_type"]))

    def test_more_events_outrank_a_quieter_type(self):
        add_events(self.conn, "busy", n=3)
        add_events(self.conn, "quiet", n=1)
        body = self.body()
        self.assertEqual(body["events_by_type_omitted"], 0)
        self.assertEqual(body["events_by_type"],
                         [{"event_type": "busy", "count": 3}, {"event_type": "quiet", "count": 1}])

    def test_a_type_with_no_events_is_not_counted(self):
        add_events(self.conn, "auth_failure", n=1)
        body = self.body()
        self.assertEqual(body["events_by_type_omitted"], 0)
        self.assertEqual(body["events_by_type"], [{"event_type": "auth_failure", "count": 1}])

    def test_hours_does_not_drop_an_older_type(self):
        add_events(self.conn, "auth_failure", n=2)
        add_events(self.conn, QUIET, n=1)
        narrow = self.body(hours=1)
        wide = self.body(hours=72)
        self.assertEqual(narrow["events_by_type"], wide["events_by_type"])
        self.assertEqual(narrow["events_by_type_omitted"], 0)
        self.assertEqual(wide["events_by_type_omitted"], 0)
        self.assertEqual(narrow["window_scope"]["note"], METRICS_WINDOW_NOTE)

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        empty = self.body()
        self.assertEqual(empty["events_by_type"], [])
        self.assertEqual(empty["events_by_type_omitted"], 0)
        self.assertEqual(empty["window_scope"]["note"], METRICS_WINDOW_NOTE)
        add_events(self.conn, "type_000")
        one = self.body()
        self.assertEqual(one["events_by_type_omitted"], 0)
        self.assertEqual(one["events_by_type"], [{"event_type": "type_000", "count": 1}])
        for i in range(1, EVENTS_BY_TYPE_LIMIT):
            add_events(self.conn, f"type_{i:03d}")
        exact = self.body()
        self.assertEqual(exact["events_by_type_omitted"], 0)
        self.assertEqual(len(exact["events_by_type"]), EVENTS_BY_TYPE_LIMIT)

    def test_the_docs_name_the_omitted_count(self):
        api = API.read_text()
        self.assertIn(
            "`events_by_type_omitted` is how many event types were past that cap"
            " (0 when there are 100 or fewer, including none)",
            api)
        self.assertIn("A type with no events is not a row", api)
        self.assertIn("`count` descending, then `event_type`", api)
        self.assertIn(
            "`hours` filters `events_ingested_window` by `ingested_at`, and `top_failure_ips`,"
            " `top_failure_users`, and `events_by_type` count every stored event.",
            api)


class EventsByTypeOmittedApiTests(ServerTestCase):
    def test_the_metrics_endpoint_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(EVENTS_BY_TYPE_LIMIT):
                add_events(db, f"type_{i:03d}", n=2)
            add_events(db, QUIET, n=1)
        status, body, headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["events_by_type_omitted"], 1)
        self.assertEqual(len(body["events_by_type"]), EVENTS_BY_TYPE_LIMIT)
        self.assertNotIn(QUIET, [row["event_type"] for row in body["events_by_type"]])
        self.assertTrue(all(row["count"] == 2 for row in body["events_by_type"]))
        self.assertIn("count every stored event", body["window_scope"]["note"])

    def test_an_empty_table_and_a_rejected_request(self):
        status, body, _ = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["events_by_type"], [])
        self.assertEqual(body["events_by_type_omitted"], 0)
        status, denied, _ = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("events_by_type_omitted", denied)
