"""Dashboard alert_timeline counts info on its own.

An info alert inside the window increments info and is not added to low. A bin
with none of that severity is 0. An alert outside the window stays out. events
counts event ts, not ingested_at. An empty table is no bins.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
DOC = (
    "`alert_timeline` (`bucket_minutes` 60 or 5, and 24 `bins` of "
    "`{start, critical, high, medium, low, info, events}` by event time, ending at the "
    "newest alert; 5-minute buckets when all recent alerts fall in the last 2 hours. "
    "`info` is its own count and is not added to `low`. A bin with none of that "
    "severity is 0. An alert outside the window stays out. `events` counts event "
    "`ts`, not `ingested_at`)"
)
SEVERITIES = ("critical", "high", "medium", "low", "info")


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alert(conn, severity, last_seen, key):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
        " status, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES ('brute_force_ip', 1, ?, ?, 'synthetic alert', 'why', 'open', ?, ?, 1, 1, ?, ?)",
        (key, severity, last_seen, last_seen, last_seen, last_seen))


def add_event(conn, ts, user, ingested_at):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ingested_at, "lab", "web01", "auth", "info", user, "[SYNTHETIC] alert timeline"))


def load_hourly(conn):
    # Newest last_seen is 12:40, so hourly bins run 2026-09-14T13:00 through 2026-09-15T12:00.
    add_alert(conn, "info", "2026-09-15T12:30:00.000Z", "info-a")
    add_alert(conn, "info", "2026-09-15T12:40:00.000Z", "info-b")
    add_alert(conn, "low", "2026-09-15T12:10:00.000Z", "low-noon")
    add_alert(conn, "urgent", "2026-09-15T12:20:00.000Z", "urgent-noon")
    add_alert(conn, "medium", "2026-09-15T08:00:00.000Z", "medium-eight")
    add_alert(conn, "critical", "2026-09-15T08:15:00.000Z", "critical-eight")
    add_alert(conn, "high", "2026-09-15T09:00:00.000Z", "high-nine")
    add_alert(conn, "info", "2026-09-14T13:00:00.000Z", "info-edge")
    # Before the window. Still inside the 24h zoom probe, so the buckets stay hourly.
    add_alert(conn, "info", "2026-09-14T12:30:00.000Z", "info-out")
    add_alert(conn, "low", "2026-09-13T12:00:00.000Z", "low-old")
    # ts in the noon bin, ingested long before. ts before the window, ingested at noon.
    add_event(conn, "2026-09-15T12:15:00.000Z", "synth-noon", "2026-01-01T00:00:00.000Z")
    add_event(conn, "2026-09-15T08:05:00.000Z", "synth-eight", "2026-09-15T12:15:00.000Z")
    add_event(conn, "2026-09-14T13:00:00.000Z", "synth-edge", "2026-09-14T13:00:00.000Z")
    add_event(conn, "2026-09-14T12:59:00.000Z", "synth-out", "2026-09-15T12:15:00.000Z")


def load_zoom(conn):
    # Newest is 12:07. Every alert inside 24h is also inside 2h, so buckets are 5 minutes.
    add_alert(conn, "info", "2026-09-15T12:07:30.000Z", "info-zoom")
    add_alert(conn, "low", "2026-09-15T11:00:00.000Z", "low-zoom")
    add_alert(conn, "info", "2026-09-15T10:10:00.000Z", "info-zoom-edge")
    add_alert(conn, "info", "2026-09-14T10:00:00.000Z", "info-zoom-out")
    add_event(conn, "2026-09-15T12:06:00.000Z", "synth-zoom", "2026-01-01T00:00:00.000Z")
    add_event(conn, "2026-09-15T10:00:00.000Z", "synth-zoom-out", "2026-09-15T12:06:00.000Z")


def by_start(timeline):
    return {row["start"]: row for row in timeline["bins"]}


class AlertTimelineTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def timeline(self):
        return dashboard(self.conn)["alert_timeline"]

    def test_empty_table_has_no_bins(self):
        timeline = self.timeline()
        self.assertEqual(timeline["bucket_minutes"], 60)
        self.assertEqual(timeline["bins"], [])

    def test_info_is_its_own_hourly_count_and_events_use_ts(self):
        load_hourly(self.conn)
        timeline = self.timeline()
        self.assertEqual(timeline["bucket_minutes"], 60)
        self.assertEqual(len(timeline["bins"]), 24)
        rows = by_start(timeline)
        noon = rows["2026-09-15T12:00:00.000Z"]
        eight = rows["2026-09-15T08:00:00.000Z"]
        nine = rows["2026-09-15T09:00:00.000Z"]
        ten = rows["2026-09-15T10:00:00.000Z"]
        edge = rows["2026-09-14T13:00:00.000Z"]
        self.assertEqual(noon["info"], 2)
        self.assertEqual(noon["low"], 1)
        self.assertEqual(noon["critical"], 0)
        self.assertEqual(noon["high"], 0)
        self.assertEqual(noon["medium"], 0)
        self.assertEqual(noon["events"], 1)
        self.assertEqual(eight["info"], 0)
        self.assertEqual(eight["medium"], 1)
        self.assertEqual(eight["critical"], 1)
        self.assertEqual(eight["events"], 1)
        self.assertEqual(nine["high"], 1)
        self.assertEqual(nine["info"], 0)
        self.assertEqual(nine["events"], 0)
        self.assertEqual([ten[name] for name in (*SEVERITIES, "events")], [0, 0, 0, 0, 0, 0])
        self.assertEqual(edge["info"], 1)
        self.assertEqual(edge["events"], 1)
        counted = {name: sum(row[name] for row in timeline["bins"]) for name in SEVERITIES}
        self.assertEqual(counted, {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 3})
        self.assertEqual(sum(row["events"] for row in timeline["bins"]), 3)
        self.assertNotIn("2026-09-14T12:00:00.000Z", rows)
        for row in timeline["bins"]:
            self.assertEqual(set(row), {"start", *SEVERITIES, "events"})

    def test_a_live_window_counts_info_on_five_minute_bins(self):
        load_zoom(self.conn)
        timeline = self.timeline()
        self.assertEqual(timeline["bucket_minutes"], 5)
        self.assertEqual(len(timeline["bins"]), 24)
        rows = by_start(timeline)
        last = rows["2026-09-15T12:05:00.000Z"]
        eleven = rows["2026-09-15T11:00:00.000Z"]
        edge = rows["2026-09-15T10:10:00.000Z"]
        quiet = rows["2026-09-15T10:15:00.000Z"]
        self.assertEqual(last["info"], 1)
        self.assertEqual(last["low"], 0)
        self.assertEqual(last["events"], 1)
        self.assertEqual(eleven["low"], 1)
        self.assertEqual(eleven["info"], 0)
        self.assertEqual(eleven["events"], 0)
        self.assertEqual(edge["info"], 1)
        self.assertEqual(edge["events"], 0)
        self.assertEqual([quiet[name] for name in (*SEVERITIES, "events")], [0, 0, 0, 0, 0, 0])
        counted = {name: sum(row[name] for row in timeline["bins"]) for name in SEVERITIES}
        self.assertEqual(counted["info"], 2)
        self.assertEqual(counted["low"], 1)
        self.assertEqual(sum(row["events"] for row in timeline["bins"]), 1)
        self.assertEqual(timeline["bins"][0]["start"], "2026-09-15T10:10:00.000Z")
        self.assertEqual(timeline["bins"][-1]["start"], "2026-09-15T12:05:00.000Z")

    def test_the_docs_name_the_info_count(self):
        self.assertIn(DOC, API.read_text())


class AlertTimelineApiTests(ServerTestCase):
    def test_the_dashboard_returns_info_on_each_bin(self):
        with sqlite3.connect(self.db_path) as db:
            load_hourly(db)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        timeline = body["alert_timeline"]
        self.assertEqual(timeline["bucket_minutes"], 60)
        rows = by_start(timeline)
        noon = rows["2026-09-15T12:00:00.000Z"]
        self.assertEqual(noon["info"], 2)
        self.assertEqual(noon["low"], 1)
        self.assertEqual(rows["2026-09-15T10:00:00.000Z"]["info"], 0)
        self.assertEqual(sum(row["info"] for row in timeline["bins"]), 3)
        self.assertEqual(sum(row["low"] for row in timeline["bins"]), 1)
        self.assertEqual(sum(row["events"] for row in timeline["bins"]), 3)
        self.assertEqual(body["alerts_total"], 10)

    def test_an_empty_timeline_and_a_rejected_request(self):
        status, body, _ = self.client("viewer").get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["alert_timeline"], {"bucket_minutes": 60, "bins": []})
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("alert_timeline", denied)
