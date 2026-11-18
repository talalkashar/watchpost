"""Open-alert aging is one aggregate, not one row per alert.

Buckets stay under 1h, 1-4h, 4-24h, 1-7d, and over 7d. An age on a boundary
belongs to the older bucket. A resolved alert is not counted. An empty open
set is five zeros and oldest_minutes None.
"""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import open_alert_aging

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


def minutes_ago(minutes):
    return iso(NOW - timedelta(minutes=minutes))


def add_alert(conn, created_at, status="open", group_key=None):
    key = group_key or f"{status}-{created_at}"
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
        " status, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES ('brute_force_ip', 1, ?, 'medium', 'synthetic alert', 'why', ?, ?, ?, 1, 1, ?, ?)",
        (key, status, created_at, created_at, created_at, created_at))


class OpenAlertAgingTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_empty_open_set_is_zeros_and_a_resolved_alert_stays_out(self):
        add_alert(self.conn, minutes_ago(10080), status="resolved")
        aging = open_alert_aging(self.conn, NOW)
        self.assertEqual(
            [(b["label"], b["count"]) for b in aging["buckets"]],
            [("under 1h", 0), ("1-4h", 0), ("4-24h", 0), ("1-7d", 0), ("over 7d", 0)])
        self.assertIsNone(aging["oldest_minutes"])

    def test_boundaries_keep_the_older_bucket(self):
        # 60 minutes minus 1 ms stays under 1h. Exactly 60 is 1-4h.
        add_alert(self.conn, minutes_ago(0), group_key="now")
        add_alert(self.conn, iso(NOW - timedelta(minutes=60) + timedelta(milliseconds=1)), group_key="just-under")
        add_alert(self.conn, minutes_ago(60), group_key="hour")
        add_alert(self.conn, minutes_ago(240), group_key="four")
        add_alert(self.conn, minutes_ago(1440), group_key="day")
        add_alert(self.conn, iso(NOW - timedelta(minutes=10080) + timedelta(milliseconds=1)), group_key="just-under-week")
        add_alert(self.conn, minutes_ago(10080), group_key="week")
        add_alert(self.conn, minutes_ago(30), group_key="second-under")
        add_alert(self.conn, minutes_ago(60 * 30), status="investigating", group_key="thirty-hours")
        add_alert(self.conn, minutes_ago(10080), status="resolved", group_key="closed")
        aging = open_alert_aging(self.conn, NOW)
        self.assertEqual(
            {b["label"]: b["count"] for b in aging["buckets"]},
            {"under 1h": 3, "1-4h": 1, "4-24h": 1, "1-7d": 3, "over 7d": 1})
        self.assertEqual(aging["oldest_minutes"], 10080.0)

    def test_a_future_alert_matches_no_bucket(self):
        add_alert(self.conn, minutes_ago(-5))
        aging = open_alert_aging(self.conn, NOW)
        self.assertEqual(sum(b["count"] for b in aging["buckets"]), 0)
        self.assertEqual(aging["oldest_minutes"], -5.0)

    def test_oldest_minutes_keeps_half_even_rounding(self):
        # 1.25 minutes. Python round half to even is 1.2; SQLite ROUND would be 1.3.
        add_alert(self.conn, iso(NOW - timedelta(seconds=75)))
        self.assertEqual(open_alert_aging(self.conn, NOW)["oldest_minutes"], 1.2)

    def test_one_aggregate_does_not_read_each_created_at(self):
        add_alert(self.conn, minutes_ago(10), group_key="a")
        add_alert(self.conn, minutes_ago(90), group_key="b")
        add_alert(self.conn, minutes_ago(3000), group_key="c")
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append((sql, args))
            return real_execute(sql, args)

        self.conn.execute = execute
        aging = open_alert_aging(self.conn, NOW)
        self.assertEqual(len(captured), 1)
        sql, args = captured[0]
        self.assertIn("SUM(", sql)
        self.assertIn("MAX(age)", sql)
        self.assertIn("status != 'resolved'", sql)
        self.assertIn("unixepoch", sql)
        self.assertNotIn("julianday", sql)
        self.assertNotIn("SELECT created_at FROM", sql)
        self.assertEqual(args, (iso(NOW), iso(NOW)))
        self.assertEqual(
            {b["label"]: b["count"] for b in aging["buckets"]},
            {"under 1h": 1, "1-4h": 1, "4-24h": 0, "1-7d": 1, "over 7d": 0})


class OpenAlertAgingApiTests(ServerTestCase):
    def test_metrics_uses_the_buckets_and_a_401_has_no_field(self):
        created = iso(datetime.now(timezone.utc) - timedelta(minutes=30))
        old = iso(datetime.now(timezone.utc) - timedelta(hours=30))
        with sqlite3.connect(self.db_path) as db:
            add_alert(db, created, group_key="recent")
            add_alert(db, old, status="investigating", group_key="old")
            add_alert(db, old, status="resolved", group_key="closed")
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/metrics")
        self.assertEqual(status, 200, body)
        aging = body["open_alert_aging"]
        self.assertEqual(
            [b["label"] for b in aging["buckets"]],
            ["under 1h", "1-4h", "4-24h", "1-7d", "over 7d"])
        counts = {b["label"]: b["count"] for b in aging["buckets"]}
        self.assertEqual(counts["under 1h"], 1)
        self.assertEqual(counts["1-7d"], 1)
        self.assertEqual(sum(counts.values()), 2)
        self.assertAlmostEqual(aging["oldest_minutes"], 30 * 60, delta=1)
        status, denied, _ = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("open_alert_aging", denied)
