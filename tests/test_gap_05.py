"""active_rule_suppressions keeps only windows that contain now.

A window is included when starts_at <= now < expires_at and ended_at is
NULL. A future, expired, or ended window is left out.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from watchpost.db import connect, init_schema, iso
from watchpost.engine import active_rule_suppressions

NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
NOW_ISO = iso(NOW)
INSERT = (
    "INSERT INTO rule_suppression_windows(rule_id, starts_at, expires_at, reason,"
    " proposed_by, approved_by, created_at, ended_at, ended_by)"
    " VALUES (?, ?, ?, 'planned maintenance', 'analyst', 'admin', ?, ?, ?)"
)


def at(delta):
    return iso(NOW + delta)


class ActiveRuleSuppressionsTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        patcher = patch("watchpost.engine.now_iso", return_value=NOW_ISO)
        patcher.start()
        self.addCleanup(patcher.stop)

    def add(self, rule_id, starts_at, expires_at, ended_at=None, ended_by=None):
        self.conn.execute(
            INSERT,
            (rule_id, starts_at, expires_at, NOW_ISO, ended_at, ended_by),
        )

    def test_open_window_containing_now_is_included(self):
        # starts_at before now, and starts_at equal to now, both count.
        # expires_at must be strictly later than now.
        self.add("brute_force_ip", at(timedelta(minutes=-30)), at(timedelta(hours=2)))
        self.add("starts_now", NOW_ISO, at(timedelta(milliseconds=1)))
        self.assertEqual(
            active_rule_suppressions(self.conn),
            {"brute_force_ip", "starts_now"},
        )

    def test_future_expired_and_ended_windows_are_left_out(self):
        self.add("open_rule", at(timedelta(minutes=-5)), at(timedelta(hours=1)))
        self.add("future_rule", at(timedelta(milliseconds=1)), at(timedelta(hours=1)))
        self.add("later_rule", at(timedelta(hours=1)), at(timedelta(hours=2)))
        self.add("expired_rule", at(timedelta(hours=-2)), at(timedelta(minutes=-1)))
        # now < expires_at is exclusive, so a window that expires at now is out.
        self.add("expires_now", at(timedelta(hours=-1)), NOW_ISO)
        self.add(
            "ended_rule",
            at(timedelta(minutes=-10)),
            at(timedelta(hours=1)),
            ended_at=at(timedelta(minutes=-1)),
            ended_by="admin",
        )
        self.assertEqual(active_rule_suppressions(self.conn), {"open_rule"})

    def test_empty_table_is_an_empty_set_and_duplicates_collapse(self):
        self.assertEqual(active_rule_suppressions(self.conn), set())
        self.add("brute_force_ip", at(timedelta(hours=-1)), at(timedelta(hours=1)))
        self.add("brute_force_ip", NOW_ISO, at(timedelta(hours=3)))
        self.add(
            "brute_force_ip",
            at(timedelta(hours=-2)),
            at(timedelta(hours=2)),
            ended_at=NOW_ISO,
            ended_by="admin",
        )
        self.assertEqual(active_rule_suppressions(self.conn), {"brute_force_ip"})
