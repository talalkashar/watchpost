"""rule_performance reads alert counts once, grouped by rule_id.

A rule with no alerts is still present, with zeros and precision None.
A resolved alert with no disposition counts as resolved and not as tp.
Benign is not part of precision. An alert for an unknown rule is not a key.
"""

import sqlite3
import unittest

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.engine import seed_rules
from watchpost.improve import rule_performance

TS = "2026-09-15T12:00:00.000Z"


def add_alert(conn, rule_id, status, disposition, group_key):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
        " status, disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?, 1, ?, 'medium', 'synthetic alert', 'why', ?, ?, ?, ?, 1, 1, ?, ?)",
        (rule_id, group_key, status, disposition, TS, TS, TS, TS))


class RulePerformanceTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        seed_rules(self.conn)
        self.addCleanup(self.conn.close)

    def test_one_group_query_keeps_the_same_counts(self):
        add_alert(self.conn, "brute_force_ip", "open", None, "open")
        add_alert(self.conn, "brute_force_ip", "investigating", None, "investigating")
        add_alert(self.conn, "brute_force_ip", "resolved", "true_positive", "tp")
        add_alert(self.conn, "brute_force_ip", "resolved", "false_positive", "fp")
        add_alert(self.conn, "brute_force_ip", "resolved", "benign", "benign")
        add_alert(self.conn, "brute_force_ip", "resolved", None, "unlabeled")
        add_alert(self.conn, "not_a_rule", "open", "true_positive", "orphan")
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append(sql)
            return real_execute(sql, args)

        self.conn.execute = execute
        perf = rule_performance(self.conn)
        grouped = [sql for sql in captured if "FROM alerts" in sql]
        self.assertEqual(len(grouped), 1)
        self.assertIn("GROUP BY rule_id", grouped[0])
        self.assertNotIn("WHERE rule_id", grouped[0])
        self.assertEqual(perf["brute_force_ip"], {
            "total": 6, "open": 1, "investigating": 1, "resolved": 4,
            "tp": 1, "fp": 1, "benign": 1, "precision": 0.5,
        })
        quiet = {
            "total": 0, "open": 0, "investigating": 0, "resolved": 0,
            "tp": 0, "fp": 0, "benign": 0, "precision": None,
        }
        self.assertEqual(perf["password_spray"], quiet)
        self.assertIsNot(perf["password_spray"], perf["web_scanner"])
        self.assertEqual(perf["web_scanner"], quiet)
        self.assertNotIn("not_a_rule", perf)
        self.assertEqual(len(perf), 15)

    def test_a_resolved_alert_with_no_disposition_is_not_a_true_positive(self):
        add_alert(self.conn, "web_scanner", "resolved", None, "only")
        perf = rule_performance(self.conn)["web_scanner"]
        self.assertEqual(perf["resolved"], 1)
        self.assertEqual((perf["tp"], perf["fp"], perf["benign"], perf["precision"]), (0, 0, 0, None))
        self.assertEqual(perf["total"], 1)
        self.assertEqual(perf["open"], 0)


class RulePerformanceApiTests(ServerTestCase):
    def test_the_rules_endpoint_returns_the_grouped_counts(self):
        with sqlite3.connect(self.db_path) as db:
            add_alert(db, "brute_force_ip", "open", None, "open")
            add_alert(db, "brute_force_ip", "resolved", "true_positive", "tp")
            add_alert(db, "brute_force_ip", "resolved", "false_positive", "fp")
            add_alert(db, "brute_force_ip", "resolved", None, "unlabeled")
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/rules")
        self.assertEqual(status, 200, body)
        by_id = {row["id"]: row["performance"] for row in body}
        self.assertEqual(by_id["brute_force_ip"], {
            "total": 4, "open": 1, "investigating": 0, "resolved": 3,
            "tp": 1, "fp": 1, "benign": 0, "precision": 0.5,
        })
        self.assertEqual(by_id["password_spray"]["total"], 0)
        self.assertIsNone(by_id["password_spray"]["precision"])
        status, denied, headers = self.client().get("/api/rules")
        self.assertEqual(status, 401)
        self.assertNotIn("performance", denied)
        self.assertIsNone(headers.get("X-Watchpost-Omitted"))
