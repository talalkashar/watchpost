"""Metrics alerts_by_rule says how many rule ids the cap of 100 dropped.

The rows stay the rule ids with the most alerts, then rule_id. A quieter rule
is the one left out. Equal counts keep the lower rule_id. A rule with no
alerts is not a row and is not omitted. A resolved alert still counts. A list
that fits, including an empty table, returns 0.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR
from watchpost.db import connect, init_schema
from watchpost.queries import ALERTS_BY_RULE_LIMIT, metrics

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
QUIET = "zzz_quiet"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_rule(conn, rule_id):
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, updated_at, updated_by)"
        " VALUES (?,?,?,?,1,'{}',?,?)",
        (rule_id, rule_id, "synthetic", "medium", ANCHOR, "test"))


def add_alerts(conn, rule_id, n=1, status="open"):
    conn.executemany(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(rule_id, 1, f"{rule_id}|{i}", "medium", "synthetic alert", "why", status, ANCHOR, ANCHOR,
          1, 1, ANCHOR, ANCHOR) for i in range(n)])


class AlertsByRuleOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def body(self):
        return metrics(self.conn)

    def test_a_quieter_rule_is_the_one_past_the_cap(self):
        kept = [f"rule_{i:03d}" for i in range(ALERTS_BY_RULE_LIMIT)]
        for rule_id in kept:
            add_alerts(self.conn, rule_id, n=2)
        add_alerts(self.conn, QUIET, n=1)
        add_rule(self.conn, "idle_rule")
        body = self.body()
        ids = [row["rule_id"] for row in body["alerts_by_rule"]]
        self.assertEqual(body["alerts_by_rule_omitted"], 1)
        self.assertEqual(ids, kept)
        self.assertNotIn(QUIET, ids)
        self.assertNotIn("idle_rule", ids)
        self.assertTrue(all(row["count"] == 2 for row in body["alerts_by_rule"]))

    def test_equal_counts_keep_the_lower_rule_id_and_a_resolved_alert_still_counts(self):
        kept = [f"rule_{i:03d}" for i in range(ALERTS_BY_RULE_LIMIT)]
        for rule_id in kept:
            add_alerts(self.conn, rule_id, n=1)
        add_alerts(self.conn, QUIET, n=1, status="resolved")
        body = self.body()
        ids = [row["rule_id"] for row in body["alerts_by_rule"]]
        self.assertEqual(body["alerts_by_rule_omitted"], 1)
        self.assertEqual(ids, kept)
        self.assertNotIn(QUIET, ids)
        self.assertTrue(all(row["count"] == 1 for row in body["alerts_by_rule"]))

    def test_more_alerts_outrank_a_quieter_rule(self):
        add_alerts(self.conn, "busy", n=2)
        add_alerts(self.conn, "busy", n=1, status="resolved")
        add_alerts(self.conn, "quiet", n=1)
        body = self.body()
        self.assertEqual(body["alerts_by_rule_omitted"], 0)
        self.assertEqual(body["alerts_by_rule"],
                         [{"rule_id": "busy", "count": 3}, {"rule_id": "quiet", "count": 1}])

    def test_a_rule_with_no_alerts_is_not_counted(self):
        add_rule(self.conn, "idle")
        add_alerts(self.conn, "busy", n=1)
        body = self.body()
        self.assertEqual(body["alerts_by_rule_omitted"], 0)
        self.assertEqual(body["alerts_by_rule"], [{"rule_id": "busy", "count": 1}])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        empty = self.body()
        self.assertEqual(empty["alerts_by_rule"], [])
        self.assertEqual(empty["alerts_by_rule_omitted"], 0)
        add_alerts(self.conn, "rule_000")
        one = self.body()
        self.assertEqual(one["alerts_by_rule_omitted"], 0)
        self.assertEqual(one["alerts_by_rule"], [{"rule_id": "rule_000", "count": 1}])
        for i in range(1, ALERTS_BY_RULE_LIMIT):
            add_alerts(self.conn, f"rule_{i:03d}")
        exact = self.body()
        self.assertEqual(exact["alerts_by_rule_omitted"], 0)
        self.assertEqual(len(exact["alerts_by_rule"]), ALERTS_BY_RULE_LIMIT)

    def test_the_docs_name_the_omitted_count(self):
        api = API.read_text()
        self.assertIn(
            "`alerts_by_rule_omitted` is how many rule ids were past that cap"
            " (0 when there are 100 or fewer, including none)",
            api)
        self.assertIn("A rule with no alerts is not a row and is not omitted", api)
        self.assertIn("A resolved alert still counts", api)
        self.assertIn("`count` descending, then `rule_id`", api)


class AlertsByRuleOmittedApiTests(ServerTestCase):
    def test_the_metrics_endpoint_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(ALERTS_BY_RULE_LIMIT):
                add_alerts(db, f"rule_{i:03d}", n=2)
            add_alerts(db, QUIET, n=1)
        status, body, headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["alerts_by_rule_omitted"], 1)
        self.assertEqual(len(body["alerts_by_rule"]), ALERTS_BY_RULE_LIMIT)
        self.assertNotIn(QUIET, [row["rule_id"] for row in body["alerts_by_rule"]])
        self.assertTrue(all(row["count"] == 2 for row in body["alerts_by_rule"]))

    def test_an_empty_table_and_a_rejected_request(self):
        status, body, _ = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["alerts_by_rule"], [])
        self.assertEqual(body["alerts_by_rule_omitted"], 0)
        status, denied, _ = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("alerts_by_rule_omitted", denied)
