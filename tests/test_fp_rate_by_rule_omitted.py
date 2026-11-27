"""Metrics false_positive_rate_by_rule says how many rule ids the cap of 100 dropped.

The rows stay the rule ids with a disposition, false-positive rate descending,
then rule_id. A quieter rule is the one left out. Equal rates keep the lower
rule_id. A rule with no disposition is not a row and is not omitted. A list
that fits, including an empty table, returns 0. omitted_metrics and the
window_scope note stay as they are.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR
from watchpost.db import connect, init_schema
from watchpost.queries import FP_RATE_BY_RULE_LIMIT, METRICS_WINDOW_NOTE, OMITTED_METRICS, metrics

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
QUIET = "zzz_quiet"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alerts(conn, rule_id, n=1, disposition="false_positive"):
    conn.executemany(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(rule_id, 1, f"{rule_id}|{disposition}|{i}", "medium", "synthetic alert", "why", "resolved",
          disposition, ANCHOR, ANCHOR, 1, 1, ANCHOR, ANCHOR) for i in range(n)])


class FalsePositiveRateOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def body(self):
        return metrics(self.conn)

    def test_a_quieter_rule_is_the_one_past_the_cap(self):
        kept = [f"rule_{i:03d}" for i in range(FP_RATE_BY_RULE_LIMIT)]
        for rule_id in kept:
            add_alerts(self.conn, rule_id)
        add_alerts(self.conn, QUIET, disposition="true_positive")
        add_alerts(self.conn, "idle_rule", disposition=None)
        body = self.body()
        ids = [row["rule_id"] for row in body["false_positive_rate_by_rule"]]
        self.assertEqual(body["false_positive_rate_by_rule_omitted"], 1)
        self.assertEqual(ids, kept)
        self.assertNotIn(QUIET, ids)
        self.assertNotIn("idle_rule", ids)
        self.assertTrue(all(row["false_positive_rate"] == 1.0 for row in body["false_positive_rate_by_rule"]))

    def test_equal_rates_keep_the_lower_rule_id(self):
        kept = [f"rule_{i:03d}" for i in range(FP_RATE_BY_RULE_LIMIT)]
        for rule_id in kept:
            add_alerts(self.conn, rule_id, n=1, disposition="false_positive")
            add_alerts(self.conn, rule_id, n=1, disposition="true_positive")
        add_alerts(self.conn, QUIET, n=1, disposition="false_positive")
        add_alerts(self.conn, QUIET, n=1, disposition="true_positive")
        body = self.body()
        ids = [row["rule_id"] for row in body["false_positive_rate_by_rule"]]
        self.assertEqual(body["false_positive_rate_by_rule_omitted"], 1)
        self.assertEqual(ids, kept)
        self.assertNotIn(QUIET, ids)
        self.assertTrue(all(row["false_positive_rate"] == 0.5 for row in body["false_positive_rate_by_rule"]))
        self.assertTrue(all(row["reviewed"] == 2 and row["false_positive"] == 1 and row["benign"] == 0
                            for row in body["false_positive_rate_by_rule"]))

    def test_a_higher_rate_outranks_a_quieter_rule(self):
        for i in range(FP_RATE_BY_RULE_LIMIT):
            add_alerts(self.conn, f"rule_{i:03d}", disposition="true_positive")
        add_alerts(self.conn, "zzz_loud", disposition="false_positive")
        body = self.body()
        ids = [row["rule_id"] for row in body["false_positive_rate_by_rule"]]
        self.assertEqual(body["false_positive_rate_by_rule_omitted"], 1)
        self.assertEqual(ids[0], "zzz_loud")
        self.assertEqual(ids[1:], [f"rule_{i:03d}" for i in range(FP_RATE_BY_RULE_LIMIT - 1)])
        self.assertNotIn("rule_099", ids)
        self.assertEqual(body["false_positive_rate_by_rule"][0]["false_positive_rate"], 1.0)

    def test_a_rule_with_no_disposition_is_not_counted(self):
        add_alerts(self.conn, "reviewed", disposition="benign")
        add_alerts(self.conn, "open_rule", disposition=None)
        body = self.body()
        self.assertEqual(body["false_positive_rate_by_rule_omitted"], 0)
        self.assertEqual(body["false_positive_rate_by_rule"],
                         [{"rule_id": "reviewed", "reviewed": 1, "false_positive": 0, "benign": 1,
                           "false_positive_rate": 0.0}])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        empty = self.body()
        self.assertEqual(empty["false_positive_rate_by_rule"], [])
        self.assertEqual(empty["false_positive_rate_by_rule_omitted"], 0)
        self.assertEqual(empty["omitted_metrics"], OMITTED_METRICS)
        self.assertEqual(empty["window_scope"]["note"], METRICS_WINDOW_NOTE)
        add_alerts(self.conn, "rule_000", disposition="benign")
        one = self.body()
        self.assertEqual(one["false_positive_rate_by_rule_omitted"], 0)
        self.assertEqual(one["false_positive_rate_by_rule"],
                         [{"rule_id": "rule_000", "reviewed": 1, "false_positive": 0, "benign": 1,
                           "false_positive_rate": 0.0}])
        for i in range(1, FP_RATE_BY_RULE_LIMIT):
            add_alerts(self.conn, f"rule_{i:03d}")
        exact = self.body()
        self.assertEqual(exact["false_positive_rate_by_rule_omitted"], 0)
        self.assertEqual(len(exact["false_positive_rate_by_rule"]), FP_RATE_BY_RULE_LIMIT)
        self.assertEqual(exact["omitted_metrics"], OMITTED_METRICS)
        self.assertEqual(exact["window_scope"]["note"], METRICS_WINDOW_NOTE)

    def test_the_docs_name_the_omitted_count(self):
        api = API.read_text()
        self.assertIn(
            "`false_positive_rate_by_rule_omitted` is how many of those rule ids were past that cap"
            " (0 when there are 100 or fewer, including none)",
            api)
        self.assertIn("A rule with no disposition is not a row and is not omitted", api)
        self.assertIn("false-positive rate descending, then `rule_id`", api)
        self.assertIn(
            "`hours` filters `events_ingested_window` by `ingested_at`, and `top_failure_ips`,"
            " `top_failure_users`, and `events_by_type` count every stored event.",
            api)
        self.assertIn("`omitted_metrics` still names time to detect and dwell time.", api)


class FalsePositiveRateOmittedApiTests(ServerTestCase):
    def test_the_metrics_endpoint_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(FP_RATE_BY_RULE_LIMIT):
                add_alerts(db, f"rule_{i:03d}")
            add_alerts(db, QUIET, disposition="true_positive")
            add_alerts(db, "idle_rule", disposition=None)
        status, body, headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["false_positive_rate_by_rule_omitted"], 1)
        ids = [row["rule_id"] for row in body["false_positive_rate_by_rule"]]
        self.assertEqual(len(ids), FP_RATE_BY_RULE_LIMIT)
        self.assertNotIn(QUIET, ids)
        self.assertNotIn("idle_rule", ids)
        self.assertTrue(all(row["false_positive_rate"] == 1.0 for row in body["false_positive_rate_by_rule"]))
        self.assertEqual([row["metric"] for row in body["omitted_metrics"]],
                         ["time_to_detect", "dwell_time"])
        self.assertEqual(body["window_scope"]["note"], METRICS_WINDOW_NOTE)

    def test_an_empty_table_and_a_rejected_request(self):
        status, body, _ = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["false_positive_rate_by_rule"], [])
        self.assertEqual(body["false_positive_rate_by_rule_omitted"], 0)
        status, denied, _ = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("false_positive_rate_by_rule_omitted", denied)
