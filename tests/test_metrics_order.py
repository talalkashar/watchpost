"""Metrics severity and disposition lists stay in catalog order.

alerts_by_severity is critical, high, medium, low, then info. dispositions is
true_positive, false_positive, then benign. A name with no rows is not
invented. An empty table is an empty list. window_scope stays as it is.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import (
    DISPOSITION_ORDER_SQL,
    METRICS_ALL_STORED_EVENTS,
    METRICS_HONORS_HOURS,
    METRICS_NEWEST_24H,
    METRICS_WINDOW_NOTE,
    SEVERITY_RANK_SQL,
    metrics,
)

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
STAMP = "2026-09-15T12:00:00.000Z"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alert(conn, severity, status="open", disposition=None, key=None):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
        " status, disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES ('brute_force_ip', 1, ?, ?, 'synthetic alert', 'why', ?, ?, ?, ?, 1, 1, ?, ?)",
        (key or f"{severity}-{status}-{disposition}", severity, status, disposition,
         STAMP, STAMP, STAMP, STAMP))


class MetricsOrderTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_empty_table_is_two_empty_lists(self):
        body = metrics(self.conn)
        self.assertEqual(body["alerts_by_severity"], [])
        self.assertEqual(body["dispositions"], [])
        self.assertEqual(body["window_scope"]["note"], METRICS_WINDOW_NOTE)
        self.assertEqual(body["window_scope"]["honors_hours"], list(METRICS_HONORS_HOURS))
        self.assertEqual(body["window_scope"]["all_stored_events"], list(METRICS_ALL_STORED_EVENTS))
        self.assertEqual(body["window_scope"]["newest_event_24h"], list(METRICS_NEWEST_24H))

    def test_catalog_order_ignores_insert_order_and_skips_empty_names(self):
        # Insert the quiet end first so a scan-order read would not match the catalog.
        for severity in reversed(SEVERITY_ORDER):
            if severity == "medium":
                continue
            add_alert(self.conn, severity, key=f"open-{severity}")
        add_alert(self.conn, "info", status="investigating", key="info-2")
        add_alert(self.conn, "critical", status="resolved", disposition="true_positive", key="closed")
        # benign first, then false_positive. true_positive is the resolved row above.
        add_alert(self.conn, "low", status="resolved", disposition="benign", key="benign-1")
        add_alert(self.conn, "low", status="resolved", disposition="benign", key="benign-2")
        add_alert(self.conn, "high", status="resolved", disposition="false_positive", key="fp")
        add_alert(self.conn, "high", status="open", disposition=None, key="open-no-disp")
        body = metrics(self.conn)
        self.assertEqual(
            body["alerts_by_severity"],
            [{"severity": "critical", "count": 1},
             {"severity": "high", "count": 2},
             {"severity": "low", "count": 1},
             {"severity": "info", "count": 2}])
        self.assertNotIn("medium", [row["severity"] for row in body["alerts_by_severity"]])
        self.assertEqual(
            body["dispositions"],
            [{"disposition": "true_positive", "count": 1},
             {"disposition": "false_positive", "count": 1},
             {"disposition": "benign", "count": 2}])
        self.assertEqual(body["window_scope"]["note"], METRICS_WINDOW_NOTE)

    def test_a_missing_disposition_is_not_invented(self):
        add_alert(self.conn, "low", status="resolved", disposition="benign", key="only-benign")
        body = metrics(self.conn)
        self.assertEqual(body["alerts_by_severity"], [])
        self.assertEqual(body["dispositions"], [{"disposition": "benign", "count": 1}])

    def test_the_queries_order_by_the_catalog(self):
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append(sql)
            return real_execute(sql, args)

        self.conn.execute = execute
        metrics(self.conn)
        severity = next(sql for sql in captured if "FROM alerts WHERE status != 'resolved'" in sql
                        and "GROUP BY severity" in sql)
        disposition = next(sql for sql in captured if "disposition IS NOT NULL" in sql
                           and "GROUP BY disposition" in sql)
        self.assertIn("ORDER BY " + SEVERITY_RANK_SQL.format(col="severity") + " DESC", severity)
        self.assertIn("ORDER BY " + DISPOSITION_ORDER_SQL.format(col="disposition"), disposition)
        self.assertNotIn("GROUP BY severity ORDER BY count", severity)

    def test_the_docs_name_the_catalog_order(self):
        api = API.read_text()
        self.assertIn(
            "`alerts_by_severity` is open and investigating alerts, ordered `critical`, `high`,"
            " `medium`, `low`, then `info`",
            api)
        self.assertIn(
            "`dispositions` is alerts that have a disposition, ordered `true_positive`,"
            " `false_positive`, then `benign`",
            api)
        self.assertIn("An empty alerts table is an empty list for both", api)
        self.assertIn("`window_scope` does not change", api)


class MetricsOrderApiTests(ServerTestCase):
    def test_the_metrics_endpoint_returns_catalog_order(self):
        with sqlite3.connect(self.db_path) as db:
            for severity in ("info", "low", "critical"):
                add_alert(db, severity, key=f"open-{severity}")
            add_alert(db, "medium", status="resolved", disposition="benign", key="benign")
            add_alert(db, "high", status="resolved", disposition="false_positive", key="fp")
            add_alert(db, "critical", status="resolved", disposition="true_positive", key="tp")
        status, body, headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(
            [row["severity"] for row in body["alerts_by_severity"]],
            ["critical", "low", "info"])
        self.assertEqual(
            [row["disposition"] for row in body["dispositions"]],
            ["true_positive", "false_positive", "benign"])
        self.assertEqual(body["window_scope"]["note"], METRICS_WINDOW_NOTE)
        status, denied, _ = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("alerts_by_severity", denied)
        self.assertNotIn("dispositions", denied)
