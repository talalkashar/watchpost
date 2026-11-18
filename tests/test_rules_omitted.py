"""The dashboard top-rules list says how many rule ids the cap dropped.

The rows stay the rule ids with the most alerts, then rule_id. A quieter rule
is the one left out when 10 busier rules fill the list. Equal counts keep the
lower rule_id. A list that fits, including an empty table, returns
rules_omitted 0. A rule with no alerts is not in that count.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR
from watchpost.db import connect, init_schema
from watchpost.queries import TOP_RULE_LIMIT, dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
QUIET = "zzz_quiet"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_rule(conn, rule_id, name, severity="medium"):
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, updated_at, updated_by)"
        " VALUES (?,?,?,?,1,'{}',?,?)",
        (rule_id, name, "synthetic", severity, ANCHOR, "test"))


def add_alerts(conn, rule_id, n=1, status="open"):
    for _ in range(n):
        conn.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rule_id, 1, "k", "medium", "synthetic alert", "why", status, ANCHOR, ANCHOR, 1, 1,
             ANCHOR, ANCHOR))


class RulesOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def board(self):
        body = dashboard(self.conn)
        return body["rules_omitted"], [row["rule_id"] for row in body["top_rules"]]

    def test_a_quieter_rule_is_the_one_past_the_cap(self):
        kept = [f"rule_{i:02d}" for i in range(TOP_RULE_LIMIT)]
        for rule_id in kept:
            add_alerts(self.conn, rule_id, n=2)
        add_alerts(self.conn, QUIET, n=1)
        omitted, ids = self.board()
        self.assertEqual(omitted, 1)
        self.assertEqual(ids, kept)
        self.assertNotIn(QUIET, ids)

    def test_equal_counts_keep_the_lower_rule_id(self):
        # The later name is inserted first. Order is rule_id, not insert order.
        add_alerts(self.conn, QUIET, n=1, status="resolved")
        kept = [f"rule_{i:02d}" for i in range(TOP_RULE_LIMIT)]
        for rule_id in reversed(kept):
            add_alerts(self.conn, rule_id, n=1)
        add_rule(self.conn, "idle", "Idle rule")
        omitted, ids = self.board()
        self.assertEqual(omitted, 1)
        self.assertEqual(ids, kept)
        self.assertNotIn(QUIET, ids)
        self.assertNotIn("idle", ids)
        rows = {r["rule_id"]: r for r in dashboard(self.conn)["top_rules"]}
        self.assertTrue(all(row["alerts"] == 1 for row in rows.values()))
        self.assertEqual(rows["rule_00"]["open"], 1)

    def test_more_alerts_outrank_a_quieter_rule(self):
        add_rule(self.conn, "busy", "Busy rule", "high")
        add_alerts(self.conn, "busy", n=3)
        add_alerts(self.conn, "mid", n=2)
        add_alerts(self.conn, "quiet", n=1, status="resolved")
        omitted, ids = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(ids, ["busy", "mid", "quiet"])
        rows = {r["rule_id"]: r for r in dashboard(self.conn)["top_rules"]}
        self.assertEqual(rows["busy"]["alerts"], 3)
        self.assertEqual(rows["busy"]["open"], 3)
        self.assertEqual(rows["busy"]["name"], "Busy rule")
        self.assertEqual(rows["busy"]["severity"], "high")
        self.assertEqual(rows["mid"]["name"], None)
        self.assertEqual(rows["quiet"]["alerts"], 1)
        self.assertEqual(rows["quiet"]["open"], 0)

    def test_a_rule_with_no_alerts_is_not_counted(self):
        add_rule(self.conn, "idle", "Idle rule")
        add_alerts(self.conn, "busy", n=1)
        omitted, ids = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(ids, ["busy"])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        self.assertEqual(self.board(), (0, []))
        add_alerts(self.conn, "rule_00")
        self.assertEqual(self.board(), (0, ["rule_00"]))
        for i in range(1, TOP_RULE_LIMIT):
            add_alerts(self.conn, f"rule_{i:02d}")
        omitted, ids = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(len(ids), TOP_RULE_LIMIT)

    def test_the_docs_name_rules_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`rules_omitted` is how many rule ids on alerts were past that cap"
            " (0 when there are 10 or fewer)",
            api)
        self.assertIn("A rule with no alerts is not in that count", api)
        self.assertIn("the top 10 by alerts, then `rule_id`", api)


class RulesOmittedApiTests(ServerTestCase):
    def test_the_dashboard_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(TOP_RULE_LIMIT):
                add_alerts(db, f"rule_{i:02d}", n=2)
            add_alerts(db, QUIET, n=1)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["rules_omitted"], 1)
        self.assertEqual(
            [row["rule_id"] for row in body["top_rules"]],
            [f"rule_{i:02d}" for i in range(TOP_RULE_LIMIT)])
        self.assertNotIn(QUIET, [row["rule_id"] for row in body["top_rules"]])
        self.assertTrue(all(row["alerts"] == 2 for row in body["top_rules"]))

    def test_an_empty_dashboard_and_a_rejected_request(self):
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["top_rules"], [])
        self.assertEqual(body["rules_omitted"], 0)
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("rules_omitted", denied)
