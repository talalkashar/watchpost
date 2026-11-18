"""The dashboard says how many scored entities the top-eight list dropped.

The rows stay the highest scores, then kind, then value. A list that fits,
including none, returns risky_entities_omitted 0. A false positive is not
scored, so it is not omitted.
"""

import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost.db import connect, init_schema
from watchpost.server import DASHBOARD_ENTITIES, dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def scored(conn, kind, value, severity="medium", disposition=None, status="open"):
    fields = {"user": None, "src_ip": None, "host": None}
    fields[kind] = value
    event = add_event(conn, ANCHOR, **fields)
    add_alert(conn, severity, ANCHOR, [event], status, disposition)


class RiskyEntitiesOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def board(self):
        body = dashboard(SimpleNamespace(conn=self.conn))
        return body["risky_entities_omitted"], [
            (row["kind"], row["value"], row["score"]) for row in body["risky_entities"]]

    def test_a_lower_score_is_the_one_past_the_cap(self):
        for i in range(DASHBOARD_ENTITIES):
            scored(self.conn, "user", f"user-{i:02d}", "critical")
        scored(self.conn, "user", "quiet", "low")
        omitted, rows = self.board()
        self.assertEqual(omitted, 1)
        self.assertEqual(len(rows), DASHBOARD_ENTITIES)
        self.assertNotIn(("user", "quiet", 5.0), rows)
        self.assertTrue(all(score == 40.0 for _, _, score in rows))

    def test_equal_scores_keep_kind_then_value(self):
        for name in ("b", "a"):
            scored(self.conn, "user", name)
            scored(self.conn, "host", name)
        for i in range(DASHBOARD_ENTITIES - 3):
            scored(self.conn, "src_ip", f"203.0.113.{i + 1}")
        omitted, rows = self.board()
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[-1], ("user", "a", 10.0))
        self.assertNotIn(("user", "b", 10.0), rows)
        self.assertEqual(rows[:3], [
            ("host", "a", 10.0), ("host", "b", 10.0), ("src_ip", "203.0.113.1", 10.0)])

    def test_a_false_positive_is_not_omitted(self):
        scored(self.conn, "user", "alice", "high")
        scored(self.conn, "user", "bob", "critical", "false_positive", "resolved")
        scored(self.conn, "host", "web01", "critical", "benign", "resolved")
        omitted, rows = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(rows, [("user", "alice", 20.0)])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        self.assertEqual(self.board(), (0, []))
        scored(self.conn, "user", "alice")
        self.assertEqual(self.board(), (0, [("user", "alice", 10.0)]))
        for i in range(1, DASHBOARD_ENTITIES):
            scored(self.conn, "user", f"user-{i:02d}")
        omitted, rows = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(len(rows), DASHBOARD_ENTITIES)

    def test_the_docs_name_risky_entities_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`risky_entities_omitted` is how many scored entities were past that cap"
            " (0 when there are 8 or fewer, including none)",
            api)
        self.assertIn(
            "A false positive or benign close is not scored and is not part of that count",
            api)
        self.assertIn("the top 8 scored entities", api)


class RiskyEntitiesOmittedApiTests(ServerTestCase):
    def test_the_dashboard_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(DASHBOARD_ENTITIES):
                scored(db, "user", f"user-{i:02d}", "critical")
            scored(db, "user", "quiet", "low")
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["risky_entities_omitted"], 1)
        self.assertEqual(len(body["risky_entities"]), DASHBOARD_ENTITIES)
        self.assertNotIn("quiet", [row["value"] for row in body["risky_entities"]])
        listed = viewer.get("/api/entities?limit=8")[1]
        self.assertEqual(body["risky_entities"], listed["entities"])
        self.assertEqual(body["risky_entities_omitted"], listed["entities_omitted"])

    def test_an_empty_dashboard_and_a_rejected_request(self):
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["risky_entities"], [])
        self.assertEqual(body["risky_entities_omitted"], 0)
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("risky_entities_omitted", denied)
