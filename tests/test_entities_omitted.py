"""The entity list says how many scored entities the limit dropped.

The rows stay the highest scores, then kind, then value. A list that fits
returns entities_omitted 0. A false positive is not scored, so it is not omitted.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def scored(conn, kind, value, severity="medium"):
    fields = {"user": None, "src_ip": None, "host": None}
    fields[kind] = value
    event = add_event(conn, ANCHOR, **fields)
    add_alert(conn, severity, ANCHOR, [event])


class EntitiesOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def listed(self, **params):
        body = entities.list_entities(self.conn, params)
        return body["entities_omitted"], [(row["kind"], row["value"], row["score"]) for row in body["entities"]]

    def test_a_lower_score_is_the_one_past_the_cap(self):
        scored(self.conn, "user", "zulu", "critical")
        scored(self.conn, "user", "yankee", "critical")
        scored(self.conn, "user", "aaaa", "low")
        omitted, rows = self.listed(limit="2")
        self.assertEqual(omitted, 1)
        self.assertEqual(rows, [("user", "yankee", 40.0), ("user", "zulu", 40.0)])

    def test_equal_scores_keep_kind_then_value(self):
        for name in ("b", "a"):
            scored(self.conn, "user", name)
            scored(self.conn, "host", name)
        omitted, rows = self.listed(limit="3")
        self.assertEqual(omitted, 1)
        self.assertEqual(rows, [
            ("host", "a", 10.0), ("host", "b", 10.0), ("user", "a", 10.0)])

    def test_a_kind_filter_counts_only_that_kind(self):
        scored(self.conn, "user", "carol", "critical")
        scored(self.conn, "user", "alice")
        scored(self.conn, "host", "web01", "critical")
        omitted, rows = self.listed(kind="user", limit="1")
        self.assertEqual(omitted, 1)
        self.assertEqual(rows, [("user", "carol", 40.0)])

    def test_a_false_positive_is_not_omitted(self):
        scored(self.conn, "user", "alice", "high")
        event = add_event(self.conn, ANCHOR, user="bob")
        add_alert(self.conn, "critical", ANCHOR, [event], "resolved", "false_positive")
        omitted, rows = self.listed(limit="1")
        self.assertEqual(omitted, 0)
        self.assertEqual(rows, [("user", "alice", 20.0)])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        self.assertEqual(self.listed()[0], 0)
        scored(self.conn, "user", "alice")
        self.assertEqual(self.listed(limit="1"), (0, [("user", "alice", 10.0)]))
        scored(self.conn, "user", "bob")
        self.assertEqual(self.listed(limit="2")[0], 0)

    def test_the_docs_name_entities_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`entities_omitted` is how many scored entities were past that cap (0 when the scored list fits)",
            api)
        self.assertIn("A false positive or benign close is not scored and is not part of that count", api)


class EntitiesOmittedApiTests(ServerTestCase):
    def test_the_list_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for name, severity in (("zulu", "critical"), ("yankee", "critical"), ("aaaa", "low")):
                scored(db, "user", name, severity)
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/entities?limit=2")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["entities_omitted"], 1)
        self.assertEqual([row["value"] for row in body["entities"]], ["yankee", "zulu"])
        filled = viewer.get("/api/entities?limit=3")[1]
        self.assertEqual(filled["entities_omitted"], 0)
        self.assertEqual([row["value"] for row in filled["entities"]], ["yankee", "zulu", "aaaa"])
