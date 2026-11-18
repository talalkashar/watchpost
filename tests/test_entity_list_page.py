"""The entity list scores past the cap without a contribution list for those rows.

The returned rows still explain their scores. Ties stay kind, then value.
A false positive or benign close is not scored and is not a contribution row.
"""

import unittest
from datetime import timedelta
from pathlib import Path

from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema, iso, parse_iso

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def ago(hours):
    return iso(parse_iso(ANCHOR) - timedelta(hours=hours))


class EntityListPageTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def listed(self, **params):
        seen = []
        real = entities._contribution

        def spy(alert, anchor):
            seen.append(alert["id"])
            return real(alert, anchor)

        entities._contribution = spy
        try:
            body = entities.list_entities(self.conn, params)
        finally:
            entities._contribution = real
        return body, seen

    def test_a_decayed_critical_is_scored_without_a_contribution_list(self):
        # 48 hours is two half-lives: critical 40 becomes 10, under a fresh high of 20.
        old_event = add_event(self.conn, ago(48), user="old")
        old_alert = add_alert(self.conn, "critical", ago(48), [old_event])
        fresh_event = add_event(self.conn, ANCHOR, user="fresh")
        fresh_alert = add_alert(self.conn, "high", ANCHOR, [fresh_event])
        quiet_events = [add_event(self.conn, ANCHOR, user="quiet") for _ in range(3)]
        quiet_alerts = [add_alert(self.conn, "low", ANCHOR, [event]) for event in quiet_events]

        body, seen = self.listed(limit="1")
        self.assertEqual(body["entities_omitted"], 2)
        self.assertEqual([(row["kind"], row["value"], row["score"]) for row in body["entities"]],
                         [("user", "fresh", 20.0)])
        self.assertEqual(set(seen), {fresh_alert})
        self.assertNotIn(old_alert, seen)
        self.assertTrue(set(quiet_alerts).isdisjoint(seen))
        # The dropped critical still decays to 10 on its own page. Ignoring decay would rank it 40.
        self.assertEqual(entities.get_entity(self.conn, "user", "old")["score"], 10.0)
        self.assertEqual(entities.get_entity(self.conn, "user", "quiet")["score"], 15.0)

    def test_equal_scores_keep_kind_then_value(self):
        ids = {}
        for kind, value in (("user", "a"), ("host", "b"), ("host", "a")):
            event = add_event(self.conn, ANCHOR, **{kind: value})
            ids[(kind, value)] = add_alert(self.conn, "medium", ANCHOR, [event])
        body, seen = self.listed(limit="2")
        self.assertEqual(body["entities_omitted"], 1)
        self.assertEqual([(row["kind"], row["value"], row["score"]) for row in body["entities"]],
                         [("host", "a", 10.0), ("host", "b", 10.0)])
        self.assertEqual(set(seen), {ids[("host", "a")], ids[("host", "b")]})
        self.assertNotIn(ids[("user", "a")], seen)

    def test_the_kept_row_explains_the_same_score(self):
        first = add_event(self.conn, ANCHOR, user="kept")
        second = add_event(self.conn, ago(1), user="kept")
        low_id = add_alert(self.conn, "medium", ANCHOR, [first], "resolved", "true_positive")
        high_id = add_alert(self.conn, "medium", ANCHOR, [second], "open")
        dropped = add_event(self.conn, ANCHOR, user="dropped")
        dropped_id = add_alert(self.conn, "low", ANCHOR, [dropped])
        body, seen = self.listed(limit="1")
        row = body["entities"][0]
        self.assertEqual(body["entities_omitted"], 1)
        self.assertEqual(row["score"], 20.0)
        self.assertEqual(row["score"], round(sum(part["weight"] for part in row["contributions"]), 2))
        self.assertEqual(row["score"], entities.get_entity(self.conn, "user", "kept")["score"])
        self.assertEqual([part["alert_id"] for part in row["contributions"]], [low_id, high_id])
        self.assertEqual(row["open_alerts"], 1)
        self.assertEqual(row["max_severity"], "medium")
        self.assertEqual(row["last_seen"], ANCHOR)
        self.assertEqual(row["alerts"], 2)
        self.assertEqual(set(seen), {low_id, high_id})
        self.assertNotIn(dropped_id, seen)

    def test_a_false_positive_and_a_benign_close_are_not_built(self):
        alice = add_event(self.conn, ANCHOR, user="alice")
        alice_id = add_alert(self.conn, "high", ANCHOR, [alice])
        bob = add_event(self.conn, ANCHOR, user="bob")
        bob_id = add_alert(self.conn, "critical", ANCHOR, [bob], "resolved", "false_positive")
        sam = add_event(self.conn, ANCHOR, user="sam")
        sam_id = add_alert(self.conn, "high", ANCHOR, [sam], "resolved", "benign")
        body, seen = self.listed(limit="1")
        self.assertEqual(body["entities_omitted"], 0)
        self.assertEqual([(row["value"], row["score"]) for row in body["entities"]], [("alice", 20.0)])
        self.assertEqual(seen, [alice_id])
        self.assertNotIn(bob_id, seen)
        self.assertNotIn(sam_id, seen)
        self.assertEqual(entities.get_entity(self.conn, "user", "bob")["score"], 0.0)

    def test_an_exact_page_and_an_empty_table_build_only_what_they_return(self):
        empty, seen = self.listed()
        self.assertEqual(empty["entities"], [])
        self.assertEqual(empty["entities_omitted"], 0)
        self.assertEqual(seen, [])
        event = add_event(self.conn, ANCHOR, user="alice")
        alert_id = add_alert(self.conn, "low", ANCHOR, [event])
        body, seen = self.listed(limit="1")
        self.assertEqual(body["entities_omitted"], 0)
        self.assertEqual(seen, [alert_id])
        self.assertEqual(body["entities"][0]["score"], 5.0)

    def test_the_docs_name_the_page(self):
        sentence = ("Contribution lists are built for the returned rows only. "
                    "An entity past that cap is scored without one")
        self.assertIn(sentence, API.read_text())
        self.assertIn(
            "That list builds a contribution list for the returned rows only; "
            "an entity past the cap is scored without one.",
            REFERENCE.read_text())
