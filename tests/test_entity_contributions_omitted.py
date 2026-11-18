"""Entity detail caps contributions at 100, highest weight first, then alert id.

The score still sums every alert. A false positive or benign close stays weight 0.
A list that fits, including none, returns contributions_omitted 0.
"""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entity_related_omitted import add_alert, add_event, memory_db
from watchpost.db import connect
from watchpost.entities import CONTRIBUTIONS_LIMIT, get_entity

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"


class EntityContributionsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_the_same_weight_keeps_the_lower_ids(self):
        event_id = add_event(self.conn)
        alerts = [add_alert(self.conn, event_id, hours=0) for _ in range(CONTRIBUTIONS_LIMIT + 1)]
        other = add_event(self.conn, user="bob")
        other_alert = add_alert(self.conn, other, hours=0, severity="critical")

        detail = get_entity(self.conn, "user", "alice")
        shown = [row["alert_id"] for row in detail["contributions"]]
        self.assertEqual(shown, alerts[:CONTRIBUTIONS_LIMIT])
        self.assertEqual(detail["contributions_omitted"], 1)
        self.assertNotIn(alerts[-1], shown)
        self.assertNotIn(other_alert, shown)
        self.assertEqual(detail["score"], (CONTRIBUTIONS_LIMIT + 1) * 10.0)
        self.assertEqual(round(sum(row["weight"] for row in detail["contributions"]), 2),
                         CONTRIBUTIONS_LIMIT * 10.0)
        self.assertTrue(all(row["counted"] for row in detail["contributions"]))
        self.assertEqual(detail["contributions"][0]["title"], "[SYNTHETIC] entity alert")

    def test_a_higher_weight_stays_ahead_of_a_lower_id(self):
        event_id = add_event(self.conn)
        quiet = [add_alert(self.conn, event_id, hours=0) for _ in range(CONTRIBUTIONS_LIMIT)]
        loud = add_alert(self.conn, event_id, hours=0, severity="critical")
        detail = get_entity(self.conn, "user", "alice")
        shown = [row["alert_id"] for row in detail["contributions"]]
        self.assertEqual(shown[0], loud)
        self.assertEqual(shown[1:], quiet[:-1])
        self.assertEqual(detail["contributions_omitted"], 1)
        self.assertNotIn(quiet[-1], shown)
        self.assertEqual(detail["contributions"][0]["weight"], 40.0)
        self.assertEqual(detail["score"], CONTRIBUTIONS_LIMIT * 10.0 + 40.0)

    def test_an_older_critical_still_adds_to_the_score_when_it_is_the_one_left_out(self):
        event_id = add_event(self.conn)
        kept = [add_alert(self.conn, event_id, hours=0, severity="high")
                for _ in range(CONTRIBUTIONS_LIMIT)]
        older = add_alert(self.conn, event_id, hours=-24, severity="low")
        detail = get_entity(self.conn, "user", "alice")
        shown = [row["alert_id"] for row in detail["contributions"]]
        self.assertEqual(shown, kept)
        self.assertEqual(detail["contributions_omitted"], 1)
        self.assertNotIn(older, shown)
        # High is 20. A day-old low is 2.5, so it is the row past the cap, and it still counts.
        self.assertEqual(detail["score"], CONTRIBUTIONS_LIMIT * 20.0 + 2.5)

    def test_a_false_positive_and_a_benign_close_stay_weight_0(self):
        event_id = add_event(self.conn)
        counted = [add_alert(self.conn, event_id, hours=0) for _ in range(CONTRIBUTIONS_LIMIT)]
        false_positive = add_alert(self.conn, event_id, hours=0, severity="critical",
                                   disposition="false_positive", status="resolved")
        benign = add_alert(self.conn, event_id, hours=0, severity="critical",
                           disposition="benign", status="resolved")
        detail = get_entity(self.conn, "user", "alice")
        shown = [row["alert_id"] for row in detail["contributions"]]
        self.assertEqual(shown, counted)
        self.assertEqual(detail["contributions_omitted"], 2)
        self.assertNotIn(false_positive, shown)
        self.assertNotIn(benign, shown)
        self.assertEqual(detail["score"], CONTRIBUTIONS_LIMIT * 10.0)

    def test_a_false_positive_stays_listed_at_weight_0_when_the_page_has_room(self):
        event_id = add_event(self.conn, user="carol")
        kept = add_alert(self.conn, event_id, hours=0)
        false_positive = add_alert(
            self.conn, event_id, hours=0, severity="critical", disposition="false_positive",
            status="resolved")
        benign = add_alert(
            self.conn, event_id, hours=0, severity="high", disposition="benign", status="resolved")
        detail = get_entity(self.conn, "user", "carol")
        by_alert = {row["alert_id"]: row for row in detail["contributions"]}
        self.assertEqual(detail["contributions_omitted"], 0)
        self.assertEqual(
            [row["alert_id"] for row in detail["contributions"]],
            [kept, false_positive, benign])
        self.assertEqual((by_alert[false_positive]["counted"], by_alert[false_positive]["weight"]),
                         (False, 0.0))
        self.assertEqual((by_alert[benign]["counted"], by_alert[benign]["weight"]), (False, 0.0))
        self.assertEqual(detail["score"], 10.0)

    def test_a_short_list_and_an_exact_cap_omit_nothing(self):
        one_event = add_event(self.conn, user="one")
        one_alert = add_alert(self.conn, one_event, hours=0)
        exact_event = add_event(self.conn, user="exact")
        exact = [add_alert(self.conn, exact_event, hours=0) for _ in range(CONTRIBUTIONS_LIMIT)]

        short = get_entity(self.conn, "user", "one")
        self.assertEqual([row["alert_id"] for row in short["contributions"]], [one_alert])
        self.assertEqual(short["contributions_omitted"], 0)
        self.assertEqual(short["score"], 10.0)

        filled = get_entity(self.conn, "user", "exact")
        self.assertEqual([row["alert_id"] for row in filled["contributions"]], exact)
        self.assertEqual(filled["contributions_omitted"], 0)
        self.assertEqual(filled["score"], CONTRIBUTIONS_LIMIT * 10.0)

        empty = get_entity(self.conn, "user", "nobody")
        self.assertEqual(empty["contributions"], [])
        self.assertEqual(empty["contributions_omitted"], 0)
        self.assertEqual(empty["score"], 0.0)

    def test_the_docs_name_the_cap_and_the_score_still_sums_every_alert(self):
        text = API.read_text()
        self.assertIn(
            "`contributions` is the first 100 by weight descending, then alert id."
            " `contributions_omitted` is how many were past that cap"
            " (0 when there are 100 or fewer, including none)."
            " The score still sums every alert."
            " A false positive or benign close stays weight 0.",
            text)
        reference = REFERENCE.read_text()
        self.assertIn(
            "`contributions` on that page is the first 100 by weight descending, then alert id."
            " `contributions_omitted` is how many were past that cap"
            " (0 when there are 100 or fewer).",
            reference)
        self.assertIn("The score still sums every alert.", reference)
        source = Path(__file__).resolve().parent.parent.joinpath("watchpost", "entities.py").read_text()
        self.assertIn('key=lambda c: (-c["weight"], c["alert_id"])', source)
        self.assertIn("contributions[:CONTRIBUTIONS_LIMIT]", source)


class EntityContributionsOmittedApiTests(ServerTestCase):
    def test_entity_detail_reports_the_dropped_contribution(self):
        conn = connect(self.db_path)
        try:
            event_id = add_event(conn)
            alerts = [add_alert(conn, event_id, hours=0, severity="high")
                      for _ in range(CONTRIBUTIONS_LIMIT)]
            dropped = add_alert(conn, event_id, hours=-24, severity="low")
            conn.commit()
        finally:
            conn.close()

        status, detail, headers = self.client("viewer").get("/api/entities/user/alice")
        self.assertEqual(status, 200, detail)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual([row["alert_id"] for row in detail["contributions"]], alerts)
        self.assertEqual(detail["contributions_omitted"], 1)
        self.assertNotIn(dropped, {row["alert_id"] for row in detail["contributions"]})
        self.assertEqual(detail["score"], CONTRIBUTIONS_LIMIT * 20.0 + 2.5)
        self.assertEqual(detail["contributions"][0]["title"], "[SYNTHETIC] entity alert")

        denied, body, denied_headers = self.client().get("/api/entities/user/alice")
        self.assertEqual(denied, 401, body)
        self.assertNotIn("contributions_omitted", body)
        self.assertEqual(denied_headers["Cache-Control"], "no-store")
