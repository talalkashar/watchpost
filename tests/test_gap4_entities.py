"""Edges of list_entities and get_entity that the other entity tests leave open.

Those two are the public functions in watchpost.entities. The cases here are the
default and maximum list size, which alerts count as open, severity rank versus
weight, one alert shared by several events, blank keys, decay rounding, and the
31-day chart boundary.
"""

import unittest
from datetime import timedelta

from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost.db import connect, init_schema, iso, parse_iso
from watchpost.entities import get_entity, list_entities
from watchpost.queries import QueryError


def ago(hours):
    return iso(parse_iso(ANCHOR) - timedelta(hours=hours))


def day(offset):
    return iso(parse_iso(ANCHOR) + timedelta(days=offset))


class Gap4EntityTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_limit_defaults_to_10_and_rejects_past_100(self):
        for i in range(11):
            event = add_event(self.conn, ANCHOR, user=f"m{i:02d}")
            add_alert(self.conn, "medium", ANCHOR, [event])

        def values(params):
            body = list_entities(self.conn, params)
            return body["entities_omitted"], [row["value"] for row in body["entities"]]

        first_ten = (1, [f"m{i:02d}" for i in range(10)])
        self.assertEqual(values({}), first_ten)
        self.assertEqual(values({"limit": ""}), first_ten)
        self.assertEqual(values({"limit": None}), first_ten)
        self.assertNotIn("m10", first_ten[1])
        self.assertEqual(values({"limit": "100"}), (0, [f"m{i:02d}" for i in range(11)]))
        self.assertEqual(values({"limit": 100}), (0, [f"m{i:02d}" for i in range(11)]))

        for bad, message in (
                ("101", "limit must be between 1 and 100"),
                ("0", "limit must be between 1 and 100"),
                ("-1", "limit must be between 1 and 100"),
                ("10.5", "limit must be an integer"),
                ("ten", "limit must be an integer")):
            with self.subTest(limit=bad):
                with self.assertRaises(QueryError) as caught:
                    list_entities(self.conn, {"limit": bad})
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), message)

        # A blank kind is not a filter. It lists every kind, same as omitting kind.
        host = add_event(self.conn, ANCHOR, host="h1")
        add_alert(self.conn, "medium", ANCHOR, [host])
        self.assertEqual(list_entities(self.conn, {"kind": ""})["entities"],
                         list_entities(self.conn, {})["entities"])
        listed = {(row["kind"], row["value"])
                  for row in list_entities(self.conn, {"kind": "", "limit": "100"})["entities"]}
        self.assertIn(("host", "h1"), listed)
        self.assertEqual(len(listed), 12)

    def test_open_alerts_and_max_severity_follow_status_and_rank(self):
        def linked(severity, seen, status="open", disposition=None):
            event = add_event(self.conn, seen, user="ada")
            return add_alert(self.conn, severity, seen, [event], status, disposition)

        # Same weight: the smaller alert id stays first. Rank, not weight, picks critical.
        first_high = linked("high", ANCHOR, "investigating")
        second_high = linked("high", ANCHOR, "investigating")
        critical = linked("critical", ago(48), "resolved", "true_positive")
        closed = linked("low", ago(48), "closed")
        info = linked("info", ago(48), "open")

        row = next(r for r in list_entities(self.conn, {})["entities"] if r["value"] == "ada")
        detail = get_entity(self.conn, "user", "ada")
        self.assertEqual([c["alert_id"] for c in row["contributions"]],
                         [first_high, second_high, critical, closed, info])
        self.assertEqual([c["alert_id"] for c in detail["contributions"]],
                         [c["alert_id"] for c in row["contributions"]])
        self.assertEqual(row["alerts"], 5)
        # "closed" is not the status resolved, so it still counts as open.
        self.assertEqual(row["open_alerts"], 4)
        self.assertEqual(row["max_severity"], "critical")
        self.assertEqual(row["last_seen"], ANCHOR)
        self.assertEqual([c["weight"] for c in row["contributions"]], [20.0, 20.0, 10.0, 1.25, 0.25])
        self.assertEqual(row["score"], 51.5)
        self.assertGreater(row["contributions"][0]["weight"], row["contributions"][2]["weight"])

    def test_one_alert_counts_once_and_blank_fields_are_not_listed(self):
        carol = [add_event(self.conn, ANCHOR, user="carol") for _ in range(3)]
        blank = add_event(self.conn, ANCHOR, user="", src_ip="", host="")
        add_event(self.conn, ANCHOR, user=None, src_ip=None, host=None)
        alert = add_alert(self.conn, "high", ANCHOR, carol + [blank])
        add_event(self.conn, ANCHOR, user="dave", synthetic=0)
        spaced = add_event(self.conn, ANCHOR, user=" carol")
        add_alert(self.conn, "low", ANCHOR, [spaced])

        detail = get_entity(self.conn, "user", "carol")
        self.assertEqual(detail["event_count"], 3)
        self.assertEqual(detail["score"], 20.0)
        self.assertEqual([c["alert_id"] for c in detail["contributions"]], [alert])
        self.assertEqual(len(detail["alerts"]), 1)
        self.assertTrue(detail["synthetic"])

        # A leading space is its own account. The fold does not strip it.
        gap = get_entity(self.conn, "user", " carol")
        self.assertEqual(gap["value"], " carol")
        self.assertEqual(gap["event_count"], 1)
        self.assertEqual(gap["score"], 5.0)
        self.assertEqual(get_entity(self.conn, "user", "carol")["score"], 20.0)

        quiet = get_entity(self.conn, "user", "dave")
        self.assertEqual(quiet["score"], 0.0)
        self.assertEqual(quiet["event_count"], 1)
        self.assertEqual(quiet["contributions"], [])
        self.assertEqual(quiet["alerts"], [])
        self.assertFalse(quiet["synthetic"])
        self.assertEqual(quiet["alerts_by_day"]["days"], [{"day": "2026-09-15", "count": 0}])

        listed = {(row["kind"], row["value"]) for row in list_entities(self.conn, {})["entities"]}
        self.assertIn(("user", "carol"), listed)
        self.assertIn(("user", " carol"), listed)
        self.assertNotIn(("user", "dave"), listed)
        self.assertNotIn(("user", ""), listed)
        self.assertNotIn(("host", ""), listed)
        self.assertNotIn(("src_ip", ""), listed)

        for bad in ("", "   ", None):
            with self.subTest(value=bad):
                with self.assertRaises(QueryError) as caught:
                    get_entity(self.conn, "src_ip", bad)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn("src_ip must be a valid IP address", str(caught.exception))

    def test_score_follows_alert_time_and_rounds_decay_apart_from_weight(self):
        erin = add_event(self.conn, ago(36), user="erin")
        add_alert(self.conn, "critical", ago(36), [erin])
        # The evidence is 36h old. The alert stamp is the anchor, so this score does not decay.
        frank = add_event(self.conn, ago(36), user="frank")
        add_alert(self.conn, "high", ANCHOR, [frank])
        old = add_event(self.conn, ago(480), user="old")
        add_alert(self.conn, "critical", ago(480), [old])

        fresh = get_entity(self.conn, "user", "frank")
        part = fresh["contributions"][0]
        self.assertEqual((part["age_hours"], part["decay"], part["weight"]), (0.0, 1.0, 20.0))
        self.assertEqual(fresh["score"], 20.0)
        # The bar uses the evidence timestamp, which is the previous UTC day.
        self.assertEqual(fresh["alerts_by_day"]["days"], [{"day": "2026-09-14", "count": 1}])
        self.assertEqual(fresh["alerts_by_day"]["end"], "2026-09-14")

        aged = get_entity(self.conn, "user", "erin")["contributions"][0]
        # 36h is 1.5 half-lives. decay is shown to 3 decimals (0.354).
        # weight is 40 times the full decay, then shown to 2 decimals (14.14, not 14.16).
        self.assertEqual((aged["age_hours"], aged["decay"], aged["weight"], aged["base_weight"]),
                         (36.0, 0.354, 14.14, 40))
        self.assertEqual(round(aged["base_weight"] * aged["decay"], 2), 14.16)

        faded = get_entity(self.conn, "user", "old")
        self.assertEqual(faded["contributions"][0]["counted"], True)
        self.assertEqual((faded["contributions"][0]["decay"], faded["contributions"][0]["weight"]), (0.0, 0.0))
        self.assertEqual(faded["score"], 0.0)
        listed = [row for row in list_entities(self.conn, {})["entities"] if row["value"] == "old"]
        self.assertEqual([(row["value"], row["score"]) for row in listed], [("old", 0.0)])

    def test_day_window_keeps_31_days_and_drops_the_32nd(self):
        early = add_event(self.conn, day(-30), host="span31")
        latest = add_event(self.conn, day(0), host="span31")
        add_alert(self.conn, "low", day(-30), [early])
        add_alert(self.conn, "low", day(0), [latest])
        kept = get_entity(self.conn, "host", "span31")["alerts_by_day"]
        self.assertEqual(len(kept["days"]), 31)
        self.assertEqual(kept["omitted"], 0)
        self.assertEqual(kept["days"][0], {"day": "2026-08-16", "count": 1})
        self.assertEqual(kept["days"][1], {"day": "2026-08-17", "count": 0})
        self.assertEqual(kept["days"][-1], {"day": "2026-09-15", "count": 1})
        self.assertEqual(sum(item["count"] for item in kept["days"]), 2)

        older = add_event(self.conn, day(-31), host="span32")
        newest = add_event(self.conn, day(0), host="span32")
        add_alert(self.conn, "low", day(-31), [older])
        add_alert(self.conn, "low", day(0), [newest])
        dropped = get_entity(self.conn, "host", "span32")["alerts_by_day"]
        self.assertEqual(len(dropped["days"]), 31)
        self.assertEqual(dropped["omitted"], 1)
        self.assertEqual(dropped["start"], "2026-08-16")
        self.assertEqual(dropped["days"][0], {"day": "2026-08-16", "count": 0})
        self.assertEqual(dropped["days"][-1], {"day": "2026-09-15", "count": 1})
        self.assertNotIn("2026-08-15", [item["day"] for item in dropped["days"]])
        self.assertEqual(sum(item["count"] for item in dropped["days"]), 1)

    @unittest.expectedFailure
    def test_blank_user_detail_ignores_rows_the_list_does_not_score(self):
        # list_entities skips a falsy user, so "" is not an entity key.
        # get_entity still matches those rows, and the day chart counts their alert.
        event = add_event(self.conn, ANCHOR, user="")
        add_alert(self.conn, "critical", ANCHOR, [event])
        detail = get_entity(self.conn, "user", "")
        self.assertEqual(
            (detail["event_count"], detail["score"], detail["alerts_by_day"]["days"]),
            (0, 0.0, []))
