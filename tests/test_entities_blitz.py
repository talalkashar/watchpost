"""Entity risk edges the list and the entity page both rely on.

Score, membership, open counts, the day window, and the detail caps. An empty
database and a bad kind or address stay the errors they are now.
"""

import unittest
from datetime import timedelta

from watchpost.db import connect, init_schema, iso, parse_iso
from watchpost.entities import RECENT_EVENTS_LIMIT, RELATED_LIMIT, get_entity, list_entities
from watchpost.queries import QueryError

ANCHOR = "2026-09-15T12:00:00.000Z"


def ago(hours):
    return iso(parse_iso(ANCHOR) - timedelta(hours=hours))


def on_day(offset):
    return iso(parse_iso(ANCHOR) + timedelta(days=offset))


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, ts, user=None, src_ip=None, host=None):
    return conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (ts, ts, "test", host, "auth_failure", "low", user, src_ip, 0)).lastrowid


def add_alert(conn, severity, last_seen, event_ids, status="open", disposition=None):
    alert_id = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status, disposition,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("brute_force_ip", 1, "k", severity, f"{severity} alert", "why", status, disposition,
         last_seen, last_seen, len(event_ids), 0, last_seen, last_seen)).lastrowid
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


def listed(conn, **params):
    return list_entities(conn, params)


class EntityBlitzTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_twelve_hour_critical_matches_on_the_list_and_the_page(self):
        add_event(self.conn, ANCHOR, user="clock")
        evidence = add_event(self.conn, ago(12), user="alice", src_ip="198.51.100.7", host="web01")
        add_alert(self.conn, "critical", ago(12), [evidence])

        detail = get_entity(self.conn, "user", "alice")
        weight = detail["contributions"][0]
        self.assertEqual(detail["anchor"], ANCHOR)
        self.assertEqual((weight["age_hours"], weight["decay"], weight["weight"]), (12.0, 0.707, 28.28))
        self.assertEqual(detail["score"], round(sum(c["weight"] for c in detail["contributions"]), 2))
        self.assertEqual(detail["score"], 28.28)

        result = listed(self.conn, kind="user")
        self.assertEqual(result["half_life_hours"], 24)
        self.assertEqual(result["severity_weights"]["critical"], 40)
        self.assertEqual(result["excluded_dispositions"], ["false_positive", "benign"])
        self.assertEqual([(r["value"], r["score"]) for r in result["entities"]], [("alice", 28.28)])
        self.assertEqual(result["entities"][0]["score"], detail["score"])

    def test_one_alert_adds_its_full_weight_to_each_entity_once(self):
        add_event(self.conn, ANCHOR, user="clock")
        alice = add_event(self.conn, ago(12), user="Alice", src_ip="198.51.100.7", host="WEB01")
        erin = add_event(self.conn, ago(12), user="ÉRIN", src_ip="198.51.100.7", host="WEB01")
        add_alert(self.conn, "critical", ago(12), [alice, erin])

        for kind, lookup, value in (
                ("user", "Alice", "alice"), ("user", "ÉRIN", "Érin"),
                ("src_ip", "198.51.100.7", "198.51.100.7"), ("host", "WEB01", "web01")):
            detail = get_entity(self.conn, kind, lookup)
            self.assertEqual(detail["value"], value)
            self.assertEqual([c["weight"] for c in detail["contributions"]], [28.28])
            self.assertEqual(detail["score"], 28.28)
        self.assertEqual(get_entity(self.conn, "user", "érin")["score"], 0)
        self.assertEqual(get_entity(self.conn, "user", "érin")["event_count"], 0)

        rows = listed(self.conn)["entities"]
        self.assertEqual([(r["kind"], r["value"], r["score"]) for r in rows], [
            ("host", "web01", 28.28),
            ("src_ip", "198.51.100.7", 28.28),
            ("user", "alice", 28.28),
            ("user", "Érin", 28.28),
        ])
        self.assertEqual(listed(self.conn, kind="")["entities"], rows)

    def test_open_count_skips_resolved_and_a_false_positive_stays_off_the_list(self):
        evidence = add_event(self.conn, ANCHOR, user="bob", src_ip="203.0.113.10")
        add_alert(self.conn, "medium", ANCHOR, [evidence], status="open")
        add_alert(self.conn, "high", ANCHOR, [evidence], status="investigating")
        add_alert(self.conn, "low", ANCHOR, [evidence], status="resolved", disposition="true_positive")
        cleared = add_alert(self.conn, "critical", ANCHOR, [evidence], status="resolved", disposition="false_positive")

        detail = get_entity(self.conn, "user", "bob")
        by_alert = {c["alert_id"]: c for c in detail["contributions"]}
        self.assertEqual(by_alert[cleared]["counted"], False)
        self.assertEqual(by_alert[cleared]["weight"], 0.0)
        self.assertEqual(detail["score"], 35.0)

        row = listed(self.conn, kind="User")["entities"][0]
        self.assertEqual(row["kind"], "user")
        self.assertEqual((row["alerts"], row["open_alerts"], row["max_severity"], row["score"]), (3, 2, "high", 35.0))
        self.assertEqual(row["score"], detail["score"])
        self.assertNotIn(cleared, [c["alert_id"] for c in row["contributions"]])

    def test_max_severity_follows_rank_when_a_fresh_high_weighs_more(self):
        old = add_event(self.conn, ago(48), user="maxsev")
        fresh = add_event(self.conn, ANCHOR, user="maxsev")
        add_alert(self.conn, "critical", ago(48), [old])
        add_alert(self.conn, "high", ANCHOR, [fresh])

        detail = get_entity(self.conn, "user", "maxsev")
        weights = {c["severity"]: c["weight"] for c in detail["contributions"]}
        self.assertEqual(weights, {"critical": 10.0, "high": 20.0})
        self.assertEqual(detail["score"], 30.0)
        row = listed(self.conn)["entities"][0]
        self.assertEqual(row["max_severity"], "critical")
        self.assertEqual(row["score"], detail["score"])

    def test_empty_database_and_bad_inputs(self):
        result = listed(self.conn)
        self.assertEqual(result["entities"], [])
        self.assertEqual(result["entities_omitted"], 0)
        self.assertIsNone(result["anchor"])
        self.assertEqual(listed(self.conn, kind="user")["entities"], [])

        missing = get_entity(self.conn, "user", "nobody")
        self.assertEqual(missing["score"], 0)
        self.assertEqual(missing["alerts"], [])
        self.assertEqual(missing["recent_events_omitted"], 0)
        self.assertIsNone(missing["anchor"])

        with self.assertRaises(QueryError) as kind_path:
            get_entity(self.conn, "User", "nobody")
        self.assertEqual(kind_path.exception.status, 404)

        with self.assertRaises(QueryError) as bad_kind:
            listed(self.conn, kind="planet")
        self.assertEqual(bad_kind.exception.status, 400)
        self.assertIn("user, src_ip, host", str(bad_kind.exception))

        with self.assertRaises(QueryError) as bad_ip:
            get_entity(self.conn, "src_ip", "not-an-ip")
        self.assertEqual(bad_ip.exception.status, 400)

        with self.assertRaises(QueryError) as bad_limit:
            listed(self.conn, limit="0")
        self.assertIn("between", str(bad_limit.exception))

        untouched = get_entity(self.conn, "src_ip", "2001:DB8::1")
        self.assertEqual(untouched["value"], "2001:db8::1")
        self.assertEqual(untouched["score"], 0)

    def test_day_window_and_this_entity_evidence_day(self):
        old = add_event(self.conn, on_day(-30), user="span")
        add_event(self.conn, ANCHOR, user="span")
        add_alert(self.conn, "low", on_day(-30), [old])
        kept = get_entity(self.conn, "user", "span")["alerts_by_day"]
        self.assertEqual(kept["start"], "2026-08-16")
        self.assertEqual(kept["end"], "2026-09-15")
        self.assertEqual(len(kept["days"]), 31)
        self.assertEqual(kept["omitted"], 0)
        self.assertEqual(kept["days"][0], {"day": "2026-08-16", "count": 1})

        wide_old = add_event(self.conn, on_day(-31), user="wide")
        add_event(self.conn, ANCHOR, user="wide")
        add_alert(self.conn, "low", on_day(-31), [wide_old])
        wide = get_entity(self.conn, "user", "wide")["alerts_by_day"]
        self.assertEqual(wide["start"], "2026-08-16")
        self.assertEqual(len(wide["days"]), 31)
        self.assertEqual(wide["omitted"], 1)
        self.assertEqual(wide["days"][0], {"day": "2026-08-16", "count": 0})

        alice = add_event(self.conn, "2026-09-14T12:00:00.000Z", user="alice", src_ip="198.51.100.20")
        bob = add_event(self.conn, ANCHOR, user="bob", src_ip="198.51.100.20")
        add_alert(self.conn, "high", ANCHOR, [alice, bob])
        alice_days = get_entity(self.conn, "user", "alice")["alerts_by_day"]
        self.assertEqual(alice_days["days"], [{"day": "2026-09-14", "count": 1}])
        self.assertEqual(alice_days["omitted"], 0)

        cleared = add_event(self.conn, ANCHOR, user="cleared")
        add_alert(self.conn, "critical", ANCHOR, [cleared], status="resolved", disposition="false_positive")
        cleared_detail = get_entity(self.conn, "user", "cleared")
        self.assertEqual(cleared_detail["alerts_by_day"]["days"], [{"day": "2026-09-15", "count": 1}])
        self.assertEqual(cleared_detail["score"], 0.0)
        self.assertNotIn("cleared", [r["value"] for r in listed(self.conn, kind="user")["entities"]])

    def test_a_newer_event_on_someone_else_decays_this_score(self):
        evidence = add_event(self.conn, ago(24), user="alice")
        add_alert(self.conn, "critical", ago(24), [evidence])
        add_event(self.conn, ANCHOR, user="bob")

        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual(detail["anchor"], ANCHOR)
        self.assertEqual(detail["contributions"][0]["age_hours"], 24.0)
        self.assertEqual(detail["contributions"][0]["weight"], 20.0)
        self.assertEqual(detail["score"], 20.0)
        self.assertNotIn("bob", [r["value"] for r in listed(self.conn)["entities"]])

    def test_the_score_keeps_an_alert_past_the_detail_cap(self):
        old = add_event(self.conn, ago(24), user="capped")
        fresh = add_event(self.conn, ANCHOR, user="capped")
        critical = add_alert(self.conn, "critical", ago(24), [old])
        for _ in range(RELATED_LIMIT):
            add_alert(self.conn, "low", ANCHOR, [fresh])

        detail = get_entity(self.conn, "user", "capped")
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(len(detail["alerts"]), RELATED_LIMIT)
        self.assertNotIn(critical, [a["id"] for a in detail["alerts"]])
        self.assertEqual(
            next(c["weight"] for c in detail["contributions"] if c["alert_id"] == critical), 20.0)
        self.assertEqual(detail["score"], 270.0)
        self.assertEqual(detail["score"], round(sum(c["weight"] for c in detail["contributions"]), 2))

    def test_the_same_last_seen_keeps_the_higher_alert_id(self):
        evidence = add_event(self.conn, ANCHOR, user="tie")
        ids = [add_alert(self.conn, "low", ANCHOR, [evidence]) for _ in range(RELATED_LIMIT + 1)]
        detail = get_entity(self.conn, "user", "tie")
        self.assertEqual(detail["alerts"][0]["id"], ids[-1])
        self.assertNotIn(ids[0], [a["id"] for a in detail["alerts"]])
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(len(detail["contributions"]), RELATED_LIMIT + 1)
        self.assertEqual(detail["score"], 255.0)

    def test_recent_events_keep_the_newest_fifty(self):
        for minutes in range(RECENT_EVENTS_LIMIT + 1):
            add_event(self.conn, iso(parse_iso(ANCHOR) - timedelta(minutes=minutes)), user="busy")
        detail = get_entity(self.conn, "user", "busy")
        self.assertEqual(detail["event_count"], RECENT_EVENTS_LIMIT + 1)
        self.assertEqual(len(detail["recent_events"]), RECENT_EVENTS_LIMIT)
        self.assertEqual(detail["recent_events_omitted"], 1)
        self.assertEqual(detail["recent_events"][0]["ts"], ANCHOR)
        self.assertEqual(detail["score"], 0)

    def test_ascii_names_fold_and_an_ipv6_path_uses_the_stored_form(self):
        evidence = add_event(self.conn, ANCHOR, user="Erin", src_ip="2001:db8::1", host="WEB01")
        add_alert(self.conn, "low", ANCHOR, [evidence])
        accented = add_event(self.conn, ANCHOR, user="ÉRIN")
        add_alert(self.conn, "high", ANCHOR, [accented])

        erin = get_entity(self.conn, "user", "ERIN")
        self.assertEqual(erin["value"], "erin")
        self.assertEqual(erin["score"], 5.0)
        self.assertEqual(get_entity(self.conn, "user", "ÉRIN")["value"], "Érin")
        self.assertEqual(get_entity(self.conn, "user", "ÉRIN")["score"], 20.0)
        self.assertEqual(get_entity(self.conn, "user", "érin")["event_count"], 0)
        address = get_entity(self.conn, "src_ip", "2001:DB8::1")
        self.assertEqual(address["value"], "2001:db8::1")
        self.assertEqual(address["score"], 5.0)
        self.assertEqual(get_entity(self.conn, "host", "web01")["value"], "web01")

        names = [r["value"] for r in listed(self.conn, kind="user")["entities"]]
        self.assertEqual(names, ["Érin", "erin"])

    def test_a_counted_alert_that_rounds_to_zero_stays_on_the_list(self):
        old = add_event(self.conn, ago(24 * 30), user="olduser")
        fresh = add_event(self.conn, ANCHOR, user="fresh")
        add_alert(self.conn, "info", ago(24 * 30), [old])
        add_alert(self.conn, "low", ANCHOR, [fresh])

        result = listed(self.conn, kind="user")
        by_value = {r["value"]: r for r in result["entities"]}
        self.assertEqual(by_value["fresh"]["score"], 5.0)
        self.assertEqual(by_value["olduser"]["score"], 0.0)
        self.assertEqual(by_value["olduser"]["alerts"], 1)
        self.assertEqual(result["entities_omitted"], 0)
