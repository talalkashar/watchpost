"""Entity detail says how many alerts and incidents the 50-row cap dropped.

The rows stay the newest 50 by last_seen, then id. A shorter list returns 0.
The score and contributions still include every alert. A false positive stays weight 0.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.entities import RELATED_LIMIT, get_entity

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def stamp(hours):
    return iso(BASE + timedelta(hours=hours))


def add_event(conn, user="alice"):
    ts = stamp(0)
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", user, "[SYNTHETIC] entity cap"))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_id, hours, severity="medium", disposition=None, status="open"):
    ts = stamp(hours)
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status, disposition,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
        ("synthetic_rule", 1, "k", severity, "[SYNTHETIC] entity alert", "synthetic",
         status, disposition, ts, ts, 1, ts, ts))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, event_id))
    return alert_id


def add_incident(conn, alert_id, hours, severity="medium"):
    ts = stamp(hours)
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,1,?,?)",
        ("[SYNTHETIC] entity incident", severity, "open", ts, ts, "{}", "[]", 1, ts, ts))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        (alert_id, incident_id, ts))
    return incident_id


class EntityRelatedOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_an_older_row_with_a_higher_id_is_the_one_past_the_cap(self):
        event_id = add_event(self.conn)
        # Later last_seen, then one earlier row. last_seen wins, so the higher id is omitted.
        kept = [add_alert(self.conn, event_id, hours=0) for _ in range(RELATED_LIMIT)]
        kept_incidents = [add_incident(self.conn, alert_id, hours=0) for alert_id in kept]
        older = add_alert(self.conn, event_id, hours=-24, severity="critical")
        older_incident = add_incident(self.conn, older, hours=-24)
        other = add_event(self.conn, user="bob")
        other_alert = add_alert(self.conn, other, hours=0, severity="critical")
        other_incident = add_incident(self.conn, other_alert, hours=0)

        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual([row["id"] for row in detail["alerts"]], list(reversed(kept)))
        self.assertEqual([row["id"] for row in detail["incidents"]], list(reversed(kept_incidents)))
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(detail["incidents_omitted"], 1)
        self.assertNotIn(older, {row["id"] for row in detail["alerts"]})
        self.assertNotIn(older_incident, {row["id"] for row in detail["incidents"]})
        self.assertNotIn(other_alert, {row["id"] for row in detail["alerts"]})
        self.assertNotIn(other_incident, {row["id"] for row in detail["incidents"]})
        self.assertEqual(detail["alerts"][0]["title"], "[SYNTHETIC] entity alert")
        self.assertEqual(detail["alerts"][0]["synthetic"], 1)
        self.assertEqual(detail["incidents"][0]["title"], "[SYNTHETIC] entity incident")
        self.assertEqual(detail["incidents"][0]["synthetic"], 1)
        # The omitted critical alert is 24h old, so it still adds half its weight. The cap does not.
        by_alert = {row["alert_id"]: row for row in detail["contributions"]}
        self.assertEqual(by_alert[older]["weight"], 20.0)
        self.assertTrue(by_alert[older]["counted"])
        self.assertEqual(len(detail["contributions"]), RELATED_LIMIT + 1)
        self.assertEqual(detail["score"], RELATED_LIMIT * 10 + 20.0)

    def test_the_same_last_seen_keeps_the_higher_ids(self):
        event_id = add_event(self.conn)
        alerts = [add_alert(self.conn, event_id, hours=0) for _ in range(RELATED_LIMIT + 1)]
        incidents = [add_incident(self.conn, alert_id, hours=0) for alert_id in alerts]
        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual([row["id"] for row in detail["alerts"]], list(reversed(alerts[1:])))
        self.assertEqual([row["id"] for row in detail["incidents"]], list(reversed(incidents[1:])))
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(detail["incidents_omitted"], 1)
        self.assertNotIn(alerts[0], {row["id"] for row in detail["alerts"]})
        self.assertNotIn(incidents[0], {row["id"] for row in detail["incidents"]})
        self.assertIn(alerts[0], {row["alert_id"] for row in detail["contributions"]})
        self.assertEqual(detail["score"], (RELATED_LIMIT + 1) * 10.0)

    def test_a_false_positive_stays_out_of_the_score_when_the_list_drops_it(self):
        event_id = add_event(self.conn)
        kept = [add_alert(self.conn, event_id, hours=0) for _ in range(RELATED_LIMIT)]
        older = add_alert(self.conn, event_id, hours=-24, severity="critical", disposition="false_positive",
                          status="resolved")
        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual([row["id"] for row in detail["alerts"]], list(reversed(kept)))
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertNotIn(older, {row["id"] for row in detail["alerts"]})
        by_alert = {row["alert_id"]: row for row in detail["contributions"]}
        self.assertEqual((by_alert[older]["counted"], by_alert[older]["weight"]), (False, 0.0))
        self.assertEqual(detail["score"], RELATED_LIMIT * 10.0)
        self.assertEqual(len(detail["contributions"]), RELATED_LIMIT + 1)

    def test_a_shown_false_positive_does_not_hide_an_older_score(self):
        event_id = add_event(self.conn)
        # Same last_seen: the highest id stays, so the false positive is shown and the first alert is dropped.
        older = [add_alert(self.conn, event_id, hours=0) for _ in range(RELATED_LIMIT)]
        fp = add_alert(self.conn, event_id, hours=0, severity="critical", disposition="false_positive",
                       status="resolved")
        detail = get_entity(self.conn, "user", "alice")
        shown = [row["id"] for row in detail["alerts"]]
        self.assertEqual(shown[0], fp)
        self.assertNotIn(older[0], shown)
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(len(shown), RELATED_LIMIT)
        by_alert = {row["alert_id"]: row for row in detail["contributions"]}
        self.assertEqual(by_alert[older[0]]["weight"], 10.0)
        self.assertTrue(by_alert[older[0]]["counted"])
        self.assertEqual((by_alert[fp]["counted"], by_alert[fp]["weight"]), (False, 0.0))
        self.assertEqual(detail["score"], RELATED_LIMIT * 10.0)

    def test_an_incident_on_a_dropped_alert_stays_when_the_incident_list_fits(self):
        event_id = add_event(self.conn)
        kept = [add_alert(self.conn, event_id, hours=0) for _ in range(RELATED_LIMIT)]
        older = add_alert(self.conn, event_id, hours=-1)
        incident = add_incident(self.conn, older, hours=0)
        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertNotIn(older, {row["id"] for row in detail["alerts"]})
        self.assertEqual([row["id"] for row in detail["incidents"]], [incident])
        self.assertEqual(detail["incidents_omitted"], 0)
        self.assertEqual(len(kept), RELATED_LIMIT)

    def test_two_alerts_in_one_incident_count_once(self):
        event_id = add_event(self.conn)
        first = add_alert(self.conn, event_id, hours=0)
        second = add_alert(self.conn, event_id, hours=0)
        incident = add_incident(self.conn, first, hours=0)
        ts = stamp(0)
        self.conn.execute(
            "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
            (second, incident, ts))
        detail = get_entity(self.conn, "user", "alice")
        self.assertEqual([row["id"] for row in detail["incidents"]], [incident])
        self.assertEqual(detail["incidents_omitted"], 0)
        self.assertEqual(detail["alerts_omitted"], 0)

    def test_a_short_list_and_an_exact_cap_omit_nothing(self):
        one_event = add_event(self.conn, user="one")
        one_alert = add_alert(self.conn, one_event, hours=0)
        one_incident = add_incident(self.conn, one_alert, hours=0)
        exact_event = add_event(self.conn, user="exact")
        exact_alerts = [add_alert(self.conn, exact_event, hours=0) for _ in range(RELATED_LIMIT)]
        exact_incidents = [add_incident(self.conn, alert_id, hours=0) for alert_id in exact_alerts]

        short = get_entity(self.conn, "user", "one")
        self.assertEqual([row["id"] for row in short["alerts"]], [one_alert])
        self.assertEqual([row["id"] for row in short["incidents"]], [one_incident])
        self.assertEqual(short["alerts_omitted"], 0)
        self.assertEqual(short["incidents_omitted"], 0)

        filled = get_entity(self.conn, "user", "exact")
        self.assertEqual(len(filled["alerts"]), RELATED_LIMIT)
        self.assertEqual(len(filled["incidents"]), RELATED_LIMIT)
        self.assertEqual(filled["alerts_omitted"], 0)
        self.assertEqual(filled["incidents_omitted"], 0)
        self.assertEqual([row["id"] for row in filled["alerts"]], list(reversed(exact_alerts)))
        self.assertEqual([row["id"] for row in filled["incidents"]], list(reversed(exact_incidents)))

        empty = get_entity(self.conn, "user", "nobody")
        self.assertEqual(empty["alerts"], [])
        self.assertEqual(empty["incidents"], [])
        self.assertEqual(empty["alerts_omitted"], 0)
        self.assertEqual(empty["incidents_omitted"], 0)
        self.assertEqual(empty["contributions"], [])
        self.assertEqual(empty["score"], 0.0)

    def test_the_api_docs_name_the_cap_and_the_omitted_counts(self):
        text = API.read_text()
        self.assertIn(
            "`alerts` (the newest 50 by `last_seen`, then `id`), `alerts_omitted`"
            " (how many of this entity's alerts were past that cap; 0 when there are 50 or fewer),"
            " `incidents` (the newest 50 by `last_seen`, then `id`), `incidents_omitted`"
            " (how many were past that cap; 0 when there are 50 or fewer)",
            text)
        self.assertIn(
            "The score and `contributions` still include every alert."
            " A false positive or benign close stays weight 0.",
            text)
        self.assertIn(
            "That page is `ORDER BY i.last_seen DESC, i.id DESC LIMIT`"
            " and the omitted count is `COUNT(DISTINCT i.id)` minus the page."
            " The score query is not limited.",
            text)
        reference = Path(__file__).resolve().parent.parent.joinpath("docs", "REFERENCE.md").read_text()
        self.assertIn("ORDER BY i.last_seen DESC, i.id DESC LIMIT", reference)
        self.assertIn("`incidents_omitted` is `COUNT(DISTINCT i.id)` minus that page", reference)
        self.assertIn("The score still sums every alert.", reference)

    def test_the_incident_page_uses_limit_and_the_score_query_does_not(self):
        event_id = add_event(self.conn)
        first = add_alert(self.conn, event_id, hours=0)
        second = add_alert(self.conn, event_id, hours=-1)
        kept = add_incident(self.conn, first, hours=0)
        older = add_incident(self.conn, second, hours=-1)
        calls = []
        real = self.conn.execute

        def execute(sql, params=()):
            calls.append((" ".join(sql.split()), params))
            return real(sql, params)

        self.conn.execute = execute
        try:
            detail = get_entity(self.conn, "user", "alice")
        finally:
            self.conn.execute = real

        pages = [call for call in calls if "FROM incidents i" in call[0] and "COUNT" not in call[0]]
        counts = [call for call in calls if call[0].startswith("SELECT COUNT(DISTINCT i.id)")]
        self.assertEqual(len(pages), 1)
        self.assertEqual(len(counts), 1)
        self.assertIn("ORDER BY i.last_seen DESC, i.id DESC LIMIT ?", pages[0][0])
        self.assertNotIn("LIMIT", counts[0][0])
        self.assertEqual(pages[0][1], [first, second, RELATED_LIMIT])
        self.assertEqual(counts[0][1], [first, second])
        scores = [call for call in calls if call[0].startswith("SELECT id, rule_id")]
        self.assertEqual(len(scores), 1)
        self.assertNotIn("LIMIT", scores[0][0])
        self.assertIn("ORDER BY last_seen DESC, id DESC", scores[0][0])
        self.assertEqual(scores[0][1], [first, second])
        self.assertEqual([row["id"] for row in detail["incidents"]], [kept, older])
        self.assertEqual(detail["incidents_omitted"], 0)
        self.assertEqual(len(detail["contributions"]), 2)
        source = Path(__file__).resolve().parent.parent.joinpath("watchpost", "entities.py").read_text()
        self.assertNotIn("incidents[:RELATED_LIMIT]", source)


class EntityRelatedOmittedApiTests(ServerTestCase):
    def test_entity_detail_reports_the_dropped_rows(self):
        conn = connect(self.db_path)
        try:
            event_id = add_event(conn)
            kept = [add_alert(conn, event_id, hours=0) for _ in range(RELATED_LIMIT)]
            kept_incidents = [add_incident(conn, alert_id, hours=0) for alert_id in kept]
            older = add_alert(conn, event_id, hours=-24, severity="critical")
            older_incident = add_incident(conn, older, hours=-24)
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get("/api/entities/user/alice")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["alerts"]], list(reversed(kept)))
        self.assertEqual([row["id"] for row in detail["incidents"]], list(reversed(kept_incidents)))
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(detail["incidents_omitted"], 1)
        self.assertNotIn(older, {row["id"] for row in detail["alerts"]})
        self.assertNotIn(older_incident, {row["id"] for row in detail["incidents"]})
        self.assertEqual(detail["score"], RELATED_LIMIT * 10 + 20.0)
        self.assertEqual(detail["alerts"][0]["title"], "[SYNTHETIC] entity alert")
        self.assertEqual(detail["alerts"][0]["synthetic"], 1)
