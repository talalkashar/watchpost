"""Incident detail says how many evidence events the 1000-row cap dropped.

The rows stay the first 1000 distinct events in ts, id order. An event linked to two
alerts is one row. A shorter incident returns events_omitted 0. A link whose event
is gone is not a row.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.incidents import INCIDENT_EVENT_LIMIT, get_incident

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes, message="[SYNTHETIC] incident cap"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_ids):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        ("synthetic_rule", 1, "web01", "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, len(event_ids), SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


def add_incident(conn, alert_ids):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("Synthetic probe", "high", "open", SEEN, SEEN,
         json.dumps({"src_ip": [], "user": [], "host": ["web01"]}),
         json.dumps(["Initial Access"]), len(alert_ids), 1, SEEN, SEEN))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, SEEN) for alert_id in alert_ids])
    return incident_id


class EventsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_events_past_the_cap_are_counted_and_the_earliest_stay(self):
        # Lower id, later time: order is ts, then id, so this row is the one past the cap.
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(INCIDENT_EVENT_LIMIT)]
        incident_id = add_incident(self.conn, [add_alert(self.conn, [late_id] + early_ids)])

        detail = get_incident(self.conn, incident_id)
        self.assertEqual([row["id"] for row in detail["events"]], early_ids)
        self.assertEqual(detail["events_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["events"]})
        self.assertEqual(detail["events"][0]["alert_ids"], [1])

    def test_a_second_alert_link_is_still_one_event(self):
        shared = add_event(self.conn, minutes=0)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(INCIDENT_EVENT_LIMIT - 1)]
        # Two join rows for `shared`. Counting join rows would report one omitted.
        exact = add_incident(self.conn, [
            add_alert(self.conn, [shared] + early_ids),
            add_alert(self.conn, [shared]),
        ])
        extra = add_event(self.conn, minutes=10)
        past = add_incident(self.conn, [
            add_alert(self.conn, early_ids + [shared, extra]),
            add_alert(self.conn, [extra]),
        ])

        exact_detail = get_incident(self.conn, exact)
        self.assertEqual(len(exact_detail["events"]), INCIDENT_EVENT_LIMIT)
        self.assertEqual(exact_detail["events_omitted"], 0)
        shared_row = next(row for row in exact_detail["events"] if row["id"] == shared)
        self.assertEqual(shared_row["alert_ids"], [1, 2])

        past_detail = get_incident(self.conn, past)
        self.assertEqual(len(past_detail["events"]), INCIDENT_EVENT_LIMIT)
        self.assertEqual(past_detail["events_omitted"], 1)
        self.assertNotIn(extra, {row["id"] for row in past_detail["events"]})

    def test_a_short_incident_and_an_exact_cap_omit_nothing(self):
        one = add_incident(self.conn, [add_alert(self.conn, [add_event(self.conn, minutes=0)])])
        exact_ids = [add_event(self.conn, minutes=1) for _ in range(INCIDENT_EVENT_LIMIT)]
        exact = add_incident(self.conn, [add_alert(self.conn, exact_ids)])
        empty = add_incident(self.conn, [add_alert(self.conn, [])])

        short = get_incident(self.conn, one)
        self.assertEqual(len(short["events"]), 1)
        self.assertEqual(short["events_omitted"], 0)
        self.assertEqual(len(get_incident(self.conn, exact)["events"]), INCIDENT_EVENT_LIMIT)
        self.assertEqual(get_incident(self.conn, exact)["events_omitted"], 0)
        self.assertEqual(get_incident(self.conn, empty)["events"], [])
        self.assertEqual(get_incident(self.conn, empty)["events_omitted"], 0)

    def test_a_link_whose_event_is_gone_is_not_an_omitted_row(self):
        incident_id = add_incident(self.conn, [add_alert(self.conn, [999_999])])
        detail = get_incident(self.conn, incident_id)
        self.assertEqual(detail["events"], [])
        self.assertEqual(detail["events_omitted"], 0)

    def test_the_api_docs_name_the_cap_and_the_omitted_count(self):
        text = API.read_text()
        self.assertIn(
            "`events` (the first 1000 distinct evidence events in `ts, id` order, each with `alert_ids`;"
            " an event on two alerts is one row), `events_omitted`"
            " (how many distinct evidence events were past that cap; 0 when the incident has 1000 or fewer)",
            text)


class EventsOmittedApiTests(ServerTestCase):
    def test_incident_detail_reports_the_dropped_row(self):
        conn = connect(self.db_path)
        try:
            late_id = add_event(conn, minutes=10)
            early_ids = [add_event(conn, minutes=0) for _ in range(INCIDENT_EVENT_LIMIT)]
            incident_id = add_incident(conn, [add_alert(conn, [late_id] + early_ids)])
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/incidents/{incident_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["events"]], early_ids)
        self.assertEqual(detail["events_omitted"], 1)
        self.assertEqual(detail["events"][0]["message"], "[SYNTHETIC] incident cap")
        self.assertEqual(detail["events"][0]["synthetic"], 1)
