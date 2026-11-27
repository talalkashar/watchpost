"""Event detail pages the newest 50 linked alerts and says how many were left out.

`alerts` stays the newest 50 by alert id, returned in id order. A later created_at
on a lower id is the one past the cap. Each row keeps id, title, and status.
alerts_omitted is 0 when the event has 50 or fewer, including none.
An alert on another event is not a row and is not omitted.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import EVENT_ALERT_LIMIT, get_event

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
EARLY = iso(BASE)
LATER = iso(BASE + timedelta(hours=2))


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, raw, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?,1)",
        (EARLY, EARLY, "lab", "web01", "auth_failure", "low", "alice",
         "[SYNTHETIC] event cap", "{}"))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_id, created_at, title, status="open"):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,1,1,?,?)",
        ("synthetic_rule", 1, "k", "medium", title, "synthetic", status,
         created_at, created_at, created_at, created_at))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, event_id))
    return alert_id


class EventAlertsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_a_later_stamp_on_the_lowest_id_is_the_one_left_out(self):
        event_id = add_event(self.conn)
        # Lowest id, later created_at. Order is alert id, so this row is past the cap.
        late_id = add_alert(self.conn, event_id, LATER, "[SYNTHETIC] later stamp", status="investigating")
        kept = [
            add_alert(self.conn, event_id, EARLY, f"[SYNTHETIC] kept {i}", status="open")
            for i in range(EVENT_ALERT_LIMIT)
        ]
        other = add_event(self.conn)
        other_id = add_alert(self.conn, other, LATER, "[SYNTHETIC] other event", status="resolved")

        detail = get_event(self.conn, event_id)
        self.assertEqual([row["id"] for row in detail["alerts"]], kept)
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["alerts"]})
        self.assertNotIn(other_id, {row["id"] for row in detail["alerts"]})
        self.assertEqual(detail["alerts"][0]["title"], "[SYNTHETIC] kept 0")
        self.assertEqual(detail["alerts"][0]["status"], "open")
        self.assertEqual(set(detail["alerts"][0]), {"id", "title", "status"})
        self.assertLess(detail["alerts"][0]["id"], detail["alerts"][-1]["id"])

        other_detail = get_event(self.conn, other)
        self.assertEqual([row["id"] for row in other_detail["alerts"]], [other_id])
        self.assertEqual(other_detail["alerts"][0]["status"], "resolved")
        self.assertEqual(other_detail["alerts_omitted"], 0)

    def test_a_list_that_fits_returns_zero(self):
        event_id = add_event(self.conn)
        one = add_alert(self.conn, event_id, EARLY, "[SYNTHETIC] one", status="investigating")
        short = get_event(self.conn, event_id)
        self.assertEqual([row["id"] for row in short["alerts"]], [one])
        self.assertEqual(short["alerts"][0]["status"], "investigating")
        self.assertEqual(short["alerts_omitted"], 0)

        exact = [add_alert(self.conn, event_id, EARLY, f"[SYNTHETIC] exact {i}") for i in range(EVENT_ALERT_LIMIT - 1)]
        filled = get_event(self.conn, event_id)
        self.assertEqual(len(filled["alerts"]), EVENT_ALERT_LIMIT)
        self.assertEqual([row["id"] for row in filled["alerts"]], [one] + exact)
        self.assertEqual(filled["alerts_omitted"], 0)

        empty_id = add_event(self.conn)
        empty = get_event(self.conn, empty_id)
        self.assertEqual(empty["alerts"], [])
        self.assertEqual(empty["alerts_omitted"], 0)
        self.assertIn("raw", empty)

    def test_the_api_docs_name_the_cap(self):
        text = API.read_text()
        self.assertIn(
            "linked alerts (`id`, `title`, `status`): the newest 50 by alert `id`, returned in `id` order."
            " `alerts_omitted` is how many linked alerts were past that cap (0 when they fit, including none)",
            text)


class EventAlertsOmittedApiTests(ServerTestCase):
    def test_event_detail_reports_the_dropped_alert(self):
        conn = connect(self.db_path)
        try:
            event_id = add_event(conn)
            late_id = add_alert(conn, event_id, LATER, "[SYNTHETIC] later stamp", status="investigating")
            kept = [
                add_alert(conn, event_id, EARLY, "[SYNTHETIC] kept", status="open")
                for _ in range(EVENT_ALERT_LIMIT)
            ]
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/events/{event_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["alerts"]], kept)
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["alerts"]})
        self.assertEqual(detail["alerts"][0]["title"], "[SYNTHETIC] kept")
        self.assertEqual(detail["alerts"][0]["status"], "open")
        self.assertEqual(set(detail["alerts"][0]), {"id", "title", "status"})
        self.assertIn("[SYNTHETIC]", detail["message"])

        denied, body, _ = self.client().get(f"/api/events/{event_id}")
        self.assertEqual(denied, 401)
        self.assertNotIn("alerts_omitted", body)
