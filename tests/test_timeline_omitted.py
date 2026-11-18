"""Alert detail says how many related events the 300-row cap dropped.

The rows stay the earliest 300 in the window, in ts, id order. An event outside
the window is not a row and is not omitted. A shorter window returns timeline_omitted 0.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import TIMELINE_LIMIT, get_alert, related_timeline

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes, user="alice", message="[SYNTHETIC] timeline cap"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", user, message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def alert_for(evidence):
    return {"first_seen": SEEN, "last_seen": SEEN, "evidence": evidence}


def add_alert(conn, event_id):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,1,1,?,?)",
        ("synthetic_rule", 1, "alice", "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, event_id))
    return alert_id


class TimelineOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_events_past_the_cap_are_counted_and_the_earliest_stay(self):
        # Lower id, later time: order is ts, then id, so this row is the one past the cap.
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(TIMELINE_LIMIT)]
        # Outside the 30-minute pad. It matches the account and must not count as omitted.
        outside_id = add_event(self.conn, minutes=31)
        alert = alert_for([{"id": early_ids[0], "user": "alice", "src_ip": None}])

        rows = related_timeline(self.conn, alert)
        self.assertEqual([row["id"] for row in rows], early_ids)
        self.assertEqual(alert["timeline_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in rows})
        self.assertNotIn(outside_id, {row["id"] for row in rows})
        self.assertTrue(rows[0]["is_evidence"])
        self.assertFalse(any(row["is_evidence"] for row in rows[1:]))

    def test_a_short_timeline_and_an_exact_cap_omit_nothing(self):
        one = add_event(self.conn, minutes=0, user="alice")
        short = alert_for([{"id": one, "user": "alice", "src_ip": None}])
        short_rows = related_timeline(self.conn, short)
        self.assertEqual(len(short_rows), 1)
        self.assertEqual(short["timeline_omitted"], 0)

        exact_ids = [add_event(self.conn, minutes=1, user="bob") for _ in range(TIMELINE_LIMIT)]
        exact = alert_for([{"id": exact_ids[0], "user": "bob", "src_ip": None}])
        self.assertEqual(len(related_timeline(self.conn, exact)), TIMELINE_LIMIT)
        self.assertEqual(exact["timeline_omitted"], 0)

        empty = alert_for([
            {"id": 1, "user": None, "src_ip": None},
            {"id": 2, "user": "", "src_ip": ""},
        ])
        self.assertEqual(related_timeline(self.conn, empty), [])
        self.assertEqual(empty["timeline_omitted"], 0)

    def test_alert_detail_reports_the_dropped_row(self):
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(TIMELINE_LIMIT)]
        alert_id = add_alert(self.conn, early_ids[0])

        detail = get_alert(self.conn, alert_id)
        self.assertEqual([row["id"] for row in detail["timeline"]], early_ids)
        self.assertEqual(detail["timeline_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["timeline"]})

    def test_the_api_docs_name_the_cap_and_the_omitted_count(self):
        text = API.read_text()
        self.assertIn(
            "`timeline` (the first 300 events involving the same source IPs, users, or hosts, ±30 min,"
            " in `ts, id` order",
            text)
        self.assertIn(
            "`timeline_omitted` (how many matching events were past that cap;"
            " 0 when the window has 300 or fewer)",
            text)


class TimelineOmittedApiTests(ServerTestCase):
    def test_alert_detail_reports_the_dropped_row(self):
        conn = connect(self.db_path)
        try:
            late_id = add_event(conn, minutes=10)
            early_ids = [add_event(conn, minutes=0) for _ in range(TIMELINE_LIMIT)]
            alert_id = add_alert(conn, early_ids[0])
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/alerts/{alert_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["timeline"]], early_ids)
        self.assertEqual(detail["timeline_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["timeline"]})
        self.assertEqual(detail["timeline"][0]["message"], "[SYNTHETIC] timeline cap")
        self.assertTrue(detail["timeline"][0]["is_evidence"])
