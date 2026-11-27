"""Alert detail says how many evidence events the 500-row cap dropped.

The rows stay the first 500 in ts, id order. A shorter alert returns evidence_omitted 0.
The count is the joined events, not the stored event_count and not a link whose event is gone.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import EVIDENCE_LIMIT, get_alert

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes, message="[SYNTHETIC] evidence cap"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_ids, event_count=1):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        ("synthetic_rule", 1, "web01", "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, event_count, SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


class EvidenceOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_events_past_the_cap_are_counted_and_the_earliest_stay(self):
        # Lower id, later time: order is ts, then id, so this row is the one past the cap.
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(EVIDENCE_LIMIT)]
        # The stored count is not the join. A reader must not subtract it from the cap.
        alert_id = add_alert(self.conn, [late_id] + early_ids, event_count=9)

        detail = get_alert(self.conn, alert_id)
        self.assertEqual([row["id"] for row in detail["evidence"]], early_ids)
        self.assertEqual(detail["evidence_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["evidence"]})

    def test_a_short_alert_and_an_exact_cap_omit_nothing(self):
        one = add_alert(self.conn, [add_event(self.conn, minutes=0)])
        exact_ids = [add_event(self.conn, minutes=1) for _ in range(EVIDENCE_LIMIT)]
        exact = add_alert(self.conn, exact_ids, event_count=EVIDENCE_LIMIT)
        empty = add_alert(self.conn, [])

        short = get_alert(self.conn, one)
        self.assertEqual(len(short["evidence"]), 1)
        self.assertEqual(short["evidence_omitted"], 0)
        self.assertEqual(len(get_alert(self.conn, exact)["evidence"]), EVIDENCE_LIMIT)
        self.assertEqual(get_alert(self.conn, exact)["evidence_omitted"], 0)
        self.assertEqual(get_alert(self.conn, empty)["evidence"], [])
        self.assertEqual(get_alert(self.conn, empty)["evidence_omitted"], 0)

    def test_a_link_whose_event_is_gone_is_not_an_omitted_row(self):
        alert_id = add_alert(self.conn, [999_999], event_count=5)
        detail = get_alert(self.conn, alert_id)
        self.assertEqual(detail["evidence"], [])
        self.assertEqual(detail["evidence_omitted"], 0)

    def test_the_api_docs_name_the_cap_and_the_omitted_count(self):
        text = API.read_text()
        self.assertIn(
            "`evidence` (the first 500 evidence events in `ts, id` order), `evidence_omitted`"
            " (how many evidence events were past that cap; 0 when the alert has 500 or fewer)",
            text)


class EvidenceOmittedApiTests(ServerTestCase):
    def test_alert_detail_reports_the_dropped_row(self):
        conn = connect(self.db_path)
        try:
            late_id = add_event(conn, minutes=10)
            early_ids = [add_event(conn, minutes=0) for _ in range(EVIDENCE_LIMIT)]
            alert_id = add_alert(conn, [late_id] + early_ids, event_count=9)
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/alerts/{alert_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["evidence"]], early_ids)
        self.assertEqual(detail["evidence_omitted"], 1)
        self.assertEqual(detail["evidence"][0]["message"], "[SYNTHETIC] evidence cap")
        self.assertEqual(detail["evidence"][0]["synthetic"], 1)
