"""related_timeline: the 30-minute pad, an empty match, and the 300-row cap.

Events that share an evidence source IP or user and fall inside
first_seen minus 30 minutes through last_seen plus 30 minutes come back
with is_evidence set. No source IP and no user is an empty timeline.
The query stops at 300, earliest by ts then id.
"""

import unittest
from datetime import datetime, timedelta, timezone

from watchpost.db import connect, init_schema, iso
from watchpost.queries import TIMELINE_LIMIT, related_timeline

FIRST = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
LAST = datetime(2026, 10, 7, 14, 0, tzinfo=timezone.utc)
IP_A = "203.0.113.10"
IP_B = "203.0.113.20"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, when, user=None, src_ip=None):
    ts = iso(when)
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", user, src_ip, "[SYNTHETIC] related timeline"))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def alert_for(evidence, first=FIRST, last=LAST):
    return {"first_seen": iso(first), "last_seen": iso(last), "evidence": evidence}


class RelatedTimelineGapTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_shared_src_ip_or_user_inside_the_pad_is_returned_with_is_evidence(self):
        # Insert out of time order. The window is the whole span plus 30 minutes on each side.
        before = add_event(self.conn, FIRST - timedelta(minutes=30, milliseconds=1), user="alice", src_ip=IP_A)
        end_edge = add_event(self.conn, LAST + timedelta(minutes=30), user="bob", src_ip="198.51.100.77")
        evidence_a = add_event(self.conn, FIRST, user="alice", src_ip=IP_A)
        after = add_event(self.conn, LAST + timedelta(minutes=30, milliseconds=1), user="bob", src_ip=IP_B)
        user_only = add_event(self.conn, FIRST + timedelta(minutes=20), user="alice", src_ip="198.51.100.8")
        neither = add_event(self.conn, FIRST + timedelta(hours=1), user="carol", src_ip="198.51.100.9")
        evidence_b = add_event(self.conn, LAST, user="bob", src_ip=IP_B)
        start_edge = add_event(self.conn, FIRST - timedelta(minutes=30), user="erin", src_ip=IP_A)
        far = add_event(self.conn, FIRST - timedelta(minutes=31), user="alice", src_ip=IP_A)
        # 13:00 is an hour from both ends, still inside first_seen-30m .. last_seen+30m.
        ip_middle = add_event(self.conn, FIRST + timedelta(hours=1), user="dave", src_ip=IP_A)

        alert = alert_for([
            {"id": evidence_a, "user": "alice", "src_ip": IP_A},
            {"id": evidence_b, "user": "bob", "src_ip": IP_B},
        ])
        rows = related_timeline(self.conn, alert)

        self.assertEqual(
            [(row["id"], row["user"], row["src_ip"], row["is_evidence"]) for row in rows],
            [
                (start_edge, "erin", IP_A, False),
                (evidence_a, "alice", IP_A, True),
                (user_only, "alice", "198.51.100.8", False),
                (ip_middle, "dave", IP_A, False),
                (evidence_b, "bob", IP_B, True),
                (end_edge, "bob", "198.51.100.77", False),
            ])
        self.assertEqual([row["ts"] for row in rows], sorted(row["ts"] for row in rows))
        self.assertTrue(all("is_evidence" in row for row in rows))
        returned = {row["id"] for row in rows}
        self.assertNotIn(before, returned)
        self.assertNotIn(after, returned)
        self.assertNotIn(neither, returned)
        self.assertNotIn(far, returned)
        self.assertEqual(alert["timeline_omitted"], 0)

    def test_no_src_ip_and_no_user_returns_empty(self):
        real_id = add_event(self.conn, FIRST, user="alice", src_ip=IP_A)
        add_event(self.conn, LAST, user="bob", src_ip=IP_B)
        cases = {
            "null identifiers": [{"id": real_id, "user": None, "src_ip": None}],
            "blank identifiers": [
                {"id": real_id, "user": "", "src_ip": ""},
                {"id": real_id, "user": None, "src_ip": ""},
            ],
            "no evidence": [],
        }
        for name, evidence in cases.items():
            with self.subTest(name=name):
                alert = alert_for(evidence)
                self.assertEqual(related_timeline(self.conn, alert), [])
                self.assertEqual(alert["timeline_omitted"], 0)

    def test_the_query_stops_at_300(self):
        self.assertEqual(TIMELINE_LIMIT, 300)
        # Lowest id, later time: order is ts then id, so this row is the one past the cap.
        late_id = add_event(self.conn, FIRST + timedelta(minutes=10), user="alice", src_ip=IP_A)
        early_ids = [
            add_event(self.conn, FIRST, user="alice", src_ip=IP_A) for _ in range(TIMELINE_LIMIT)]
        # Same IP, outside the pad. It is not a row and it is not omitted.
        outside_id = add_event(self.conn, FIRST + timedelta(minutes=31), user="alice", src_ip=IP_A)
        alert = alert_for(
            [{"id": early_ids[0], "user": "alice", "src_ip": IP_A}],
            first=FIRST, last=FIRST)
        captured = {}
        real_execute = self.conn.execute

        def execute(sql, args=()):
            if "LIMIT" in sql:
                captured["sql"] = sql
            return real_execute(sql, args)

        self.conn.execute = execute
        rows = related_timeline(self.conn, alert)

        self.assertTrue(captured["sql"].rstrip().endswith("LIMIT 300"))
        self.assertEqual(len(rows), 300)
        self.assertEqual([row["id"] for row in rows], early_ids)
        self.assertEqual(alert["timeline_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in rows})
        self.assertNotIn(outside_id, {row["id"] for row in rows})
        self.assertTrue(rows[0]["is_evidence"])
        self.assertFalse(any(row["is_evidence"] for row in rows[1:]))
