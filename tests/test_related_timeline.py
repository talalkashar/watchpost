"""Alert related timeline matches user names case-insensitively. Source IPs stay exact.

NOCASE folds ASCII letters only, the same way event search does.
"""

import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.queries import related_timeline

BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes, user=None, src_ip=None, message="[SYNTHETIC] timeline"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", user, src_ip, message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def alert_for(evidence):
    return {"first_seen": SEEN, "last_seen": SEEN, "evidence": evidence}


class RelatedTimelineTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_ascii_user_spellings_are_one_account_and_ips_stay_exact(self):
        evidence_id = add_event(self.conn, 0, user="Alice", src_ip="192.0.2.10")
        add_event(self.conn, 1, user="alice", src_ip="192.0.2.20")
        add_event(self.conn, 2, user="ALICE", src_ip=None)
        add_event(self.conn, 3, user="other", src_ip="192.0.2.10")
        # A different spelling of an address is not the same source IP.
        add_event(self.conn, 4, user="other", src_ip="2001:DB8::1")
        add_event(self.conn, 5, user="bob", src_ip="2001:db8::1")
        # Outside the 30-minute pad, even when the account matches.
        add_event(self.conn, 31, user="alice", src_ip="192.0.2.10")
        add_event(self.conn, -31, user="Alice", src_ip="192.0.2.10")

        evidence = [{"id": evidence_id, "user": "Alice", "src_ip": "192.0.2.10"},
                    {"id": evidence_id, "user": None, "src_ip": "2001:db8::1"}]
        # The second evidence row names the lowercase address only. 2001:DB8::1 is a different string.
        rows = related_timeline(self.conn, alert_for(evidence))
        self.assertEqual(
            [(row["user"], row["src_ip"], row["is_evidence"]) for row in rows],
            [
                ("Alice", "192.0.2.10", True),
                ("alice", "192.0.2.20", False),
                ("ALICE", None, False),
                ("other", "192.0.2.10", False),
                ("bob", "2001:db8::1", False),
            ])
        self.assertEqual([row["ts"] for row in rows], sorted(row["ts"] for row in rows))

    def test_a_non_ascii_letter_stays_two_accounts(self):
        evidence_id = add_event(self.conn, 0, user="érin", src_ip=None)
        add_event(self.conn, 1, user="Érin", src_ip=None)
        add_event(self.conn, 2, user="erin", src_ip=None)
        rows = related_timeline(self.conn, alert_for([
            {"id": evidence_id, "user": "érin", "src_ip": None}]))
        self.assertEqual([row["user"] for row in rows], ["érin"])

    def test_an_ascii_second_account_still_folds(self):
        first = add_event(self.conn, 0, user="Alice", src_ip="192.0.2.10")
        second = add_event(self.conn, 1, user="Bob", src_ip="192.0.2.11")
        add_event(self.conn, 2, user="bob", src_ip="192.0.2.99")
        rows = related_timeline(self.conn, alert_for([
            {"id": first, "user": "Alice", "src_ip": "192.0.2.10"},
            {"id": second, "user": "Bob", "src_ip": "192.0.2.11"},
        ]))
        self.assertEqual([row["user"] for row in rows], ["Alice", "Bob", "bob"])
        self.assertEqual([row["is_evidence"] for row in rows], [True, True, False])

    def test_no_ip_and_no_user_is_an_empty_timeline(self):
        add_event(self.conn, 0, user="alice", src_ip="192.0.2.10")
        self.assertEqual(related_timeline(self.conn, alert_for([
            {"id": 1, "user": None, "src_ip": None},
            {"id": 2, "user": "", "src_ip": ""},
        ])), [])

    def test_the_user_comparison_is_nocase_and_the_ip_comparison_is_not(self):
        evidence_id = add_event(self.conn, 0, user="Alice", src_ip="192.0.2.10")
        captured = {}
        real_execute = self.conn.execute

        def execute(sql, args=()):
            if "FROM events" in sql and "BETWEEN" in sql:
                captured["sql"] = sql
                captured["args"] = list(args)
            return real_execute(sql, args)

        self.conn.execute = execute
        related_timeline(self.conn, alert_for([
            {"id": evidence_id, "user": "Alice", "src_ip": "192.0.2.10"}]))
        self.assertIn("user COLLATE NOCASE IN (?)", captured["sql"])
        self.assertIn("src_ip IN (?)", captured["sql"])
        self.assertNotIn("src_ip COLLATE", captured["sql"])
        self.assertEqual(captured["args"][2:], ["192.0.2.10", "Alice"])


class RelatedTimelineApiTests(ServerTestCase):
    def test_alert_detail_includes_the_other_user_spelling(self):
        conn = connect(self.db_path)
        try:
            evidence_id = add_event(conn, 0, user="Alice", src_ip="192.0.2.10")
            other_id = add_event(conn, 2, user="alice", src_ip="192.0.2.20")
            missed_id = add_event(conn, 3, user="other", src_ip="2001:DB8::1")
            conn.execute(
                "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
                " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,1,1,?,?)",
                ("synthetic_rule", 1, "alice|192.0.2.10", "high", "synthetic alert", "synthetic", "open",
                 SEEN, SEEN, SEEN, SEEN))
            alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, evidence_id))
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/alerts/{alert_id}")
        self.assertEqual(status, 200, detail)
        by_id = {row["id"]: row for row in detail["timeline"]}
        self.assertEqual(set(by_id), {evidence_id, other_id})
        self.assertNotIn(missed_id, by_id)
        self.assertTrue(by_id[evidence_id]["is_evidence"])
        self.assertFalse(by_id[other_id]["is_evidence"])
        self.assertEqual(by_id[other_id]["user"], "alice")
