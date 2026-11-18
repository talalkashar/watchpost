"""Metrics top_failure_users folds ASCII case with SQLite lower(), the same fold hunt groups use.

Alice and alice are one row named alice, so one account does not take two of the five slots.
Érin and érin stay two rows. top_failure_ips keeps the stored address.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import metrics

TS = "2026-09-15T12:00:00.000Z"


def add_failure(conn, user=None, src_ip=None, event_type="auth_failure"):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (TS, TS, "test", event_type, "low", user, src_ip, "synthetic labeled"))


class FailureUserTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_ascii_spellings_are_one_account_so_the_sixth_stays_in_the_top_five(self):
        # Without the fold, Alice (6) and alice (5) are two of the five slots and eve (1) is out.
        for user, count in (("Alice", 6), ("alice", 5), ("bob", 4), ("carol", 3), ("dave", 2), ("eve", 1)):
            for _ in range(count):
                add_failure(self.conn, user=user, src_ip="198.51.100.10")
        add_failure(self.conn, user="alice", src_ip="198.51.100.10", event_type="auth_success")
        rows = metrics(self.conn)["top_failure_users"]
        self.assertEqual(rows, [
            {"user": "alice", "count": 11},
            {"user": "bob", "count": 4},
            {"user": "carol", "count": 3},
            {"user": "dave", "count": 2},
            {"user": "eve", "count": 1},
        ])

    def test_a_non_ascii_letter_stays_two_rows_and_addresses_stay_stored(self):
        for _ in range(3):
            add_failure(self.conn, user="ÉRIN", src_ip="2001:DB8::1")
        for _ in range(2):
            add_failure(self.conn, user="érin", src_ip="2001:db8::1")
        # É folds neither way. The ASCII letters in ÉRIN do, so this row joins ÉRIN.
        add_failure(self.conn, user="Érin", src_ip="2001:DB8::1")
        body = metrics(self.conn)
        self.assertEqual(body["top_failure_users"], [
            {"user": "Érin", "count": 4},
            {"user": "érin", "count": 2},
        ])
        self.assertEqual(body["top_failure_ips"], [
            {"src_ip": "2001:DB8::1", "count": 4},
            {"src_ip": "2001:db8::1", "count": 2},
        ])

    def test_the_user_query_groups_with_sqlite_lower(self):
        add_failure(self.conn, user="Alice", src_ip="198.51.100.10")
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append((sql, args))
            return real_execute(sql, args)

        self.conn.execute = execute
        metrics(self.conn)
        user_sql = [sql for sql, _ in captured if "auth_failure" in sql and " AS user" in sql]
        ip_sql = [sql for sql, _ in captured if "src_ip, COUNT" in sql]
        self.assertEqual(len(user_sql), 1)
        self.assertIn("SELECT lower(user) AS user", user_sql[0])
        self.assertIn("GROUP BY lower(user)", user_sql[0])
        self.assertIn("ORDER BY count DESC, lower(user)", user_sql[0])
        self.assertNotIn("GROUP BY user", user_sql[0].replace("GROUP BY lower(user)", ""))
        self.assertEqual(len(ip_sql), 1)
        self.assertIn("GROUP BY src_ip", ip_sql[0])
        self.assertIn("ORDER BY count DESC, src_ip", ip_sql[0])
        self.assertNotIn("lower(", ip_sql[0])

    def test_the_docs_name_the_ascii_fold(self):
        text = (Path(__file__).resolve().parent.parent / "docs" / "API.md").read_text()
        self.assertIn("`Alice`, `alice`, and `ALICE` are one row named `alice`", text)
        self.assertIn("`Érin` and `érin` stay two rows", text)
        self.assertIn("`top_failure_ips` groups the stored address", text)
        self.assertIn("`2001:DB8::1` and `2001:db8::1` stay two addresses", text)


class FailureUserApiTests(ServerTestCase):
    def test_the_metrics_endpoint_returns_the_folded_account(self):
        with sqlite3.connect(self.db_path) as db:
            for user, count, ip in (
                ("ALICE", 2, "203.0.113.8"),
                ("alice", 1, "203.0.113.8"),
                ("ÉRIN", 2, "2001:DB8::2"),
                ("érin", 1, "2001:db8::2"),
            ):
                for _ in range(count):
                    add_failure(db, user=user, src_ip=ip)
        status, body, headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200)
        self.assertEqual(body["top_failure_users"], [
            {"user": "alice", "count": 3},
            {"user": "Érin", "count": 2},
            {"user": "érin", "count": 1},
        ])
        self.assertEqual(body["top_failure_ips"], [
            {"src_ip": "203.0.113.8", "count": 3},
            {"src_ip": "2001:DB8::2", "count": 2},
            {"src_ip": "2001:db8::2", "count": 1},
        ])
        self.assertEqual(headers["Cache-Control"], "no-store")
