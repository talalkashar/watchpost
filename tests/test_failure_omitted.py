"""Metrics failure lists say how many groups the cap of 5 dropped.

The rows stay the groups with the most auth failures. A quieter group is the
one left out. A list that fits, including an empty table, returns 0. A success
is not a group, and a missing address or account is not a group. The user fold
and the stored IP spelling stay as they are.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import TOP_FAILURE_LIMIT, metrics

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
TS = "2026-09-15T12:00:00.000Z"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, user=None, src_ip=None, event_type="auth_failure", n=1):
    for _ in range(n):
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (TS, TS, "test", event_type, "low", user, src_ip, "synthetic labeled"))


class FailureOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def body(self):
        return metrics(self.conn)

    def test_a_quieter_address_and_account_are_the_ones_past_the_cap(self):
        for i in range(TOP_FAILURE_LIMIT):
            add_event(self.conn, user=f"user{i}", src_ip=f"198.51.100.{i + 1}", n=TOP_FAILURE_LIMIT - i + 1)
        add_event(self.conn, user="quiet", src_ip="198.51.100.90", n=1)
        body = self.body()
        self.assertEqual(body["top_failure_ips_omitted"], 1)
        self.assertEqual(body["top_failure_users_omitted"], 1)
        self.assertEqual(len(body["top_failure_ips"]), TOP_FAILURE_LIMIT)
        self.assertEqual(len(body["top_failure_users"]), TOP_FAILURE_LIMIT)
        self.assertNotIn("198.51.100.90", [row["src_ip"] for row in body["top_failure_ips"]])
        self.assertNotIn("quiet", [row["user"] for row in body["top_failure_users"]])
        self.assertEqual(body["top_failure_ips"][0], {"src_ip": "198.51.100.1", "count": TOP_FAILURE_LIMIT + 1})
        self.assertEqual(body["top_failure_users"][0], {"user": "user0", "count": TOP_FAILURE_LIMIT + 1})

    def test_folded_spellings_are_one_group_and_stored_addresses_stay_apart(self):
        for i in range(TOP_FAILURE_LIMIT):
            add_event(self.conn, user=f"user{i}", src_ip=f"198.51.100.{i + 1}", n=4)
        # Without the fold these two spellings would be two omitted groups.
        add_event(self.conn, user="Alice", src_ip="203.0.113.8", n=2)
        add_event(self.conn, user="alice", src_ip="203.0.113.8", n=1)
        add_event(self.conn, user="ÉRIN", src_ip="2001:DB8::1", n=3)
        add_event(self.conn, user="érin", src_ip="2001:db8::1", n=2)
        body = self.body()
        users = {row["user"]: row["count"] for row in body["top_failure_users"]}
        ips = {row["src_ip"]: row["count"] for row in body["top_failure_ips"]}
        self.assertEqual(users["user0"], 4)
        self.assertNotIn("alice", users)
        self.assertNotIn("Érin", users)
        self.assertNotIn("érin", users)
        # Five accounts of 4, plus alice (3), Érin (3), and érin (2). Folding the
        # accented pair would put that group of 5 in the list and leave omitted at 2.
        self.assertEqual(body["top_failure_users_omitted"], 3)
        self.assertEqual(ips["198.51.100.1"], 4)
        self.assertNotIn("203.0.113.8", ips)
        self.assertNotIn("2001:DB8::1", ips)
        self.assertNotIn("2001:db8::1", ips)
        # Those two spellings are two groups. One merged address would leave omitted at 2.
        self.assertEqual(body["top_failure_ips_omitted"], 3)

    def test_a_success_and_a_missing_field_are_not_groups(self):
        add_event(self.conn, user="alice", src_ip="198.51.100.10", n=2)
        add_event(self.conn, user="sam", src_ip="198.51.100.11", event_type="auth_success", n=3)
        add_event(self.conn, user=None, src_ip="198.51.100.12", n=4)
        add_event(self.conn, user="bob", src_ip=None, n=4)
        body = self.body()
        self.assertEqual(body["top_failure_ips_omitted"], 0)
        self.assertEqual(body["top_failure_users_omitted"], 0)
        self.assertEqual([row["src_ip"] for row in body["top_failure_ips"]],
                         ["198.51.100.12", "198.51.100.10"])
        self.assertEqual([row["user"] for row in body["top_failure_users"]], ["bob", "alice"])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        empty = self.body()
        self.assertEqual(empty["top_failure_ips"], [])
        self.assertEqual(empty["top_failure_users"], [])
        self.assertEqual(empty["top_failure_ips_omitted"], 0)
        self.assertEqual(empty["top_failure_users_omitted"], 0)
        add_event(self.conn, user="alice", src_ip="198.51.100.1")
        one = self.body()
        self.assertEqual(one["top_failure_ips_omitted"], 0)
        self.assertEqual(one["top_failure_users_omitted"], 0)
        for i in range(1, TOP_FAILURE_LIMIT):
            add_event(self.conn, user=f"user{i}", src_ip=f"198.51.100.{i + 1}")
        exact = self.body()
        self.assertEqual(exact["top_failure_ips_omitted"], 0)
        self.assertEqual(exact["top_failure_users_omitted"], 0)
        self.assertEqual(len(exact["top_failure_ips"]), TOP_FAILURE_LIMIT)
        self.assertEqual(len(exact["top_failure_users"]), TOP_FAILURE_LIMIT)

    def test_the_docs_name_both_omitted_counts(self):
        api = API.read_text()
        self.assertIn(
            "`top_failure_ips_omitted` and `top_failure_users_omitted` are how many groups"
            " were past that cap (0 when there are 5 or fewer)",
            api)
        self.assertIn("A success is not a group", api)
        self.assertIn("A missing address or account is not a group", api)
        self.assertIn("`top_failure_ips` groups the stored address", api)


class FailureOmittedApiTests(ServerTestCase):
    def test_the_metrics_endpoint_returns_both_omitted_counts(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(TOP_FAILURE_LIMIT):
                add_event(db, user=f"user{i}", src_ip=f"198.51.100.{i + 1}", n=2)
            add_event(db, user="quiet", src_ip="198.51.100.90", n=1)
        status, body, headers = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["top_failure_ips_omitted"], 1)
        self.assertEqual(body["top_failure_users_omitted"], 1)
        self.assertEqual(len(body["top_failure_ips"]), TOP_FAILURE_LIMIT)
        self.assertEqual(len(body["top_failure_users"]), TOP_FAILURE_LIMIT)
        self.assertNotIn("198.51.100.90", [row["src_ip"] for row in body["top_failure_ips"]])
        self.assertNotIn("quiet", [row["user"] for row in body["top_failure_users"]])

    def test_an_empty_table_and_a_rejected_request(self):
        status, body, _ = self.client("viewer").get("/api/metrics")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["top_failure_ips"], [])
        self.assertEqual(body["top_failure_users"], [])
        self.assertEqual(body["top_failure_ips_omitted"], 0)
        self.assertEqual(body["top_failure_users_omitted"], 0)
        status, denied, _ = self.client().get("/api/metrics")
        self.assertEqual(status, 401)
        self.assertNotIn("top_failure_ips_omitted", denied)
        self.assertNotIn("top_failure_users_omitted", denied)
