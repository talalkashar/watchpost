"""Hunt aggregate keywords fold ASCII letters only.

COUNT, DC(USER), and count(DISTINCT Host) are count and dc().
count(DİSTINCT user) and count(dıstinct user) stay the unknown-aggregate error.
User grouping SQL stays COUNT(DISTINCT lower(user)).
"""

import inspect
import re
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
HUNT = Path(__file__).resolve().parent.parent / "watchpost" / "hunt.py"

# Alice, alice, and ALICE are one account. WEB01 and web01 stay two hosts.
EVENTS = (
    ("2026-10-07T10:00:00.000Z", "Alice", "WEB01"),
    ("2026-10-07T10:05:00.000Z", "alice", "web01"),
    ("2026-10-07T10:10:00.000Z", "ALICE", "WEB01"),
    ("2026-10-07T10:15:00.000Z", "\u00c9RIN", "\u00c9rin-host"),
    ("2026-10-07T10:20:00.000Z", "\u00e9rin", "\u00e9rin-host"),
)
DOTTED = "count(D\u0130STINCT user)"
DOTLESS = "count(d\u0131stinct user)"
BARE = "D\u0130STINCT"


def aggregate_error(token):
    return (f"unknown aggregate {token!r}; stats supports count and dc(<field>)"
            " (also written count(distinct <field>))")


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for ts, user, host in EVENTS:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, ts, "lab", host, "auth_failure", "low", user, "[SYNTHETIC] login", 1))
    return conn


class AggregateFoldTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text})

    def test_keywords_fold_ascii_letters_only(self):
        folded = self.run_q("| stats COUNT, DC(USER), count(DISTINCT Host)")
        plain = self.run_q("| stats count, dc(user), count(distinct host)")
        self.assertEqual(folded["columns"], ["count", "dc(user)", "dc(host)"])
        self.assertEqual(folded["rows"], [[5, 3, 4]])
        self.assertEqual(plain["rows"], folded["rows"])
        spaced = self.run_q("| stats Dc( USER ), count( distinct Host )")
        self.assertEqual(spaced["columns"], ["dc(user)", "dc(host)"])
        self.assertEqual(spaced["rows"], [[3, 4]])
        # The account still folds. The host does not, so WEB01 and web01 stay two.
        by_user = self.run_q("| stats count(distinct Host) by user")
        self.assertEqual(by_user["columns"], ["user", "dc(host)"])
        self.assertEqual(by_user["rows"], [["alice", 2], ["\u00c9rin", 1], ["\u00e9rin", 1]])
        self.assertEqual(hunt._group_expr("user", "user"), "lower(user)")
        self.assertEqual(hunt._group_expr("host", "host"), "host")
        self.assertEqual(hunt._aggregate_sql("user", "user"), "COUNT(DISTINCT lower(user))")
        self.assertEqual(hunt._aggregate_sql("host", "host"), "COUNT(DISTINCT host)")

    def test_lookalike_distinct_stays_unknown(self):
        for token in (DOTTED, DOTLESS, BARE):
            with self.subTest(token=token):
                with self.assertRaises(hunt.HuntError) as caught:
                    self.run_q(f"| stats {token}")
                self.assertEqual(str(caught.exception), aggregate_error(token))
                self.assertEqual(caught.exception.status, 400)
                self.assertIsNone(hunt._read_aggregate(token))
        self.assertEqual(self.run_q("| stats dc(user)")["rows"], [[3]])

    def test_folded_spellings_are_one_aggregate(self):
        for query in ("| stats COUNT, count", "| stats DC(user), count(distinct user)"):
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    self.run_q(query)
                self.assertIn("at most 3 different aggregates", str(caught.exception))

    def test_matcher_does_not_ignore_case(self):
        self.assertFalse(hunt._AGGREGATE.flags & re.IGNORECASE)
        self.assertNotIn("(?i)", hunt._AGGREGATE.pattern)
        source = inspect.getsource(hunt._read_aggregate)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)
        self.assertNotIn("IGNORECASE", source)
        self.assertNotIn("re.I", source)
        compile_line = next(line for line in HUNT.read_text().splitlines() if "_AGGREGATE = re.compile" in line)
        self.assertNotIn("IGNORECASE", compile_line)
        self.assertNotIn("re.I", compile_line)

    def test_docs_name_the_ascii_fold(self):
        stats = next(line for line in REFERENCE.read_text().splitlines()
                     if line.startswith("| `stats "))
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        for text in (stats, hunt_row):
            self.assertIn("`count`, `dc`, and `distinct` fold ASCII letters only", text)
            self.assertIn("`COUNT`", text)
            self.assertIn("`DC(USER)`", text)
            self.assertIn("`count(DISTINCT Host)`", text)
            self.assertIn("`count(D\u0130STINCT user)`", text)
            self.assertIn("`count(d\u0131stinct user)`", text)


class AggregateApiTests(ServerTestCase):
    def test_hunt_accepts_folded_aggregates(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": ts, "type": "login-failed", "user": user, "host": host,
             "message": "[SYNTHETIC] login"}
            for ts, user, host in EVENTS
        ]})
        self.assertEqual(status, 201, body)

        def rows(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return data["rows"]

        self.assertEqual(rows("| stats COUNT, DC(USER), count(distinct Host)"), [[5, 3, 4]])
        self.assertEqual(rows("| stats count(distinct Host) by user"),
                         [["alice", 2], ["\u00c9rin", 1], ["\u00e9rin", 1]])
        for token in (DOTTED, DOTLESS, BARE):
            with self.subTest(token=token):
                status, data, headers = client.get("/api/hunt?q=" + quote(f"| stats {token}"))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], aggregate_error(token))
                self.assertEqual(headers["Cache-Control"], "no-store")
