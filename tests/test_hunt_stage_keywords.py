"""Hunt stage keywords fold ASCII letters only.

| timechart SPAN=1H count is span 1h. BY and COUNT stay those keywords.
A keyword containing İ is not that word, and the error names the original
token with no combining dot. The keyword list does not call str.lower().
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"

DOTTED_I = "\u0130"
COMBINING_DOT = "\u0307"
BY_LOOKALIKE = "b" + DOTTED_I
COUNT_LOOKALIKE = "COUN" + DOTTED_I
SPAN_LOOKALIKE = "SPA" + DOTTED_I + "=1h"
SPAN_VALUE = "span=1" + DOTTED_I

EVENTS = (
    ("2026-10-07T10:00:00.000Z", "alice"),
    ("2026-10-07T10:05:00.000Z", "Alice"),
    ("2026-10-07T10:10:00.000Z", "bob"),
)


def unexpected(token):
    return f"unexpected {token!r}; use | timechart span=1h [count] [by <field>]"


def unknown_aggregate(token):
    return (f"unknown aggregate {token!r}; stats supports count and dc(<field>)"
            " (also written count(distinct <field>))")


def span_error():
    return f"timechart span must be one of {', '.join(hunt.SPANS)} (given once)"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for ts, user in EVENTS:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, ts, "lab", "web01", "auth_failure", "low", user, "[SYNTHETIC] login", 1))
    return conn


class HuntStageKeywordTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text})

    def test_ascii_keywords_fold(self):
        chart = hunt.parse_stage("TIMECHART SPAN=1H COUNT BY user")
        self.assertEqual(chart["command"], "timechart")
        self.assertEqual(chart["span"], "1h")
        self.assertEqual(chart["by"], [("user", "user")])
        folded = self.run_q("| timechart SPAN=1H COUNT BY user")
        plain = self.run_q("| timechart span=1h count by user")
        self.assertEqual(folded["kind"], "timechart")
        self.assertEqual(folded["span"], "1h")
        self.assertEqual(folded["columns"][1], "alice")
        self.assertEqual(plain["rows"], folded["rows"])
        self.assertGreater(sum(row[1] for row in folded["rows"]), 0)
        stats = self.run_q("| stats COUNT BY user")
        self.assertEqual(stats["kind"], "stats")
        self.assertEqual(stats["columns"], ["user", "count"])
        self.assertEqual(stats["rows"], [["alice", 2], ["bob", 1]])
        self.assertEqual(self.run_q("| stats count by user")["rows"], stats["rows"])

    def test_dotted_capital_i_is_not_a_keyword(self):
        self.assertIn(DOTTED_I, BY_LOOKALIKE)
        self.assertIn(COMBINING_DOT, BY_LOOKALIKE.lower())
        self.assertNotEqual(BY_LOOKALIKE.translate(hunt._ASCII_FOLD), "by")
        self.assertNotEqual(COUNT_LOOKALIKE.translate(hunt._ASCII_FOLD), "count")
        self.assertFalse(SPAN_LOOKALIKE.translate(hunt._ASCII_FOLD).startswith("span="))
        self.assertNotIn(SPAN_VALUE.translate(hunt._ASCII_FOLD)[5:], hunt.SPANS)
        cases = (
            (f"| timechart span=1h {BY_LOOKALIKE} user", unexpected(BY_LOOKALIKE)),
            (f"| timechart span=1h {COUNT_LOOKALIKE}", unexpected(COUNT_LOOKALIKE)),
            (f"| timechart {SPAN_LOOKALIKE} count", unexpected(SPAN_LOOKALIKE)),
            (f"| timechart {SPAN_VALUE} count", span_error()),
            (f"| timechart SPAN=1{DOTTED_I} count", span_error()),
            (f"| stats count {BY_LOOKALIKE} user", unknown_aggregate(BY_LOOKALIKE)),
            (f"| stats {COUNT_LOOKALIKE} by user", unknown_aggregate(COUNT_LOOKALIKE)),
        )
        for query, message in cases:
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    self.run_q(query)
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(caught.exception.status, 400)
                self.assertNotIn(COMBINING_DOT, str(caught.exception))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], len(EVENTS))
        again = self.run_q("| timechart SPAN=1H count")
        self.assertEqual(again["span"], "1h")
        self.assertGreater(sum(row[1] for row in again["rows"]), 0)

    def test_keyword_list_does_not_call_lower(self):
        source = inspect.getsource(hunt.parse_stage)
        assignment = next(line for line in source.splitlines() if "for t in rest" in line)
        self.assertIn("translate(_ASCII_FOLD)", assignment)
        self.assertNotIn(".lower(", assignment)
        self.assertNotIn("casefold(", assignment)
        self.assertNotIn(".lower(", source.replace("str.lower()", ""))
        self.assertNotIn("casefold(", source)

    def test_docs_name_the_keyword_fold(self):
        stage = next(line for line in REFERENCE.read_text().splitlines() if line.startswith("- Only one stage."))
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        for text in (stage, hunt_row):
            self.assertIn("Stage keywords fold ASCII letters only", text)
            self.assertIn("| timechart SPAN=1H count", text)
            self.assertIn("`1h`", text)
            self.assertIn("`BY`", text)
            self.assertIn("`COUNT`", text)
            self.assertIn("\u0130", text)
            self.assertIn("not that word", text)
            self.assertIn("no combining dot", text)


class HuntStageKeywordApiTests(ServerTestCase):
    def test_hunt_folds_stage_keywords(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": ts, "type": "login-failed", "user": user, "message": "[SYNTHETIC] login"}
            for ts, user in EVENTS
        ]})
        self.assertEqual(status, 201, body)

        status, data, headers = client.get("/api/hunt?q=" + quote("| timechart SPAN=1H COUNT BY user"))
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(data["kind"], "timechart")
        self.assertEqual(data["span"], "1h")
        self.assertEqual(data["columns"][1], "alice")

        status, data, headers = client.get("/api/hunt?q=" + quote("| stats COUNT BY user"))
        self.assertEqual(status, 200, data)
        self.assertEqual(data["rows"], [["alice", 2], ["bob", 1]])
        self.assertEqual(headers["Cache-Control"], "no-store")

        for query, message in (
            (f"| timechart span=1h {BY_LOOKALIKE} user", unexpected(BY_LOOKALIKE)),
            (f"| timechart span=1h {COUNT_LOOKALIKE}", unexpected(COUNT_LOOKALIKE)),
            (f"| timechart {SPAN_LOOKALIKE} count", unexpected(SPAN_LOOKALIKE)),
            (f"| timechart {SPAN_VALUE} count", span_error()),
        ):
            with self.subTest(query=query):
                status, data, headers = client.get("/api/hunt?q=" + quote(query))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], message)
                self.assertNotIn(COMBINING_DOT, data["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")
