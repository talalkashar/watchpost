"""Hunt stage commands fold ASCII letters only.

| STATS count by user is stats. A command containing İ is not stats, top,
or timechart, and the error names the original token with no combining dot.
The command assignment does not call str.lower().
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
LOOKALIKES = ("st" + DOTTED_I + "ts", "t" + DOTTED_I + "p", "t" + DOTTED_I + "mechart")

EVENTS = (
    ("2026-10-07T10:00:00.000Z", "alice"),
    ("2026-10-07T10:05:00.000Z", "Alice"),
    ("2026-10-07T10:10:00.000Z", "bob"),
)


def unknown(token):
    return f"unknown command {token!r}; supported commands are stats, top and timechart"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for ts, user in EVENTS:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, ts, "lab", "web01", "auth_failure", "low", user, "[SYNTHETIC] login", 1))
    return conn


class HuntCommandFoldTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text})

    def test_ascii_commands_fold(self):
        self.assertEqual(hunt.parse_stage("STATS count by user")["command"], "stats")
        self.assertEqual(hunt.parse_stage("TOP user")["command"], "top")
        self.assertEqual(hunt.parse_stage("TIMECHART span=1h count")["command"], "timechart")
        folded = self.run_q("| STATS count by user")
        plain = self.run_q("| stats count by user")
        self.assertEqual(folded["kind"], "stats")
        self.assertEqual(folded["columns"], ["user", "count"])
        self.assertEqual(folded["rows"], [["alice", 2], ["bob", 1]])
        self.assertEqual(plain["rows"], folded["rows"])
        top = self.run_q("| TOP user")
        self.assertEqual(top["kind"], "top")
        self.assertEqual(top["rows"][0][0], "alice")
        chart = self.run_q("| TIMECHART span=1h count")
        self.assertEqual(chart["kind"], "timechart")
        self.assertEqual(chart["span"], "1h")
        self.assertGreater(sum(row[1] for row in chart["rows"]), 0)

    def test_dotted_capital_i_is_not_a_command(self):
        for token in LOOKALIKES:
            with self.subTest(token=token):
                self.assertIn(DOTTED_I, token)
                self.assertIn(COMBINING_DOT, token.lower())
                self.assertNotIn(token.translate(hunt._ASCII_FOLD), hunt.COMMANDS)
                with self.assertRaises(hunt.HuntError) as caught:
                    self.run_q(f"| {token} count by user")
                self.assertEqual(str(caught.exception), unknown(token))
                self.assertEqual(caught.exception.status, 400)
                self.assertNotIn(COMBINING_DOT, str(caught.exception))
                self.assertNotIn("stats", str(caught.exception).split(";", 1)[0])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], len(EVENTS))
        again = self.run_q("| STATS count by user")
        self.assertEqual(again["rows"], [["alice", 2], ["bob", 1]])

    def test_command_assignment_does_not_call_lower(self):
        source = inspect.getsource(hunt.parse_stage)
        assignment = next(line for line in source.splitlines() if "tokens[0]" in line and "command" in line)
        self.assertIn("translate(_ASCII_FOLD)", assignment)
        self.assertNotIn(".lower(", assignment)
        self.assertNotIn("casefold(", assignment)

    def test_docs_name_the_command_fold(self):
        stage = next(line for line in REFERENCE.read_text().splitlines() if line.startswith("- Only one stage."))
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        for text in (stage, hunt_row):
            self.assertIn("Stage commands fold ASCII letters only", text)
            self.assertIn("| STATS count by user", text)
            self.assertIn("`stats`", text)
            self.assertIn("\u0130", text)
            self.assertIn("not `stats`, `top`, or `timechart`", text)
            self.assertIn("original token", text)
            self.assertIn("no combining dot", text)


class HuntCommandFoldApiTests(ServerTestCase):
    def test_hunt_folds_the_command(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": ts, "type": "login-failed", "user": user, "message": "[SYNTHETIC] login"}
            for ts, user in EVENTS
        ]})
        self.assertEqual(status, 201, body)

        status, data, headers = client.get("/api/hunt?q=" + quote("| STATS count by user"))
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(data["kind"], "stats")
        self.assertEqual(data["rows"], [["alice", 2], ["bob", 1]])

        for token in LOOKALIKES:
            with self.subTest(token=token):
                status, data, headers = client.get("/api/hunt?q=" + quote(f"| {token} count by user"))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], unknown(token))
                self.assertNotIn(COMBINING_DOT, data["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")
