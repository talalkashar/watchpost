"""Hunt group fields fold ASCII letters only.

| stats count by USER groups by user.
| stats count by useK is unknown field useK, not usek and not user.
| stats count by USİR is unknown field USİR, and the error has no combining dot.
_group_field does not call str.lower().
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

KELVIN = "use\u212a"
DOTTED = "US\u0130R"
COMBINING_DOT = "\u0307"

EVENTS = (
    ("2026-10-07T10:00:00.000Z", "alice", "web01"),
    ("2026-10-07T10:05:00.000Z", "Alice", "WEB01"),
    ("2026-10-07T10:10:00.000Z", "bob", "db01"),
)


def unknown(name):
    return f"unknown field {name!r}; group by one of {', '.join(hunt.GROUPABLE)}"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for ts, user, host in EVENTS:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, ts, "lab", host, "auth_failure", "low", user, "[SYNTHETIC] login", 1))
    return conn


class HuntGroupFoldTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text})

    def test_user_and_host_fold_ascii_letters_only(self):
        self.assertEqual(hunt._group_field("USER"), ("user", "user"))
        self.assertEqual(hunt._group_field("Host"), ("host", "host"))
        folded = self.run_q("| stats count by USER")
        plain = self.run_q("| stats count by user")
        self.assertEqual(folded["columns"], ["user", "count"])
        self.assertEqual(folded["rows"], [["alice", 2], ["bob", 1]])
        self.assertEqual(plain["rows"], folded["rows"])
        by_host = self.run_q("| stats count by HOST")
        self.assertEqual(by_host["columns"], ["host", "count"])
        self.assertEqual(by_host["rows"], [["WEB01", 1], ["db01", 1], ["web01", 1]])
        self.assertEqual(self.run_q("| top USER")["columns"], ["user", "count", "percent"])
        self.assertEqual(self.run_q("| top USER")["rows"][0][0], "alice")
        chart = self.run_q("| timechart span=1h count by USER")
        self.assertEqual(chart["columns"][1], "alice")

    def test_lookalike_letters_stay_unknown(self):
        self.assertEqual(KELVIN.lower(), "usek")
        self.assertIn(COMBINING_DOT, DOTTED.lower())
        for name in (KELVIN, DOTTED):
            with self.subTest(name=name):
                with self.assertRaises(hunt.HuntError) as caught:
                    self.run_q(f"| stats count by {name}")
                self.assertEqual(str(caught.exception), unknown(name))
                self.assertEqual(caught.exception.status, 400)
                self.assertNotIn(COMBINING_DOT, str(caught.exception))
                self.assertNotIn("usek", str(caught.exception))
                with self.assertRaises(hunt.HuntError) as dc:
                    self.run_q(f"| stats dc({name})")
                self.assertEqual(str(dc.exception), unknown(name))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], len(EVENTS))

    def test_group_field_does_not_call_lower(self):
        source = inspect.getsource(hunt._group_field)
        self.assertIn("translate(_ASCII_FOLD)", source)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)

    def test_docs_name_the_group_fold(self):
        stats = next(line for line in REFERENCE.read_text().splitlines()
                     if line.startswith("| `stats "))
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        for text in (stats, hunt_row):
            self.assertIn("Group field names fold ASCII letters only", text)
            self.assertIn("`user`", text)
            self.assertIn("use\u212a", text)
            self.assertIn("not `usek`", text)
            self.assertIn("US\u0130R", text)
            self.assertIn("no combining dot", text)


class HuntGroupFoldApiTests(ServerTestCase):
    def test_hunt_groups_the_folded_field(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": ts, "type": "login-failed", "user": user, "host": host,
             "message": "[SYNTHETIC] login"}
            for ts, user, host in EVENTS
        ]})
        self.assertEqual(status, 201, body)

        status, data, headers = client.get("/api/hunt?q=" + quote("| stats count by USER"))
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(data["columns"], ["user", "count"])
        self.assertEqual(data["rows"], [["alice", 2], ["bob", 1]])

        for name in (KELVIN, DOTTED):
            with self.subTest(name=name):
                status, data, headers = client.get("/api/hunt?q=" + quote(f"| stats count by {name}"))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], unknown(name))
                self.assertNotIn(COMBINING_DOT, data["error"])
                self.assertNotIn("usek", data["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")
