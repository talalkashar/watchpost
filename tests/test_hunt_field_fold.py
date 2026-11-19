"""Hunt filter field names fold ASCII letters only.

The capture is [A-Za-z_]+, so the name is already ASCII.
user:alice and USER:alice stay the user field.
That assignment does not call str.lower() or casefold.
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


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        ("2026-10-07T10:00:00.000Z", "2026-10-07T10:00:00.000Z", "lab", "web01",
         "auth_failure", "low", "alice", "[SYNTHETIC] login", 1))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        ("2026-10-07T10:05:00.000Z", "2026-10-07T10:05:00.000Z", "lab", "db01",
         "auth_success", "info", "bob", "[SYNTHETIC] other", 1))
    return conn


class HuntFieldFoldTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, query):
        page = hunt.run(self.conn, {"q": query})
        return [event["user"] for event in page["events"]]

    def test_field_names_fold_ascii_letters_only(self):
        self.assertEqual(hunt._FIELD.pattern, r"([A-Za-z_]+):")
        for query in ("user:alice", "USER:alice", "User:alice"):
            with self.subTest(query=query):
                terms = hunt.parse(query)
                self.assertEqual(terms[0]["field"], "user")
                self.assertEqual(terms[0]["value"], "alice")
                self.assertEqual(self.users(query), ["alice"])
                self.assertEqual(hunt.explain(query)[0]["field"], "user")
        self.assertEqual(hunt.parse("HOST:web01")[0]["field"], "host")
        self.assertEqual(self.users("HOST:web01"), ["alice"])
        self.assertEqual(self.users("user:bob"), ["bob"])

    def test_lookalike_letter_is_not_a_field_name(self):
        # Kelvin K is outside [A-Za-z_], so the token stays a message search.
        term = hunt.parse("use\u212a:alice")[0]
        self.assertEqual(term["field"], "message")
        self.assertEqual(term["value"], "use\u212a:alice")
        self.assertEqual(self.users("use\u212a:alice"), [])

    def test_assignment_does_not_call_lower(self):
        source = inspect.getsource(hunt._parse)
        assignment = next(line for line in source.splitlines() if "match.group(1)" in line)
        self.assertIn("translate(_ASCII_FOLD)", assignment)
        self.assertNotIn(".lower(", assignment)
        self.assertNotIn("casefold(", assignment)
        self.assertNotIn(".lower(", source)
        self.assertNotIn(".casefold(", source)


class HuntFieldFoldApiTests(ServerTestCase):
    def test_hunt_keeps_the_folded_field(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [{
            "ts": "2026-10-07T10:00:00.000Z", "type": "login", "user": "alice",
            "host": "web01", "message": "[SYNTHETIC] login",
        }]})
        self.assertEqual(status, 201, body)

        def hunt_users(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(data["terms"][0]["field"], "user")
            return [event["user"] for event in data["events"]]

        self.assertEqual(hunt_users("user:alice"), ["alice"])
        self.assertEqual(hunt_users("USER:alice"), ["alice"])

    def test_docs_name_the_field_fold(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        fields = next(line for line in REFERENCE.read_text().splitlines()
                      if line.startswith("Fields: `user`"))
        for text in (hunt_row, fields):
            self.assertIn("Filter field names fold ASCII letters only", text)
            self.assertIn("`[A-Za-z_]+`", text)
            self.assertIn("`user:alice`", text)
            self.assertIn("`USER:alice`", text)
            self.assertIn("`user` field", text)
