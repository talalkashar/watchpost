"""GET /api/tokens stays a bare array and names the rows past 100.

The order is newest id first, including revoked rows. A later created_at on
a lower id is the one left out. A revoked row in that page keeps revoked_at.
X-Watchpost-Omitted is that count, including 0 when the list fits. A 401
sends no header. The secret and its hash stay absent. Revoking a token past
the cap by id still works.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from watchpost.auth import list_api_tokens
from watchpost.db import connect, init_schema

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
OMITTED = "X-Watchpost-Omitted"
INSERT = (
    "INSERT INTO api_tokens(name, token_hash, prefix, created_by, created_at, capabilities)"
    " VALUES (?, ?, 'wp_test', 'admin', ?, '[\"ingest\"]')"
)


def _insert(db, specs):
    """specs: created_at. Ids follow insert order. token_hash is the row's own secret stand-in."""
    db.executemany(INSERT, [(f"shipper-{i}", f"secret-hash-{i}", stamp) for i, stamp in enumerate(specs, start=1)])


def _fill(count, stamp="2026-01-01T00:00:00.000Z"):
    return [stamp for _ in range(count)]


class TokensOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_left_out(self):
        _insert(self.conn, ["2026-09-01T00:00:00.000Z"] + _fill(100))
        self.conn.execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE id = 101",
            ("2026-06-01T00:00:00.000Z",))
        rows, omitted = list_api_tokens(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["id"], 101)
        self.assertEqual([row["id"] for row in rows], list(range(101, 1, -1)))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertEqual(
            self.conn.execute("SELECT created_at FROM api_tokens WHERE id = 1").fetchone()[0],
            "2026-09-01T00:00:00.000Z")
        self.assertEqual(rows[0]["revoked_at"], "2026-06-01T00:00:00.000Z")
        self.assertIsNone(rows[1]["revoked_at"])
        self.assertEqual(rows[0]["capabilities"], ["ingest"])
        dumped = json.dumps(rows)
        self.assertNotIn("token_hash", dumped)
        self.assertNotIn("secret-hash-", dumped)

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _fill(100))
        rows, omitted = list_api_tokens(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertIn(1, [row["id"] for row in rows])
        self.assertTrue(all(row["revoked_at"] is None for row in rows))
        self.conn.execute("DELETE FROM api_tokens")
        rows, omitted = list_api_tokens(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class TokensOmittedApiTests(ServerTestCase):
    def _load(self, stamps):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM api_tokens")
            if stamps:
                _insert(db, stamps)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load(["2026-09-01T00:00:00.000Z"] + _fill(100))
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE api_tokens SET revoked_at = ? WHERE id = 101",
                ("2026-06-01T00:00:00.000Z",))
        admin = self.client("admin")
        status, body, headers = admin.get("/api/tokens")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[0]["id"], 101)
        self.assertNotIn(1, [row["id"] for row in body])
        self.assertEqual(body[0]["revoked_at"], "2026-06-01T00:00:00.000Z")
        self.assertEqual(body[0]["capabilities"], ["ingest"])
        dumped = json.dumps(body)
        self.assertNotIn("token_hash", dumped)
        self.assertNotIn("secret-hash-", dumped)
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load(_fill(100))
        status, fitted, headers = admin.get("/api/tokens")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = admin.get("/api/tokens")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_revoking_past_the_cap_still_ends_that_token(self):
        self._load(["2026-09-01T00:00:00.000Z"] + _fill(100))
        admin = self.client("admin")
        status, body, _ = admin.post("/api/tokens/1/revoke")
        self.assertEqual(status, 200, body)
        status, listed, headers = admin.get("/api/tokens")
        self.assertEqual(status, 200, listed)
        self.assertEqual(len(listed), 100)
        self.assertEqual(headers[OMITTED], "1")
        self.assertNotIn(1, [row["id"] for row in listed])
        with sqlite3.connect(self.db_path) as db:
            revoked = db.execute("SELECT revoked_at FROM api_tokens WHERE id = 1").fetchone()[0]
        self.assertIsNotNone(revoked)

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_fill(101))
        status, _body, headers = self.client().get("/api/tokens")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines() if row.startswith("| `GET /api/tokens`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many tokens were past that cap (0 when the list fits)",
            line)
        self.assertIn("never includes the secret or its hash", line)
        self.assertIn("Revoking a token past the cap by `id` still works", line)
        reference = REFERENCE.read_text()
        self.assertIn("newest by `id`, at most 100", reference)
        self.assertIn("never includes the secret or its hash", reference)


if __name__ == "__main__":
    unittest.main()
