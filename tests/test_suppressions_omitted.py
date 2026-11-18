"""GET /api/suppressions stays a bare array and names the rows past 100.

The order stays newest id first. A later created_at on a lower id is the one
left out. active stays false once expired or revoked. X-Watchpost-Omitted is
that count, including 0 when the list fits. A 401 sends no header.
"""

import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.improve import list_suppressions

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
FUTURE = "2099-01-01T00:00:00.000Z"
INSERT = ("INSERT INTO suppressions(rule_id, group_key, reason, expires_at, proposed_by, approved_by, created_at)"
          " VALUES ('brute_force_ip', ?, 'synthetic scanner', ?, 'analyst', 'admin', ?)")


def _insert(db, specs):
    """specs: created_at. Ids follow insert order. expires_at stays in the future."""
    db.executemany(INSERT, [(f"group-{i}", FUTURE, stamp) for i, stamp in enumerate(specs, start=1)])


def _fill(count, stamp="2026-01-01T00:00:00.000Z"):
    return [stamp for _ in range(count)]


class SuppressionsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_left_out(self):
        _insert(self.conn, ["2026-09-01T00:00:00.000Z"] + _fill(100))
        self.conn.execute("UPDATE suppressions SET expires_at = ? WHERE id = 101", ("2020-01-01T00:00:00.000Z",))
        self.conn.execute(
            "UPDATE suppressions SET revoked_at = ?, revoked_by = ? WHERE id = 100",
            ("2026-06-01T00:00:00.000Z", "admin"))
        rows, omitted = list_suppressions(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["id"], 101)
        self.assertEqual([row["id"] for row in rows], list(range(101, 1, -1)))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertEqual(
            self.conn.execute("SELECT created_at FROM suppressions WHERE id = 1").fetchone()[0],
            "2026-09-01T00:00:00.000Z")
        by_id = {row["id"]: row for row in rows}
        self.assertFalse(by_id[101]["active"])
        self.assertFalse(by_id[100]["active"])
        self.assertEqual(by_id[100]["revoked_by"], "admin")
        self.assertTrue(by_id[99]["active"])

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _fill(100))
        rows, omitted = list_suppressions(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertTrue(all(row["active"] for row in rows))
        self.assertIn(1, [row["id"] for row in rows])
        self.conn.execute("DELETE FROM suppressions")
        rows, omitted = list_suppressions(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class SuppressionsOmittedApiTests(ServerTestCase):
    def _load(self, stamps):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM suppressions")
            if stamps:
                _insert(db, stamps)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load(["2026-09-01T00:00:00.000Z"] + _fill(100))
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/suppressions")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[0]["id"], 101)
        self.assertNotIn(1, [row["id"] for row in body])
        self.assertTrue(body[0]["active"])
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load(_fill(100))
        status, fitted, headers = viewer.get("/api/suppressions")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = viewer.get("/api/suppressions")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_fill(101))
        status, _body, headers = self.client().get("/api/suppressions")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/suppressions`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many exceptions were past that cap (0 when the list fits)",
            line)


if __name__ == "__main__":
    unittest.main()
