"""GET /api/changes stays a bare array and names the rows past 100.

The order stays newest id first. A later created_at on a lower id is the one
left out. X-Watchpost-Omitted is that count, including 0 when the list fits.
A status filter counts only that status. A 401 sends no header.
"""

import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.improve import list_changes

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
INSERT = ("INSERT INTO change_requests(kind, target, payload, reason, proposed_by, status, created_at)"
          " VALUES ('setting_update','retention','{}','synthetic reason','analyst',?,?)")


def _insert(db, specs):
    """specs: (status, created_at). Ids follow insert order."""
    db.executemany(INSERT, specs)


def _fill(count, status="pending", stamp="2026-01-01T00:00:00.000Z"):
    return [(status, stamp) for _ in range(count)]


class ChangesOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_left_out(self):
        _insert(self.conn, [("pending", "2026-09-01T00:00:00.000Z")] + _fill(100))
        rows, omitted = list_changes(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["id"], 101)
        self.assertEqual([row["id"] for row in rows], list(range(101, 1, -1)))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertEqual(self.conn.execute("SELECT created_at FROM change_requests WHERE id = 1").fetchone()[0],
                         "2026-09-01T00:00:00.000Z")

    def test_a_status_filter_counts_only_that_status(self):
        _insert(self.conn, _fill(101, "pending") + [("approved", "2026-06-01T00:00:00.000Z")])
        rows, omitted = list_changes(self.conn, "pending")
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertTrue(all(row["status"] == "pending" for row in rows))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertNotIn(102, [row["id"] for row in rows])
        approved, approved_omitted = list_changes(self.conn, "approved")
        self.assertEqual([row["id"] for row in approved], [102])
        self.assertEqual(approved_omitted, 0)
        other, other_omitted = list_changes(self.conn, "rejected")
        self.assertEqual(other, [])
        self.assertEqual(other_omitted, 0)

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _fill(100))
        rows, omitted = list_changes(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertIn(1, [row["id"] for row in rows])
        self.conn.execute("DELETE FROM change_requests")
        rows, omitted = list_changes(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class ChangesOmittedApiTests(ServerTestCase):
    def _load(self, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM change_requests")
            _insert(db, specs)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load([("pending", "2026-09-01T00:00:00.000Z")] + _fill(100) + [
            ("approved", "2026-06-01T00:00:00.000Z")])
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/changes")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[0]["id"], 102)
        self.assertNotIn(1, [row["id"] for row in body])
        self.assertEqual(headers[OMITTED], "2")
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, pending, headers = viewer.get("/api/changes?status=pending")
        self.assertEqual(status, 200, pending)
        self.assertIsInstance(pending, list)
        self.assertEqual(len(pending), 100)
        self.assertTrue(all(row["status"] == "pending" for row in pending))
        self.assertNotIn(1, [row["id"] for row in pending])
        self.assertEqual(headers[OMITTED], "1")
        status, approved, headers = viewer.get("/api/changes?status=approved")
        self.assertEqual(status, 200)
        self.assertEqual([row["id"] for row in approved], [102])
        self.assertEqual(headers[OMITTED], "0")
        self._load(_fill(100))
        status, fitted, headers = viewer.get("/api/changes")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = viewer.get("/api/changes")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_fill(101))
        status, _body, headers = self.client().get("/api/changes")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/changes?status=pending`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many matched change requests were past that cap "
            "(0 when the list fits)",
            line)


if __name__ == "__main__":
    unittest.main()
