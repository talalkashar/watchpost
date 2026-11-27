"""GET /api/evaluations stays a bare array and names the runs past 20.

The order stays newest id first. A later created_at on a lower id is the one
left out. X-Watchpost-Omitted is that count, including 0 when the history
fits. A 401 sends no header.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.improve import list_evaluations

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
INSERT = ("INSERT INTO evaluation_runs(created_at, trigger, created_by, results)"
          " VALUES (?, 'manual', 'analyst', ?)")


def _insert(db, specs):
    """specs: created_at. Ids follow insert order."""
    db.executemany(INSERT, [(stamp, json.dumps({"n": i})) for i, stamp in enumerate(specs, start=1)])


def _fill(count, stamp="2026-01-01T00:00:00.000Z"):
    return [stamp for _ in range(count)]


class EvaluationsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_left_out(self):
        _insert(self.conn, ["2026-09-01T00:00:00.000Z"] + _fill(20))
        rows, omitted = list_evaluations(self.conn)
        self.assertEqual(len(rows), 20)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["id"], 21)
        self.assertEqual([row["id"] for row in rows], list(range(21, 1, -1)))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertEqual(self.conn.execute("SELECT created_at FROM evaluation_runs WHERE id = 1").fetchone()[0],
                         "2026-09-01T00:00:00.000Z")

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _fill(20))
        rows, omitted = list_evaluations(self.conn)
        self.assertEqual(len(rows), 20)
        self.assertEqual(omitted, 0)
        self.assertIn(1, [row["id"] for row in rows])
        self.conn.execute("DELETE FROM evaluation_runs")
        rows, omitted = list_evaluations(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class EvaluationsOmittedApiTests(ServerTestCase):
    def _load(self, stamps):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM evaluation_runs")
            if stamps:
                _insert(db, stamps)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load(["2026-09-01T00:00:00.000Z"] + _fill(20))
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/evaluations")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 20)
        self.assertEqual(body[0]["id"], 21)
        self.assertNotIn(1, [row["id"] for row in body])
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load(_fill(20))
        status, fitted, headers = viewer.get("/api/evaluations")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 20)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = viewer.get("/api/evaluations")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_fill(21))
        status, _body, headers = self.client().get("/api/evaluations")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/evaluations`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many runs were past that cap (0 when the history fits)",
            line)


if __name__ == "__main__":
    unittest.main()
