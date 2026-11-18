"""GET /api/hunt/saved stays a bare array and names searches past 100.

Order is name COLLATE NOCASE. A name that sorts later under that fold is the
one left out, even when its id is lower. ASCII order would keep `Zebra` and
drop `a099`; NOCASE drops `Zebra`. Names are unique under that fold, so two
spellings of one name are not two rows. X-Watchpost-Omitted is that count,
including 0 when the list fits. A 401 sends no header.
"""

import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.hunt import list_saved

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
INSERT = ("INSERT INTO saved_searches(name, query, description, owner, created_at)"
          " VALUES (?, ?, ?, ?, ?)")
STAMP = "2026-01-01T00:00:00.000Z"


def _insert(db, specs):
    """specs: (name, owner)."""
    db.executemany(INSERT, [
        (name, "user:alice", f"hunt {name}", owner, STAMP) for name, owner in specs
    ])


def _named(prefix, count, owner="analyst", start=0):
    return [(f"{prefix}{i:03d}", owner) for i in range(start, start + count)]


class SavedSearchesOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_nocase_order_leaves_out_the_later_name(self):
        _insert(self.conn, [("Zebra", "analyst")])
        _insert(self.conn, _named("a", 100))
        rows, omitted = list_saved(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual([row["name"] for row in rows], [f"a{i:03d}" for i in range(100)])
        self.assertNotIn("Zebra", [row["name"] for row in rows])
        kept = self.conn.execute(
            "SELECT id FROM saved_searches WHERE name = 'Zebra'").fetchone()[0]
        self.assertLess(kept, rows[0]["id"])
        self.assertEqual(rows[0]["query"], "user:alice")
        self.assertEqual(rows[0]["description"], "hunt a000")
        self.assertEqual(rows[0]["owner"], "analyst")
        self.assertEqual(rows[0]["created_at"], STAMP)

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _named("a", 100))
        rows, omitted = list_saved(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertEqual(rows[-1]["name"], "a099")
        self.conn.execute("DELETE FROM saved_searches")
        rows, omitted = list_saved(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class SavedSearchesOmittedApiTests(ServerTestCase):
    def _load(self, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM saved_searches")
            if specs:
                _insert(db, specs)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load([("Zebra", "analyst")] + _named("a", 100))
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/hunt/saved")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[0]["name"], "a000")
        self.assertEqual(body[0]["query"], "user:alice")
        self.assertEqual(body[0]["description"], "hunt a000")
        self.assertEqual(body[0]["owner"], "analyst")
        self.assertNotIn("Zebra", [row["name"] for row in body])
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load(_named("a", 100))
        status, fitted, headers = viewer.get("/api/hunt/saved")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = viewer.get("/api/hunt/saved")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_named("a", 101))
        status, _body, headers = self.client().get("/api/hunt/saved")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/hunt/saved`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn("name COLLATE NOCASE", line)
        self.assertIn("at most 100", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many saved searches were past that cap (0 when the list fits)",
            line)


if __name__ == "__main__":
    unittest.main()
