"""GET /api/dashboard/views stays a bare array and names views past 100.

Order is name COLLATE NOCASE, then id. A name that sorts later is the one
left out, even when its id is lower. The same folded name keeps the lower
id. A private view owned by someone else is not a row and is not counted.
X-Watchpost-Omitted is that count, including 0 when the list fits. A 401
sends no header.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from watchpost.dashboard_views import list_views
from watchpost.db import connect, init_schema

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
INSERT = ("INSERT INTO dashboard_views"
          "(name, filters, layout, visibility, owner, created_at, updated_at)"
          " VALUES (?, ?, ?, ?, ?, ?, ?)")
FILTERS = json.dumps({"severities": ["high"]})
LAYOUT = json.dumps(["p-board"])
STAMP = "2026-01-01T00:00:00.000Z"


def _insert(db, specs):
    """specs: (name, owner, visibility)."""
    db.executemany(INSERT, [
        (name, FILTERS, LAYOUT, visibility, owner, STAMP, STAMP)
        for name, owner, visibility in specs
    ])


def _named(prefix, count, owner, visibility, start=0):
    return [(f"{prefix}{i:03d}", owner, visibility) for i in range(start, start + count)]


class DashboardViewsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_last_name_is_the_one_left_out(self):
        _insert(self.conn, [("zzz", "analyst", "private")])
        _insert(self.conn, _named("v", 100, "analyst", "private"))
        _insert(self.conn, [("aaa", "admin", "private")])
        rows, omitted = list_views(self.conn, "analyst")
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual([row["name"] for row in rows], [f"v{i:03d}" for i in range(100)])
        self.assertNotIn("zzz", [row["name"] for row in rows])
        self.assertNotIn("aaa", [row["name"] for row in rows])
        self.assertEqual(rows[0]["filters"], {"severities": ["high"]})
        self.assertEqual(rows[0]["layout"], ["p-board"])
        kept = self.conn.execute(
            "SELECT id FROM dashboard_views WHERE name = 'zzz'").fetchone()[0]
        self.assertLess(kept, rows[0]["id"])
        admin, admin_omitted = list_views(self.conn, "admin")
        self.assertEqual([row["name"] for row in admin], ["aaa"])
        self.assertEqual(admin_omitted, 0)

    def test_the_same_folded_name_keeps_the_lower_id(self):
        _insert(self.conn, _named("a", 99, "analyst", "private"))
        _insert(self.conn, [("dup", "analyst", "shared"), ("DUP", "admin", "shared")])
        rows, omitted = list_views(self.conn, "analyst")
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[-1]["name"], "dup")
        self.assertEqual(rows[-1]["owner"], "analyst")
        self.assertNotIn("DUP", [row["name"] for row in rows])
        viewer, viewer_omitted = list_views(self.conn, "viewer")
        self.assertEqual(viewer_omitted, 0)
        self.assertEqual([(row["name"], row["owner"]) for row in viewer],
                         [("dup", "analyst"), ("DUP", "admin")])

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _named("v", 100, "analyst", "private"))
        _insert(self.conn, [("hidden", "admin", "private")])
        rows, omitted = list_views(self.conn, "analyst")
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertIn("v000", [row["name"] for row in rows])
        self.conn.execute("DELETE FROM dashboard_views")
        rows, omitted = list_views(self.conn, "analyst")
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class DashboardViewsOmittedApiTests(ServerTestCase):
    def _load(self, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM dashboard_views")
            if specs:
                _insert(db, specs)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load([("zzz", "analyst", "private")]
                   + _named("v", 100, "analyst", "private")
                   + [("aaa", "admin", "private")])
        analyst = self.client("analyst")
        status, body, headers = analyst.get("/api/dashboard/views")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[0]["name"], "v000")
        self.assertEqual(body[0]["filters"], {"severities": ["high"]})
        self.assertNotIn("zzz", [row["name"] for row in body])
        self.assertNotIn("aaa", [row["name"] for row in body])
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load(_named("v", 100, "analyst", "shared") + [("hidden", "admin", "private")])
        status, fitted, headers = analyst.get("/api/dashboard/views")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")
        viewer = self.client("viewer")
        status, shared, headers = viewer.get("/api/dashboard/views")
        self.assertEqual(status, 200)
        self.assertEqual(len(shared), 100)
        self.assertNotIn("hidden", [row["name"] for row in shared])
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = analyst.get("/api/dashboard/views")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_named("v", 101, "analyst", "private"))
        status, _body, headers = self.client().get("/api/dashboard/views")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/dashboard/views`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn("A private view owned by someone else is not a row and is not counted", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many visible views were past that cap (0 when the list fits)",
            line)


if __name__ == "__main__":
    unittest.main()
