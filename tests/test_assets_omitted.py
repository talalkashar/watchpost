"""GET /api/assets caps assets at 100, most critical first, then name.

assets_omitted is how many were past that cap (0 when they fit, including none).
The object wrapper stays. A 401 has no field. Matching still reads every asset.
"""

import sqlite3
import unittest
from pathlib import Path

from watchpost.assets import list_assets, list_assets_page
from watchpost.db import connect, init_schema

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
INSERT = ("INSERT INTO assets(name, kind, criticality, data_tags, addresses, owner, description,"
          " synthetic, created_at, updated_at, updated_by)"
          " VALUES (?, 'server', ?, '[]', '[]', 'ops', 'synthetic host', 1, ?, ?, 'admin')")
STAMP = "2026-01-01T00:00:00.000Z"


def _insert(db, specs):
    """specs: (name, criticality)."""
    db.executemany(INSERT, [(name, crit, STAMP, STAMP) for name, crit in specs])


def _named(count, criticality="critical", prefix="n"):
    width = len(str(count - 1))
    return [(f"{prefix}{i:0{width}d}", criticality) for i in range(count)]


class AssetsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_a_lower_criticality_is_the_one_left_out(self):
        _insert(self.conn, _named(100) + [("aaa", "low")])
        rows, omitted = list_assets_page(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["name"], "n00")
        self.assertEqual(rows[-1]["name"], "n99")
        self.assertNotIn("aaa", [row["name"] for row in rows])
        self.assertTrue(all(row["criticality"] == "critical" for row in rows))
        self.assertIn("aaa", [row["name"] for row in list_assets(self.conn)])

    def test_the_last_name_is_the_one_left_out(self):
        _insert(self.conn, _named(101))
        rows, omitted = list_assets_page(self.conn)
        self.assertEqual([row["name"] for row in rows], [f"n{i:03d}" for i in range(100)])
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["name"], "n000")
        self.assertNotIn("n100", [row["name"] for row in rows])
        self.assertEqual(len(list_assets(self.conn)), 101)

    def test_criticality_outranks_name(self):
        _insert(self.conn, _named(99, prefix="c") + [("zzz", "high"), ("aaa", "low")])
        rows, omitted = list_assets_page(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[-1]["name"], "zzz")
        self.assertEqual(rows[-1]["criticality"], "high")
        self.assertNotIn("aaa", [row["name"] for row in rows])
        self.assertEqual([row["name"] for row in rows[:99]], [f"c{i:02d}" for i in range(99)])

    def test_an_exact_cap_and_none_return_zero(self):
        _insert(self.conn, _named(98) + [("zzz", "high"), ("aaa", "medium")])
        rows, omitted = list_assets_page(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertEqual(rows[-1]["name"], "aaa")
        self.conn.execute("DELETE FROM assets")
        rows, omitted = list_assets_page(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class AssetsOmittedApiTests(ServerTestCase):
    def _load(self, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM assets")
            if specs:
                _insert(db, specs)

    def test_the_response_keeps_the_wrapper_and_names_the_one_left_out(self):
        self._load(_named(100) + [("aaa", "low")])
        status, body, headers = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, dict)
        self.assertEqual(len(body["assets"]), 100)
        self.assertEqual(body["assets"][0]["name"], "n00")
        self.assertNotIn("aaa", [row["name"] for row in body["assets"]])
        self.assertEqual(body["assets_omitted"], 1)
        self.assertEqual(body["pending_omitted"], 0)
        self.assertEqual(body["criticalities"], ["low", "medium", "high", "critical"])
        self.assertIn("kinds", body)
        self.assertIn("data_tags", body)
        self.assertEqual(body["pending"], [])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        self._load(_named(100))
        status, fitted, _ = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted["assets"]), 100)
        self.assertEqual(fitted["assets_omitted"], 0)
        self._load([])
        status, empty, _ = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200)
        self.assertEqual(empty["assets"], [])
        self.assertEqual(empty["assets_omitted"], 0)
        self.assertIn("pending_omitted", empty)

    def test_a_rejected_request_has_no_field(self):
        self._load(_named(101))
        status, body, _ = self.client().get("/api/assets")
        self.assertEqual(status, 401)
        self.assertNotIn("assets_omitted", body)

    def test_the_docs_row_names_assets_omitted(self):
        row = next(line for line in API.read_text().splitlines() if line.startswith("| `GET /api/assets`"))
        self.assertIn("assets_omitted", row)
        self.assertIn("first 100", row)
        self.assertIn("then name", row)
