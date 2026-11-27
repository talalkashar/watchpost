"""GET /api/assets pending is asset changes only, newest 100 by id.

A pending rule change is neither in the list nor in pending_omitted. A later
created_at on a lower id is the one left out of 101. An exact 100 and none
return 0. A 401 has no field.
"""

import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.improve import ASSET_KINDS, list_changes

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
INSERT = ("INSERT INTO change_requests(kind, target, payload, reason, proposed_by, status, created_at)"
          " VALUES (?,?,'{}','synthetic reason','admin',?,?)")


def _insert(db, specs):
    """specs: (kind, target, status, created_at). Ids follow insert order."""
    db.executemany(INSERT, specs)


def _assets(count, kind="asset_add", status="pending", stamp="2026-01-01T00:00:00.000Z"):
    return [(kind, f"host-{i}", status, stamp) for i in range(count)]


class AssetsPendingOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def _pending(self):
        return list_changes(self.conn, "pending", kinds=ASSET_KINDS)

    def test_the_lowest_id_is_the_one_left_out(self):
        _insert(self.conn, [("asset_add", "host-old", "pending", "2026-09-01T00:00:00.000Z")]
                 + _assets(100, "asset_update"))
        rows, omitted = self._pending()
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["id"], 101)
        self.assertEqual([row["id"] for row in rows], list(range(101, 1, -1)))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertTrue(all(row["kind"] in ASSET_KINDS for row in rows))
        self.assertEqual(self.conn.execute("SELECT created_at FROM change_requests WHERE id = 1").fetchone()[0],
                         "2026-09-01T00:00:00.000Z")

    def test_a_pending_rule_change_is_not_in_the_list_or_the_count(self):
        _insert(self.conn, _assets(1) + [("rule_update", "brute_force_ip", "pending",
                                          "2026-09-01T00:00:00.000Z")] * 100)
        rows, omitted = self._pending()
        self.assertEqual([row["id"] for row in rows], [1])
        self.assertEqual(omitted, 0)
        self.assertEqual(rows[0]["kind"], "asset_add")
        _insert(self.conn, [("sigma_add", "rule-x", "pending", "2026-09-02T00:00:00.000Z"),
                            ("setting_update", "retention", "pending", "2026-09-02T00:00:00.000Z"),
                            ("asset_delete", "host-old", "approved", "2026-09-02T00:00:00.000Z")])
        rows, omitted = self._pending()
        self.assertEqual([row["id"] for row in rows], [1])
        self.assertEqual(omitted, 0)
        self.assertNotIn("rule_update", [row["kind"] for row in rows])

    def test_an_exact_cap_and_none_return_zero(self):
        _insert(self.conn, [("asset_add", "a", "pending", "2026-01-01T00:00:00.000Z"),
                            ("asset_update", "b", "pending", "2026-01-01T00:00:00.000Z"),
                            ("asset_delete", "c", "pending", "2026-01-01T00:00:00.000Z")]
                 + _assets(97))
        rows, omitted = self._pending()
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertEqual({row["kind"] for row in rows}, set(ASSET_KINDS))
        self.conn.execute("DELETE FROM change_requests")
        rows, omitted = self._pending()
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class AssetsPendingOmittedApiTests(ServerTestCase):
    def _load(self, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM change_requests")
            if specs:
                _insert(db, specs)

    def test_the_response_names_only_asset_changes_past_the_cap(self):
        self._load([("asset_add", "host-old", "pending", "2026-09-01T00:00:00.000Z")]
                   + _assets(100, "asset_update")
                   + [("rule_update", "brute_force_ip", "pending", "2026-09-02T00:00:00.000Z")])
        status, body, headers = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body["pending"]), 100)
        self.assertEqual(body["pending"][0]["id"], 101)
        self.assertEqual([row["id"] for row in body["pending"]], list(range(101, 1, -1)))
        self.assertTrue(all(row["kind"] in ASSET_KINDS for row in body["pending"]))
        self.assertNotIn(102, [row["id"] for row in body["pending"]])
        self.assertEqual(body["pending_omitted"], 1)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_newer_rule_changes_do_not_hide_an_older_asset(self):
        self._load(_assets(1) + [("rule_update", "brute_force_ip", "pending",
                                  "2026-09-01T00:00:00.000Z")] * 100)
        status, body, _ = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200, body)
        self.assertEqual([row["id"] for row in body["pending"]], [1])
        self.assertEqual(body["pending"][0]["kind"], "asset_add")
        self.assertEqual(body["pending_omitted"], 0)

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        self._load([("asset_add", "a", "pending", "2026-01-01T00:00:00.000Z"),
                    ("asset_update", "b", "pending", "2026-01-01T00:00:00.000Z"),
                    ("asset_delete", "c", "pending", "2026-01-01T00:00:00.000Z")] + _assets(97)
                   + [("asset_delete", "gone", "approved", "2026-06-01T00:00:00.000Z")])
        status, fitted, _ = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted["pending"]), 100)
        self.assertEqual({row["kind"] for row in fitted["pending"]}, set(ASSET_KINDS))
        self.assertEqual(fitted["pending_omitted"], 0)
        self.assertNotIn(101, [row["id"] for row in fitted["pending"]])
        self._load([])
        status, empty, _ = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200)
        self.assertEqual(empty["pending"], [])
        self.assertEqual(empty["pending_omitted"], 0)

    def test_a_rejected_request_has_no_field(self):
        self._load(_assets(101))
        status, body, _ = self.client().get("/api/assets")
        self.assertEqual(status, 401)
        self.assertNotIn("pending_omitted", body)

    def test_the_docs_row_names_pending_omitted(self):
        row = next(line for line in API.read_text().splitlines() if line.startswith("| `GET /api/assets`"))
        self.assertIn("pending_omitted", row)
        self.assertIn("asset_add", row)
        self.assertIn("asset_update", row)
        self.assertIn("asset_delete", row)
