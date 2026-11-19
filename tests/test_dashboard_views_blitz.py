"""Ids, limits, and list snapshots for dashboard views.

A view id SQLite cannot store is a 404, not a 500, and it does not write.
A float is not truncated onto another row. A negative limit is not "every row".
The omitted count and the page are one snapshot, so the leftover is not negative.
"""

import os
import tempfile
import unittest

from watchpost import dashboard_views
from watchpost.dashboard_views import ViewError, delete, list_views, save
from watchpost.db import connect, init_schema, transaction

FILTERS = '{"severities": ["high"]}'
LAYOUT = '["p-board"]'
STAMP = "2026-01-01T00:00:00.000Z"
INSERT = ("INSERT INTO dashboard_views"
          "(name, filters, layout, visibility, owner, created_at, updated_at)"
          " VALUES (?, ?, ?, ?, ?, ?, ?)")


class DashboardViewBlitzTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def _body(self, name="Queue", visibility="private", severities=None, layout=None):
        return {"name": name, "visibility": visibility,
                "filters": {"severities": ["high"] if severities is None else severities},
                "layout": ["p-board"] if layout is None else layout}

    def _save(self, name="Queue", actor="analyst", visibility="private", view_id=None):
        return save(self.conn, self._body(name, visibility), actor, view_id)

    def _raises(self, fn, status, message):
        with self.assertRaises(ViewError) as caught:
            fn()
        self.assertEqual(caught.exception.status, status)
        self.assertEqual(str(caught.exception), message)

    def _count(self):
        return self.conn.execute("SELECT COUNT(*) FROM dashboard_views").fetchone()[0]

    def _name(self, view_id):
        return self.conn.execute("SELECT name FROM dashboard_views WHERE id = ?",
                                 (view_id,)).fetchone()["name"]

    def _names(self):
        return [row["name"] for row in self.conn.execute(
            "SELECT name FROM dashboard_views ORDER BY id")]

    def _audit_count(self, action):
        return self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = ?", (action,)).fetchone()[0]

    def test_ids_sqlite_cannot_store_do_not_write(self):
        saved = self._save("kept")
        self.assertEqual(saved["id"], 1)
        updated = self._audit_count("dashboard_view_updated")
        deleted = self._audit_count("dashboard_view_deleted")
        bad_ids = (1.9, True, False, 0, -1, 2**63, 10**30, "1.9", "9" * 30)
        for view_id in bad_ids:
            with self.subTest(view_id=view_id):
                self._raises(lambda: save(self.conn, self._body("changed"), "analyst", view_id),
                             404, "dashboard view not found")
                self._raises(lambda: delete(self.conn, view_id, "analyst"),
                             404, "dashboard view not found")
        self._raises(lambda: delete(self.conn, None, "analyst"), 404, "dashboard view not found")
        self.assertEqual(self._name(saved["id"]), "kept")
        self.assertEqual(self._count(), 1)
        self.assertEqual(self._audit_count("dashboard_view_updated"), updated)
        self.assertEqual(self._audit_count("dashboard_view_deleted"), deleted)
        self.assertFalse(self.conn.in_transaction)
        renamed = save(self.conn, self._body("renamed"), "analyst", str(saved["id"]))
        self.assertEqual((renamed["id"], renamed["name"]), (saved["id"], "renamed"))
        padded = save(self.conn, self._body("padded"), "analyst", "01")
        self.assertEqual((padded["id"], padded["name"]), (1, "padded"))

    def test_missing_and_foreign_rows_stay_put(self):
        saved = self._save("mine")
        self._raises(lambda: save(self.conn, self._body("stolen"), "admin", saved["id"]),
                     404, "dashboard view not found")
        self._raises(lambda: delete(self.conn, saved["id"], "admin"),
                     404, "dashboard view not found")
        self._raises(lambda: save(self.conn, self._body("nope"), "analyst", 999),
                     404, "dashboard view not found")
        self._raises(lambda: delete(self.conn, 999, "analyst"), 404, "dashboard view not found")
        self.assertEqual(self._name(saved["id"]), "mine")
        self.assertEqual(self._audit_count("dashboard_view_updated"), 0)
        self.assertEqual(self._audit_count("dashboard_view_deleted"), 0)
        self.assertFalse(self.conn.in_transaction)

    def test_limit_must_be_a_non_negative_sqlite_integer(self):
        self._save("only")
        for limit in (-1, None, 1.5, True, False, 2**63, "1"):
            with self.subTest(limit=limit):
                self._raises(lambda: list_views(self.conn, "analyst", limit),
                             400, "limit must be a non-negative integer")
        rows, omitted = list_views(self.conn, "analyst", 2**63 - 1)
        self.assertEqual([row["name"] for row in rows], ["only"])
        self.assertEqual(omitted, 0)
        self.assertFalse(self.conn.in_transaction)

    def test_list_orders_by_name_then_id_and_skips_other_private(self):
        self._save("b")
        self._save("a")
        self._save("aaa", actor="admin", visibility="private")
        self._save("M", actor="admin", visibility="shared")
        folded = self._save("A", actor="admin", visibility="shared")
        rows, omitted = list_views(self.conn, "analyst")
        # "a" and "A" tie under NOCASE, so the lower id stays ahead. "aaa" is someone else's private view.
        self.assertEqual([row["name"] for row in rows], ["a", "A", "b", "M"])
        self.assertEqual(omitted, 0)
        self.assertLess(rows[0]["id"], folded["id"])
        self.assertEqual(rows[1]["id"], folded["id"])
        page, left = list_views(self.conn, "analyst", 2)
        self.assertEqual([row["name"] for row in page], ["a", "A"])
        self.assertEqual(left, 2)
        none, all_left = list_views(self.conn, "analyst", 0)
        self.assertEqual(none, [])
        self.assertEqual(all_left, 4)

    def test_listing_inside_an_open_transaction_keeps_that_transaction(self):
        with transaction(self.conn):
            self.conn.execute(INSERT, ("inside", FILTERS, LAYOUT, "private", "analyst", STAMP, STAMP))
            rows, omitted = list_views(self.conn, "analyst")
            self.assertEqual([row["name"] for row in rows], ["inside"])
            self.assertEqual(omitted, 0)
            self.assertTrue(self.conn.in_transaction)
        self.assertFalse(self.conn.in_transaction)
        self.assertEqual(self._names(), ["inside"])

    def test_save_rejects_a_bad_body_without_inserting(self):
        bad = [
            (None, "view must be an object"),
            (self._body("   "), "name must be 1-80 characters"),
            (self._body("n" * 81), "name must be 1-80 characters"),
            ({**self._body(), "visibility": "public"}, "visibility must be private or shared"),
            ({**self._body(), "filters": {"severities": ["high"], "host": "x"}},
             "filters must contain only severities"),
            ({**self._body(), "filters": {"severities": ["High", "high"]}},
             "severities must be a non-empty list of unique known severities"),
            ({**self._body(), "layout": []},
             "layout must be a non-empty list of unique dashboard panels"),
            ({**self._body(), "layout": ["p-board", "p-board"]},
             "layout must be a non-empty list of unique dashboard panels"),
            ({**self._body(), "layout": ["p-secret"]},
             "layout must be a non-empty list of unique dashboard panels"),
        ]
        for body, message in bad:
            with self.subTest(message=message):
                self._raises(lambda: save(self.conn, body, "analyst"), 400, message)
        self.assertEqual(self._count(), 0)

    def test_save_stores_the_stripped_name_and_catalog_spelling(self):
        wide = self._save("n" * 80)
        self.assertEqual(wide["name"], "n" * 80)
        body = self._body("  Night queue  ", "Private")
        body["filters"] = {"severities": ["LOW", "High"]}
        body["layout"] = ["p-feed", "p-map"]
        saved = save(self.conn, body, "analyst")
        self.assertEqual(saved["name"], "Night queue")
        self.assertEqual(saved["visibility"], "private")
        self.assertEqual(saved["filters"]["severities"], ["low", "high"])
        self.assertEqual(saved["layout"], ["p-feed", "p-map"])
        self.assertEqual(saved["owner"], "analyst")

    def test_name_clash_uses_the_stored_spelling(self):
        stored = self._save("dup")
        other = self._save("other")
        self._raises(lambda: save(self.conn, self._body("DUP"), "analyst", other["id"]),
                     409, "you already have a dashboard view named 'dup'")
        self.assertEqual(self._name(other["id"]), "other")
        renamed = save(self.conn, self._body("DUP"), "analyst", stored["id"])
        self.assertEqual((renamed["id"], renamed["name"]), (stored["id"], "DUP"))
        admin = self._save("DUP", actor="admin")
        self.assertEqual((admin["owner"], admin["name"]), ("admin", "DUP"))

    def test_identical_resave_keeps_the_row(self):
        saved = self._save("same")
        original = dashboard_views.now_iso
        dashboard_views.now_iso = lambda: saved["updated_at"]
        self.addCleanup(setattr, dashboard_views, "now_iso", original)
        again = save(self.conn, self._body("same"), "analyst", saved["id"])
        self.assertEqual(again["id"], saved["id"])
        self.assertEqual(again["created_at"], saved["created_at"])
        self.assertEqual(again["name"], "same")
        self.assertEqual(self._count(), 1)

    def test_delete_removes_only_the_owned_row(self):
        first = self._save("one")
        second = self._save("two")
        self.assertEqual(delete(self.conn, first["id"], "analyst"), {"ok": True})
        self.assertEqual(self._names(), ["two"])
        self.assertEqual(self._audit_count("dashboard_view_deleted"), 1)
        self._raises(lambda: delete(self.conn, first["id"], "analyst"),
                     404, "dashboard view not found")
        self.assertEqual(self._audit_count("dashboard_view_deleted"), 1)
        self.assertEqual(self._name(second["id"]), "two")

    def test_save_returns_the_row_decoded_before_commit(self):
        # A delete that lands on COMMIT must not turn the save into a TypeError,
        # and the caller still receives the row that was written.
        real = self.conn.execute

        def execute(sql, params=()):
            if sql == "COMMIT":
                real("DELETE FROM dashboard_views")
            return real(sql, params)

        self.conn.execute = execute
        try:
            saved = self._save("survives")
        finally:
            self.conn.execute = real
        self.assertEqual(saved["name"], "survives")
        self.assertEqual(saved["filters"], {"severities": ["high"]})
        self.assertEqual(saved["layout"], ["p-board"])
        self.assertEqual(saved["visibility"], "private")
        self.assertEqual(self._count(), 0)

    def test_count_and_page_share_one_snapshot(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = os.path.join(temp.name, "views.db")
        left = connect(path)
        self.addCleanup(left.close)
        init_schema(left)
        right = connect(path)
        self.addCleanup(right.close)
        mode = left.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "wal")
        save(left, self._body("alpha"), "analyst")
        real = left.execute
        planted = {"done": False}

        def execute(sql, params=()):
            result = real(sql, params)
            # After the count has its snapshot, a second connection commits a visible row.
            if not planted["done"] and "COUNT(*)" in sql:
                planted["done"] = True
                right.execute(INSERT, ("beta", FILTERS, LAYOUT, "private", "analyst", STAMP, STAMP))
            return result

        left.execute = execute
        try:
            rows, omitted = list_views(left, "analyst")
        finally:
            left.execute = real
        self.assertTrue(planted["done"])
        self.assertEqual([row["name"] for row in rows], ["alpha"])
        self.assertEqual(omitted, 0)
        self.assertEqual(
            [row["name"] for row in left.execute("SELECT name FROM dashboard_views ORDER BY name")],
            ["alpha", "beta"])
        self.assertFalse(left.in_transaction)


if __name__ == "__main__":
    unittest.main()
