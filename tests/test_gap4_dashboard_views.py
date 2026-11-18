"""Edges for list_views, save, and delete that the other dashboard view tests skip.

list_views orders by name COLLATE NOCASE, then id. A limit of 0 returns no
rows and still counts every visible view. save strips the name before the
1-80 check and the per-owner uniqueness check, keeps the caller's severity
and panel order, and will not update a missing or foreign row. delete
removes only the caller's own row.
"""

import json
import unittest

from watchpost import dashboard_views
from watchpost.dashboard_views import ViewError
from watchpost.db import connect, init_schema

FILTERS = json.dumps({"severities": ["high"]})
LAYOUT = json.dumps(["p-board"])
STAMP = "2026-01-01T00:00:00.000Z"
INSERT = ("INSERT INTO dashboard_views"
          "(name, filters, layout, visibility, owner, created_at, updated_at)"
          " VALUES (?, ?, ?, ?, ?, ?, ?)")


class Gap4DashboardViewTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def body(self, name="Queue", visibility="private", severities=None, layout=None):
        return {
            "name": name,
            "visibility": visibility,
            "filters": {"severities": ["high"] if severities is None else severities},
            "layout": ["p-board"] if layout is None else layout,
        }

    def test_list_views_orders_nocase_and_honors_a_short_limit(self):
        # Binary order of these names is C, a, b. NOCASE order is a, b, C.
        self.conn.executemany(INSERT, [
            (name, FILTERS, LAYOUT, "private", "analyst", STAMP, STAMP)
            for name in ("C", "b", "a")
        ])
        by_name = {row["name"]: row["id"] for row in self.conn.execute("SELECT id, name FROM dashboard_views")}
        self.assertLess(by_name["C"], by_name["b"])
        self.assertLess(by_name["b"], by_name["a"])

        rows, omitted = dashboard_views.list_views(self.conn, "analyst", 0)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 3)

        rows, omitted = dashboard_views.list_views(self.conn, "analyst", 2)
        self.assertEqual([row["name"] for row in rows], ["a", "b"])
        self.assertEqual(omitted, 1)

        rows, omitted = dashboard_views.list_views(self.conn, "analyst")
        self.assertEqual([row["name"] for row in rows], ["a", "b", "C"])
        self.assertEqual([row["id"] for row in rows], [by_name["a"], by_name["b"], by_name["C"]])
        self.assertEqual(omitted, 0)

    def test_save_strips_the_name_before_length_and_uniqueness(self):
        self.assertEqual(dashboard_views.save(self.conn, self.body("Q"), "analyst")["name"], "Q")
        self.assertEqual(dashboard_views.save(self.conn, self.body("n" * 80), "analyst")["name"], "n" * 80)
        padded = "  " + ("m" * 80) + "\n"
        self.assertEqual(dashboard_views.save(self.conn, self.body(padded), "analyst")["name"], "m" * 80)
        self.assertEqual(
            dashboard_views.save(self.conn, self.body("  Night queue  "), "analyst")["name"], "Night queue")

        with self.assertRaises(ViewError) as caught:
            dashboard_views.save(self.conn, self.body("  Night queue  "), "analyst")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), "you already have a dashboard view named 'Night queue'")

        for name in ("n" * 81, " " + ("n" * 81), " \t\n", "   "):
            with self.subTest(name=name):
                with self.assertRaises(ViewError) as caught:
                    dashboard_views.save(self.conn, self.body(name), "analyst")
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), "name must be 1-80 characters")

        self.assertEqual(
            [row["name"] for row in self.conn.execute("SELECT name FROM dashboard_views ORDER BY id")],
            ["Q", "n" * 80, "m" * 80, "Night queue"])

    def test_save_rejects_malformed_fields_and_keeps_caller_order(self):
        layout = list(reversed(dashboard_views.PANELS))
        severities = ["low", "critical", "medium", "high"]
        saved = dashboard_views.save(
            self.conn, self.body("Boards", severities=severities, layout=layout), "analyst")
        self.assertEqual(saved["filters"], {"severities": severities})
        self.assertEqual(saved["layout"], layout)
        self.assertEqual(saved["created_at"], saved["updated_at"])
        self.assertEqual((saved["owner"], saved["visibility"]), ("analyst", "private"))

        base = self.body()
        cases = [
            ("non-object none", None, "view must be an object"),
            ("non-object list", [], "view must be an object"),
            ("non-object string", "view", "view must be an object"),
            ("missing name", {k: v for k, v in base.items() if k != "name"}, "name must be 1-80 characters"),
            ("name none", {**base, "name": None}, "name must be 1-80 characters"),
            ("name number", {**base, "name": 80}, "name must be 1-80 characters"),
            ("name list", {**base, "name": ["Queue"]}, "name must be 1-80 characters"),
            ("filters none", {**base, "filters": None}, "filters must contain only severities"),
            ("filters list", {**base, "filters": ["high"]}, "filters must contain only severities"),
            ("severities string", {**base, "filters": {"severities": "high"}},
             "severities must be a non-empty list of unique known severities"),
            ("severities tuple", {**base, "filters": {"severities": ("high",)}},
             "severities must be a non-empty list of unique known severities"),
            ("blank severity", self.body(severities=["high", ""]),
             "severities must be a non-empty list of unique known severities"),
            ("padded severity", self.body(severities=[" high"]),
             "severities must be a non-empty list of unique known severities"),
            ("layout none", {**base, "layout": None},
             "layout must be a non-empty list of unique dashboard panels"),
            ("layout string", {**base, "layout": "p-board"},
             "layout must be a non-empty list of unique dashboard panels"),
            ("layout null panel", {**base, "layout": [None]},
             "layout must be a non-empty list of unique dashboard panels"),
        ]
        for label, data, message in cases:
            with self.subTest(label=label):
                with self.assertRaises(ViewError) as caught:
                    dashboard_views.save(self.conn, data, "analyst")
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(caught.exception.status, 400)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM dashboard_views").fetchone()[0], 1)

    def test_update_keeps_created_at_and_refuses_a_missing_or_foreign_row(self):
        saved = dashboard_views.save(self.conn, self.body("Queue"), "analyst")
        updated = dashboard_views.save(
            self.conn, self.body("Renamed", visibility="shared"), "analyst", str(saved["id"]))
        self.assertEqual(updated["id"], saved["id"])
        self.assertEqual((updated["name"], updated["visibility"], updated["owner"]),
                         ("Renamed", "shared", "analyst"))
        self.assertEqual(updated["created_at"], saved["created_at"])
        self.assertGreaterEqual(updated["updated_at"], saved["updated_at"])

        with self.assertRaises(ViewError) as caught:
            dashboard_views.save(self.conn, self.body("Ghost"), "analyst", saved["id"] + 50)
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(str(caught.exception), "dashboard view not found")

        foreign = dashboard_views.save(self.conn, self.body("Shared", visibility="shared"), "admin")
        # The caller's own name is checked before ownership, so this is a clash, not a 404.
        with self.assertRaises(ViewError) as caught:
            dashboard_views.save(self.conn, self.body("Renamed"), "analyst", foreign["id"])
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), "you already have a dashboard view named 'Renamed'")

        with self.assertRaises(ViewError) as caught:
            dashboard_views.save(self.conn, self.body("Stolen", visibility="private"), "analyst", foreign["id"])
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(str(caught.exception), "dashboard view not found")
        row = self.conn.execute(
            "SELECT name, visibility, owner FROM dashboard_views WHERE id = ?", (foreign["id"],)).fetchone()
        self.assertEqual((row["name"], row["visibility"], row["owner"]), ("Shared", "shared", "admin"))

        with self.assertRaises(ValueError):
            dashboard_views.save(self.conn, self.body("Nope"), "analyst", "nope")

        self.assertEqual(
            [row["name"] for row in self.conn.execute("SELECT name FROM dashboard_views ORDER BY id")],
            ["Renamed", "Shared"])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'dashboard_view_updated'").fetchone()[0], 1)

    def test_delete_removes_only_the_owned_row(self):
        own = dashboard_views.save(self.conn, self.body("Mine", visibility="shared"), "analyst")
        dashboard_views.save(self.conn, self.body("Sibling"), "analyst")
        foreign = dashboard_views.save(self.conn, self.body("Theirs", visibility="shared"), "admin")

        for view_id in (0, foreign["id"]):
            with self.subTest(view_id=view_id):
                with self.assertRaises(ViewError) as caught:
                    dashboard_views.delete(self.conn, view_id, "analyst")
                self.assertEqual(caught.exception.status, 404)
                self.assertEqual(str(caught.exception), "dashboard view not found")

        with self.assertRaises(ValueError):
            dashboard_views.delete(self.conn, "nope", "analyst")

        self.assertEqual(dashboard_views.delete(self.conn, str(own["id"]), "analyst"), {"ok": True})
        self.assertIsNone(self.conn.execute(
            "SELECT id FROM dashboard_views WHERE id = ?", (own["id"],)).fetchone())

        with self.assertRaises(ViewError) as caught:
            dashboard_views.delete(self.conn, own["id"], "analyst")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(str(caught.exception), "dashboard view not found")

        self.assertEqual(
            [(row["name"], row["owner"]) for row in self.conn.execute(
                "SELECT name, owner FROM dashboard_views ORDER BY id")],
            [("Sibling", "analyst"), ("Theirs", "admin")])
        rows, omitted = dashboard_views.list_views(self.conn, "analyst")
        self.assertEqual([row["name"] for row in rows], ["Sibling", "Theirs"])
        self.assertEqual(omitted, 0)

        deleted = self.conn.execute(
            "SELECT actor, target, detail FROM audit_log WHERE action = 'dashboard_view_deleted'").fetchall()
        self.assertEqual(len(deleted), 1)
        self.assertEqual((deleted[0]["actor"], deleted[0]["target"]), ("analyst", "Mine"))
        self.assertEqual(json.loads(deleted[0]["detail"]), {"id": own["id"]})


if __name__ == "__main__":
    unittest.main()
