import sqlite3
import unittest

from tests.helpers import ServerTestCase
from watchpost import dashboard_views
from watchpost.dashboard_views import ViewError, _payload
from watchpost.db import connect, init_schema


class DashboardViewApiTests(ServerTestCase):
    def payload(self, name="Critical queue", visibility="shared"):
        return {"name": name, "visibility": visibility,
                "filters": {"severities": ["critical", "high"]},
                "layout": ["p-board", "p-timeline", "p-feed"]}

    def test_shared_views_are_readable_by_viewers_but_viewers_cannot_change_them(self):
        analyst, viewer = self.client("analyst"), self.client("viewer")
        status, saved, _ = analyst.post("/api/dashboard/views", self.payload())
        self.assertEqual(status, 201, saved)
        self.assertEqual((saved["owner"], saved["visibility"]), ("analyst", "shared"))
        self.assertEqual(viewer.get("/api/dashboard/views")[1], [saved])
        self.assertEqual(viewer.post("/api/dashboard/views", self.payload("x"))[0], 403)
        self.assertEqual(viewer.post(f"/api/dashboard/views/{saved['id']}", self.payload("x"))[0], 403)
        self.assertEqual(viewer.post(f"/api/dashboard/views/{saved['id']}/delete")[0], 403)

    def test_private_views_and_ownership_are_enforced(self):
        analyst, admin, viewer = self.client("analyst"), self.client("admin"), self.client("viewer")
        saved = analyst.post("/api/dashboard/views", self.payload(visibility="private"))[1]
        self.assertEqual(analyst.get("/api/dashboard/views")[1], [saved])
        self.assertEqual(admin.get("/api/dashboard/views")[1], [])
        self.assertEqual(viewer.get("/api/dashboard/views")[1], [])
        self.assertEqual(admin.post(f"/api/dashboard/views/{saved['id']}", self.payload("stolen"))[0], 404)
        self.assertEqual(admin.post(f"/api/dashboard/views/{saved['id']}/delete")[0], 404)

    def test_owner_updates_and_deletes_with_audit_history(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        saved = analyst.post("/api/dashboard/views", self.payload())[1]
        changed = self.payload("Escalations", "private")
        changed["filters"] = {"severities": ["critical"]}
        changed["layout"] = ["p-board", "p-entities"]
        status, updated, _ = analyst.post(f"/api/dashboard/views/{saved['id']}", changed)
        self.assertEqual(status, 200)
        self.assertEqual((updated["name"], updated["filters"], updated["layout"]),
                         ("Escalations", changed["filters"], changed["layout"]))
        self.assertEqual(analyst.post(f"/api/dashboard/views/{saved['id']}/delete")[0], 200)
        self.assertEqual(analyst.get("/api/dashboard/views")[1], [])
        actions = [row["action"] for row in admin.get("/api/audit")[1]]
        self.assertTrue({"dashboard_view_created", "dashboard_view_updated", "dashboard_view_deleted"}
                        <= set(actions))

    def test_validation_rejects_unknown_or_ambiguous_state(self):
        analyst = self.client("analyst")
        bad = [
            {**self.payload(), "name": ""},
            {**self.payload(), "visibility": "public"},
            {**self.payload(), "filters": {}},
            {**self.payload(), "filters": {"severities": []}},
            {**self.payload(), "filters": {"severities": ["urgent"]}},
            {**self.payload(), "filters": {"severities": ["high", "high"]}},
            {**self.payload(), "filters": {"severities": ["high"], "host": "web01"}},
            {**self.payload(), "layout": []},
            {**self.payload(), "layout": ["p-board", "p-board"]},
            {**self.payload(), "layout": ["p-secret"]},
        ]
        for body in bad:
            with self.subTest(body=body):
                self.assertEqual(analyst.post("/api/dashboard/views", body)[0], 400)

    def test_ascii_case_is_stored_as_the_catalog_spelling(self):
        analyst = self.client("analyst")
        body = self.payload("Night queue", "Private")
        body["filters"] = {"severities": ["HIGH", "Low"]}
        status, saved, _ = analyst.post("/api/dashboard/views", body)
        self.assertEqual(status, 201, saved)
        self.assertEqual(saved["visibility"], "private")
        self.assertEqual(saved["filters"]["severities"], ["high", "low"])
        listed = analyst.get("/api/dashboard/views")[1]
        self.assertEqual(listed[0]["filters"]["severities"], ["high", "low"])
        self.assertEqual(listed[0]["visibility"], "private")

    def test_case_only_name_names_the_stored_row(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.assertEqual(analyst.post("/api/dashboard/views", self.payload("dup"))[0], 201)
        status, data, headers = analyst.post("/api/dashboard/views", self.payload("DUP"))
        self.assertEqual(status, 409, data)
        self.assertEqual(data["error"], "you already have a dashboard view named 'dup'")
        self.assertNotIn("DUP", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        other = analyst.post("/api/dashboard/views", self.payload("other"))[1]
        status, data, _ = analyst.post(f"/api/dashboard/views/{other['id']}", self.payload("Dup"))
        self.assertEqual(status, 409, data)
        self.assertEqual(data["error"], "you already have a dashboard view named 'dup'")
        status, saved, _ = admin.post("/api/dashboard/views", self.payload("DUP"))
        self.assertEqual(status, 201, saved)
        self.assertEqual((saved["owner"], saved["name"]), ("admin", "DUP"))
        status, renamed, _ = analyst.post(f"/api/dashboard/views/{other['id']}", self.payload("OTHER"))
        self.assertEqual(status, 200, renamed)
        self.assertEqual(renamed["name"], "OTHER")

    def test_existing_database_gains_the_table(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DROP TABLE dashboard_views")
            db.execute("UPDATE meta SET value = '13' WHERE key = 'schema_version'")
        from watchpost.server import App
        App(self.config)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "15")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM dashboard_views").fetchone()[0], 0)


class DashboardViewCaseTests(unittest.TestCase):
    def body(self, visibility="private", severities=None, layout=None):
        return {"name": "Queue", "visibility": visibility,
                "filters": {"severities": ["high"] if severities is None else severities},
                "layout": ["p-board"] if layout is None else layout}

    def test_ascii_case_folds_onto_the_catalog_spelling(self):
        name, visibility, filters, layout = _payload(
            self.body("SHARED", ["Critical", "HIGH", "Medium", "low"]))
        self.assertEqual((name, visibility), ("Queue", "shared"))
        self.assertEqual(filters["severities"], ["critical", "high", "medium", "low"])
        self.assertEqual(layout, ["p-board"])

    def test_high_with_high_stays_a_duplicate_and_info_stays_out(self):
        for severities in (["High", "high"], ["HIGH", "High"], ["info"], ["INFO"], ["Hıgh"]):
            with self.subTest(severities=severities):
                with self.assertRaises(ViewError) as caught:
                    _payload(self.body(severities=severities))
                self.assertEqual(str(caught.exception),
                                 "severities must be a non-empty list of unique known severities")

    def test_visibility_folds_ascii_only_and_panel_ids_stay_exact(self):
        self.assertEqual(_payload(self.body("Private"))[1], "private")
        for visibility in ("public", "Prıvate", "PRIVATE ", None, 1):
            with self.subTest(visibility=visibility):
                with self.assertRaises(ViewError) as caught:
                    _payload(self.body(visibility))
                self.assertEqual(str(caught.exception), "visibility must be private or shared")
        for layout in (["P-board"], ["p-Board"], ["p-BOARD"]):
            with self.subTest(layout=layout):
                with self.assertRaises(ViewError) as caught:
                    _payload(self.body(layout=layout))
                self.assertEqual(str(caught.exception),
                                 "layout must be a non-empty list of unique dashboard panels")


class DashboardViewNameTests(unittest.TestCase):
    """A name that differs only by case is this owner's stored row, answered 409, never a unique-constraint 500."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def body(self, name):
        return {"name": name, "visibility": "private",
                "filters": {"severities": ["high"]}, "layout": ["p-board"]}

    def test_case_only_difference_names_the_stored_row(self):
        dashboard_views.save(self.conn, self.body("dup"), "analyst")
        for variant in ("DUP", "dup"):
            with self.subTest(variant=variant):
                with self.assertRaises(ViewError) as caught:
                    dashboard_views.save(self.conn, self.body(variant), "analyst")
                self.assertEqual(caught.exception.status, 409)
                self.assertEqual(str(caught.exception), "you already have a dashboard view named 'dup'")
        self.assertEqual(
            [row["name"] for row in self.conn.execute("SELECT name FROM dashboard_views")], ["dup"])

    def test_another_owners_view_is_not_a_conflict(self):
        dashboard_views.save(self.conn, self.body("dup"), "analyst")
        saved = dashboard_views.save(self.conn, self.body("DUP"), "admin")
        self.assertEqual((saved["owner"], saved["name"]), ("admin", "DUP"))
        names = [(row["owner"], row["name"]) for row in self.conn.execute(
            "SELECT owner, name FROM dashboard_views ORDER BY owner")]
        self.assertEqual(names, [("admin", "DUP"), ("analyst", "dup")])

    def test_renaming_onto_another_view_names_the_stored_row(self):
        stored = dashboard_views.save(self.conn, self.body("dup"), "analyst")
        other = dashboard_views.save(self.conn, self.body("other"), "analyst")
        with self.assertRaises(ViewError) as caught:
            dashboard_views.save(self.conn, self.body("DUP"), "analyst", other["id"])
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), "you already have a dashboard view named 'dup'")
        self.assertEqual(self.conn.execute(
            "SELECT name FROM dashboard_views WHERE id = ?", (other["id"],)).fetchone()["name"], "other")
        folded = dashboard_views.save(self.conn, self.body("DUP"), "analyst", stored["id"])
        self.assertEqual((folded["id"], folded["name"]), (stored["id"], "DUP"))

    def test_unique_conflict_names_the_stored_row(self):
        dashboard_views.save(self.conn, self.body("dup"), "analyst")
        real = self.conn.execute
        skipped = {"done": False}
        lookup = "SELECT name FROM dashboard_views WHERE owner = ? AND name = ? COLLATE NOCASE"

        def execute(sql, params=()):
            # The lookup misses once, so the insert hits UNIQUE (owner, name COLLATE NOCASE).
            if not skipped["done"] and sql == lookup:
                skipped["done"] = True
                return real("SELECT name FROM dashboard_views WHERE 0")
            return real(sql, params)

        self.conn.execute = execute
        with self.assertRaises(ViewError) as caught:
            dashboard_views.save(self.conn, self.body("DUP"), "analyst")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), "you already have a dashboard view named 'dup'")
        self.assertTrue(skipped["done"])
        self.conn.execute = real
        self.assertEqual(
            [row["name"] for row in self.conn.execute("SELECT name FROM dashboard_views")], ["dup"])
        created = self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'dashboard_view_created'").fetchone()[0]
        self.assertEqual(created, 1)


if __name__ == "__main__":
    unittest.main()
