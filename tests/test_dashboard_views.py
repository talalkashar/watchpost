import unittest
import sqlite3

from tests.helpers import ServerTestCase


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

    def test_existing_database_gains_the_table(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DROP TABLE dashboard_views")
            db.execute("UPDATE meta SET value = '13' WHERE key = 'schema_version'")
        from watchpost.server import App
        App(self.config)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "14")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM dashboard_views").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
