"""Incident case record: chronological evidence, workflow activity, notes, and exports."""

import json
import urllib.error
import urllib.request
import unittest

from .helpers import ServerTestCase


class CaseExportTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        self.assertEqual(self.admin.post("/api/demo/load")[0], 200)
        self.analyst = self.client("analyst")
        incident = next(i for i in self.analyst.get("/api/incidents")[1] if i["alert_count"] >= 2)
        self.incident_id = incident["id"]
        self.alert_id = self.analyst.get(f"/api/incidents/{self.incident_id}")[1]["alerts"][0]["id"]

        self.assertEqual(self.analyst.post(f"/api/alerts/{self.alert_id}/assign",
                                           {"assignee": "admin"})[0], 200)
        self.assertEqual(self.analyst.post(f"/api/alerts/{self.alert_id}/notes",
                                           {"body": "Called *alice* <script> about 10.0.1.20 | awaiting reply"})[0],
                         201)
        self.assertEqual(self.analyst.post(f"/api/alerts/{self.alert_id}/status",
                                           {"status": "investigating"})[0], 200)
        self.assertEqual(self.analyst.post(f"/api/incidents/{self.incident_id}/status",
                                           {"status": "investigating",
                                            "note": "alice confirmed the 10.0.1.20 session"})[0], 200)

    def raw(self, client, path):
        try:
            with client.opener.open(urllib.request.Request(self.base + path), timeout=30) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read(), exc.headers

    def test_json_case_is_one_chronological_record(self):
        status, body, headers = self.raw(self.analyst, f"/api/incidents/{self.incident_id}/case.json")
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Content-Disposition"],
                         f'attachment; filename="watchpost-incident-{self.incident_id}-case.json"')
        case = json.loads(body)
        self.assertEqual((case["id"], case["status"], case["assignee"]),
                         (self.incident_id, "investigating", "analyst"))
        self.assertEqual([entry["sequence"] for entry in case["timeline"]],
                         list(range(1, len(case["timeline"]) + 1)))
        self.assertEqual(case["timeline"], sorted(case["timeline"], key=lambda entry: entry["sequence"]))

        types = {entry["type"] for entry in case["timeline"]}
        self.assertTrue({"evidence", "incident_created", "alert_added", "assigned", "status_changed",
                         "analyst_note", "incident_status_changed"} <= types, types)
        note = next(entry for entry in case["timeline"] if entry["type"] == "analyst_note")
        self.assertEqual((note["alert_id"], note["author"], note["body"]),
                         (self.alert_id, "analyst",
                          "Called *alice* <script> about 10.0.1.20 | awaiting reply"))
        incident_status = next(entry for entry in case["timeline"]
                               if entry["type"] == "incident_status_changed")
        self.assertEqual(incident_status["note"], "alice confirmed the 10.0.1.20 session")
        evidence = next(entry for entry in case["timeline"] if entry["type"] == "evidence")
        self.assertTrue(evidence["alert_ids"])
        self.assertIn("message", evidence["event"])

    def test_markdown_case_uses_the_same_record_and_escapes_table_content(self):
        status, body, headers = self.raw(self.analyst, f"/api/incidents/{self.incident_id}/case.md")
        self.assertEqual(status, 200, body[:200])
        self.assertTrue(headers["Content-Type"].startswith("text/markdown"))
        text = body.decode()
        self.assertTrue(text.startswith(f"# Incident case #{self.incident_id}:"))
        self.assertIn("## Chronological timeline", text)
        self.assertIn("Alert assigned", text)
        self.assertIn("Incident status changed", text)
        self.assertIn(r"Called \*alice\* \<script\> about 10.0.1.20 \| awaiting reply", text)

    def test_access_errors_and_exports_are_audited(self):
        path = f"/api/incidents/{self.incident_id}/case.json"
        self.assertEqual(self.raw(self.client(), path)[0], 401)
        self.assertEqual(self.raw(self.client("viewer"), path)[0], 200)
        status, body, _ = self.raw(self.analyst, "/api/incidents/999999/case.json")
        self.assertEqual((status, json.loads(body)["error"]), (404, "incident not found"))
        self.assertEqual(self.raw(self.analyst, f"/api/incidents/{self.incident_id}/case.txt")[0], 404)
        self.assertEqual(self.raw(self.analyst, f"/api/incidents/{self.incident_id}/case.md")[0], 200)
        exported = [row for row in self.admin.get("/api/audit")[1] if row["action"] == "case_exported"]
        self.assertEqual({(row["target"], json.loads(row["detail"])["format"]) for row in exported},
                         {(f"incident:{self.incident_id}", "json"), (f"incident:{self.incident_id}", "md")})


if __name__ == "__main__":
    unittest.main()
