"""Asset modeling: importance weights, sensitive-data tags, and their effect on alerts, incidents, and reports."""

import json
import sqlite3
import unittest
from datetime import timedelta

from tests.helpers import ServerTestCase
from watchpost import assets
from watchpost.db import iso, utcnow


def recent(seconds_ago):
    return iso(utcnow() - timedelta(seconds=seconds_ago))


def failures(host, count=12, ip="203.0.113.77", user="svc", dest_ip=None):
    """Enough failed logins from one IP inside the brute_force_ip window (10 in 300 s)."""
    return [{"ts": recent(600 - i * 10), "event_type": "auth_failure", "user": user, "src_ip": ip, "host": host,
             "dest_ip": dest_ip, "message": "Failed password"} for i in range(count)]


class PureWeightingTests(unittest.TestCase):
    def asset(self, name, criticality="medium", tags=(), addresses=()):
        return {"id": 1, "name": name, "kind": "server", "criticality": criticality, "data_tags": list(tags),
                "addresses": list(addresses), "synthetic": 0}

    def test_validate_normalizes_and_rejects(self):
        clean = assets.validate({"name": " db01 ", "criticality": "critical", "data_tags": "PII, pci",
                                 "addresses": "10.0.0.10, 10.0.0.10", "owner": "x", "kind": "database"})
        self.assertEqual((clean["name"], clean["data_tags"], clean["addresses"]), ("db01", ["pci", "pii"], ["10.0.0.10"]))
        for bad in ({"name": ""}, {"name": "a b"}, {"name": "ok", "criticality": "urgent"},
                    {"name": "ok", "data_tags": ["secret-sauce"]}, {"name": "ok", "addresses": ["not-an-ip"]},
                    {"name": "ok", "kind": "toaster"}, "db01"):
            with self.subTest(bad=bad):
                self.assertRaises(assets.AssetError, assets.validate, bad)

    def test_match_by_host_name_case_insensitively_and_by_address(self):
        idx = assets.index([self.asset("DB01", addresses=["10.0.0.10"]), self.asset("web01")])
        events = [{"host": "db01"}, {"host": "other", "dest_ip": "10.0.0.10"}, {"host": None, "src_ip": "10.9.9.9"}]
        self.assertEqual([a["name"] for a in assets.match(idx, events)], ["DB01"])
        self.assertEqual(assets.match(idx, [{"host": "nothing"}]), [])

    def test_boost_levels(self):
        self.assertEqual(assets.boost([]), (0, None))
        self.assertEqual(assets.boost([self.asset("a", "low")])[0], 0)
        self.assertEqual(assets.boost([self.asset("a", "high")])[0], 1)
        self.assertEqual(assets.boost([self.asset("a", "critical")])[0], 2)
        self.assertEqual(assets.boost([self.asset("a", "medium", ["pii"])])[0], 1)
        self.assertEqual(assets.boost([self.asset("a", "high", ["pii"])])[0], 2)
        # Capped at two levels even for a critical asset with sensitive data.
        levels, note = assets.boost([self.asset("a", "critical", ["pii", "pci"])])
        self.assertEqual(levels, 2)
        self.assertIn("critical-criticality", note)
        self.assertIn("sensitive data on a (pii, pci)", note)

    def test_weigh_never_passes_critical_and_keeps_base(self):
        w = assets.weigh("medium", [self.asset("a", "critical")])
        self.assertEqual((w["severity"], w["base_severity"]), ("critical", "medium"))
        w = assets.weigh("high", [self.asset("a", "critical", ["phi"])])
        self.assertEqual(w["severity"], "critical")
        w = assets.weigh("critical", [self.asset("a", "high")])
        self.assertEqual(w["severity"], "critical")
        self.assertTrue(w["severity_note"].startswith("already critical"))
        w = assets.weigh("low", [self.asset("a", "low")])
        self.assertEqual((w["severity"], w["assets"][0]["name"]), ("low", "a"))
        self.assertIn("no severity change", w["severity_note"])
        self.assertEqual(assets.weigh("low", []), {"severity": "low", "base_severity": "low", "assets": [],
                                                    "severity_note": None})


class AssetApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        self.analyst = self.client("analyst")

    def test_crud_roles_and_audit(self):
        status, data, _ = self.admin.post("/api/assets", {"name": "db01", "criticality": "critical",
                                                          "data_tags": ["pii"], "kind": "database"})
        self.assertEqual(status, 201, data)
        asset = data["asset"]
        self.assertEqual((asset["name"], asset["criticality"], asset["data_tags"]), ("db01", "critical", ["pii"]))
        self.assertEqual(data["alerts_rescored"], 0)
        # Names are unique, ignoring case.
        self.assertEqual(self.admin.post("/api/assets", {"name": "DB01"})[0], 409)
        self.assertEqual(self.admin.post("/api/assets", {"name": "x", "criticality": "huge"})[0], 400)
        # Everyone signed in can read the inventory; only admins change it.
        status, listing, _ = self.client("viewer").get("/api/assets")
        self.assertEqual(status, 200)
        self.assertEqual([a["name"] for a in listing["assets"]], ["db01"])
        self.assertIn("pii", listing["data_tags"])
        self.assertEqual(self.analyst.post("/api/assets", {"name": "web01"})[0], 403)
        self.assertEqual(self.analyst.post(f"/api/assets/{asset['id']}/delete")[0], 403)
        # Update and delete.
        status, data, _ = self.admin.post(f"/api/assets/{asset['id']}", {"name": "db01", "criticality": "high"})
        self.assertEqual((status, data["asset"]["criticality"]), (200, "high"))
        self.assertEqual(self.admin.post("/api/assets/999", {"name": "ghost"})[0], 404)
        self.assertEqual(self.admin.post(f"/api/assets/{asset['id']}/delete")[0], 200)
        self.assertEqual(self.admin.post(f"/api/assets/{asset['id']}/delete")[0], 404)
        self.assertEqual(self.admin.get("/api/assets")[1]["assets"], [])
        actions = [a["action"] for a in self.admin.get("/api/audit")[1]]
        for action in ("asset_created", "asset_updated", "asset_deleted"):
            self.assertIn(action, actions)

    def test_alert_severity_is_raised_by_a_critical_sensitive_asset(self):
        self.admin.post("/api/assets", {"name": "db01", "criticality": "critical", "data_tags": ["pci"]})
        status, result, _ = self.analyst.post("/api/ingest", {"source": "t", "events": failures("db01")})
        self.assertEqual(status, 201, result)
        alerts = self.analyst.get("/api/alerts?rule_id=brute_force_ip")[1]
        self.assertEqual(len(alerts), 1)
        a = self.analyst.get(f"/api/alerts/{alerts[0]['id']}")[1]
        self.assertEqual((a["base_severity"], a["severity"]), ("high", "critical"))
        self.assertEqual([x["name"] for x in a["assets"]], ["db01"])
        self.assertIn("db01 is a critical-criticality asset", a["severity_note"])
        self.assertIn("severity_changed", [x["action"] for x in a["activity"]])
        # The rule itself is untouched: the same attack on an unknown host keeps the rule severity.
        self.analyst.post("/api/ingest", {"source": "t", "events": failures("kiosk07", ip="203.0.113.78")})
        plain = next(x for x in self.analyst.get("/api/alerts?rule_id=brute_force_ip")[1]
                     if x["group_key"] == "203.0.113.78")
        self.assertEqual((plain["base_severity"], plain["severity"], plain["assets"]), ("high", "high", []))

    def test_match_by_destination_address(self):
        self.admin.post("/api/assets", {"name": "pay-db", "criticality": "medium", "data_tags": ["pci"],
                                        "addresses": ["10.0.5.5"]})
        self.analyst.post("/api/ingest", {"source": "t", "events": failures("jump01", dest_ip="10.0.5.5")})
        a = self.analyst.get("/api/alerts?rule_id=brute_force_ip")[1][0]
        self.assertEqual((a["base_severity"], a["severity"]), ("high", "critical"))
        self.assertEqual(a["assets"][0]["name"], "pay-db")

    def test_inventory_change_rescored_open_alerts_and_incidents(self):
        # Detection first, inventory second: the open alert is re-weighed when the asset appears.
        self.analyst.post("/api/ingest", {"source": "t", "events": failures("db01")})
        before = self.analyst.get("/api/alerts?rule_id=brute_force_ip")[1][0]
        self.assertEqual((before["severity"], before["assets"]), ("high", []))
        status, data, _ = self.admin.post("/api/assets", {"name": "db01", "criticality": "critical"})
        # Both open alerts on db01 (brute force by IP and repeated failures on the account) are re-weighed.
        self.assertEqual(status, 201)
        self.assertEqual(data["alerts_rescored"], len(self.analyst.get("/api/alerts")[1]))
        self.assertGreaterEqual(data["alerts_rescored"], 1)
        after = self.analyst.get(f"/api/alerts/{before['id']}")[1]
        self.assertEqual((after["severity"], after["base_severity"]), ("critical", "high"))
        # A single critical alert is enough to open an incident, which inherits the weighted severity.
        incidents = self.analyst.get("/api/incidents")[1]
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "critical")
        detail = self.analyst.get(f"/api/incidents/{incidents[0]['id']}")[1]
        self.assertEqual([a["name"] for a in detail["assets"]], ["db01"])
        # Removing the asset re-weighs what is still open; resolved alerts keep the severity they closed with.
        self.analyst.post(f"/api/alerts/{before['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        still_open = [a["id"] for a in self.analyst.get("/api/alerts?status=open,investigating")[1]]
        status, data, _ = self.admin.post(f"/api/assets/{data['asset']['id']}/delete")
        self.assertEqual((status, data["alerts_rescored"]), (200, len(still_open)))
        self.assertEqual(self.analyst.get(f"/api/alerts/{before['id']}")[1]["severity"], "critical")
        for alert_id in still_open:
            a = self.analyst.get(f"/api/alerts/{alert_id}")[1]
            self.assertEqual((a["severity"], a["assets"]), (a["base_severity"], []))

    def test_reports_show_assets_and_weighting(self):
        self.admin.post("/api/assets", {"name": "db01", "criticality": "high", "data_tags": ["pii"]})
        self.analyst.post("/api/ingest", {"source": "t", "events": failures("db01")})
        alert_id = self.analyst.get("/api/alerts?rule_id=brute_force_ip")[1][0]["id"]
        req = __import__("urllib.request").request.Request(self.base + f"/api/alerts/{alert_id}/report.md")
        with self.analyst.opener.open(req) as resp:
            text = resp.read().decode()
        self.assertIn("## Assets", text)
        self.assertIn("| db01 | server | high | pii |", text)
        self.assertIn("Asset weighting:", text)
        self.assertIn("rule severity high", text)
        self.assertIn("1 processing sensitive data (db01)", text)
        req = __import__("urllib.request").request.Request(self.base + f"/api/alerts/{alert_id}/report.pdf")
        with self.analyst.opener.open(req) as resp:
            self.assertTrue(resp.read().startswith(b"%PDF"))

    def test_demo_load_seeds_a_synthetic_inventory_once(self):
        self.assertEqual(self.admin.post("/api/demo/load")[0], 200)
        listing = self.admin.get("/api/assets")[1]["assets"]
        self.assertEqual({a["name"] for a in listing}, {a["name"] for a in assets.DEMO_ASSETS})
        self.assertTrue(all(a["synthetic"] for a in listing))
        db01 = next(a for a in listing if a["name"] == "db01")
        self.assertEqual((db01["criticality"], db01["data_tags"]), ("critical", ["pci", "pii"]))
        # Loading again leaves the inventory alone (an edited asset is not overwritten).
        self.admin.post(f"/api/assets/{db01['id']}", {**db01, "criticality": "low"})
        self.assertEqual(self.admin.post("/api/demo/load", {"force": True})[0], 200)
        listing = self.admin.get("/api/assets")[1]["assets"]
        self.assertEqual(len(listing), len(assets.DEMO_ASSETS))
        self.assertEqual(next(a for a in listing if a["name"] == "db01")["criticality"], "low")
        # Demo alerts on inventoried hosts carry their assets and a visible base severity.
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT severity, base_severity, assets FROM alerts").fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(r[1] for r in rows))
        self.assertTrue(any(json.loads(r[2]) for r in rows))


if __name__ == "__main__":
    unittest.main()
