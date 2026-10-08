"""Detection content portability: rule export/import (tuning only, through review) and the ECS field mapping."""

import json
import unittest

from watchpost import ecs, portability
from watchpost.ratelimit import TokenBucketLimiter

from .helpers import ServerTestCase

RULE = "brute_force_ip"
SAMPLE = {"id": 7, "ts": "2026-09-15T14:00:00Z", "ingested_at": "2026-09-15T14:00:02Z", "source": "vpn01",
          "host": "vpn-gw", "event_type": "auth_failure", "outcome": "failure", "severity": "low",
          "user": "alice", "src_ip": "203.0.113.7", "dest_ip": "10.0.0.5", "dest_port": 443, "bytes": None,
          "message": "login failed", "raw": "{\"type\": \"login_failed\"}", "synthetic": 1, "batch_id": "b1"}


class ExportImportTests(ServerTestCase):
    def export(self, client):
        status, doc, headers = client.get("/api/rules/export")
        self.assertEqual(status, 200, doc)
        return doc, headers

    def do_import(self, client, doc, query="?label=tuning.json"):
        raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
        return client.request("POST", f"/api/rules/import{query}", raw=raw,
                              headers={"Content-Type": "application/json"})

    def outcome(self, result, rule_id):
        return next(r for r in result["rules"] if r["id"] == rule_id)

    def test_export_shape_and_determinism(self):
        viewer = self.client("viewer")
        doc, headers = self.export(viewer)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertEqual((doc["format"], doc["format_version"]), ("watchpost-rules", 1))
        self.assertTrue(doc["watchpost_version"] and doc["exported_at"])
        self.assertIn("not exported", doc["note"])
        ids = [r["id"] for r in doc["rules"]]
        self.assertEqual(ids, sorted(ids))
        self.assertIn(RULE, ids)
        rule = doc["rules"][ids.index(RULE)]
        self.assertEqual(set(rule), {"id", "name", "version", "enabled", "severity", "params", "techniques",
                                     "description"})
        self.assertEqual(rule["techniques"], ["T1110.001"])
        self.assertEqual(rule["params"]["threshold"], 10)
        again, _ = self.export(viewer)
        self.assertEqual({**doc, "exported_at": None}, {**again, "exported_at": None})
        # Sorted keys on the wire, so two exports diff cleanly as text.
        raw = viewer.opener.open(self.base + "/api/rules/export").read().decode()
        self.assertEqual(raw, json.dumps(json.loads(raw), sort_keys=True, indent=2))

    def test_round_trip_is_all_unchanged(self):
        analyst = self.client("analyst")
        doc, _ = self.export(analyst)
        status, result, _ = self.do_import(analyst, doc)
        self.assertEqual(status, 200, result)
        self.assertEqual({r["outcome"] for r in result["rules"]}, {"unchanged"})
        self.assertEqual(result["summary"], {"proposed": 0, "unchanged": len(doc["rules"]), "refused": 0})
        self.assertEqual(analyst.get("/api/changes")[1], [])

    def test_changed_param_becomes_a_pending_change_request(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        doc, _ = self.export(analyst)
        rule = next(r for r in doc["rules"] if r["id"] == RULE)
        rule["params"]["threshold"] = 25
        rule["enabled"] = False
        status, result, _ = self.do_import(analyst, doc)
        self.assertEqual(status, 200, result)
        out = self.outcome(result, RULE)
        self.assertEqual(out["outcome"], "proposed")
        self.assertEqual(out["changes"], {"params": {"threshold": 25}, "enabled": False})
        self.assertEqual(result["summary"]["proposed"], 1)
        change = admin.get("/api/changes")[1][0]
        self.assertEqual((change["id"], change["kind"], change["target"], change["status"]),
                         (out["change_id"], "rule_update", RULE, "pending"))
        self.assertEqual(change["reason"], "imported from tuning.json")
        self.assertEqual(change["payload"], {"params": {"threshold": 25}, "enabled": False})
        self.assertIn("backtest", change["evaluation"])
        # Not applied: the rule is as it was until a different admin approves.
        live = next(r for r in admin.get("/api/rules")[1] if r["id"] == RULE)
        self.assertEqual((live["params"]["threshold"], live["enabled"], live["version"]), (10, 1, 1))
        imported = [e for e in admin.get("/api/audit")[1] if e["action"] == "rules_imported"]
        self.assertEqual(len(imported), 1)
        self.assertEqual(json.loads(imported[0]["detail"])["proposed"], [out["change_id"]])

    def test_dry_run_creates_nothing(self):
        analyst = self.client("analyst")
        doc, _ = self.export(analyst)
        next(r for r in doc["rules"] if r["id"] == RULE)["params"]["threshold"] = 25
        status, result, _ = self.do_import(analyst, doc, "?dry_run=1&label=x.json")
        self.assertEqual(status, 200, result)
        self.assertTrue(result["dry_run"])
        out = self.outcome(result, RULE)
        self.assertEqual(out["outcome"], "would_propose")
        self.assertNotIn("change_id", out)
        self.assertEqual(analyst.get("/api/changes")[1], [])

    def test_document_level_refusals(self):
        analyst = self.client("analyst")
        doc, _ = self.export(analyst)
        for bad in ({**doc, "format": "sigma"}, {**doc, "format_version": 2}, {**doc, "format_version": True},
                    {**doc, "extra": 1}, {**doc, "rules": {}}, [doc]):
            with self.subTest(bad=str(bad)[:60]):
                status, data, _ = self.do_import(analyst, bad)
                self.assertEqual(status, 400, data)
        status, data, _ = self.do_import(analyst, b"{not json")
        self.assertEqual(status, 400, data)
        status, data, _ = self.do_import(analyst, b" " * (portability.MAX_IMPORT_BYTES + 1))
        self.assertEqual(status, 413, data)
        self.assertEqual(analyst.get("/api/changes")[1], [])

    def test_per_rule_refusals(self):
        analyst = self.client("analyst")
        doc, _ = self.export(analyst)
        good = next(r for r in doc["rules"] if r["id"] == RULE)
        doc["rules"] = [
            {**good, "id": "no_such_rule"},
            {**good, "id": "password_spray", "logic": "def x(): pass"},
            {**good, "id": "web_scanner", "params": {"threshold": "lots"}},
            {**good, "id": "firewall_port_sweep", "params": {"bogus_param": 3}},
            {**good, "id": "impossible_geo_login", "enabled": "yes"},
            {**good, "params": {**good["params"], "threshold": 30}},
        ]
        status, result, _ = self.do_import(analyst, doc)
        self.assertEqual(status, 200, result)
        outcomes = {(r["id"], r["outcome"]) for r in result["rules"]}
        self.assertEqual(outcomes, {("no_such_rule", "refused"), ("password_spray", "refused"),
                                    ("web_scanner", "refused"), ("firewall_port_sweep", "refused"),
                                    ("impossible_geo_login", "refused"), (RULE, "proposed")})
        reasons = {r["id"]: r["reason"] for r in result["rules"] if r["outcome"] == "refused"}
        self.assertIn("unknown rule", reasons["no_such_rule"])
        self.assertIn("unknown key(s): logic", reasons["password_spray"])
        self.assertIn("threshold must be an integer", reasons["web_scanner"])
        self.assertIn("bogus_param", reasons["firewall_port_sweep"])
        self.assertIn("enabled must be true or false", reasons["impossible_geo_login"])
        self.assertEqual(len(analyst.get("/api/changes")[1]), 1)

    def test_roles(self):
        viewer = self.client("viewer")
        doc, _ = self.export(viewer)
        self.assertEqual(self.do_import(viewer, doc)[0], 403)
        self.assertEqual(self.do_import(viewer, doc, "?dry_run=1")[0], 403)

    def test_import_spends_the_change_backtest_quota(self):
        analyst = self.client("analyst")
        doc, _ = self.export(analyst)
        changed = ["brute_force_ip", "password_spray", "account_repeated_failures", "web_scanner",
                   "firewall_port_sweep", "success_after_failures"]
        for rule in doc["rules"]:
            if rule["id"] in changed:
                rule["enabled"] = False
        # A dry run proposes nothing, runs no backtest and spends nothing.
        self.assertEqual(self.do_import(analyst, doc, "?dry_run=1")[0], 200)
        for i in range(17):
            self.assertEqual(analyst.post(f"/api/rules/{RULE}/proposals",
                                          {"params": {"threshold": 13 + i}, "reason": "tune it down"})[0], 201)
        # 3 left (plus a trickle of refill) cannot cover 6: refused up front, nothing proposed.
        status, data, headers = self.do_import(analyst, doc)
        self.assertEqual(status, 429, data)
        self.assertIn("6", data["error"])
        self.assertEqual(len(analyst.get("/api/changes")[1]), 17)
        # Two changes fit, and spend two.
        for rule in doc["rules"]:
            rule["enabled"] = rule["id"] not in changed[:2]
        status, result, _ = self.do_import(analyst, doc)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["summary"]["proposed"], 2)
        codes = [analyst.post(f"/api/rules/{RULE}/proposals", {"params": {"threshold": 50 + i}, "reason": "again"})[0]
                 for i in range(3)]
        self.assertEqual(codes[-1], 429)


class LimiterCostTests(unittest.TestCase):
    def test_cost_is_all_or_nothing(self):
        now = [0.0]
        limiter = TokenBucketLimiter(5, 60, clock=lambda: now[0])
        self.assertEqual(limiter.allow("a", cost=3), (True, 0))
        allowed, retry = limiter.allow("a", cost=3)
        self.assertFalse(allowed)
        self.assertEqual(retry, 1)
        self.assertEqual(limiter.allow("a", cost=2), (True, 0))  # the refused call spent nothing
        self.assertFalse(limiter.allow("a")[0])
        with self.assertRaises(ValueError):
            limiter.allow("a", cost=6)  # more than the bucket can ever hold


class EcsTests(ServerTestCase):
    def test_to_ecs_on_a_sample_event(self):
        doc = ecs.to_ecs(SAMPLE)
        self.assertEqual(doc["@timestamp"], "2026-09-15T14:00:00Z")
        self.assertEqual(doc["source"], {"ip": "203.0.113.7"})
        self.assertEqual(doc["destination"], {"ip": "10.0.0.5", "port": 443})
        self.assertEqual(doc["user"], {"name": "alice"})
        self.assertEqual(doc["host"], {"name": "vpn-gw"})
        self.assertEqual(doc["message"], "login failed")
        self.assertEqual(doc["labels"], {"synthetic": "true"})
        self.assertEqual(doc["event"], {"id": "7", "kind": "event", "action": "auth_failure", "outcome": "failure",
                                        "category": ["authentication"], "type": ["start"],
                                        "module": "vpn01", "ingested": "2026-09-15T14:00:02Z",
                                        "original": "{\"type\": \"login_failed\"}"})
        # No clean ECS field: kept under a custom namespace instead of an invented ECS name.
        self.assertEqual(doc["watchpost"], {"severity": "low", "batch_id": "b1"})
        self.assertNotIn("bytes", json.dumps(doc))  # None values are left out

    def test_unmapped_types_and_outcomes_stay_out_of_ecs_fields(self):
        doc = ecs.to_ecs({**SAMPLE, "event_type": "cloud_api_call", "outcome": "throttled", "synthetic": 0})
        self.assertNotIn("category", doc["event"])
        self.assertNotIn("outcome", doc["event"])
        self.assertEqual(doc["watchpost"]["outcome"], "throttled")
        self.assertEqual(doc["labels"], {"synthetic": "false"})
        for event_type, (category, _) in ecs.EVENT_TYPE_CATEGORIES.items():
            self.assertTrue(set(category) <= ecs.ECS_CATEGORIES, event_type)

    def test_ecs_route(self):
        analyst, viewer = self.client("analyst"), self.client("viewer")
        status, data, _ = analyst.post("/api/ingest", {"source": "vpn01", "events": [
            {"timestamp": "2026-09-15T14:00:00Z", "type": "login_failed", "user": "alice", "src_ip": "203.0.113.7"}]})
        self.assertEqual(status, 201, data)
        event_id = viewer.get("/api/events")[1]["events"][0]["id"]
        status, doc, _ = viewer.get(f"/api/events/{event_id}/ecs")
        self.assertEqual(status, 200, doc)
        self.assertEqual((doc["event"]["action"], doc["source"]["ip"], doc["user"]["name"]),
                         ("auth_failure", "203.0.113.7", "alice"))
        self.assertEqual(viewer.get("/api/events/999999/ecs")[0], 404)


if __name__ == "__main__":
    unittest.main()
