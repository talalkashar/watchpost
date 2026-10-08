"""Asset modeling: importance weights, sensitive-data tags, and their effect on alerts, incidents, and reports."""

import json
import sqlite3
import unittest
from datetime import timedelta
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import assets
from watchpost.auth import create_user
from watchpost.db import connect, iso, utcnow


def recent(seconds_ago):
    return iso(utcnow() - timedelta(seconds=seconds_ago))


def failures(host, count=12, ip="203.0.113.77", user="svc", dest_ip=None):
    """Enough failed logins from one IP inside the brute_force_ip window (10 in 300 s)."""
    return [{"ts": recent(600 - i * 10), "event_type": "auth_failure", "user": user, "src_ip": ip, "host": host,
             "dest_ip": dest_ip, "message": "Failed password"} for i in range(count)]


def second_admin(case):
    """A second admin account on a ServerTestCase's database, signed in. Two-person review needs one."""
    conn = connect(case.db_path)
    if not conn.execute("SELECT 1 FROM users WHERE username = 'admin2'").fetchone():
        create_user(conn, "admin2", "second-admin-password", "admin")
    conn.close()
    client = case.client()
    case.assertEqual(client.login("admin2", "second-admin-password")[0], 200)
    return client


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
        # An update that cannot lower severity applies directly; a delete always goes through review.
        status, data, _ = self.admin.post(f"/api/assets/{asset['id']}", {"name": "db01", "criticality": "critical",
                                                                         "data_tags": ["pii", "pci"]})
        self.assertEqual((status, data["asset"]["data_tags"]), (200, ["pci", "pii"]))
        self.assertEqual(self.admin.post("/api/assets/999", {"name": "ghost"})[0], 404)
        self.assertEqual(self.admin.post("/api/assets/999/delete")[0], 404)
        self.assertEqual(self.admin.post(f"/api/assets/{asset['id']}/delete")[0], 409)
        self.assertEqual(len(self.admin.get("/api/assets")[1]["assets"]), 1)
        actions = [a["action"] for a in self.admin.get("/api/audit")[1]]
        for action in ("asset_created", "asset_updated"):
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
        # Removing the asset (approved by a second admin) re-weighs what is still open; resolved alerts keep
        # the severity they closed with.
        self.analyst.post(f"/api/alerts/{before['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        still_open = [a["id"] for a in self.analyst.get("/api/alerts?status=open,investigating")[1]]
        status, change, _ = self.admin.post(f"/api/assets/{data['asset']['id']}/proposals",
                                            {"delete": True, "reason": "decommissioned"})
        self.assertEqual(status, 201, change)
        status, data, _ = second_admin(self).post(f"/api/changes/{change['id']}/review", {
            "decision": "approve", "evidence_digest": change["evidence_digest"]})
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
        self.assertEqual(self.admin.post(f"/api/assets/{db01['id']}", {**db01, "owner": "dba-team"})[0], 200)
        self.assertEqual(self.admin.post("/api/demo/load", {"force": True})[0], 200)
        listing = self.admin.get("/api/assets")[1]["assets"]
        self.assertEqual(len(listing), len(assets.DEMO_ASSETS))
        self.assertEqual(next(a for a in listing if a["name"] == "db01")["owner"], "dba-team")
        # Demo alerts on inventoried hosts carry their assets and a visible base severity.
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT severity, base_severity, assets FROM alerts").fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(r[1] for r in rows))
        self.assertTrue(any(json.loads(r[2]) for r in rows))

    def test_admin_page_redraws_the_inventory_after_a_demo_load(self):
        # No JS runtime in CI: the demo-load handler must refetch the inventory and swap the card in place.
        app = (Path(__file__).resolve().parent.parent / "static" / "app.js").read_text()
        handler = app[app.index('api("/api/demo/load"'):app.index('"Load synthetic demo data"')]
        self.assertIn('assetsCard(await api("/api/assets"))', handler)
        self.assertIn("inventoryCard.replaceWith(", handler)


class ReviewGateTests(unittest.TestCase):
    """Which inventory edits could lower alert severity, and so need a second admin."""

    def asset(self, **kw):
        return assets.validate({"name": "db01", "criticality": "critical", "data_tags": ["pii", "pci"],
                                "addresses": ["10.0.0.10", "10.0.0.11"], "owner": "dba", **kw})

    def test_edits_that_can_lower_severity_need_review(self):
        before = self.asset()
        for kw, words in (({"criticality": "low"}, "lowers criticality from critical to low"),
                          ({"data_tags": ["pii"]}, "removes sensitive-data tag pci"),
                          ({"addresses": ["10.0.0.10"]}, "removes address 10.0.0.11"),
                          ({"name": "db02"}, "renames db01 to db02")):
            with self.subTest(kw=kw):
                self.assertEqual(assets.review_reasons(before, self.asset(**kw)), [words])
        self.assertEqual(assets.review_reasons(before, None), ["deletes the asset"])
        # A new address already inventoried on another asset could take over that asset's matches.
        self.assertEqual(assets.review_reasons(None, self.asset(), {"10.0.0.11"}),
                         ["claims address 10.0.0.11, which another asset already has"])

    def test_edits_that_cannot_lower_severity_apply_directly(self):
        before = self.asset(criticality="high", data_tags=["pii"])
        for kw in ({"criticality": "critical"}, {"data_tags": ["pii", "phi"]},
                   {"addresses": ["10.0.0.10", "10.0.0.11", "10.0.0.12"]}, {"owner": "someone-else"},
                   {"description": "new words"}, {"kind": "database"}, {"name": "DB01"}):
            with self.subTest(kw=kw):
                self.assertEqual(assets.review_reasons(before, self.asset(**{"criticality": "high",
                                                                            "data_tags": ["pii"], **kw})), [])
        self.assertEqual(assets.review_reasons(None, self.asset()), [])


class AssetReviewApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        self.analyst = self.client("analyst")
        status, data, _ = self.admin.post("/api/assets", {"name": "db01", "kind": "database", "criticality": "critical",
                                                          "data_tags": ["pii", "pci"], "addresses": ["10.0.0.10"],
                                                          "owner": "dba"})
        self.assertEqual(status, 201, data)
        self.db01 = data["asset"]

    def current(self, asset_id=None):
        listing = self.admin.get("/api/assets")[1]["assets"]
        return next((a for a in listing if a["id"] == (asset_id or self.db01["id"])), None)

    def propose(self, body, asset_id=None, client=None):
        path = "/api/assets/proposals" if asset_id is False else f"/api/assets/{asset_id or self.db01['id']}/proposals"
        return (client or self.admin).post(path, {"reason": "inventory review", **body})

    def review(self, client, change, decision="approve"):
        body = {"decision": decision, "note": "checked"}
        if decision == "approve":
            body["evidence_digest"] = change["evidence_digest"]
        return client.post(f"/api/changes/{change['id']}/review", body)

    def actions(self):
        return [a["action"] for a in self.admin.get("/api/audit")[1]]

    def assert_chain_verified(self):
        status, chain, _ = self.admin.get("/api/audit/verify")
        self.assertEqual((status, chain["ok"], chain["status"]), (200, True, "verified"), chain)

    def test_each_gated_edit_is_refused_directly_and_proposed_without_effect(self):
        edits = [{"criticality": "low"}, {"data_tags": ["pii"]}, {"addresses": []}, {"name": "db02"}]
        for edit in edits:
            with self.subTest(edit=edit):
                status, data, _ = self.admin.post(f"/api/assets/{self.db01['id']}", {**self.db01, **edit})
                self.assertEqual(status, 409, data)
                self.assertTrue(data["review_required"])
                self.assertEqual(data["proposal_route"], f"/api/assets/{self.db01['id']}/proposals")
                self.assertTrue(data["reasons"])
                self.assertIn("second admin", data["error"])
        status, data, _ = self.admin.post(f"/api/assets/{self.db01['id']}/delete")
        self.assertEqual((status, data["reasons"]), (409, ["deletes the asset"]))
        self.assertEqual(self.current()["criticality"], "critical")

        proposals = []
        for edit in edits:
            status, change, _ = self.propose({**self.db01, **edit})
            self.assertEqual((status, change["kind"], change["status"]), (201, "asset_update", "pending"), change)
            self.assertTrue(change["evaluation"]["needs_review"])
            self.assertEqual(change["payload"], edit)  # only the fields that change are stored
            proposals.append(change)
        status, change, _ = self.propose({"delete": True})
        self.assertEqual((status, change["kind"], change["payload"]), (201, "asset_delete", {}), change)
        proposals.append(change)
        # Nothing changed, and the inventory lists every pending proposal against the asset.
        now = self.current()
        for field in ("name", "criticality", "data_tags", "addresses"):
            self.assertEqual(now[field], self.db01[field])
        pending = self.admin.get("/api/assets")[1]["pending"]
        self.assertEqual(sorted(c["id"] for c in pending), sorted(c["id"] for c in proposals))
        self.assertEqual(self.actions().count("change_proposed"), len(proposals))
        self.assertNotIn("asset_deleted", self.actions())

    def test_proposer_cannot_approve_own_change(self):
        _, change, _ = self.propose({**self.db01, "criticality": "low"})
        status, data, _ = self.review(self.admin, change)
        self.assertEqual(status, 403, data)
        self.assertIn("second person", data["error"])
        self.assertEqual(self.review(self.admin, change, "reject")[0], 403)
        self.assertEqual(self.current()["criticality"], "critical")
        self.assertEqual(self.admin.get(f"/api/changes")[1][0]["status"], "pending")

    def test_approval_applies_the_change_and_reweighs_open_alerts(self):
        self.analyst.post("/api/ingest", {"source": "t", "events": failures("db01")})
        alert = self.analyst.get("/api/alerts?rule_id=brute_force_ip")[1][0]
        self.assertEqual((alert["base_severity"], alert["severity"]), ("high", "critical"))
        _, change, _ = self.propose({**self.db01, "criticality": "low", "data_tags": []})
        evidence = change["evaluation"]
        self.assertEqual((evidence["before"]["criticality"], evidence["after"]["criticality"]), ("critical", "low"))
        self.assertEqual({c["field"] for c in evidence["changes"]}, {"criticality", "data_tags"})
        shift = next(x for x in evidence["severity_changes"]["recent"] if x["id"] == alert["id"])
        self.assertEqual((shift["from"], shift["to"]), ("critical", "high"))
        self.assertEqual(self.analyst.get(f"/api/alerts/{alert['id']}")[1]["severity"], "critical")

        status, data, _ = self.review(second_admin(self), change)
        self.assertEqual((status, data["status"], data["reviewed_by"]), (200, "approved", "admin2"), data)
        self.assertGreaterEqual(data["alerts_rescored"], 1)
        self.assertEqual((self.current()["criticality"], self.current()["data_tags"]), ("low", []))
        self.assertEqual(self.analyst.get(f"/api/alerts/{alert['id']}")[1]["severity"], "high")
        self.assertEqual(self.admin.get("/api/assets")[1]["pending"], [])
        entry = next(a for a in self.admin.get("/api/audit")[1] if a["action"] == "asset_updated"
                     and a["actor"] == "admin2")
        self.assertEqual(json.loads(entry["detail"])["change_request"], change["id"])
        for action in ("change_proposed", "change_approved", "asset_updated"):
            self.assertIn(action, self.actions())
        self.assert_chain_verified()

    def test_approved_delete_and_add(self):
        admin2 = second_admin(self)
        _, change, _ = self.propose({"delete": True})
        self.assertEqual(self.review(admin2, change)[0], 200)
        self.assertIsNone(self.current())
        self.assertIn("asset_deleted", self.actions())
        # An add can be sent through review voluntarily; it applies only on approval.
        status, change, _ = self.propose({"name": "web02", "criticality": "high"}, asset_id=False)
        self.assertEqual((status, change["kind"], change["target"]), (201, "asset_add", "web02"), change)
        self.assertEqual(change["evaluation"]["needs_review"], [])
        self.assertEqual(self.admin.get("/api/assets")[1]["assets"], [])
        self.assertEqual(self.review(admin2, change)[0], 200)
        self.assertEqual([a["name"] for a in self.admin.get("/api/assets")[1]["assets"]], ["web02"])
        self.assert_chain_verified()

    def test_reject_leaves_the_inventory_unchanged(self):
        _, change, _ = self.propose({"delete": True})
        status, data, _ = self.review(second_admin(self), change, "reject")
        self.assertEqual((status, data["status"]), (200, "rejected"))
        self.assertEqual(self.current()["name"], "db01")
        self.assertIn("change_rejected", self.actions())
        self.assertNotIn("asset_deleted", self.actions())
        self.assert_chain_verified()

    def test_conflicts_fail_cleanly_and_leave_the_request_pending(self):
        admin2 = second_admin(self)
        # The asset is deleted while an edit to it waits.
        _, rename, _ = self.propose({**self.db01, "name": "db02"})
        _, delete, _ = self.propose({"delete": True})
        self.assertEqual(self.review(admin2, delete)[0], 200)
        status, data, _ = self.review(admin2, rename)
        self.assertEqual(status, 409, data)
        self.assertIn("no longer exists", data["error"])
        self.assertEqual({c["id"]: c for c in self.admin.get("/api/changes")[1]}[rename["id"]]["status"], "pending")
        self.assertEqual(self.review(admin2, rename, "reject")[0], 200)

        # The new name is taken while the rename waits.
        _, web, _ = self.admin.post("/api/assets", {"name": "web01", "criticality": "high"})
        _, rename, _ = self.propose({**web["asset"], "name": "web02"}, web["asset"]["id"])
        self.assertEqual(self.admin.post("/api/assets", {"name": "WEB02"})[0], 201)
        status, data, _ = self.review(admin2, rename)
        self.assertEqual(status, 409, data)
        self.assertIn("already exists", data["error"])
        self.assertEqual(self.current(web["asset"]["id"])["name"], "web01")

        # The same name is added directly while an add proposal waits.
        _, add, _ = self.propose({"name": "mail01"}, asset_id=False)
        self.assertEqual(self.admin.post("/api/assets", {"name": "mail01"})[0], 201)
        status, data, _ = self.review(admin2, add)
        self.assertEqual(status, 409, data)
        self.assertIn("already exists", data["error"])

        # The asset changes in a way that applies directly: the evidence is refreshed, the old digest is
        # refused, and approving the fresh evidence keeps the direct edit.
        _, lower, _ = self.propose({**web["asset"], "criticality": "low"}, web["asset"]["id"])
        self.assertEqual(self.admin.post(f"/api/assets/{web['asset']['id']}",
                                         {**web["asset"], "owner": "web-team"})[0], 200)
        status, data, _ = self.review(admin2, lower)
        self.assertEqual(status, 409, data)
        self.assertIn("evidence changed", data["error"])
        fresh = {c["id"]: c for c in self.admin.get("/api/changes")[1]}[lower["id"]]
        self.assertEqual(fresh["evaluation"]["before"]["owner"], "web-team")
        self.assertEqual(self.review(admin2, fresh)[0], 200)
        self.assertEqual((self.current(web["asset"]["id"])["criticality"],
                          self.current(web["asset"]["id"])["owner"]), ("low", "web-team"))
        self.assert_chain_verified()

    def test_proposals_are_validated_like_direct_edits(self):
        for body, code in (({**self.db01, "criticality": "huge"}, 400), ({**self.db01, "addresses": ["nope"]}, 400),
                           ({**self.db01, "reason": ""}, 400), ({**self.db01}, 409)):
            with self.subTest(body=body):
                self.assertEqual(self.propose(body)[0], code)
        self.assertEqual(self.propose({"delete": True}, asset_id=999)[0], 404)
        self.assertEqual(self.propose({"name": "db01"}, asset_id=False)[0], 409)
        self.assertEqual(self.admin.get("/api/changes")[1], [])

    def test_edits_that_cannot_lower_severity_apply_directly(self):
        path = f"/api/assets/{self.db01['id']}"
        for edit in ({"criticality": "critical", "data_tags": ["pii", "pci", "phi"]},
                     {"addresses": ["10.0.0.10", "10.0.0.12"]}, {"owner": "data-platform"},
                     {"description": "customer database"}):
            with self.subTest(edit=edit):
                status, data, _ = self.admin.post(path, {**self.current(), **edit})
                self.assertEqual(status, 200, data)
        self.assertEqual(self.admin.post("/api/assets", {"name": "web01", "criticality": "low"})[0], 201)
        # A new asset that claims an inventoried address could take over db01's matches.
        status, data, _ = self.admin.post("/api/assets", {"name": "aaa", "addresses": ["10.0.0.10"]})
        self.assertEqual((status, data["proposal_route"]), (409, "/api/assets/proposals"), data)
        self.assertEqual(self.admin.get("/api/changes")[1], [])
        self.assertEqual(self.actions().count("asset_updated"), 4)

    def test_only_admins_propose_and_review(self):
        _, change, _ = self.propose({"delete": True})
        viewer = self.client("viewer")
        for client in (viewer, self.analyst):
            with self.subTest(role="viewer" if client is viewer else "analyst"):
                self.assertEqual(self.propose({"delete": True}, client=client)[0], 403)
                self.assertEqual(self.propose({"name": "x1"}, asset_id=False, client=client)[0], 403)
                self.assertEqual(self.review(client, change)[0], 403)
                self.assertEqual(client.post(f"/api/assets/{self.db01['id']}/delete")[0], 403)
        # The viewer can still see the inventory and what is pending.
        self.assertEqual([c["id"] for c in viewer.get("/api/assets")[1]["pending"]], [change["id"]])
        self.assertEqual(self.current()["name"], "db01")

    def test_ui_offers_review_for_gated_edits(self):
        # No JS runtime in CI: the asset card shows pending proposals and the dialog falls back to proposing.
        app = (Path(__file__).resolve().parent.parent / "static" / "app.js").read_text()
        card = app[app.index("function assetsCard("):app.index("function storyCard(")]
        self.assertIn("pending review", card)
        self.assertIn("review_required", card)
        self.assertIn("/proposals", card)
        self.assertNotIn("innerHTML", card)


if __name__ == "__main__":
    unittest.main()
