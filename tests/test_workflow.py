"""End-to-end: ingest -> detect -> investigate -> resolve -> feedback -> reviewed rule change."""

import json
import os
import sqlite3
import stat
import unittest

from datetime import timedelta

from tests.helpers import ServerTestCase
from watchpost.config import Config
from watchpost.health import run_health_checks
from watchpost.db import connect, iso, utcnow


class EndToEndTests(ServerTestCase):
    def test_full_analyst_flow(self):
        admin, analyst = self.client("admin"), self.client("analyst")

        # 1. Load labeled synthetic data (admin only, refuses to double-load).
        status, loaded, _ = admin.post("/api/demo/load")
        self.assertEqual(status, 200, loaded)
        self.assertTrue(all(r["detection"]["status"] == "ok" for r in loaded.values()))
        self.assertEqual(admin.post("/api/demo/load")[0], 409)

        # 2. Expected alerts exist, all flagged synthetic.
        alerts = analyst.get("/api/alerts")[1]
        by_rule = {}
        for a in alerts:
            by_rule.setdefault(a["rule_id"], []).append(a)
            self.assertEqual(a["synthetic"], 1)
        self.assertEqual({a["group_key"] for a in by_rule["brute_force_ip"]}, {"203.0.113.45", "10.0.50.5"})
        self.assertEqual(len(by_rule["brute_force_ip"]), 3)  # attacker + two scanner passes
        self.assertEqual(by_rule["password_spray"][0]["group_key"], "198.51.100.23")
        self.assertEqual(by_rule["success_after_failures"][0]["group_key"], "dave|192.0.2.77")
        self.assertEqual(by_rule["success_after_failures"][0]["severity"], "critical")
        self.assertIn("off_hours_privileged_login", by_rule)
        self.assertEqual(alerts[0]["severity"], "critical")  # sorted most severe first

        # 3. Investigate the compromise: evidence, explanation, and related timeline.
        alert_id = by_rule["success_after_failures"][0]["id"]
        detail = analyst.get(f"/api/alerts/{alert_id}")[1]
        self.assertEqual(len(detail["evidence"]), 8)
        self.assertIn("after 7 failed attempts", detail["explanation"])
        self.assertEqual(detail["rule"]["id"], "success_after_failures")
        self.assertTrue(any(e["is_evidence"] for e in detail["timeline"]))
        self.assertEqual(detail["activity"][0]["action"], "created")

        self.assertEqual(analyst.post(f"/api/alerts/{alert_id}/status", {"status": "investigating"})[0], 200)
        self.assertEqual(analyst.post(f"/api/alerts/{alert_id}/notes",
                                      {"body": "Reset dave's password; checking VPN logs."})[0], 201)
        # Resolving requires a disposition; bad values are rejected.
        self.assertEqual(analyst.post(f"/api/alerts/{alert_id}/status", {"status": "resolved"})[0], 400)
        self.assertEqual(analyst.post(f"/api/alerts/{alert_id}/status",
                                      {"status": "resolved", "disposition": "maybe"})[0], 400)
        self.assertEqual(analyst.post(f"/api/alerts/{alert_id}/status", {"status": "closed"})[0], 400)
        status, resolved, _ = analyst.post(f"/api/alerts/{alert_id}/status",
                                           {"status": "resolved", "disposition": "true_positive",
                                            "note": "Confirmed credential guessing."})
        self.assertEqual(status, 200)
        self.assertEqual((resolved["status"], resolved["disposition"], resolved["assignee"]),
                         ("resolved", "true_positive", "analyst"))
        detail = analyst.get(f"/api/alerts/{alert_id}")[1]
        self.assertEqual(len(detail["notes"]), 2)
        self.assertEqual([a["action"] for a in detail["activity"]],
                         ["created", "status_changed", "note_added", "status_changed", "note_added"])
        self.assertEqual(analyst.get("/api/alerts/99999")[0], 404)
        self.assertEqual(analyst.post("/api/alerts/99999/notes", {"body": "x"})[0], 404)

        # 4. Metrics reflect the workflow.
        m = analyst.get("/api/metrics")[1]
        self.assertEqual(m["alerts_resolved"], 1)
        self.assertEqual(m["synthetic_events"], m["events_total"])
        self.assertEqual(len(m["activity_last_24h_of_data"]), 24)
        self.assertEqual(m["top_failure_ips"][0]["src_ip"], "203.0.113.45")

        # 5. Feedback: analyst marks the scanner alerts false positive, the attacker true positive.
        for a in by_rule["brute_force_ip"]:
            verdict = "true_positive" if a["group_key"] == "203.0.113.45" else "false_positive"
            analyst.post(f"/api/alerts/{a['id']}/status", {"status": "resolved", "disposition": verdict})
        perf = {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]["performance"]
        self.assertEqual((perf["tp"], perf["fp"], perf["precision"]), (1, 2, 0.333))

        # 6. Suggestion: exclude the scanner IP, with before/after evaluation attached.
        status, suggestions, _ = analyst.post("/api/rules/suggestions")
        self.assertEqual(status, 200)
        created = [c for c in suggestions["created"] if c["target"] == "brute_force_ip"]
        self.assertEqual(len(created), 1)
        change = created[0]
        self.assertEqual(change["payload"], {"params": {"ignore_ips": ["10.0.50.5"]}})
        self.assertEqual(change["status"], "pending")
        self.assertGreater(change["evaluation"]["before"]["fp"], change["evaluation"]["after"]["fp"])
        self.assertEqual(change["evaluation"]["before"]["tp"], change["evaluation"]["after"]["tp"])
        # Asking again does not create a duplicate.
        self.assertEqual([c for c in analyst.post("/api/rules/suggestions")[1]["created"]
                          if c["target"] == "brute_force_ip"], [])

        # 7. Nothing changes until an admin approves.
        rule = {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual((rule["version"], rule["params"]["ignore_ips"]), (1, []))
        self.assertEqual(analyst.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 403)
        status, reviewed, _ = admin.post(f"/api/changes/{change['id']}/review",
                                         {"decision": "approve", "note": "Scanner is authorized.", "evidence_digest": change["evidence_digest"]})
        self.assertEqual(status, 200, reviewed)
        self.assertEqual(reviewed["status"], "approved")
        self.assertEqual(admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 409)

        rule = {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual((rule["version"], rule["params"]["ignore_ips"]), (2, ["10.0.50.5"]))
        history = analyst.get("/api/rules/brute_force_ip/history")[1]
        self.assertEqual([h["version"] for h in history], [2, 1])
        self.assertEqual((history[0]["approved_by"], history[0]["changed_by"]), ("admin", "system:feedback"))
        evaluations = analyst.get("/api/evaluations")[1]
        self.assertEqual(evaluations[0]["trigger"], "post_change")
        self.assertEqual(evaluations[0]["results"]["rules"]["brute_force_ip"]["fp"], 0)

        # 8. New scanner traffic no longer alerts; new attacker traffic still does.
        status, sim, _ = analyst.post("/api/demo/simulate", {"scenario": "noisy_scanner", "seed": 1})
        self.assertEqual(status, 201)
        self.assertEqual(sim["detection"]["alerts_created"], 0)
        self.assertEqual(len(analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1]), 0)
        # The previous attacker alert is resolved, so a replay opens a fresh alert.
        sim = analyst.post("/api/demo/simulate", {"scenario": "brute_force", "seed": 1})[1]
        open_bf = analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1]
        self.assertEqual([a["group_key"] for a in open_bf], ["203.0.113.45"])
        self.assertEqual(analyst.post("/api/demo/simulate", {"scenario": "nope"})[0], 400)

        # 9. Everything above is in the audit trail.
        actions = {a["action"] for a in admin.get("/api/audit")[1]}
        self.assertTrue({"demo_loaded", "change_proposed", "change_approved", "rule_changed"} <= actions)

    def test_manual_rule_proposal_review_rules(self):
        admin, analyst = self.client("admin"), self.client("analyst")
        bad = [({"params": {"threshold": 0}, "reason": "lower it"}, 400),
               ({"params": {"bogus": 1}, "reason": "typo"}, 400),
               ({"enabled": "no", "reason": "disable"}, 400),
               ({"reason": "empty change"}, 400),
               ({"params": {"threshold": 20}}, 400)]  # missing reason
        for body, code in bad:
            with self.subTest(body=body):
                self.assertEqual(analyst.post("/api/rules/brute_force_ip/proposals", body)[0], code)
        self.assertEqual(analyst.post("/api/rules/no_such_rule/proposals",
                                      {"enabled": False, "reason": "x" * 10})[0], 404)

        status, change, _ = admin.post("/api/rules/brute_force_ip/proposals",
                                       {"enabled": False, "reason": "testing self-review"})
        self.assertEqual(status, 201)
        # Admins cannot approve their own proposal.
        status, data, _ = admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})
        self.assertEqual(status, 403)
        self.assertIn("second person", data["error"])

        status, change, _ = analyst.post("/api/rules/brute_force_ip/proposals",
                                         {"params": {"threshold": 20}, "reason": "too noisy"})
        self.assertEqual(admin.post(f"/api/changes/{change['id']}/review", {"decision": "maybe"})[0], 400)
        status, rejected, _ = admin.post(f"/api/changes/{change['id']}/review",
                                         {"decision": "reject", "note": "would miss slow attacks"})
        self.assertEqual(rejected["status"], "rejected")
        rule = {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual((rule["version"], rule["params"]["threshold"]), (1, 10))

    def test_security_setting_change_requires_second_admin(self):
        admin = self.client("admin")
        self.assertEqual(admin.post("/api/settings/login_lockout_threshold/proposals",
                                    {"value": 99, "reason": "too high"})[0], 400)
        self.assertEqual(admin.post("/api/settings/unknown/proposals", {"value": 3, "reason": "no such key"})[0], 404)
        status, change, _ = admin.post("/api/settings/login_lockout_threshold/proposals",
                                       {"value": 3, "reason": "tighten lockout"})
        self.assertEqual(status, 201)
        self.assertEqual(admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 403)

        # A second admin approves; the new threshold takes effect for logins.
        from watchpost.auth import create_user
        conn = connect(self.db_path)
        create_user(conn, "admin2", "second-admin-password", "admin")
        conn.close()
        admin2 = self.client()
        self.assertEqual(admin2.login("admin2", "second-admin-password")[0], 200)
        self.assertEqual(admin2.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 200)
        settings = {s["key"]: s for s in admin.get("/api/settings")[1]}
        self.assertEqual(settings["login_lockout_threshold"]["value"], "3")
        victim = self.client()
        for _ in range(3):
            victim.login("analyst", "wrong-password-xx")
        self.assertEqual(victim.login("analyst", "analyst-test-password-1")[0], 429)


class ChangeEvidenceTests(ServerTestCase):
    """What the admin reviews is what approval does: stale evidence is refreshed, never applied."""

    def exception(self, client, key="10.0.50.5", rule="brute_force_ip"):
        return client.post(f"/api/rules/{rule}/suppressions",
                           {"group_key": key, "days": 30, "reason": "Authorized internal scanner."})

    def approve(self, client, change, **extra):
        """Approve with the digest of the evidence in `change`, as the UI does for the row it rendered."""
        return client.post(f"/api/changes/{change['id']}/review",
                           {"decision": "approve", "evidence_digest": change["evidence_digest"], **extra})

    def second_admin(self):
        from watchpost.auth import create_user
        conn = connect(self.db_path)
        create_user(conn, "admin2", "second-admin-password", "admin")
        conn.close()
        client = self.client()
        self.assertEqual(client.login("admin2", "second-admin-password")[0], 200)
        return client

    def stored(self, client, change):
        return {c["id"]: c for c in client.get("/api/changes")[1]}[change["id"]]

    def scanner_alert(self, analyst, **sim):
        analyst.post("/api/demo/simulate", {"scenario": "noisy_scanner", **sim})
        return analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1][0]

    def test_stale_rule_evidence_is_refreshed_then_applies_on_the_second_approve(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        first = analyst.post("/api/rules/brute_force_ip/proposals",
                             {"params": {"ignore_ips": ["10.0.50.5"]}, "reason": "authorized scanner"})[1]
        second = analyst.post("/api/rules/brute_force_ip/proposals",
                              {"params": {"threshold": 12}, "reason": "slightly less noise"})[1]
        self.assertEqual(second["evaluation"]["before"]["fp"], 2)
        self.assertEqual(self.approve(admin, first)[0], 200)

        # The rule changed under the second proposal: its evidence no longer describes the action.
        status, data, _ = self.approve(admin, second)
        self.assertEqual(status, 409)
        self.assertIn("evidence changed", data["error"])
        change = self.stored(admin, second)
        self.assertEqual((change["status"], change["reviewed_by"]), ("pending", None))
        self.assertEqual(change["evaluation"]["before"]["fp"], 0)
        rule = lambda: {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual((rule()["version"], rule()["params"]["threshold"]), (2, 10))
        self.assertIn("change_evidence_refreshed", [a["action"] for a in admin.get("/api/audit")[1]])

        # Resending the digest the reviewer first saw is refused again: only the evidence now stored applies.
        self.assertEqual(self.approve(admin, second)[0], 409)
        self.assertNotEqual(change["evidence_digest"], second["evidence_digest"])
        status, reviewed, _ = self.approve(admin, change)
        self.assertEqual((status, reviewed["status"]), (200, "approved"))
        self.assertEqual(reviewed["evaluation"], change["evaluation"])
        self.assertEqual((rule()["version"], rule()["params"]["threshold"]), (3, 12))

    def test_stale_exception_evidence_is_refreshed_then_applies_on_the_second_approve(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = self.exception(analyst)[1]
        self.assertEqual(change["evaluation"]["live_impact"]["alerts"], 0)
        alert = self.scanner_alert(analyst)  # a live alert now matches the key

        self.assertEqual(self.approve(admin, change)[0], 409)
        self.assertEqual(analyst.get("/api/suppressions")[1], [])
        fresh = self.stored(admin, change)
        self.assertEqual(fresh["status"], "pending")
        self.assertEqual(fresh["evaluation"]["live_impact"]["alerts"], 1)
        self.assertEqual(fresh["evaluation"]["live_impact"]["recent"][0]["id"], alert["id"])

        self.assertEqual(self.approve(admin, fresh)[0], 200)
        self.assertEqual(len(analyst.get("/api/suppressions")[1]), 1)

    def test_approval_is_bound_to_the_evidence_digest_the_reviewer_sends(self):
        analyst, admin, admin2 = self.client("analyst"), self.client("admin"), self.second_admin()
        change = self.exception(analyst)[1]
        self.assertRegex(change["evidence_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.stored(admin, change)["evidence_digest"], change["evidence_digest"])
        review = f"/api/changes/{change['id']}/review"
        # No digest: the server cannot know what the reviewer looked at.
        for body in ({"decision": "approve"}, {"decision": "approve", "evidence_digest": ""},
                     {"decision": "approve", "evidence_digest": 5}):
            status, data, _ = admin.post(review, body)
            self.assertEqual(status, 400, body)
            self.assertIn("evidence_digest", data["error"])
        self.assertEqual(self.stored(admin, change)["status"], "pending")

        self.scanner_alert(analyst)  # the evidence changes after both reviewers loaded the list
        self.assertEqual(self.approve(admin, change)[0], 409)
        fresh = self.stored(admin, change)
        self.assertNotEqual(fresh["evidence_digest"], change["evidence_digest"])
        # A second reviewer (or a retry) cannot ride that 409: the stored evidence is fresh now, but
        # they never displayed it, and nothing applies until someone sends its digest.
        self.assertEqual(self.approve(admin2, change)[0], 409)
        self.assertEqual(admin2.post(review, {"decision": "approve"})[0], 400)
        self.assertEqual(analyst.get("/api/suppressions")[1], [])
        self.assertEqual(self.stored(admin, change)["status"], "pending")
        status, reviewed, _ = self.approve(admin2, fresh)
        self.assertEqual((status, reviewed["status"], reviewed["reviewed_by"]), (200, "approved", "admin2"))
        self.assertEqual(len(analyst.get("/api/suppressions")[1]), 1)

    def test_a_verdict_flipped_from_true_positive_still_blocks_the_exception(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        alert = self.scanner_alert(analyst)
        verdict = lambda **body: analyst.post(f"/api/alerts/{alert['id']}/status", body)
        verdict(status="resolved", disposition="true_positive")
        verdict(status="open")
        verdict(status="resolved", disposition="benign")
        # The current disposition is benign; the alert's history still says it was a true positive.
        status, data, _ = self.exception(analyst)
        self.assertEqual(status, 400)
        self.assertIn("true positive", data["error"])
        self.assertEqual(admin.get("/api/changes")[1], [])

    def test_the_proposers_own_verdict_changes_are_shown_to_the_reviewer(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        alert = self.scanner_alert(analyst)
        admin.post(f"/api/alerts/{alert['id']}/status", {"status": "investigating"})
        analyst.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "false_positive"})
        other = analyst.get("/api/alerts?rule_id=account_repeated_failures&status=open")[1][0]
        analyst.post(f"/api/alerts/{other['id']}/status", {"status": "resolved", "disposition": "benign"})
        impact = self.exception(analyst)[1]["evaluation"]["live_impact"]
        self.assertEqual(impact["ever_true_positive"], 0)
        own = impact["proposer_verdict_changes"]
        self.assertEqual(own["count"], 1)  # not the admin's change, not the other rule's alert
        self.assertEqual([(c["alert_id"], c["detail"]) for c in own["recent"]],
                         [(alert["id"], "investigating -> resolved (false_positive)")])
        # The same key proposed by someone who touched nothing shows none.
        impact = self.exception(self.second_admin())[1]["evaluation"]["live_impact"]
        self.assertEqual(impact["proposer_verdict_changes"], {"count": 0, "recent": []})

    def ignore(self, client, *ips, rule="brute_force_ip"):
        return client.post(f"/api/rules/{rule}/proposals",
                           {"params": {"ignore_ips": list(ips)}, "reason": "authorized scanner"})

    def test_an_ignore_list_entry_is_gated_like_an_exception(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        alert = self.scanner_alert(analyst)
        verdict = lambda **body: analyst.post(f"/api/alerts/{alert['id']}/status", body)

        # No alerts for the value: allowed, and the (empty) impact is part of the evidence.
        status, change, _ = self.ignore(analyst, "10.9.9.9")
        self.assertEqual(status, 201, change)
        added = change["evaluation"]["ignore_additions"]
        self.assertEqual([(x["param"], x["value"], x["live_impact"]["alerts"]) for x in added],
                         [("ignore_ips", "10.9.9.9", 0)])

        # An open alert, then a true-positive verdict between propose and approve: the approve is blocked.
        pending = self.ignore(analyst, "10.0.50.5")[1]
        impact = pending["evaluation"]["ignore_additions"][0]["live_impact"]
        self.assertEqual((impact["alerts"], impact["by_status"], impact["ever_true_positive"]), (1, {"open": 1}, 0))
        self.assertEqual(impact["recent"][0]["id"], alert["id"])
        verdict(status="resolved", disposition="true_positive")
        status, data, _ = self.approve(admin, pending)
        self.assertEqual(status, 400)
        self.assertIn("true positive", data["error"])
        self.assertIn("10.0.50.5", data["error"])
        self.assertEqual(self.stored(admin, pending)["status"], "pending")
        rule = lambda: {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual((rule()["version"], rule()["params"]["ignore_ips"]), (1, []))

        # Refused at propose too, also beside a harmless value, and still after the verdict is flipped.
        for ips in (("10.0.50.5",), ("10.9.9.9", "10.0.50.5")):
            status, data, _ = self.ignore(analyst, *ips)
            self.assertEqual(status, 400, ips)
            self.assertIn("true positive", data["error"])
        verdict(status="open")
        verdict(status="resolved", disposition="benign")
        self.assertEqual(self.ignore(analyst, "10.0.50.5")[0], 400)
        # The proposer's own verdict changes are in the evidence of the request that is still pending.
        self.assertEqual(self.approve(admin, self.stored(admin, pending))[0], 400)
        own = self.stored(admin, pending)["evaluation"]["ignore_additions"][0]["live_impact"]["proposer_verdict_changes"]
        self.assertEqual(own["count"], 3)
        # Other parameters of the same rule are not affected by that history.
        self.assertEqual(analyst.post("/api/rules/brute_force_ip/proposals",
                                      {"params": {"threshold": 11}, "reason": "unrelated"})[1]["evaluation"]
                         ["ignore_additions"], [])

    def test_an_ignore_list_entry_with_only_benign_history_applies_and_can_be_removed(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        alert = self.scanner_alert(analyst)
        analyst.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "benign"})
        change = self.ignore(analyst, "10.0.50.5")[1]
        impact = change["evaluation"]["ignore_additions"][0]["live_impact"]
        self.assertEqual((impact["alerts"], impact["by_disposition"], impact["ever_true_positive"]),
                         (1, {"benign": 1}, 0))
        self.assertEqual(self.approve(admin, change)[0], 200)
        # A user entry matches alerts by their evidence, whatever the rule's group key is.
        user = analyst.post("/api/rules/brute_force_ip/proposals",
                            {"params": {"ignore_users": ["SVC_SCAN"]}, "reason": "scanner account"})[1]
        self.assertEqual([(x["param"], x["value"], x["live_impact"]["alerts"])
                          for x in user["evaluation"]["ignore_additions"]], [("ignore_users", "SVC_SCAN", 1)])
        # Removing a value is not an addition, whatever the history says.
        admin.post(f"/api/alerts/{alert['id']}/status", {"status": "open"})
        admin.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        status, removal, _ = analyst.post("/api/rules/brute_force_ip/proposals",
                                          {"params": {"ignore_ips": []}, "reason": "stop ignoring it"})
        self.assertEqual((status, removal["evaluation"]["ignore_additions"]), (201, []))
        self.assertEqual(self.approve(admin, removal)[0], 200)

    def confirmed(self, analyst, scenario, rule):
        """Replay a scenario and close the rule's alert as a true positive. Returns the alert."""
        analyst.post("/api/demo/simulate", {"scenario": scenario})
        alert = analyst.get(f"/api/alerts?rule_id={rule}&status=open")[1][0]
        analyst.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        return alert

    def propose(self, client, rule, **params):
        return client.post(f"/api/rules/{rule}/proposals", {"params": params, "reason": "gate check"})

    def test_the_gate_reads_a_sanctioned_service_entry_the_way_the_rule_does(self):
        analyst = self.client("analyst")
        self.confirmed(analyst, "shadow_it", "unsanctioned_cloud_service")
        base = ["amazonaws.com", "corp-drive.example"]
        # The rule strips leading dots, lowercases, and honours a parent domain; so must the refusal.
        for entry in ("personal-drive.example", ".personal-drive.example", "..Personal-Drive.EXAMPLE", "example"):
            with self.subTest(entry=entry):
                status, data, _ = self.propose(analyst, "unsanctioned_cloud_service", sanctioned_services=base + [entry])
                self.assertEqual(status, 400, data)
                self.assertIn("true positive", data["error"])
        # The rule gives % and _ no special meaning, and neither does the gate.
        for entry in ("personal-drive.exampl_", "%", "drive.example"):
            with self.subTest(entry=entry):
                status, change, _ = self.propose(analyst, "unsanctioned_cloud_service", sanctioned_services=base + [entry])
                self.assertEqual(status, 201, change)
                self.assertEqual([(x["value"], x["live_impact"]["alerts"]) for x in change["evaluation"]["ignore_additions"]],
                                 [(entry, 0)])
        # An entry that is only a respelling of one already on the list adds nothing.
        change = self.propose(analyst, "unsanctioned_cloud_service", sanctioned_services=base + [".CORP-drive.example"])[1]
        self.assertEqual(change["evaluation"]["ignore_additions"], [])

    def test_the_gate_folds_user_names_the_way_the_rule_does(self):
        analyst = self.client("analyst")
        now = iso(utcnow() - timedelta(minutes=5))
        status, data, _ = analyst.post("/api/ingest", {"source": "auth01", "events": [
            {"ts": now, "type": "login_failed", "user": "\u00c1dmin", "src_ip": "198.51.100.77"} for _ in range(12)]})
        self.assertEqual(status, 201, data)
        alert = analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1][0]
        analyst.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        # Python lowercases the non-ASCII capital, so the rule would skip these events for either spelling.
        for names in (["\u00e1dmin"], ["\u00c1DMIN"], ["someone", "\u00e1dmin", "\u00c1dmin"]):
            with self.subTest(names=names):
                status, data, _ = self.propose(analyst, "brute_force_ip", ignore_users=names)
                self.assertEqual(status, 400, data)
                self.assertIn("true positive", data["error"])
        # Spellings that fold to one name are one addition, not two.
        change = self.propose(analyst, "brute_force_ip", ignore_users=["Bob", "bob", "BOB"])[1]
        self.assertEqual([(x["param"], x["value"]) for x in change["evaluation"]["ignore_additions"]],
                         [("ignore_users", "Bob")])

    def test_removing_a_privileged_user_is_gated_like_ignoring_them(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        # Narrowing the list while root has no confirmed history is allowed, and the impact is in the evidence.
        analyst.post("/api/demo/simulate", {"scenario": "off_hours_admin"})
        alert = analyst.get("/api/alerts?rule_id=off_hours_privileged_login&status=open")[1][0]
        pending = self.propose(analyst, "off_hours_privileged_login", privileged_users=["admin", "administrator"])[1]
        self.assertEqual([(x["param"], x["change"], x["value"], x["live_impact"]["alerts"])
                          for x in pending["evaluation"]["ignore_additions"]], [("privileged_users", "removed", "root", 1)])
        analyst.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        status, data, _ = self.approve(admin, pending, acknowledge_detection_loss=True)
        self.assertEqual(status, 400)
        self.assertIn("true positive", data["error"])
        self.assertEqual(self.propose(analyst, "off_hours_privileged_login", privileged_users=["admin"])[0], 400)
        # Adding a user widens the rule, and a respelling removes nobody.
        change = self.propose(analyst, "off_hours_privileged_login",
                              privileged_users=["ROOT", "admin", "administrator", "dbadmin"])[1]
        self.assertEqual(change["evaluation"]["ignore_additions"], [])

    def test_a_rule_change_that_loses_a_labeled_detection_needs_an_acknowledgement(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        rule = lambda rid: {r["id"]: r for r in analyst.get("/api/rules")[1]}[rid]
        loosen = analyst.post("/api/rules/brute_force_ip/proposals",
                              {"params": {"threshold": 500}, "reason": "far too high on purpose"})[1]
        disable = analyst.post("/api/rules/web_scanner/proposals", {"enabled": False, "reason": "testing the gate"})[1]
        for change, lost in ((loosen, "brute_force"), (disable, "web_scan")):
            with self.subTest(target=change["target"]):
                self.assertIn(lost, change["evaluation"]["before"]["detected"])
                self.assertIn(lost, change["evaluation"]["after"]["missed"])
                for extra in ({}, {"acknowledge_detection_loss": False}, {"acknowledge_detection_loss": "yes"}):
                    status, data, _ = self.approve(admin, change, **extra)
                    self.assertEqual(status, 400, extra)
                    self.assertIn("acknowledge_detection_loss", data["error"])
                    self.assertIn(lost, data["error"])
                self.assertEqual(rule(change["target"])["version"], 1)
                # The acknowledgement does not replace the digest.
                self.assertEqual(admin.post(f"/api/changes/{change['id']}/review",
                                            {"decision": "approve", "acknowledge_detection_loss": True})[0], 400)
                status, reviewed, _ = self.approve(admin, change, acknowledge_detection_loss=True)
                self.assertEqual((status, reviewed["status"]), (200, "approved"))
                entry = next(a for a in admin.get("/api/audit")[1]
                             if a["action"] == "change_approved" and json.loads(a["detail"])["id"] == change["id"])
                self.assertIn(lost, json.loads(entry["detail"])["acknowledged_detection_loss"])
        self.assertEqual((rule("brute_force_ip")["params"]["threshold"], bool(rule("web_scanner")["enabled"])), (500, False))
        # A change that loses nothing needs no acknowledgement and records none.
        quiet = analyst.post("/api/rules/password_spray/proposals",
                             {"params": {"window_seconds": 301}, "reason": "no effect on scenarios"})[1]
        self.assertEqual(self.approve(admin, quiet)[0], 200)
        entry = next(a for a in admin.get("/api/audit")[1] if a["action"] == "change_approved")
        self.assertNotIn("acknowledged_detection_loss", json.loads(entry["detail"]))

    def test_exception_evidence_counts_matching_live_alerts(self):
        analyst = self.client("analyst")
        old = self.scanner_alert(analyst)
        analyst.post(f"/api/alerts/{old['id']}/status", {"status": "resolved", "disposition": "false_positive"})
        new = self.scanner_alert(analyst, seed=3)
        self.assertNotEqual(new["id"], old["id"])
        impact = self.exception(analyst)[1]["evaluation"]["live_impact"]
        self.assertEqual((impact["alerts"], impact["by_status"], impact["by_disposition"]),
                         (2, {"open": 1, "resolved": 1}, {"false_positive": 1}))
        self.assertEqual([(a["id"], a["title"], a["status"], a["disposition"]) for a in impact["recent"]],
                         [(new["id"], new["title"], "open", None), (old["id"], old["title"], "resolved", "false_positive")])
        self.assertEqual((impact["in_labeled_scenario"], impact["effect"]), (True, "skip"))

        # A key no labeled scenario contains: before == after says nothing about it, and the evidence says so.
        status, change, _ = self.exception(analyst, key="10.9.9.9")
        self.assertEqual(status, 201)
        evidence = change["evaluation"]
        self.assertEqual(evidence["before"], evidence["after"])
        self.assertEqual((evidence["live_impact"]["alerts"], evidence["live_impact"]["in_labeled_scenario"]), (0, False))

        # For the exfil rule nothing is hidden; the evidence states the baseline mode.
        impact = self.exception(analyst, key="10.0.5.10", rule="data_exfil_volume")[1]["evaluation"]["live_impact"]
        self.assertEqual((impact["effect"], impact["in_labeled_scenario"]), ("baseline", True))
        self.assertIn("baseline", impact["effect_note"])

    def test_confirmed_malicious_activity_cannot_be_excepted(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        # The key of a labeled attack: the exception would make the rule miss it.
        status, data, _ = self.exception(analyst, key="203.0.113.45")
        self.assertEqual(status, 400)
        self.assertIn("labeled attack", data["error"])
        self.assertEqual(admin.get("/api/changes")[1], [])

        # A key whose live alert an analyst closed as a true positive.
        pending = self.exception(analyst)[1]
        alert = self.scanner_alert(analyst)
        analyst.post(f"/api/alerts/{alert['id']}/status", {"status": "resolved", "disposition": "true_positive"})
        status, data, _ = self.exception(analyst)
        self.assertEqual(status, 400)
        self.assertIn("true positive", data["error"])
        # The same refusal at approve time, for a request proposed before the verdict; it can still be rejected.
        status, data, _ = self.approve(admin, pending)
        self.assertEqual(status, 400)
        self.assertIn("true positive", data["error"])
        self.assertEqual(analyst.get("/api/suppressions")[1], [])
        self.assertEqual(self.stored(admin, pending)["status"], "pending")
        self.assertEqual(admin.post(f"/api/changes/{pending['id']}/review", {"decision": "reject"})[1]["status"],
                         "rejected")

    def test_review_roles_are_unchanged(self):
        analyst, admin, viewer = self.client("analyst"), self.client("admin"), self.client("viewer")
        change = self.exception(analyst)[1]
        self.assertEqual(self.approve(viewer, change)[0], 403)
        self.assertEqual(self.approve(analyst, change)[0], 403)
        own = self.exception(admin, key="10.9.9.9")[1]
        status, data, _ = self.approve(admin, own)
        self.assertEqual(status, 403)
        self.assertIn("second person", data["error"])
        self.assertEqual(self.approve(admin, change)[0], 200)


class HealthRecoveryTests(ServerTestCase):
    def details(self, client):
        status, data, _ = client.get("/api/health/details")
        self.assertEqual(status, 200)
        return {c["name"]: c for c in data["checks"]}, data

    def test_healthy_baseline(self):
        checks, data = self.details(self.client("admin"))
        self.assertEqual(data["status"], "ok", data)
        self.assertEqual(checks["storage"]["details"]["events"], 0)

    def test_detection_failure_is_reported_and_recovers(self):
        admin, analyst = self.client("admin"), self.client("analyst")
        # Simulate a corrupted rule definition (bypassing the review workflow, as a bad migration might).
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE rules SET params = ? WHERE id = 'brute_force_ip'",
                       (json.dumps({"threshold": -5, "window_seconds": 300, "ignore_ips": [], "ignore_users": []}),))

        status, result, _ = analyst.post("/api/demo/simulate", {"scenario": "brute_force"})
        # Events are stored even though detection failed, and the response says so.
        self.assertEqual(status, 201)
        self.assertEqual(result["accepted"], 40)
        self.assertEqual(result["detection"]["status"], "failed")
        self.assertIn("RuleConfigError", result["detection"]["error"])
        self.assertEqual(analyst.get("/api/alerts")[1], [])

        checks, data = self.details(admin)
        self.assertEqual(data["status"], "failing")
        self.assertEqual(checks["detection"]["status"], "failing")
        self.assertIn("Run detection", checks["detection"]["guidance"])
        self.assertEqual(data["recent_errors"][0]["component"], "detection")
        public = self.client().get("/api/health")
        self.assertEqual(public[0], 503)
        self.assertEqual(public[1]["checks"]["detection"], "failing")

        # Operator fixes the rule; the backlog is still flagged until detection is re-run.
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE rules SET params = ? WHERE id = 'brute_force_ip'",
                       (json.dumps({"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []}),))
        analyst.post("/api/ingest", [])  # unrelated empty ingest does not hide the backlog
        checks, _ = self.details(admin)
        self.assertEqual(checks["detection"]["status"], "failing")

        status, run, _ = analyst.post("/api/detection/run")
        self.assertEqual((status, run["status"]), (200, "ok"))
        self.assertGreaterEqual(run["alerts_created"], 2)
        checks, data = self.details(admin)
        self.assertEqual(checks["detection"]["status"], "ok")
        self.assertEqual(checks["detection"]["details"]["unprocessed_failed_batches"], 0)
        self.assertEqual(data["status"], "ok")
        batches = analyst.get("/api/ingest/batches")[1]
        self.assertIn("recovered", {b["detection_status"] for b in batches})

    def test_backlog_warning_when_later_ingest_succeeds(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE rules SET params = '{\"threshold\": \"x\"}' WHERE id = 'password_spray'")
        analyst.post("/api/demo/simulate", {"scenario": "password_spray"})
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE rules SET params = ? WHERE id = 'password_spray'",
                       (json.dumps({"distinct_users": 5, "window_seconds": 600, "ignore_ips": [], "ignore_users": []}),))
        # A later successful ingest-triggered run only scans its own time range...
        analyst.post("/api/demo/simulate", {"scenario": "off_hours_admin"})
        checks, _ = self.details(admin)
        # ...so health stays degraded (not ok) until a full run processes the failed batch.
        self.assertEqual(checks["detection"]["status"], "degraded")
        analyst.post("/api/detection/run")
        checks, _ = self.details(admin)
        self.assertEqual(checks["detection"]["status"], "ok")

    def test_all_rules_disabled_is_degraded(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE rules SET enabled = 0")
        checks, data = self.details(self.client("admin"))
        self.assertEqual(checks["detection"]["status"], "degraded")
        self.assertEqual(data["status"], "degraded")

    def test_high_reject_rate_is_degraded(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        analyst.post("/api/ingest", [{"ts": "bad"}] * 30)
        checks, _ = self.details(admin)
        self.assertEqual(checks["ingestion"]["status"], "degraded")
        self.assertIn("rejected", checks["ingestion"]["message"])

    def test_unhandled_error_is_recorded_without_secrets(self):
        admin = self.client("admin")
        with sqlite3.connect(self.db_path) as db:
            db.execute("DROP TABLE alert_notes")
        status, data, _ = admin.post("/api/alerts/1/notes", {"body": "password=hunter2"})
        self.assertIn(status, (404, 500))
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
                       " first_seen, last_seen, event_count, created_at, updated_at) VALUES"
                       " ('x',1,'k','low','t','e','2026-01-01','2026-01-01',0,'2026-01-01','2026-01-01')")
        status, data, _ = admin.post("/api/alerts/1/notes", {"body": "my password=hunter2"})
        self.assertEqual(status, 500)
        self.assertNotIn("hunter2", json.dumps(data))
        _, details = self.details(admin)
        self.assertEqual(details["recent_errors"][0]["component"], "api")
        self.assertNotIn("hunter2", json.dumps(details))

    def test_storage_unavailable_is_failing_not_a_crash(self):
        # A regular file where a directory should be: unusable even for root, which ignores chmod.
        blocked = os.path.join(self.tmp.name, "blocked")
        with open(blocked, "w") as handle:
            handle.write("not a directory")
        report = run_health_checks(lambda: connect(os.path.join(blocked, "sub", "x.db")),
                                   os.path.join(blocked, "sub", "x.db"))
        self.assertEqual(report["status"], "failing")
        self.assertEqual(report["checks"][0]["name"], "storage")
        self.assertIn("SIEM_DB", report["checks"][0]["guidance"])

        # Recovery: pointing at a writable location reports healthy again.
        good = os.path.join(self.tmp.name, "good", "x.db")
        from watchpost.server import App
        App(Config.from_env(db_path=good, admin_password="a" * 12, analyst_password="b" * 12))
        report = run_health_checks(lambda: connect(good), good)
        self.assertEqual(report["status"], "ok", report)

    def test_generated_credentials_file_is_private(self):
        from watchpost.server import App
        path = os.path.join(self.tmp.name, "gen", "x.db")
        app = App(Config.from_env(db_path=path, admin_password=None, analyst_password=None))
        mode = stat.S_IMODE(os.stat(app.credentials_file).st_mode)
        self.assertEqual(mode, 0o600)
        with open(app.credentials_file) as fh:
            self.assertIn("admin:", fh.read())
        # Restarting does not regenerate or overwrite credentials.
        self.assertIsNone(App(Config.from_env(db_path=path)).credentials_file)


if __name__ == "__main__":
    unittest.main()
