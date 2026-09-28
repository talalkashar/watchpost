"""End-to-end: ingest -> detect -> investigate -> resolve -> feedback -> reviewed rule change."""

import json
import os
import sqlite3
import stat
import unittest

from tests.helpers import ServerTestCase
from watchpost.config import Config
from watchpost.health import run_health_checks
from watchpost.db import connect


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
                                         {"decision": "approve", "note": "Scanner is authorized."})
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
        blocked = os.path.join(self.tmp.name, "blocked")
        os.mkdir(blocked)
        os.chmod(blocked, stat.S_IRUSR | stat.S_IXUSR)
        try:
            report = run_health_checks(lambda: connect(os.path.join(blocked, "sub", "x.db")),
                                       os.path.join(blocked, "sub", "x.db"))
            self.assertEqual(report["status"], "failing")
            self.assertEqual(report["checks"][0]["name"], "storage")
            self.assertIn("SIEM_DB", report["checks"][0]["guidance"])
        finally:
            os.chmod(blocked, stat.S_IRWXU)

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
