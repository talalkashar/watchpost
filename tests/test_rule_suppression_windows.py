"""Reviewed, time-bounded suppression windows for an entire detection rule."""

import sqlite3
from datetime import timedelta

from tests.helpers import ServerTestCase
from tests.test_search_rules import GOOD_SAMPLE, RULE_ID, WEB_QUERY, definition
from watchpost.db import iso, utcnow


class RuleSuppressionWindowApiTests(ServerTestCase):
    def propose(self, client, rule="brute_force_ip", **overrides):
        body = {
            "starts_at": iso(utcnow() - timedelta(minutes=1)),
            "expires_at": iso(utcnow() + timedelta(hours=2)),
            "reason": "Planned authentication migration; ticket SEC-240.",
            **overrides,
        }
        return client.post(f"/api/rules/{rule}/suppression-windows", body)

    def approve(self, admin, change, acknowledge=True):
        return admin.post(f"/api/changes/{change['id']}/review", {
            "decision": "approve",
            "evidence_digest": change["evidence_digest"],
            "acknowledge_detection_loss": acknowledge,
        })

    def test_active_window_is_reviewed_applied_counted_and_ended(self):
        analyst, admin, viewer = self.client("analyst"), self.client("admin"), self.client("viewer")
        analyst.post("/api/demo/simulate", {"scenario": "brute_force"})
        status, change, _ = self.propose(analyst)
        self.assertEqual(status, 201, change)
        self.assertEqual((change["kind"], change["target"], change["status"]),
                         ("rule_suppression_add", "brute_force_ip", "pending"))
        self.assertIn("brute_force", change["evaluation"]["after"]["missed"])
        self.assertGreaterEqual(change["evaluation"]["backtest"]["counts"]["open_alerts_lost"], 1)
        self.assertEqual(analyst.get("/api/rule-suppression-windows")[1], [])

        status, refused, _ = self.approve(admin, change, acknowledge=False)
        self.assertEqual(status, 400, refused)
        self.assertIn("acknowledge_detection_loss", refused["error"])
        status, reviewed, _ = self.approve(admin, change)
        self.assertEqual((status, reviewed["status"]), (200, "approved"))

        windows = viewer.get("/api/rule-suppression-windows")[1]
        self.assertEqual(len(windows), 1)
        window = windows[0]
        self.assertEqual((window["rule_id"], window["state"], window["active"]),
                         ("brute_force_ip", "active", True))
        self.assertEqual((window["proposed_by"], window["approved_by"], window["change_request_id"]),
                         ("analyst", "admin", change["id"]))

        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE alerts SET status = 'resolved'")
        sim = analyst.post("/api/demo/simulate", {"scenario": "brute_force"})[1]
        self.assertGreaterEqual(sim["detection"]["alerts_suppressed"], 1)
        self.assertEqual(analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1], [])

        path = f"/api/rule-suppression-windows/{window['id']}/end"
        self.assertEqual(viewer.post(path)[0], 403)
        status, ended, _ = admin.post(path)
        self.assertEqual((status, ended["state"], ended["active"], ended["ended_by"]),
                         (200, "ended", False, "admin"))
        self.assertEqual(admin.post(path)[0], 409)

        sim = analyst.post("/api/demo/simulate", {"scenario": "brute_force", "seed": 3})[1]
        self.assertEqual(sim["detection"]["alerts_suppressed"], 0)
        self.assertTrue(analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1])
        actions = [a["action"] for a in admin.get("/api/audit")[1]]
        self.assertIn("rule_suppression_window_added", actions)
        self.assertIn("rule_suppression_window_ended", actions)

    def test_sampled_rule_and_live_alert_losses_need_acknowledgement(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        base = utcnow() - timedelta(hours=2)
        events = [{"ts": iso(base + timedelta(seconds=30 * n)), "type": "web_request",
                   "src_ip": "203.0.113.9", "message": f"GET /cgi-bin/probe{n}"} for n in range(4)]
        self.assertEqual(analyst.post("/api/ingest", {"source": "web", "events": events})[0], 201)
        saved = analyst.post("/api/hunt/saved", {"name": "CGI probe burst", "query": WEB_QUERY})[1]
        body = {**definition(techniques=["T1190"]), "sample": GOOD_SAMPLE,
                "reason": "Review this sampled detection."}
        added = analyst.post(f"/api/hunt/saved/{saved['id']}/promote", body)[1]
        self.assertEqual(admin.post(f"/api/changes/{added['id']}/review", {
            "decision": "approve", "evidence_digest": added["evidence_digest"],
        })[0], 200)
        enabled = analyst.post(f"/api/rules/{RULE_ID}/proposals", {
            "enabled": True, "reason": "Enable the reviewed detection.",
        })[1]
        self.assertEqual(admin.post(f"/api/changes/{enabled['id']}/review", {
            "decision": "approve", "evidence_digest": enabled["evidence_digest"],
        })[0], 200)
        analyst.post("/api/detection/run")
        self.assertTrue(analyst.get(f"/api/alerts?rule_id={RULE_ID}&status=open")[1])

        status, change, _ = self.propose(analyst, rule=RULE_ID)
        self.assertEqual(status, 201, change)
        sample_name = f"search_sample:{RULE_ID}"
        self.assertIn(sample_name, change["evaluation"]["before"]["detected"])
        self.assertIn(sample_name, change["evaluation"]["after"]["missed"])
        self.assertGreaterEqual(change["evaluation"]["backtest"]["counts"]["open_alerts_lost"], 1)
        status, refused, _ = self.approve(admin, change, acknowledge=False)
        self.assertEqual(status, 400, refused)
        self.assertIn("acknowledge_detection_loss", refused["error"])

    def test_upcoming_and_expired_windows_do_not_apply_and_state_is_visible(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = self.propose(
            analyst,
            starts_at=iso(utcnow() + timedelta(hours=1)),
            expires_at=iso(utcnow() + timedelta(hours=2)),
        )[1]
        self.assertEqual(self.approve(admin, change)[0], 200)
        self.assertEqual(analyst.get("/api/rule-suppression-windows")[1][0]["state"], "upcoming")
        sim = analyst.post("/api/demo/simulate", {"scenario": "brute_force"})[1]
        self.assertEqual(sim["detection"]["alerts_suppressed"], 0)

        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE rule_suppression_windows SET starts_at = ?, expires_at = ?",
                       (iso(utcnow() - timedelta(hours=2)), iso(utcnow() - timedelta(hours=1))))
        listed = analyst.get("/api/rule-suppression-windows")[1][0]
        self.assertEqual((listed["state"], listed["active"]), ("expired", False))

    def test_validation_roles_and_schema_upgrade(self):
        analyst, viewer = self.client("analyst"), self.client("viewer")
        self.assertEqual(self.propose(viewer)[0], 403)
        self.assertEqual(self.client().get("/api/rule-suppression-windows")[0], 401)
        self.assertEqual(analyst.post("/api/rules/no_such_rule/suppression-windows", {
            "starts_at": iso(utcnow()), "expires_at": iso(utcnow() + timedelta(hours=1)),
            "reason": "A valid operational reason.",
        })[0], 404)
        bad_ranges = [
            ("not-a-time", iso(utcnow() + timedelta(hours=1))),
            (iso(utcnow() + timedelta(hours=2)), iso(utcnow() + timedelta(hours=1))),
            (iso(utcnow()), iso(utcnow() + timedelta(days=31))),
        ]
        for starts_at, expires_at in bad_ranges:
            with self.subTest(starts_at=starts_at, expires_at=expires_at):
                self.assertEqual(self.propose(analyst, starts_at=starts_at, expires_at=expires_at)[0], 400)
        self.assertEqual(self.propose(analyst, reason="no")[0], 400)
