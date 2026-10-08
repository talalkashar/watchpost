"""Rule backtesting: a proposed rule change replayed over stored events, and the review gate it feeds."""

import json
import unittest
from datetime import timedelta
from urllib.parse import quote

from watchpost import backtest, engine, improve
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.normalize import parse_payload

from .helpers import ServerTestCase

RULE = "brute_force_ip"  # threshold 10 failed logins from one IP within 300 s


def failures(ip, n, minutes_ago=10, user="alice"):
    start = utcnow().replace(microsecond=0) - timedelta(minutes=minutes_ago)
    return [{"ts": iso(start + timedelta(seconds=5 * i)), "type": "login_failed", "user": user, "src_ip": ip}
            for i in range(n)]


class BacktestTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def ingest(self, events, synthetic=False):
        normalized, rejections = parse_payload(json.dumps(events), "json", "auth01")
        self.assertEqual(rejections, [])
        return engine.ingest(self.conn, normalized, rejections, "auth01", "json", "test", synthetic)

    def run_bt(self, **params):
        return backtest.backtest(self.conn, RULE, {**self.current(), **params})

    def current(self):
        return improve.current_params(self.conn, include_disabled=True)[RULE]

    def keys(self, result):
        return {side: [x["group_key"] for x in result[side]] for side in ("kept", "new", "lost")}

    def test_kept_new_and_lost_are_classified_by_group_key(self):
        self.ingest(failures("198.51.100.1", 12) + failures("198.51.100.2", 6, 20) + failures("198.51.100.3", 25, 30))
        result = self.run_bt(threshold=5, ignore_ips=["198.51.100.1"])
        self.assertEqual(self.keys(result), {"kept": ["198.51.100.3"], "new": ["198.51.100.2"], "lost": ["198.51.100.1"]})
        self.assertEqual(result["counts"], {"kept": 1, "new": 1, "lost": 1, "open_alerts_lost": 1})
        new = result["new"][0]
        self.assertEqual((new["event_count"], new["findings"]), (6, 1))
        self.assertEqual(new["entities"], {"user": ["alice"], "src_ip": ["198.51.100.2"], "host": []})
        self.assertEqual(len(new["evidence_event_ids"]), backtest.EVIDENCE_IDS)
        self.assertLess(new["first_seen"], new["last_seen"])
        self.assertEqual(result["kept"][0]["event_count_today"], 25)
        self.assertEqual(result["events_scanned"], 43)
        self.assertEqual((result["capped"], result["synthetic"], result["window_days"]), (False, "none", 7))

    def test_identical_params_keep_everything(self):
        self.ingest(failures("198.51.100.1", 12) + failures("198.51.100.3", 25, 30))
        result = self.run_bt()
        self.assertEqual(self.keys(result), {"kept": ["198.51.100.1", "198.51.100.3"], "new": [], "lost": []})
        self.assertEqual(result["open_alerts_lost"], [])

    def test_lowering_a_threshold_produces_new_findings(self):
        self.ingest(failures("198.51.100.2", 6) + failures("198.51.100.4", 8, 20))
        self.assertEqual(self.keys(self.run_bt(threshold=6))["new"], ["198.51.100.2", "198.51.100.4"])  # newest first

    def test_raising_a_threshold_loses_the_open_alert_it_raised(self):
        self.ingest(failures("198.51.100.1", 12))
        alert = self.conn.execute("SELECT id FROM alerts WHERE rule_id = ?", (RULE,)).fetchone()["id"]
        result = self.run_bt(threshold=13)
        self.assertEqual(self.keys(result)["lost"], ["198.51.100.1"])
        self.assertEqual(result["lost"][0]["open_alert_ids"], [alert])
        self.assertEqual([a["id"] for a in result["open_alerts_lost"]], [alert])
        # Resolved, it is history: losing the finding is no longer losing an open alert.
        self.conn.execute("UPDATE alerts SET status = 'resolved'")
        self.assertEqual(self.run_bt(threshold=13)["counts"]["open_alerts_lost"], 0)

    def test_disabling_the_rule_loses_every_finding(self):
        self.ingest(failures("198.51.100.1", 12))
        result = backtest.backtest(self.conn, RULE, self.current(), running=(True, False))
        self.assertEqual(self.keys(result), {"kept": [], "new": [], "lost": ["198.51.100.1"]})

    def test_active_suppressions_apply_to_both_sides(self):
        self.ingest(failures("198.51.100.1", 12) + failures("198.51.100.3", 25, 30))
        for expires in (iso(utcnow() + timedelta(days=5)), iso(utcnow() - timedelta(days=1))):
            self.conn.execute(
                "INSERT INTO suppressions(rule_id, group_key, reason, expires_at, proposed_by, approved_by, created_at)"
                " VALUES (?, '198.51.100.1', 'scanner', ?, 'analyst', 'admin', ?)", (RULE, expires, iso(utcnow())))
        result = self.run_bt(threshold=5)
        self.assertEqual(self.keys(result), {"kept": ["198.51.100.3"], "new": [], "lost": []})
        self.assertEqual(result["suppressed"], {"today": 1, "proposed": 1})  # the expired one skips nothing

    def test_lookback_is_capped_by_event_count(self):
        self.ingest(failures("198.51.100.1", 12, 3 * 1440) + failures("198.51.100.2", 12, 1500)
                    + failures("198.51.100.3", 12))
        full = self.run_bt()
        self.assertEqual((full["capped"], full["events_scanned"], len(full["kept"])), (False, 36, 3))
        capped = backtest.backtest(self.conn, RULE, self.current(), max_events=15)
        self.assertTrue(capped["capped"])
        self.assertLessEqual(capped["events_scanned"], 15)
        self.assertGreater(capped["window"]["start"], full["window"]["start"])
        self.assertEqual(self.keys(capped)["kept"], ["198.51.100.3"])
        # The window itself: one day back from the newest stored event leaves the older bursts out.
        day = backtest.backtest(self.conn, RULE, self.current(), window_days=1)
        self.assertEqual(self.keys(day)["kept"], ["198.51.100.3"])
        self.assertEqual(backtest.backtest(self.conn, RULE, self.current(), window_days=999)["window_days"],
                         backtest.MAX_WINDOW_DAYS)

    def test_synthetic_share_is_reported(self):
        self.assertEqual(self.run_bt()["window"], None)  # nothing stored: an empty, honest result
        self.ingest(failures("198.51.100.1", 12), synthetic=True)
        self.assertEqual(self.run_bt()["synthetic"], "all")
        self.ingest(failures("198.51.100.2", 3))
        result = self.run_bt()
        self.assertEqual((result["synthetic"], result["synthetic_events"]), ("some", 12))

    def test_evidence_digest_ignores_unrelated_events_and_changes_with_the_findings(self):
        self.ingest(failures("198.51.100.1", 12))
        payload = {"params": {"threshold": 13}}
        first = improve._evidence(self.conn, "rule_update", RULE, payload, "analyst")
        self.assertEqual(first["backtest"]["counts"]["lost"], 1)
        digest = improve.evidence_digest(first)
        self.assertEqual(improve.evidence_digest(improve._evidence(self.conn, "rule_update", RULE, payload, "analyst")),
                         digest)
        # An unrelated event moves the scan window but not the findings: the reviewer's approval still holds.
        self.ingest([{"ts": iso(utcnow()), "type": "login_success", "user": "bob", "src_ip": "10.0.0.9"}])
        self.assertEqual(improve.evidence_digest(improve._evidence(self.conn, "rule_update", RULE, payload,
                                                                   "analyst")), digest)
        # A new finding the proposal would lose changes the evidence, so the reviewer must look again.
        self.ingest(failures("198.51.100.3", 12))
        self.assertNotEqual(improve.evidence_digest(improve._evidence(self.conn, "rule_update", RULE, payload,
                                                                      "analyst")), digest)

    def test_approval_that_loses_an_open_alert_needs_an_acknowledgement(self):
        self.ingest(failures("198.51.100.1", 12))
        alert = self.conn.execute("SELECT id FROM alerts WHERE rule_id = ?", (RULE,)).fetchone()["id"]
        change = improve.propose_change(self.conn, "rule_update", RULE, {"params": {"threshold": 13}},
                                        "too noisy for the helpdesk", "analyst")
        self.assertEqual(change["evaluation"]["after"]["missed"], [])  # the labeled scenarios see no loss
        for ack in (False, "yes"):
            with self.assertRaises(improve.ChangeError) as caught:
                improve.review_change(self.conn, change["id"], "approve", "admin", digest=change["evidence_digest"],
                                      acknowledge_detection_loss=ack)
            self.assertIn(f"#{alert}", str(caught.exception))
            self.assertIn("acknowledge_detection_loss", str(caught.exception))
        self.assertEqual(improve.get_change(self.conn, change["id"])["status"], "pending")
        done = improve.review_change(self.conn, change["id"], "approve", "admin", digest=change["evidence_digest"],
                                     acknowledge_detection_loss=True)
        self.assertEqual(done["status"], "approved")
        entry = self.conn.execute("SELECT detail FROM audit_log WHERE action = 'change_approved'").fetchone()
        self.assertEqual(json.loads(entry["detail"])["acknowledged_open_alerts_lost"], [alert])

    def test_a_change_that_keeps_open_alerts_needs_no_acknowledgement(self):
        self.ingest(failures("198.51.100.1", 12))
        change = improve.propose_change(self.conn, "rule_update", RULE, {"params": {"threshold": 8}},
                                        "catch slower guessing", "analyst")
        done = improve.review_change(self.conn, change["id"], "approve", "admin", digest=change["evidence_digest"])
        self.assertEqual(done["status"], "approved")


class BacktestApiTests(ServerTestCase):
    def url(self, params, rule=RULE, extra=""):
        return f"/api/rules/{rule}/backtest?params={quote(params if isinstance(params, str) else json.dumps(params))}{extra}"

    def test_preview_roles_validation_and_evidence(self):
        analyst, viewer = self.client("analyst"), self.client("viewer")
        status, data, _ = analyst.post("/api/ingest", {"source": "auth01", "events": failures("198.51.100.1", 12)})
        self.assertEqual(status, 201, data)
        status, result, _ = analyst.get(self.url({"threshold": 13}))
        self.assertEqual(status, 200, result)
        self.assertEqual([x["group_key"] for x in result["lost"]], ["198.51.100.1"])
        self.assertEqual(result["counts"]["open_alerts_lost"], 1)
        # A preview changes nothing.
        self.assertEqual(analyst.get("/api/changes")[1], [])
        self.assertEqual({r["id"]: r for r in analyst.get("/api/rules")[1]}[RULE]["version"], 1)

        self.assertEqual(viewer.get(self.url({"threshold": 13}))[0], 403)
        admin = self.client("admin")  # each account has its own preview budget; these spend the admin's
        for params, code in (("{not json", 400), ("[1]", 400), ({"threshold": "x"}, 400), ({"threshold": 1}, 400),
                             ({"nope": 1}, 400), ({"enabled": False}, 400)):
            with self.subTest(params=params):
                status, data, _ = admin.get(self.url(params))
                self.assertEqual(status, code, data)
        self.assertEqual(analyst.get(self.url({}, rule="no_such_rule"))[0], 404)
        for days in ("0", "31", "x"):
            self.assertEqual(analyst.get(self.url({}, extra=f"&days={days}"))[0], 400)
        self.assertEqual(analyst.get(self.url({}, extra="&days=2"))[1]["window_days"], 2)

        # The viewer reads the backtest inside the review evidence.
        status, change, _ = analyst.post(f"/api/rules/{RULE}/proposals",
                                         {"params": {"threshold": 13}, "reason": "quieter on the helpdesk"})
        self.assertEqual(status, 201, change)
        listed = viewer.get("/api/changes")[1][0]
        self.assertEqual(listed["evaluation"]["backtest"]["counts"],
                         {"kept": 0, "new": 0, "lost": 1, "open_alerts_lost": 1})

    def test_previews_are_rate_limited_per_account(self):
        admin = self.client("admin")
        codes = [admin.get(self.url({}))[0] for _ in range(22)]
        self.assertEqual(codes[:20], [200] * 20)
        self.assertEqual(codes[-1], 429)
        self.assertEqual(self.client("analyst").get(self.url({}))[0], 200)  # another account has its own bucket

    def test_rule_proposals_and_approvals_spend_the_backtest_quota(self):
        # Proposing a rule change and approving one both run a backtest, so they draw on the same bucket.
        analyst, admin = self.client("analyst"), self.client("admin")
        codes = [analyst.post(f"/api/rules/{RULE}/proposals", {"params": {"threshold": 13 + i}, "reason": "tune it down"})[0]
                 for i in range(22)]
        self.assertEqual(codes[:20], [201] * 20)
        self.assertEqual(codes[-1], 429)
        for _ in range(20):
            admin.get(self.url({}))
        status, data, _ = admin.post("/api/changes/1/review", {"decision": "approve", "evidence_digest": "x"})
        self.assertEqual(status, 429, data)
        # Rejecting runs no backtest and is not limited.
        self.assertEqual(admin.post("/api/changes/1/review", {"decision": "reject", "note": "no"})[0], 200)
