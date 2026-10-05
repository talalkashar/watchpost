"""Watchpost 3.0 detection quality: benign look-alikes, baseline-aware exfil, exceptions, shadow IT."""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from watchpost import engine, improve, queries, rules, simulate, storyline
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.normalize import classify_web_request, parse_payload

from .helpers import ServerTestCase

BASE = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)  # a Tuesday
DEFAULTS = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}


def make(events):
    return [{"id": i, **e} for i, e in enumerate(events, start=1)]


def ev(sec, event_type, user=None, ip="10.0.5.10", **extra):
    return {"ts": iso(BASE + timedelta(seconds=sec)), "event_type": event_type, "user": user, "src_ip": ip, **extra}


class ScenarioTests(unittest.TestCase):
    def test_lookalikes_are_labeled_benign_and_name_a_real_rule(self):
        lookalikes = {n: s for n, s in simulate.SCENARIOS.items() if "lookalike_of" in s}
        self.assertGreaterEqual(len(lookalikes), 10)
        for name, spec in lookalikes.items():
            with self.subTest(scenario=name):
                self.assertFalse(spec["malicious"])
                self.assertEqual(spec["expected"], {})
                self.assertIn(spec["lookalike_of"], rules.RULE_FUNCTIONS)

    def test_every_rule_has_a_lookalike(self):
        covered = {s["lookalike_of"] for s in simulate.SCENARIOS.values() if "lookalike_of" in s}
        self.assertEqual(covered, set(rules.RULE_FUNCTIONS))

    def test_demo_dataset_is_unchanged_by_the_lookalikes(self):
        # The original scanner passes stay in the demo; the 3.0 look-alikes are evaluated, not loaded.
        self.assertEqual(list(simulate.build(seed=7)), simulate.DEMO_SCENARIOS)
        self.assertIn("noisy_scanner", simulate.DEMO_SCENARIOS)
        self.assertNotIn("nightly_backup", simulate.DEMO_SCENARIOS)
        self.assertEqual(list(simulate.build(["nightly_backup"])), ["nightly_backup"])

    def test_synthetic_labeling_conventions_hold(self):
        for name, events in simulate.build(list(simulate.SCENARIOS)).items():
            for e in events:
                with self.subTest(scenario=name):
                    self.assertIn("SYNTHETIC", e["message"])
                    self.assertEqual(e["source"].split(":")[0], "demo")
                    for ip in (e["src_ip"], e["dest_ip"]):
                        self.assertTrue(ip.startswith(("10.", "172.16.", "192.168.", "192.0.2.", "198.51.100.",
                                                        "203.0.113.")), ip)

    def test_uptime_monitor_event_types_match_the_web_log_classifier(self):
        for e in simulate.build(["uptime_monitor"])["uptime_monitor"]:
            path = e["message"].split()[1]
            self.assertEqual(e["event_type"], classify_web_request(path, 200), path)


class EvaluateLookalikeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = improve.evaluate(DEFAULTS)

    def test_each_rule_lists_lookalikes_tested_and_fired(self):
        for rule_id, r in self.result["rules"].items():
            with self.subTest(rule=rule_id):
                self.assertTrue(r["lookalikes"])
                self.assertLessEqual(set(r["lookalikes_fired"]), set(r["lookalikes"]))
                self.assertLessEqual(set(r["lookalikes_fired"]), set(r["false_positives"]))
                self.assertEqual(r["recall"], 1.0)
        bf = self.result["rules"]["brute_force_ip"]
        self.assertEqual(bf["lookalikes"], ["noisy_scanner", "noisy_scanner_repeat"])
        self.assertEqual(bf["lookalikes_fired"], ["noisy_scanner", "noisy_scanner_repeat"])

    def test_nightly_backup_is_quiet_and_exfiltration_still_fires(self):
        exfil = self.result["rules"]["data_exfil_volume"]
        self.assertEqual(exfil["lookalikes"], ["nightly_backup"])
        self.assertEqual(exfil["lookalikes_fired"], [])
        self.assertEqual(exfil["fp"], 0)
        self.assertEqual(exfil["detected"], ["exfiltration"])

    def test_without_a_baseline_the_backup_is_noise(self):
        flat = rules.validate_params("data_exfil_volume", {"baseline_multiplier": 0})
        exfil = improve.evaluate({"data_exfil_volume": flat})["rules"]["data_exfil_volume"]
        self.assertEqual(exfil["lookalikes_fired"], ["nightly_backup"])
        self.assertEqual(exfil["detected"], ["exfiltration"])

    def test_noise_is_reported_not_hidden(self):
        # No principled fix exists for these, so they stay noisy and the lab says so.
        fired = {rid: r["lookalikes_fired"] for rid, r in self.result["rules"].items()}
        self.assertEqual(fired["password_spray"], ["password_expiry_nat"])
        self.assertEqual(fired["off_hours_privileged_login"], ["oncall_admin"])
        self.assertEqual(fired["firewall_port_sweep"], ["authorized_port_scan"])
        self.assertEqual(fired["success_after_failures"], [])
        self.assertIn("stale_password_device", self.result["rules"]["success_after_failures"]["false_positives"])

    def test_suppressions_drop_matching_findings_and_are_counted(self):
        r = improve.evaluate({"brute_force_ip": DEFAULTS["brute_force_ip"]},
                             suppressions={("brute_force_ip", "10.0.50.5")})["rules"]["brute_force_ip"]
        self.assertEqual((r["fp"], r["lookalikes_fired"], r["suppressed"]), (0, [], 2))
        self.assertEqual(r["recall"], 1.0)
        # Suppressing the attacker's key hides a real attack, and the evaluation shows it.
        r = improve.evaluate({"brute_force_ip": DEFAULTS["brute_force_ip"]},
                             suppressions={("brute_force_ip", "203.0.113.45")})["rules"]["brute_force_ip"]
        self.assertEqual(r["missed"], ["brute_force"])


class BaselineExfilTests(unittest.TestCase):
    def nightly(self, nights, per_event):
        return [ev(-86400 * back + i * 60, "fw_allow", bytes=per_event) for back in nights for i in range(5)]

    def test_comparable_history_does_not_alert(self):
        p = rules.validate_params("data_exfil_volume", {})
        self.assertEqual(p["baseline_multiplier"], 3)
        events = make(self.nightly((3, 2, 1, 0), 400_000_000))
        found = rules.data_exfil_volume(events, p)
        # Only the first night, which has no history of its own yet, stands out.
        self.assertEqual([f["first_seen"] for f in found], [iso(BASE - timedelta(days=3))])
        self.assertIn("no earlier transfers", found[0]["explanation"])

    def test_jump_above_own_baseline_alerts_and_explains_the_ratio(self):
        p = rules.validate_params("data_exfil_volume", {})
        events = make(self.nightly((3, 2, 1), 40_000_000) + self.nightly((0,), 400_000_000))
        found = rules.data_exfil_volume(events, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["first_seen"], iso(BASE))
        self.assertIn("200.0 MB", found[0]["explanation"])  # the baseline
        self.assertIn("10.0x", found[0]["explanation"])     # the ratio
        self.assertIn("3x", found[0]["explanation"])        # the multiplier

    def test_history_outside_the_window_is_not_a_baseline(self):
        p = rules.validate_params("data_exfil_volume", {"history_seconds": 86400})
        events = make(self.nightly((3, 0), 400_000_000))
        self.assertEqual(len(rules.data_exfil_volume(events, p)), 2)

    def test_another_principals_history_is_not_a_baseline(self):
        p = rules.validate_params("data_exfil_volume", {})
        events = make(self.nightly((1,), 400_000_000)
                      + [ev(i * 60, "fw_allow", ip="10.0.9.99", bytes=400_000_000) for i in range(5)])
        self.assertEqual({f["group_key"] for f in rules.data_exfil_volume(events, p)}, {"10.0.5.10", "10.0.9.99"})

    def test_param_validation(self):
        for bad in ({"baseline_multiplier": -1}, {"baseline_multiplier": "3"}, {"history_seconds": 5}):
            with self.assertRaises(rules.RuleConfigError):
                rules.validate_params("data_exfil_volume", bad)


class FlaggedHistoryTests(unittest.TestCase):
    """History the engine already alerted on, and nobody cleared, is not a baseline."""

    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def ingest(self, events, source="demo:test"):
        normalized, rejections = parse_payload(__import__("json").dumps(events), "json", source)
        self.assertEqual(rejections, [])
        return engine.ingest(self.conn, normalized, rejections, source, "json", "test", synthetic=True)["detection"]

    def exfil_alerts(self, since):
        """{group_key: alert ids} of exfil alerts with evidence at or after `since`."""
        found = {}
        for r in self.conn.execute(
                "SELECT DISTINCT a.id, a.group_key FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id"
                " JOIN events e ON e.id = ae.event_id WHERE a.rule_id = 'data_exfil_volume' AND e.ts >= ?", (since,)):
            found.setdefault(r["group_key"], set()).add(r["id"])
        return found

    def night(self, days_ago):
        start = utcnow().replace(microsecond=0) - timedelta(days=days_ago, hours=1)
        return [{"ts": iso(start + timedelta(seconds=i * 150)), "event_type": "fw_allow", "src_ip": "10.0.5.10",
                 "host": "fw01", "bytes": 400_000_000, "message": "[SYNTHETIC] firewall allow (nightly backup)"}
                for i in range(12)], iso(start)

    def test_rule_ignores_flagged_history_and_multiplier_zero_still_disables_the_baseline(self):
        p = rules.validate_params("data_exfil_volume", {})
        nightly = lambda back: [ev(-86400 * back + i * 60, "fw_allow", bytes=400_000_000) for i in range(5)]
        events = make(nightly(1) + nightly(0))
        self.assertEqual([f["first_seen"] for f in rules.data_exfil_volume(events, p)], [iso(BASE - timedelta(days=1))])
        for e in events[:5]:
            e["alerted"] = True
        found = rules.data_exfil_volume(events, p)
        self.assertEqual(len(found), 2)
        self.assertIn("already flagged", found[1]["explanation"])
        off = rules.validate_params("data_exfil_volume", {"baseline_multiplier": 0})
        self.assertEqual(len(rules.data_exfil_volume(make(nightly(1) + nightly(0)), off)), 2)

    def test_storyline_replayed_into_one_database_alerts_on_exfil_every_time(self):
        timeline = storyline.build(7, 1.0)
        first = utcnow().replace(microsecond=0) - timedelta(hours=50)
        for start in (first, first + timedelta(hours=2), first + timedelta(days=2)):
            batches = {}
            for offset, event, _ in timeline:  # shipped in story-time buckets, as the runner does
                batches.setdefault(int(offset // storyline.BATCH_SECONDS), []).append(
                    dict(event, ts=iso(start + timedelta(seconds=offset))))
            for key in sorted(batches):
                self.ingest(batches[key], storyline.SOURCE)
            with self.subTest(start=iso(start)):
                alerts = self.exfil_alerts(iso(start))
                self.assertEqual(set(alerts), {storyline.ROGUE_PRINCIPAL, "10.0.0.10"})
                ids = sorted(set().union(*alerts.values()))
                stages = [__import__("json").loads(r["stages"]) for r in self.conn.execute(
                    "SELECT DISTINCT i.id, i.stages FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id"
                    f" WHERE ia.alert_id IN ({','.join('?' for _ in ids)})", ids)]
                self.assertTrue(any("Exfiltration" in s for s in stages), stages)

    def test_exfiltration_scenario_replayed_a_day_later_alerts_again(self):
        for now in (utcnow() - timedelta(days=1), utcnow()):
            events = simulate.build(["exfiltration"], now=now)["exfiltration"]
            self.ingest(events)
            with self.subTest(day=str(simulate.demo_day(now))):
                self.assertIn("svc-deploy-tmp", self.exfil_alerts(min(e["ts"] for e in events)))

    def test_nightly_backup_alerts_until_an_analyst_closes_one_as_benign(self):
        (first, t1), (second, t2), (third, t3), (fourth, t4) = (self.night(d) for d in (3, 2, 1, 0))
        self.assertEqual(self.ingest(first)["alerts_created"], 1)   # no baseline yet
        # Left open, the flagged first night is no baseline, so the second night alerts as well.
        self.assertEqual(self.ingest(second)["alerts_created"], 1)
        first_id = min(self.exfil_alerts(t1)["10.0.5.10"])
        # Confirmed as a true positive it is still no baseline.
        queries.update_status(self.conn, first_id, "analyst", "resolved", disposition="true_positive")
        self.assertEqual(self.ingest(third)["alerts_created"], 1)
        # Closed as benign, the first night is this job's normal: the next night stays quiet.
        self.conn.execute("UPDATE alerts SET disposition = 'benign' WHERE id = ?", (first_id,))
        self.conn.commit()
        run = self.ingest(fourth)
        self.assertEqual((run["alerts_created"], run["alerts_updated"]), (0, 0))
        self.assertEqual(self.exfil_alerts(t4), {})


class ShadowItTests(unittest.TestCase):
    def cloud(self, sec, service, user="judy", event_type="cloud_data_access"):
        return ev(sec, event_type, user, "10.0.1.40", message=f"UploadFile on {service} (x)")

    def test_unsanctioned_service_fires_once_per_user_and_service(self):
        p = rules.validate_params("unsanctioned_cloud_service", {})
        events = make([self.cloud(i * 30, "personal-drive.example") for i in range(4)]
                      + [self.cloud(500, "Paste.Example", event_type="cloud_api_call")])
        found = rules.unsanctioned_cloud_service(events, p)
        self.assertEqual(sorted(f["group_key"] for f in found), ["judy|paste.example", "judy|personal-drive.example"])
        big = next(f for f in found if f["group_key"].endswith("personal-drive.example"))
        self.assertEqual(len(big["event_ids"]), 4)
        self.assertIn("not on the sanctioned list", big["explanation"])

    def test_sanctioned_services_and_their_subdomains_are_quiet(self):
        p = rules.validate_params("unsanctioned_cloud_service", {})
        events = make([self.cloud(0, "s3.amazonaws.com"), self.cloud(10, "corp-drive.example"),
                       self.cloud(20, "eu.corp-drive.example"),
                       # No service in the message: never guessed.
                       ev(30, "cloud_api_call", "judy", "10.0.1.40", message="something happened"),
                       # Not a subdomain, only a similar suffix.
                       self.cloud(40, "notcorp-drive.example")])
        self.assertEqual([f["group_key"] for f in rules.unsanctioned_cloud_service(events, p)],
                         ["judy|notcorp-drive.example"])

    def test_trailing_text_naming_a_sanctioned_service_does_not_hide_the_real_one(self):
        # The service is the one right after the action; a resource name after it must not replace it.
        p = rules.validate_params("unsanctioned_cloud_service", {})
        events = make([ev(0, "cloud_data_access", "judy", "10.0.1.40",
                          message="UploadFile on personal-drive.example (copy on corp-drive.example)")])
        self.assertEqual([f["group_key"] for f in rules.unsanctioned_cloud_service(events, p)],
                         ["judy|personal-drive.example"])

    def test_sanctioned_list_is_a_reviewable_param(self):
        p = rules.validate_params("unsanctioned_cloud_service",
                                  {"sanctioned_services": ["amazonaws.com", "personal-drive.example"]})
        self.assertEqual(rules.unsanctioned_cloud_service(make([self.cloud(0, "personal-drive.example")]), p), [])
        with self.assertRaises(rules.RuleConfigError):
            rules.validate_params("unsanctioned_cloud_service", {"sanctioned_services": []})

    def test_mapped_to_exfiltration_over_web_service(self):
        rule = next(r for r in rules.DEFAULT_RULES if r["id"] == "unsanctioned_cloud_service")
        self.assertEqual([(t["id"], t["tactic"]) for t in rule["techniques"]], [("T1567", "Exfiltration")])

    def test_cloudtrail_style_json_reaches_the_rule(self):
        record = {"eventTime": iso(utcnow() - timedelta(minutes=5)), "eventName": "PutObject",
                  "eventSource": "storage.unapproved-cloud.example", "sourceIPAddress": "10.0.1.40",
                  "userIdentity": {"userName": "judy"}}
        events, rejections = parse_payload(__import__("json").dumps([record]), "json", "cloudtrail")
        self.assertEqual(rejections, [])
        found = rules.unsanctioned_cloud_service(make(events), rules.validate_params("unsanctioned_cloud_service", {}))
        self.assertEqual([f["group_key"] for f in found], ["judy|storage.unapproved-cloud.example"])


class SuppressionApiTests(ServerTestCase):
    def propose(self, client, rule="brute_force_ip", **overrides):
        body = {"group_key": "10.0.50.5", "days": 30,
                "reason": "Authorized internal vulnerability scanner; ticket SEC-142.", **overrides}
        return client.post(f"/api/rules/{rule}/suppressions", body)

    def test_scanner_exception_is_reviewed_applied_counted_and_expires(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        brute = lambda: [a["group_key"] for a in analyst.get("/api/alerts?rule_id=brute_force_ip&status=open")[1]]
        sim = analyst.post("/api/demo/simulate", {"scenario": "noisy_scanner"})[1]
        self.assertEqual(sim["detection"]["alerts_suppressed"], 0)
        self.assertEqual(brute(), ["10.0.50.5"])

        status, change, _ = self.propose(analyst)
        self.assertEqual(status, 201, change)
        self.assertEqual((change["kind"], change["target"], change["status"]),
                         ("suppression_add", "brute_force_ip", "pending"))
        self.assertEqual(change["payload"], {"days": 30, "group_key": "10.0.50.5"})
        # Scored against the labeled scenarios before review: noise goes, the attack is still caught.
        self.assertEqual((change["evaluation"]["before"]["fp"], change["evaluation"]["after"]["fp"]), (2, 0))
        self.assertEqual(change["evaluation"]["after"]["missed"], [])

        # Nothing is suppressed until a different person with the admin role approves.
        self.assertEqual(analyst.get("/api/suppressions")[1], [])
        self.assertEqual(analyst.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 403)
        status, reviewed, _ = admin.post(f"/api/changes/{change['id']}/review",
                                         {"decision": "approve", "note": "Confirmed with the scan owner."})
        self.assertEqual((status, reviewed["status"]), (200, "approved"))

        listed = self.client("viewer").get("/api/suppressions")[1]
        self.assertEqual(len(listed), 1)
        sup = listed[0]
        self.assertEqual((sup["rule_id"], sup["group_key"], sup["active"]), ("brute_force_ip", "10.0.50.5", True))
        self.assertEqual((sup["proposed_by"], sup["approved_by"], sup["change_request_id"]),
                         ("analyst", "admin", change["id"]))
        self.assertGreater(sup["expires_at"], iso(utcnow() + timedelta(days=29)))
        self.assertLess(sup["expires_at"], iso(utcnow() + timedelta(days=31)))

        # The scanner's next pass makes no alert and the run says why; a real attacker still alerts.
        # (The exception is for one rule and one key: account_repeated_failures on svc_scan is untouched.)
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE alerts SET status = 'resolved'")
        sim = analyst.post("/api/demo/simulate", {"scenario": "noisy_scanner_repeat"})[1]
        self.assertGreaterEqual(sim["detection"]["alerts_suppressed"], 1)
        self.assertEqual(brute(), [])
        self.assertEqual(len(analyst.get("/api/alerts?rule_id=account_repeated_failures&status=open")[1]), 1)
        analyst.post("/api/demo/simulate", {"scenario": "brute_force"})
        self.assertEqual(brute(), ["203.0.113.45"])
        runs = analyst.get("/api/health/details")[1]["recent_detection_runs"]
        self.assertEqual(runs[1]["alerts_suppressed"], sim["detection"]["alerts_suppressed"])
        # The rule itself was not edited.
        rule = {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual((rule["version"], rule["params"]["ignore_ips"]), (1, []))

        actions = [a["action"] for a in admin.get("/api/audit")[1]]
        for action in ("change_proposed", "suppression_added", "change_approved"):
            self.assertIn(action, actions)

        # Once expired it stops applying, and is still listed as history.
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE suppressions SET expires_at = ?", (iso(utcnow() - timedelta(minutes=1)),))
            db.execute("UPDATE alerts SET status = 'resolved'")
        self.assertFalse(analyst.get("/api/suppressions")[1][0]["active"])
        sim = analyst.post("/api/demo/simulate", {"scenario": "noisy_scanner", "seed": 3})[1]
        self.assertEqual(sim["detection"]["alerts_suppressed"], 0)
        # The pass that was skipped while the exception was active surfaces again on the rescan.
        self.assertEqual(set(brute()), {"10.0.50.5"})

    def test_validation_and_roles(self):
        analyst, admin, viewer = self.client("analyst"), self.client("admin"), self.client("viewer")
        self.assertEqual(self.propose(viewer)[0], 403)
        self.assertEqual(self.client().get("/api/suppressions")[0], 401)
        self.assertEqual(self.propose(analyst, rule="no_such_rule")[0], 404)
        for bad in ({"days": 0}, {"days": 91}, {"days": "30"}, {"days": True}, {"group_key": ""},
                    {"group_key": "x" * 300}, {"group_key": 5}, {"reason": "no"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.propose(analyst, **bad)[0], 400)
        # A rejected proposal suppresses nothing.
        change = self.propose(analyst)[1]
        self.assertEqual(admin.post(f"/api/changes/{change['id']}/review", {"decision": "reject"})[1]["status"],
                         "rejected")
        self.assertEqual(analyst.get("/api/suppressions")[1], [])
        # An admin cannot approve their own exception.
        own = self.propose(admin)[1]
        self.assertEqual(admin.post(f"/api/changes/{own['id']}/review", {"decision": "approve"})[0], 403)


class EngineSuppressionTests(unittest.TestCase):
    def test_existing_database_gains_the_suppression_schema(self):
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        conn.execute("DROP TABLE suppressions")
        conn.execute("ALTER TABLE detection_runs DROP COLUMN alerts_suppressed")
        init_schema(conn)
        engine.seed_rules(conn)
        self.assertEqual(engine.run_detection(conn)["alerts_suppressed"], 0)
        self.assertEqual(improve.list_suppressions(conn), [])


class NoiseLabApiTests(ServerTestCase):
    def test_one_honest_row_per_rule(self):
        viewer = self.client("viewer")
        status, lab, _ = viewer.get("/api/noise-lab")
        self.assertEqual(status, 200)
        self.assertEqual(self.client().get("/api/noise-lab")[0], 401)
        rows = {r["rule_id"]: r for r in lab["rules"]}
        self.assertEqual(set(rows), set(rules.RULE_FUNCTIONS))
        for row in rows.values():
            with self.subTest(rule=row["rule_id"]):
                self.assertEqual(set(row) >= {"name", "recall", "precision", "lookalikes_tested", "lookalikes_fired",
                                              "other_benign_fired", "verdict", "summary"}, True)
                self.assertIn(row["verdict"], ("quiet", "noisy"))
                self.assertEqual(row["verdict"] == "noisy",
                                 bool(row["lookalikes_fired"] or row["other_benign_fired"]))
        self.assertEqual(rows["data_exfil_volume"]["verdict"], "quiet")
        self.assertEqual(rows["brute_force_ip"]["verdict"], "noisy")
        self.assertEqual(rows["success_after_failures"]["other_benign_fired"], ["stale_password_device"])
        self.assertIn("password_expiry_nat", rows["password_spray"]["summary"])
        names = {s["name"]: s for s in lab["scenarios"]}
        self.assertEqual(names["nightly_backup"]["lookalike_of"], "data_exfil_volume")
        self.assertEqual(lab["summary"], {"rules": len(rows), "noisy": sum(r["verdict"] == "noisy" for r in rows.values()),
                                          "lookalikes": sum("lookalike_of" in s for s in simulate.SCENARIOS.values())})

    def test_an_approved_exception_shows_up_in_the_lab(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = analyst.post("/api/rules/brute_force_ip/suppressions",
                              {"group_key": "10.0.50.5", "days": 7, "reason": "Authorized scanner."})[1]
        admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})
        row = {r["rule_id"]: r for r in analyst.get("/api/noise-lab")[1]["rules"]}["brute_force_ip"]
        self.assertEqual((row["verdict"], row["lookalikes_fired"], row["suppressed"]), ("quiet", [], 2))
        self.assertIn("exception", row["summary"])

    def test_a_disabled_rule_is_a_blind_spot_not_a_quiet_rule(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = analyst.post("/api/rules/web_scanner/proposals", {"enabled": False, "reason": "testing the lab"})[1]
        admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})
        row = {r["rule_id"]: r for r in analyst.get("/api/noise-lab")[1]["rules"]}["web_scanner"]
        self.assertEqual((row["enabled"], row["verdict"]), (False, "disabled"))


if __name__ == "__main__":
    unittest.main()
