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

    def test_without_an_exception_the_backup_is_noise_and_exfiltration_fires(self):
        exfil = self.result["rules"]["data_exfil_volume"]
        self.assertEqual(exfil["lookalikes"], ["nightly_backup"])
        self.assertEqual(exfil["lookalikes_fired"], ["nightly_backup"])
        self.assertEqual(exfil["detected"], ["exfiltration"])

    def test_an_exception_for_the_backup_principal_turns_on_its_baseline(self):
        params = {"data_exfil_volume": DEFAULTS["data_exfil_volume"]}
        exfil = improve.evaluate(params, suppressions={("data_exfil_volume", "10.0.5.10")})["rules"]["data_exfil_volume"]
        self.assertEqual((exfil["lookalikes_fired"], exfil["fp"], exfil["detected"]), ([], 0, ["exfiltration"]))
        self.assertEqual(exfil["suppressed"], 0)  # nothing is skipped: the rule itself stays quiet
        # An exception for the attacker's principal does not skip its findings either.
        exfil = improve.evaluate(params, suppressions={("data_exfil_volume", "svc-deploy-tmp")})["rules"]["data_exfil_volume"]
        self.assertEqual((exfil["missed"], exfil["suppressed"]), ([], 0))
        # baseline_multiplier 0 keeps the rule flat even with the exception.
        flat = {"data_exfil_volume": rules.validate_params("data_exfil_volume", {"baseline_multiplier": 0})}
        exfil = improve.evaluate(flat, suppressions={("data_exfil_volume", "10.0.5.10")})["rules"]["data_exfil_volume"]
        self.assertEqual(exfil["lookalikes_fired"], ["nightly_backup"])

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


def exfil_params(principals=(), **overrides):
    """Params as the engine hands them to the rule: saved params plus the excepted principals."""
    return rules.exception_params("data_exfil_volume", rules.validate_params("data_exfil_volume", overrides),
                                  {("data_exfil_volume", p) for p in principals})


class BaselineExfilTests(unittest.TestCase):
    """The baseline applies only to principals with an approved tuning exception."""

    def nightly(self, nights, per_event):
        return [ev(-86400 * back + i * 60, "fw_allow", bytes=per_event) for back in nights for i in range(5)]

    def test_sub_threshold_priming_does_not_hide_a_burst_without_an_exception(self):
        # 0.9 GB a night never alerts; 2.6 GB is under 3x that, and must alert on the flat threshold.
        events = make(self.nightly((3, 2, 1), 180_000_000) + self.nightly((0,), 520_000_000))
        found = rules.data_exfil_volume(events, exfil_params())
        self.assertEqual([f["first_seen"] for f in found], [iso(BASE)])
        self.assertIn("Flat thresholds", found[0]["explanation"])
        self.assertNotIn("Baseline mode", found[0]["explanation"])

    def test_without_an_exception_history_never_quiets_the_rule(self):
        events = make(self.nightly((3, 2, 1, 0), 400_000_000))
        self.assertEqual(len(rules.data_exfil_volume(events, exfil_params())), 4)
        # The saved params alone (no engine-supplied principals) behave the same.
        self.assertEqual(len(rules.data_exfil_volume(events, rules.validate_params("data_exfil_volume", {}))), 4)
        # Someone else's exception changes nothing for this principal.
        self.assertEqual(len(rules.data_exfil_volume(events, exfil_params(["10.0.9.99"]))), 4)

    def test_an_exception_turns_on_the_baseline_for_that_principal(self):
        events = make(self.nightly((3, 2, 1, 0), 400_000_000))
        found = rules.data_exfil_volume(events, exfil_params(["10.0.5.10"]))
        # Only the first night, which has no history of its own yet, stands out.
        self.assertEqual([f["first_seen"] for f in found], [iso(BASE - timedelta(days=3))])
        self.assertIn("Baseline mode", found[0]["explanation"])
        self.assertIn("no earlier transfers", found[0]["explanation"])

    def test_excepted_principal_bursting_over_its_baseline_alerts_and_explains_the_ratio(self):
        events = make(self.nightly((3, 2, 1), 400_000_000) + self.nightly((0,), 1_200_000_000))
        found = rules.data_exfil_volume(events, exfil_params(["10.0.5.10"]))
        self.assertEqual([f["first_seen"] for f in found][1:], [iso(BASE)])
        text = found[-1]["explanation"]
        self.assertIn("Baseline mode", text)
        self.assertIn("2.0 GB", text)   # the baseline
        self.assertIn("3.0x", text)     # the ratio
        self.assertIn("3x", text)       # the multiplier
        # Just under 3x its own normal stays quiet.
        events = make(self.nightly((3, 2, 1), 400_000_000) + self.nightly((0,), 1_190_000_000))
        self.assertEqual(len(rules.data_exfil_volume(events, exfil_params(["10.0.5.10"]))), 1)

    def test_baseline_multiplier_zero_is_flat_even_with_an_exception(self):
        events = make(self.nightly((3, 2, 1, 0), 400_000_000))
        found = rules.data_exfil_volume(events, exfil_params(["10.0.5.10"], baseline_multiplier=0))
        self.assertEqual(len(found), 4)
        self.assertIn("Flat thresholds", found[0]["explanation"])

    def test_history_outside_the_window_is_not_a_baseline(self):
        events = make(self.nightly((3, 0), 400_000_000))
        self.assertEqual(len(rules.data_exfil_volume(events, exfil_params(["10.0.5.10"], history_seconds=86400))), 2)

    def test_param_validation(self):
        for bad in ({"baseline_multiplier": -1}, {"baseline_multiplier": "3"}, {"history_seconds": 5},
                    {"baseline_principals": ["10.0.5.10"]}):  # engine-supplied, never a saved or proposed param
            with self.assertRaises(rules.RuleConfigError):
                rules.validate_params("data_exfil_volume", bad)
        self.assertNotIn("baseline_principals", rules.validate_params("data_exfil_volume", {}))


class EngineExfilExceptionTests(unittest.TestCase):
    """Through the engine: only an approved, unexpired exception changes how the exfil rule behaves."""

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

    def night(self, days_ago, per_event=400_000_000):
        start = utcnow().replace(microsecond=0) - timedelta(days=days_ago, hours=1)
        return [{"ts": iso(start + timedelta(seconds=i * 150)), "event_type": "fw_allow", "src_ip": "10.0.5.10",
                 "host": "fw01", "bytes": per_event, "message": "[SYNTHETIC] firewall allow (nightly backup)"}
                for i in range(12)]

    def allow(self, expires_in_days):
        self.conn.execute(
            "INSERT INTO suppressions(rule_id, group_key, reason, expires_at, proposed_by, approved_by, created_at)"
            " VALUES ('data_exfil_volume', '10.0.5.10', 'nightly backup', ?, 'analyst', 'admin', ?)",
            (iso(utcnow() + timedelta(days=expires_in_days)), iso(utcnow())))
        self.conn.commit()

    def test_an_analyst_verdict_alone_never_quiets_the_rule(self):
        self.assertEqual(self.ingest(self.night(3))["alerts_created"], 1)
        for verdict in ("benign", "false_positive"):
            for row in self.conn.execute("SELECT id FROM alerts WHERE status != 'resolved'").fetchall():
                queries.update_status(self.conn, row["id"], "analyst", "resolved", disposition=verdict)
            with self.subTest(verdict=verdict):
                self.assertEqual(self.ingest(self.night({"benign": 2, "false_positive": 1}[verdict]))["alerts_created"], 1)

    def test_exception_enables_the_baseline_and_expiry_reverts_to_flat(self):
        self.allow(30)
        self.assertEqual(self.ingest(self.night(4))["alerts_created"], 1)   # no history yet
        run = self.ingest(self.night(3))
        self.assertEqual((run["alerts_created"], run["alerts_updated"], run["alerts_suppressed"]), (0, 0, 0))
        # Three times its own normal still alerts: the exception is not a blanket skip.
        self.assertEqual(self.ingest(self.night(2, 1_200_000_000))["alerts_created"], 1)
        # Expired: back to the flat threshold, whatever the history.
        self.conn.execute("UPDATE suppressions SET expires_at = ?", (iso(utcnow() - timedelta(minutes=1)),))
        self.conn.commit()
        self.assertEqual(self.ingest(self.night(0))["alerts_created"], 1)

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
        self.assertEqual(rows["data_exfil_volume"]["verdict"], "noisy")
        self.assertEqual(rows["data_exfil_volume"]["lookalikes_fired"], ["nightly_backup"])
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

    def test_an_approved_exception_gives_the_backup_a_baseline(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = analyst.post("/api/rules/data_exfil_volume/suppressions",
                              {"group_key": "10.0.5.10", "days": 30, "reason": "Nightly off-site backup."})[1]
        self.assertEqual((change["evaluation"]["before"]["fp"], change["evaluation"]["after"]["fp"]), (1, 0))
        self.assertEqual(change["evaluation"]["after"]["missed"], [])
        exfil = lambda: {r["rule_id"]: r for r in analyst.get("/api/noise-lab")[1]["rules"]}["data_exfil_volume"]
        self.assertEqual(exfil()["verdict"], "noisy")  # proposed is not approved
        admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})
        row = exfil()
        self.assertEqual((row["verdict"], row["lookalikes_fired"], row["detected"], row["suppressed"]),
                         ("quiet", [], ["exfiltration"], 0))

    def test_a_disabled_rule_is_a_blind_spot_not_a_quiet_rule(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = analyst.post("/api/rules/web_scanner/proposals", {"enabled": False, "reason": "testing the lab"})[1]
        admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})
        row = {r["rule_id"]: r for r in analyst.get("/api/noise-lab")[1]["rules"]}["web_scanner"]
        self.assertEqual((row["enabled"], row["verdict"]), (False, "disabled"))


if __name__ == "__main__":
    unittest.main()
