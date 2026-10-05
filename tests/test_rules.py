import unittest
from datetime import datetime, timedelta, timezone

from watchpost import rules
from watchpost.db import iso
from watchpost.improve import evaluate

BASE = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)  # a Tuesday


def params(rule_id, **overrides):
    return rules.validate_params(rule_id, overrides)


def make(events):
    return [{"id": i, **e} for i, e in enumerate(events, start=1)]


def fail(sec, user="admin", ip="203.0.113.1"):
    return {"ts": iso(BASE + timedelta(seconds=sec)), "event_type": "auth_failure", "user": user, "src_ip": ip}


def ok(sec, user="admin", ip="203.0.113.1", base=BASE):
    return {"ts": iso(base + timedelta(seconds=sec)), "event_type": "auth_success", "user": user, "src_ip": ip}


class BruteForceTests(unittest.TestCase):
    def test_threshold_boundary(self):
        p = params("brute_force_ip")
        self.assertEqual(rules.brute_force_ip(make([fail(i) for i in range(9)]), p), [])
        found = rules.brute_force_ip(make([fail(i) for i in range(10)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertEqual(len(found[0]["event_ids"]), 10)
        self.assertIn("threshold of 10", found[0]["explanation"])

    def test_events_outside_window_do_not_count(self):
        # 10 failures spread over 10 minutes: never 10 inside 300s.
        self.assertEqual(rules.brute_force_ip(make([fail(i * 60) for i in range(10)]), params("brute_force_ip")), [])

    def test_separate_bursts_make_separate_findings(self):
        events = [fail(i) for i in range(10)] + [fail(3600 + i) for i in range(10)]
        self.assertEqual(len(rules.brute_force_ip(make(events), params("brute_force_ip"))), 2)

    def test_ignore_ips_and_users(self):
        events = make([fail(i) for i in range(12)])
        self.assertEqual(rules.brute_force_ip(events, params("brute_force_ip", ignore_ips=["203.0.113.1"])), [])
        self.assertEqual(rules.brute_force_ip(events, params("brute_force_ip", ignore_users=["ADMIN"])), [])

    def test_unordered_input_and_missing_ip(self):
        events = [fail(i) for i in reversed(range(10))] + [{**fail(1), "src_ip": None}]
        self.assertEqual(len(rules.brute_force_ip(make(events), params("brute_force_ip"))), 1)


class OtherRuleTests(unittest.TestCase):
    def test_password_spray(self):
        events = make([fail(i * 30, user=f"u{i}") for i in range(5)])
        self.assertEqual(len(rules.password_spray(events, params("password_spray"))), 1)
        same_user = make([fail(i * 30) for i in range(20)])
        self.assertEqual(rules.password_spray(same_user, params("password_spray")), [])

    def test_account_repeated_failures_across_ips(self):
        events = make([fail(i * 10, ip=f"192.0.2.{i}") for i in range(8)])
        found = rules.account_repeated_failures(events, params("account_repeated_failures"))
        self.assertEqual(len(found), 1)
        self.assertIn("8 source IP", found[0]["explanation"])
        self.assertEqual(rules.brute_force_ip(events, params("brute_force_ip")), [])

    def test_success_after_failures(self):
        p = params("success_after_failures")
        events = make([fail(i * 10, user="dave") for i in range(5)] + [ok(60, user="Dave")])
        found = rules.success_after_failures(events, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "dave|203.0.113.1")
        self.assertIn("same IP", found[0]["explanation"])
        # Four failures is below the threshold; a success long after is outside the window.
        self.assertEqual(rules.success_after_failures(make([fail(i, user="d") for i in range(4)] + [ok(9, user="d")]), p), [])
        self.assertEqual(rules.success_after_failures(make([fail(i, user="d") for i in range(5)] + [ok(7200, user="d")]), p), [])
        # A success *before* the failures is not "after failures".
        self.assertEqual(rules.success_after_failures(make([ok(0, user="d")] + [fail(10 + i, user="d") for i in range(5)]), p), [])

    def test_off_hours(self):
        p = params("off_hours_privileged_login")
        night = datetime(2026, 9, 15, 3, 0, tzinfo=timezone.utc)
        saturday = datetime(2026, 9, 19, 11, 0, tzinfo=timezone.utc)
        self.assertEqual(len(rules.off_hours_privileged_login(make([ok(0, "root", base=night)]), p)), 1)
        self.assertEqual(len(rules.off_hours_privileged_login(make([ok(0, "root", base=saturday)]), p)), 1)
        self.assertEqual(rules.off_hours_privileged_login(make([ok(0, "root")]), p), [])  # Tuesday 14:00
        self.assertEqual(rules.off_hours_privileged_login(make([ok(0, "alice", base=night)]), p), [])


def ev(sec, event_type, user=None, ip="203.0.113.1", **extra):
    return {"ts": iso(BASE + timedelta(seconds=sec)), "event_type": event_type, "user": user, "src_ip": ip, **extra}


class WebAndFirewallRuleTests(unittest.TestCase):
    def test_web_scanner(self):
        p = params("web_scanner")
        probes = [ev(i * 5, "web_scan", message=f"GET /probe{i} -> 404") for i in range(5)]
        found = rules.web_scanner(make(probes), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertIn("/probe0", found[0]["explanation"])
        self.assertEqual(rules.web_scanner(make(probes[:4]), p), [])
        # Ordinary requests never count, and spread-out probes stay under the window.
        self.assertEqual(rules.web_scanner(make([ev(i, "web_request") for i in range(20)]), p), [])
        self.assertEqual(rules.web_scanner(make([ev(i * 120, "web_scan") for i in range(5)]), p), [])

    def test_firewall_port_sweep(self):
        p = params("firewall_port_sweep")
        sweep = [ev(i, "fw_deny", dest_ip="10.0.0.10", dest_port=1000 + i) for i in range(10)]
        found = rules.firewall_port_sweep(make(sweep), p)
        self.assertEqual(len(found), 1)
        self.assertIn("10 distinct ports", found[0]["explanation"])
        same_port = [ev(i, "fw_deny", dest_port=22) for i in range(30)]
        self.assertEqual(rules.firewall_port_sweep(make(same_port), p), [])
        allowed = [ev(i, "fw_allow", dest_port=1000 + i) for i in range(30)]
        self.assertEqual(rules.firewall_port_sweep(make(allowed), p), [])
        no_port = [ev(i, "fw_deny") for i in range(30)]
        self.assertEqual(rules.firewall_port_sweep(make(no_port), p), [])


class GeoLoginRuleTests(unittest.TestCase):
    def test_impossible_travel(self):
        p = params("impossible_geo_login")
        events = make([ev(0, "auth_success", "erin", "10.0.1.24"), ev(25 * 60, "vpn_login", "Erin", "203.0.113.150")])
        found = rules.impossible_geo_login(events, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "erin|10.0.1.24|203.0.113.150")
        self.assertIn("Riverton HQ", found[0]["explanation"])
        self.assertIn("synthetic geo", found[0]["explanation"])

    def test_plausible_or_unknown_travel_is_quiet(self):
        p = params("impossible_geo_login")
        # Same city, or enough time to fly there, or an address the synthetic table does not know.
        cases = [
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(60, "auth_success", "erin", "10.9.9.9")],
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(15 * 3600, "auth_success", "erin", "203.0.113.150")],
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(60, "auth_success", "erin", "8.8.8.8")],
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(60, "auth_success", "bob", "203.0.113.150")],
            [ev(0, "auth_failure", "erin", "10.0.1.24"), ev(60, "auth_success", "erin", "203.0.113.150")],
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(rules.impossible_geo_login(make(case), p), [])

    def test_privilege_escalation_after_login(self):
        p = params("privilege_escalation_after_login")
        attack = [ev(i * 20, "auth_failure", "frank", "192.0.2.140") for i in range(3)]
        attack += [ev(60, "auth_success", "frank", "192.0.2.140"),
                   ev(420, "privilege_escalation", "frank", "192.0.2.140", host="web01")]
        found = rules.privilege_escalation_after_login(make(attack), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "frank|web01")
        self.assertEqual(len(found[0]["event_ids"]), 5)
        # Too few failures; escalation long after the login; escalation with no login at all.
        self.assertEqual(rules.privilege_escalation_after_login(make(attack[1:]), p), [])
        late = attack[:4] + [ev(60 + 3600, "privilege_escalation", "frank", host="web01")]
        self.assertEqual(rules.privilege_escalation_after_login(make(late), p), [])
        self.assertEqual(rules.privilege_escalation_after_login(
            make(attack[:3] + [ev(400, "privilege_escalation", "frank", host="web01")]), p), [])


class CloudRuleTests(unittest.TestCase):
    def test_iam_change_by_new_principal(self):
        p = params("cloud_iam_change_by_new_principal")
        known = [ev(0, "cloud_api_call", "ops-admin"), ev(600, "cloud_iam_change", "ops-admin")]
        new = [ev(900 + i * 30, "cloud_iam_change", "svc-new", message=f"{a} on iam.amazonaws.com")
               for i, a in enumerate(["CreateUser", "CreateAccessKey"])]
        found = rules.cloud_iam_change_by_new_principal(make(known + new), p)
        self.assertEqual([f["group_key"] for f in found], ["svc-new"])
        self.assertEqual(len(found[0]["event_ids"]), 2)
        self.assertIn("CreateAccessKey", found[0]["explanation"])
        # History older than history_seconds does not count as history.
        stale = [ev(0, "cloud_api_call", "ops-admin"), ev(2 * 86400, "cloud_iam_change", "ops-admin")]
        self.assertEqual(len(rules.cloud_iam_change_by_new_principal(make(stale), p)), 1)

    def test_data_exfil_volume(self):
        p = params("data_exfil_volume")
        reads = [ev(i * 10, "cloud_data_access", "svc", bytes=50_000_000) for i in range(20)]
        found = rules.data_exfil_volume(make(reads), p)
        self.assertEqual(len(found), 1)
        self.assertIn("1.0 GB", found[0]["explanation"])
        self.assertEqual(rules.data_exfil_volume(make(reads[:19]), p), [])
        many_small = [ev(i, "cloud_data_access", "svc", bytes=10) for i in range(100)]
        self.assertEqual(len(rules.data_exfil_volume(make(many_small), p)), 1)
        # Outbound firewall bytes count per source IP when there is no account.
        uploads = [ev(i * 60, "fw_allow", None, "10.0.3.15", bytes=600_000_000) for i in range(2)]
        self.assertEqual([f["group_key"] for f in rules.data_exfil_volume(make(uploads), p)], ["10.0.3.15"])
        self.assertEqual(rules.data_exfil_volume(make([ev(0, "fw_allow", None, "10.0.3.15")] * 3), p), [])


class TechniqueMappingTests(unittest.TestCase):
    def test_every_rule_has_techniques_and_a_function(self):
        for rule in rules.DEFAULT_RULES:
            with self.subTest(rule=rule["id"]):
                self.assertIn(rule["id"], rules.RULE_FUNCTIONS)
                self.assertTrue(rule["techniques"])
                for t in rule["techniques"]:
                    self.assertEqual(set(t), {"id", "name", "tactic"})

    def test_lookback_covers_escalation_and_history(self):
        active = [{"params": rules.validate_params(r["id"], {})} for r in rules.DEFAULT_RULES]
        self.assertGreaterEqual(rules.lookback_seconds(active), 600 + 1800)
        self.assertEqual(rules.history_seconds(active), 604800)  # data_exfil_volume baseline


class ValidationTests(unittest.TestCase):
    def test_rejects_bad_params(self):
        bad = [
            ("brute_force_ip", {"threshold": 1}),
            ("brute_force_ip", {"threshold": "10"}),
            ("brute_force_ip", {"threshold": True}),
            ("brute_force_ip", {"nope": 1}),
            ("brute_force_ip", {"ignore_ips": ["not-an-ip"]}),
            ("off_hours_privileged_login", {"business_start_hour": 18, "business_end_hour": 8}),
            ("off_hours_privileged_login", {"privileged_users": []}),
            ("firewall_port_sweep", {"distinct_ports": 1}),
            ("impossible_geo_login", {"max_speed_kmh": 10}),
            ("privilege_escalation_after_login", {"escalation_seconds": 5}),
            ("cloud_iam_change_by_new_principal", {"history_seconds": "1d"}),
            ("data_exfil_volume", {"bytes_threshold": 0}),
            ("web_scanner", {"distinct_ports": 5}),
            ("missing_rule", {}),
        ]
        for rule_id, p in bad:
            with self.subTest(rule=rule_id, params=p):
                with self.assertRaises(rules.RuleConfigError):
                    rules.validate_params(rule_id, p)


class EvaluationTests(unittest.TestCase):
    def test_default_rules_on_labeled_scenarios(self):
        defaults = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}
        result = evaluate(defaults)["rules"]
        for rule_id, r in result.items():
            with self.subTest(rule=rule_id):
                self.assertEqual(r["fn"], 0, r)
                self.assertEqual(r["recall"], 1.0)
        # The internal scanner is a deliberate false-positive source for the feedback demo.
        self.assertIn("noisy_scanner", result["brute_force_ip"]["false_positives"])
        # 3.0 look-alike: a branch NAT after a password-expiry day is the spray rule's only noise.
        self.assertEqual(result["password_spray"]["false_positives"], ["password_expiry_nat"])

    def test_allowlisting_scanner_removes_false_positive(self):
        defaults = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}
        tuned = rules.validate_params("brute_force_ip", {"ignore_ips": ["10.0.50.5"]})
        after = evaluate({"brute_force_ip": tuned})["rules"]["brute_force_ip"]
        self.assertEqual(after["fp"], 0)
        self.assertEqual(after["tp"], evaluate(defaults)["rules"]["brute_force_ip"]["tp"])


if __name__ == "__main__":
    unittest.main()
