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
        self.assertEqual(result["password_spray"]["fp"], 0)

    def test_allowlisting_scanner_removes_false_positive(self):
        defaults = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}
        tuned = rules.validate_params("brute_force_ip", {"ignore_ips": ["10.0.50.5"]})
        after = evaluate({"brute_force_ip": tuned})["rules"]["brute_force_ip"]
        self.assertEqual(after["fp"], 0)
        self.assertEqual(after["tp"], evaluate(defaults)["rules"]["brute_force_ip"]["tp"])


if __name__ == "__main__":
    unittest.main()
