"""Fail-closed edges for detection-as-code checks. The CLI contract stays in test_detection_cli.py."""

import json
import unittest

from watchpost import detection_tests, rules, simulate


def params_of(rule_id, **overrides):
    source = next(rule["params"] for rule in rules.DEFAULT_RULES if rule["id"] == rule_id)
    copied = {key: list(value) if isinstance(value, list) else value for key, value in source.items()}
    copied.update(overrides)
    return copied


def document(*rule_ids, enabled=True, **overrides):
    return {
        "format": "watchpost-rules",
        "format_version": 1,
        "rules": [
            {"id": rule_id, "enabled": enabled, "params": params_of(rule_id, **overrides)}
            for rule_id in rule_ids
        ],
    }


class DetectionTestsBlitz(unittest.TestCase):
    def test_clean_rule_passes_and_report_is_json(self):
        result = detection_tests.check(document("success_after_failures"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["seed"], 7)
        self.assertIs(type(result["seed"]), int)
        self.assertEqual(result["summary"], {"tested": 1, "passed": 1, "failed": 0, "skipped": 0})
        rule = result["rules"][0]
        self.assertEqual(rule["malicious"], {"passed": ["compromise"], "failed": []})
        self.assertEqual(rule["benign"], {"passed": ["password_typo"], "failed": []})
        json.dumps(result)

    def test_known_noisy_rule_fails_only_its_labeled_lookalikes(self):
        result = detection_tests.check(document("brute_force_ip"))
        self.assertFalse(result["ok"])
        rule = result["rules"][0]
        self.assertEqual(rule["malicious"], {"passed": ["brute_force"], "failed": []})
        self.assertEqual(rule["benign"]["failed"], ["noisy_scanner", "noisy_scanner_repeat"])

    def test_mixed_rules_keep_document_order_and_skip_disabled(self):
        doc = document("success_after_failures")
        doc["rules"].append({"id": "brute_force_ip", "enabled": False, "params": params_of("brute_force_ip")})
        doc["rules"].append({"id": "web_scanner", "enabled": True, "params": params_of("web_scanner")})
        result = detection_tests.check(doc)
        self.assertEqual([item["id"] for item in result["rules"]],
                         ["success_after_failures", "brute_force_ip", "web_scanner"])
        self.assertEqual([item["status"] for item in result["rules"]], ["passed", "skipped", "passed"])
        self.assertEqual(result["rules"][1], {"id": "brute_force_ip", "status": "skipped", "reason": "disabled"})
        self.assertEqual(result["summary"], {"tested": 2, "passed": 2, "failed": 0, "skipped": 1})
        self.assertTrue(result["ok"])

    def test_threshold_that_misses_the_attack_fails_the_rule(self):
        result = detection_tests.check(document("brute_force_ip", threshold=10000))
        rule = result["rules"][0]
        self.assertEqual(rule["status"], "failed")
        self.assertEqual(rule["malicious"], {"passed": [], "failed": ["brute_force"]})
        self.assertFalse(result["ok"])

    def test_low_failure_bar_fires_on_the_typo_lookalike(self):
        result = detection_tests.check(document("success_after_failures", failures=2))
        rule = result["rules"][0]
        self.assertEqual(rule["malicious"], {"passed": ["compromise"], "failed": []})
        self.assertEqual(rule["benign"], {"passed": [], "failed": ["password_typo"]})
        self.assertFalse(result["ok"])

    def test_seed_must_be_a_real_integer(self):
        bad = [None, True, False, 1.5, "7", b"ab", bytearray(b"ab"), [], {}, object()]
        for seed in bad:
            for enabled in (True, False):
                with self.subTest(seed=type(seed).__name__, enabled=enabled):
                    with self.assertRaises(detection_tests.ValidationError) as caught:
                        detection_tests.check(document("success_after_failures", enabled=enabled), seed=seed)
                    self.assertEqual(str(caught.exception), "seed must be an integer")
        for seed in (0, -1):
            result = detection_tests.check(document("success_after_failures", enabled=False), seed=seed)
            self.assertEqual(result["seed"], seed)
            self.assertIs(type(result["seed"]), int)
            self.assertTrue(result["ok"])
            json.dumps(result)

    def test_non_string_keys_raise_validation_error(self):
        top = document("success_after_failures")
        top[1] = "x"
        entry = document("success_after_failures")
        entry["rules"][0][1] = "x"
        numbered = document("success_after_failures")
        numbered["rules"][0]["params"][1] = 9
        paired = document("success_after_failures")
        paired["rules"][0]["params"][(1, 2)] = 9
        cases = [
            (top, "the import has a non-string key"),
            (entry, "rule entry 0 has a non-string key"),
            (numbered, "rule 'success_after_failures' params has a non-string key"),
            (paired, "rule 'success_after_failures' params has a non-string key"),
        ]
        for doc, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(detection_tests.ValidationError) as caught:
                    detection_tests.check(doc)
                self.assertEqual(str(caught.exception), message)

    def test_missing_malicious_or_lookalike_sample_is_refused(self):
        cases = (
            ("uptime_monitor", "lookalike_of", "web_scanner"),
            ("web_scan", "expected", "web_scanner"),
        )
        for scenario, field, rule_id in cases:
            spec = simulate.SCENARIOS[scenario]
            saved = spec[field]
            try:
                if field == "expected":
                    spec[field] = {key: value for key, value in saved.items() if key != rule_id}
                else:
                    spec[field] = None
                for enabled in (True, False):
                    with self.subTest(scenario=scenario, enabled=enabled):
                        with self.assertRaises(detection_tests.ValidationError) as caught:
                            detection_tests.check(document(rule_id, enabled=enabled))
                        self.assertIn("no bundled detection-as-code samples", str(caught.exception))
            finally:
                spec[field] = saved

    def test_sample_omitted_by_evaluate_is_a_failure(self):
        real = detection_tests.improve.evaluate

        def ghost(rule_params, seed=7, suppressions=()):
            result = real(rule_params, seed=seed, suppressions=suppressions)
            rule = result["rules"]["web_scanner"]
            for key in ("detected", "missed"):
                rule[key] = [name for name in rule[key] if name != "web_scan"]
            for key in ("lookalikes", "lookalikes_fired"):
                rule[key] = [name for name in rule[key] if name != "uptime_monitor"]
            return result

        detection_tests.improve.evaluate = ghost
        try:
            result = detection_tests.check(document("web_scanner"))
        finally:
            detection_tests.improve.evaluate = real
        self.assertFalse(result["ok"])
        rule = result["rules"][0]
        self.assertEqual(rule["status"], "failed")
        self.assertEqual(rule["malicious"], {"passed": [], "failed": ["web_scan"]})
        self.assertEqual(rule["benign"], {"passed": [], "failed": ["uptime_monitor"]})
