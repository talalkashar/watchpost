"""Detection-as-code checks for exported Watchpost rules."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from watchpost import detection_tests, rules


ROOT = Path(__file__).resolve().parents[1]


def document(*rule_ids, enabled=True):
    defaults = {rule["id"]: rule for rule in rules.DEFAULT_RULES}
    return {
        "format": "watchpost-rules",
        "format_version": 1,
        "rules": [
            {"id": rule_id, "enabled": enabled, "params": defaults[rule_id]["params"]}
            for rule_id in rule_ids
        ],
    }


class DetectionChecksTests(unittest.TestCase):
    def test_clean_rule_passes_its_malicious_and_benign_samples(self):
        result = detection_tests.check(document("success_after_failures"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"], {"tested": 1, "passed": 1, "failed": 0, "skipped": 0})
        rule = result["rules"][0]
        self.assertEqual((rule["id"], rule["status"]), ("success_after_failures", "passed"))
        self.assertEqual(rule["malicious"], {"passed": ["compromise"], "failed": []})
        self.assertEqual(rule["benign"], {"passed": ["password_typo"], "failed": []})

    def test_known_noisy_rule_fails_on_labeled_benign_samples(self):
        result = detection_tests.check(document("brute_force_ip"))
        self.assertFalse(result["ok"])
        rule = result["rules"][0]
        self.assertEqual(rule["malicious"]["failed"], [])
        self.assertEqual(rule["benign"]["failed"], ["noisy_scanner", "noisy_scanner_repeat"])

    def test_disabled_rule_is_validated_then_skipped(self):
        result = detection_tests.check(document("success_after_failures", enabled=False))
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"], {"tested": 0, "passed": 0, "failed": 0, "skipped": 1})
        self.assertEqual(result["rules"][0]["status"], "skipped")

    def test_invalid_documents_fail_closed(self):
        cases = [
            {**document("success_after_failures"), "format": "sigma"},
            document(),
            document("success_after_failures", "success_after_failures"),
            {**document("success_after_failures"), "rules": [{"id": "missing", "enabled": True, "params": {}}]},
            {**document("success_after_failures"), "rules": [{"id": "success_after_failures",
                                                                 "enabled": "yes", "params": {}}]},
            {**document("success_after_failures"), "rules": [{"id": "success_after_failures", "enabled": True,
                                                                 "params": {"failures": "five"}}]},
        ]
        for bad in cases:
            with self.subTest(document=bad):
                with self.assertRaises(detection_tests.ValidationError):
                    detection_tests.check(bad)

    def run_cli(self, doc):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as stream:
            json.dump(doc, stream)
            stream.flush()
            return subprocess.run(
                [sys.executable, "scripts/test_detections.py", stream.name],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

    def test_cli_prints_json_and_uses_exit_status_for_detection_failures(self):
        passed = self.run_cli(document("success_after_failures"))
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertTrue(json.loads(passed.stdout)["ok"])

        failed = self.run_cli(document("brute_force_ip"))
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertFalse(json.loads(failed.stdout)["ok"])

    def test_cli_reports_invalid_json_as_machine_readable_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as stream:
            stream.write("{not json")
            stream.flush()
            proc = subprocess.run(
                [sys.executable, "scripts/test_detections.py", stream.name],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["error"]["type"], "validation")
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
