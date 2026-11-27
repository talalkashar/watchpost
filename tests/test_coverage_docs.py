"""The coverage example in the API docs must show evidence level, not the old enabled-rule meaning."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "docs" / "API.md"
SENTENCE = ("`covered` is true only when the technique is validated on a labeled scenario, "
            "not merely because a rule is enabled.")


def coverage_example():
    text = API.read_text()
    start = text.index("### `GET /api/attack/coverage` example")
    fence = text.index("```json", start)
    body = text[fence + len("```json"):text.index("```", fence + 3)]
    return text[start:text.index("## Reports", start)], json.loads(body)


class CoverageDocsTests(unittest.TestCase):
    def test_example_shows_level_and_covered_means_validated(self):
        section, example = coverage_example()
        self.assertIn(SENTENCE, section)
        self.assertNotIn("covered means the rule is enabled", section.lower())
        self.assertEqual(example["levels"], ["validated", "mapped", "disabled", "gap"])
        self.assertEqual(example["summary"]["covered"], example["summary"]["levels"]["validated"])
        by_id = {t["id"]: t for t in example["techniques"]}
        self.assertEqual(set(by_id), {"T1110.003", "T1190"})
        for technique in by_id.values():
            self.assertIn(technique["level"], example["levels"])
            self.assertEqual(technique["covered"], technique["level"] == "validated")
            self.assertTrue(any(rule["enabled"] for rule in technique["rules"]))
        mapped = by_id["T1190"]
        self.assertEqual(mapped["level"], "mapped")
        self.assertFalse(mapped["covered"])
        self.assertEqual(mapped["scenarios"], [])
        self.assertIn("never exploits", mapped["why"])
        validated = by_id["T1110.003"]
        self.assertEqual(validated["level"], "validated")
        self.assertTrue(validated["covered"])
        self.assertEqual(validated["scenarios"], ["password_spray"])
        self.assertIsNone(validated["why"])
