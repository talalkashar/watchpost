"""Alert detail header shows the rule severity and the raised severity together."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class RaisedSeverityTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def raised(self, alert):
        script = function_body(self.app, "raisedSeverity") + """
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(raisedSeverity(input)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps(alert),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_lifted_alert_names_both_severities(self):
        self.assertEqual(self.raised({"base_severity": "high", "severity": "critical"}),
                         {"base": "high", "raised": "critical"})
        self.assertEqual(self.raised({"base_severity": "low", "severity": "high"}),
                         {"base": "low", "raised": "high"})

    def test_an_unraised_alert_stays_a_single_severity(self):
        for alert in (
            {"base_severity": "high", "severity": "high"},
            {"base_severity": "critical", "severity": "high"},
            {"severity": "high"},
            {"base_severity": "", "severity": "high"},
            {"base_severity": "severe", "severity": "high"},
            {"base_severity": "medium", "severity": "urgent"},
            None,
            {},
        ):
            with self.subTest(alert=alert):
                self.assertIsNone(self.raised(alert))


class AlertHeaderTests(unittest.TestCase):
    def test_title_row_shows_the_pair_and_the_body_still_explains_why(self):
        app = read("app.js")
        detail = function_body(app, "alertDetail")
        header = function_body(app, "alertHeaderSevs")
        self.assertLess(detail.index('class: "row alert-head"'), detail.index("a.title"))
        self.assertIn("alertHeaderSevs(a)", detail)
        self.assertIn("raisedSeverity(alert)", header)
        self.assertIn('class: "sev-raise"', header)
        self.assertIn('"raised to"', header)
        self.assertIn("sev(lifted.base)", header)
        self.assertIn("sev(lifted.raised)", header)
        self.assertIn("return sev(alert.severity)", header)
        # The assets sentence stays: it is the reason, not the only place the two levels appear.
        self.assertIn("Rule severity ${a.base_severity}", detail)
        self.assertIn("a.severity_note", detail)
        css = read("style.css")
        self.assertIn(".alert-head", css)
        self.assertIn(".sev-raise-label", css)


if __name__ == "__main__":
    unittest.main()
