"""Built-in rules show their noise-lab verdict beside the name."""

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


class RuleLabMarkTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def mark(self, rule, lab_rules):
        script = function_body(self.app, "ruleLabMark") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(ruleLabMark(input.rule, input.lab)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"rule": rule, "lab": lab_rules}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_built_in_rule_keeps_the_lab_verdict_and_summary(self):
        lab = [{"rule_id": "data_exfil_volume", "verdict": "noisy",
                "summary": "Noisy: catches its attack but also fires on benign activity (nightly_backup)."}]
        self.assertEqual(self.mark({"id": "data_exfil_volume"}, lab), {
            "verdict": "noisy",
            "summary": lab[0]["summary"],
        })
        self.assertEqual(self.mark({"id": "web_scanner"}, [
            {"rule_id": "web_scanner", "verdict": "quiet", "summary": "Quiet."},
        ])["verdict"], "quiet")
        for verdict in ("blind", "disabled", "untested"):
            with self.subTest(verdict=verdict):
                self.assertEqual(self.mark({"id": "web_scanner"}, [
                    {"rule_id": "web_scanner", "verdict": verdict},
                ]), {"verdict": verdict, "summary": ""})

    def test_imported_rules_and_unknown_words_stay_unmarked(self):
        lab = [{"rule_id": "sigma_web", "verdict": "quiet", "summary": "Quiet."},
               {"rule_id": "search_exports", "verdict": "noisy", "summary": "Noisy."}]
        self.assertIsNone(self.mark({"id": "sigma_web", "sigma": {"source": "title: x"}}, lab))
        self.assertIsNone(self.mark({"id": "search_exports", "search": {"query": "event_type:x"}}, lab))
        self.assertIsNone(self.mark({"id": "brute_force_ip"}, [{"rule_id": "brute_force_ip", "verdict": "maybe"}]))
        self.assertIsNone(self.mark({"id": "brute_force_ip"}, []))
        self.assertIsNone(self.mark({"id": "brute_force_ip"}, None))
        self.assertIsNone(self.mark(None, lab))


class RuleListUiTests(unittest.TestCase):
    def test_the_verdict_sits_beside_the_built_in_rule_name(self):
        app = read("app.js")
        page = function_body(app, "rules")
        name_at = page.index('class: "row rule-name"')
        self.assertLess(page.index('api("/api/noise-lab")'), name_at)
        self.assertLess(name_at, page.index("r.name"))
        self.assertLess(page.index("r.name"), page.index("ruleLabPill(ruleLabMark(r, lab.rules))"))
        self.assertLess(page.index("ruleLabPill(ruleLabMark(r, lab.rules))"), page.index("sev(r.severity)"))
        pill = function_body(app, "ruleLabPill")
        self.assertIn("Noise lab ${mark.verdict}", pill)
        self.assertIn("mark.summary", pill)
        self.assertIn("VERDICT_CLASS[mark.verdict]", pill)
        self.assertIn('class: `pill rule-lab ${VERDICT_CLASS[mark.verdict] || "st-rejected"}`', pill)
        css = read("style.css")
        self.assertIn(".rule-name h2 { margin: 0; }", css)
        self.assertIn(".rule-head, .rule-name { align-items: center; }", css)


if __name__ == "__main__":
    unittest.main()
