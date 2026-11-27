"""Incident detail draws the full ATT&CK kill chain, not only the tactics that fired."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from watchpost.attack import TACTICS

STATIC = Path(__file__).resolve().parent.parent / "static"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class IncidentKillChainTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def chain(self, tactics, incident):
        script = function_body(self.app, "incidentKillChain") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(incidentKillChain(input.tactics, input.incident)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"tactics": tactics, "incident": incident}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_fired_stages_keep_their_technique_ids_and_the_rest_stay_empty(self):
        tactics = [
            ["Reconnaissance", "Recon"], ["Initial Access", "Init"],
            ["Execution", "Exec"], ["Credential Access", "Cred"],
        ]
        chain = self.chain(tactics, {
            "stages": ["Initial Access", "Credential Access"],
            "techniques_by_tactic": [
                {"tactic": "Initial Access", "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"}]},
                {"tactic": "Credential Access", "techniques": [
                    {"id": "T1110", "name": "Brute Force"},
                    {"id": "T1110", "name": "Brute Force"},
                    "T1110.001"]},
            ],
        })
        self.assertEqual(
            [(s["name"], s["fired"], s["techniques"]) for s in chain],
            [
                ("Reconnaissance", False, []),
                ("Initial Access", True, ["T1190"]),
                ("Execution", False, []),
                ("Credential Access", True, ["T1110", "T1110.001"]),
            ])

    def test_unknown_stage_is_appended_and_an_empty_incident_is_all_quiet(self):
        tactics = [["Impact", "Impact"]]
        extra = self.chain(tactics, {
            "stages": ["Impact", "Not a tactic", "Impact"],
            "techniques_by_tactic": [{"tactic": "Not a tactic", "techniques": [{"id": "T0000"}]}],
        })
        self.assertEqual(
            [(s["name"], s["fired"], s["techniques"]) for s in extra],
            [("Impact", True, []), ("Not a tactic", True, ["T0000"])])
        quiet = self.chain(tactics, {})
        self.assertEqual(quiet, [{"name": "Impact", "fired": False, "techniques": []}])

    def test_page_draws_every_catalog_tactic(self):
        src = read("dashboard.js")
        match = re.search(r"const TACTICS = \[(.*?)\];", src, re.S)
        self.assertIsNotNone(match)
        names = re.findall(r'\["([^"]+)"', match.group(1))
        self.assertEqual(names, [name for _, name in TACTICS])
        detail = function_body(self.app, "incidentDetail")
        self.assertIn("killChainList(i)", detail)
        self.assertNotIn("i.stages.map", detail)
        view = function_body(self.app, "killChainList")
        self.assertIn("incidentKillChain(TACTICS, incident)", view)
        self.assertIn('s.fired ? "kc fired" : "kc quiet"', view)
        self.assertIn("s.techniques.join", view)
        self.assertIn('"—"', view)
        css = read("style.css")
        self.assertIn(".kc.fired", css)
        self.assertIn(".kc.quiet", css)
        self.assertIn(".kc-ids", css)


if __name__ == "__main__":
    unittest.main()
