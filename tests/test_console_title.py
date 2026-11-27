"""Signed-in document title names the open critical count and resets on sign-out."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
PUBLIC = "Watchpost: an open-source SIEM and SOC console in Python"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class ConsoleTitleTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.dash = read("dashboard.js")

    def title(self, signed_in, critical_open):
        const_line = re.search(r"^const PUBLIC_TITLE = .*;$", self.dash, re.M)
        self.assertIsNotNone(const_line)
        script = const_line.group(0) + "\n" + function_body(self.dash, "consoleTitle") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(consoleTitle(input.signedIn, input.criticalOpen)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"signedIn": signed_in, "criticalOpen": critical_open}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_signed_in_count_names_open_critical_alerts(self):
        self.assertEqual(self.title(True, 2), "Watchpost · 2 critical")
        self.assertEqual(self.title(True, 0), "Watchpost · 0 critical")
        self.assertEqual(self.title(True, 1), "Watchpost · 1 critical")

    def test_sign_out_and_a_missing_count_use_the_public_title(self):
        for signed_in, count in (
            (False, 2),
            (False, 0),
            (None, 2),
            (True, None),
            (True, -1),
            (True, 1.5),
            (True, "2"),
        ):
            with self.subTest(signed_in=signed_in, count=count):
                self.assertEqual(self.title(signed_in, count), PUBLIC)

    def test_the_strip_sets_the_title_and_sign_out_resets_it(self):
        html = read("index.html")
        self.assertIn(f'const PUBLIC_TITLE = "{PUBLIC}";', self.dash)
        self.assertIn(f"<title>{PUBLIC}</title>", html)
        self.assertLess(html.index('src="/dashboard.js"'), html.index('src="/app.js"'))
        start = self.dash.index("renderStrip() {")
        strip = self.dash[start:self.dash.index("async pollStory()", start)]
        self.assertIn("document.title = consoleTitle(!!state.user, d ? d.alerts_critical_open : undefined)", strip)
        login = function_body(read("app.js"), "showLogin")
        self.assertLess(login.index("state.user = null"), login.index("document.title = consoleTitle(false)"))
        self.assertIn("document.title = consoleTitle(false)", login)


if __name__ == "__main__":
    unittest.main()
