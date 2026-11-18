"""An empty dashboard is one explanation, plus a load control for an admin."""

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


def method_body(source, name):
    match = re.search(rf"^  (?:async )?{name}\(.*?^  \}},$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"method {name} not found")
    return match.group(0)


class EmptyDashboardTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")

    def copy(self, events_total, is_admin):
        script = function_body(read("dashboard.js"), "emptyDashboard") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const copy = emptyDashboard(input.eventsTotal, input.isAdmin);
process.stdout.write(JSON.stringify(copy));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"eventsTotal": events_total, "isAdmin": is_admin}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_zero_events_is_one_explanation_and_only_an_admin_can_load(self):
        admin = self.copy(0, True)
        self.assertEqual(admin["title"], "No events yet")
        self.assertIn("Ingest", admin["body"])
        self.assertNotIn("synthetic", admin["body"].lower())
        self.assertNotIn("real", admin["body"].lower())
        self.assertTrue(admin["load"])
        self.assertEqual(admin["hint"], "")

        viewer = self.copy(0, False)
        self.assertEqual(viewer["title"], admin["title"])
        self.assertEqual(viewer["body"], admin["body"])
        self.assertFalse(viewer["load"])
        self.assertIn("admin", viewer["hint"].lower())

    def test_any_stored_event_hides_the_empty_state(self):
        for events_total in (1, 40, None, "0"):
            with self.subTest(events_total=events_total):
                self.assertIsNone(self.copy(events_total, True))
                self.assertIsNone(self.copy(events_total, False))


class EmptyDashboardUiTests(unittest.TestCase):
    def test_the_empty_store_hides_the_panel_grid_and_offers_one_load_control(self):
        src = read("dashboard.js")
        mount = method_body(src, "mount")
        self.assertLess(mount.index('id: "dash-empty"'), mount.index('id: "soc"'))

        update = method_body(src, "update")
        self.assertLess(update.index("this.renderEmpty()"), update.index("fillFeed"))

        render = method_body(src, "renderEmpty")
        self.assertIn("emptyDashboard(this.data.events_total, can(\"admin\"))", render)
        self.assertIn("soc.hidden = true", render)
        self.assertLess(render.index("copy.load"), render.index('id: "dash-load-demo"'))
        self.assertLess(render.index('id: "dash-load-demo"'), render.index("copy.hint"))
        self.assertIn("Load demo data", render)

        load = method_body(src, "loadDemo")
        self.assertIn('api("/api/demo/load", { method: "POST", body: {} })', load)
        self.assertIn("force: true", load)
        self.assertIn("Live.refreshSummary()", load)

        redraw = method_body(src, "redraw")
        self.assertLess(redraw.index("emptyDashboard(this.data.events_total, false)"), redraw.index("renderMap"))
        self.assertIn(
            'if ($("#soc")?.hidden && this.summary && this.summary.events_total > 0) Dash.update(this.summary);',
            src)

        css = read("style.css")
        self.assertIn("#dash-empty[hidden] { display: none; }", css)
        # Panel notes stay for a store that has events but an empty chart.
        self.assertIn("No events received yet.", src)
        self.assertIn("No rule has fired yet.", src)
