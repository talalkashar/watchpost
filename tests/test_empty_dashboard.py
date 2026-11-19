"""An empty dashboard is one next action: upload for an analyst, read-only for a viewer."""

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

    def copy(self, events_total, role):
        script = function_body(read("dashboard.js"), "emptyDashboard") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const copy = emptyDashboard(input.eventsTotal, input.role);
process.stdout.write(JSON.stringify(copy));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"eventsTotal": events_total, "role": role}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_zero_events_offers_ingest_only_when_authorized(self):
        for role in ("analyst", "admin"):
            with self.subTest(role=role):
                copy = self.copy(0, role)
                self.assertEqual(copy["title"], "No events yet")
                self.assertEqual(copy["body"], "No events are stored.")
                self.assertEqual(copy["href"], "#ingest")
                self.assertEqual(copy["label"], "Upload a log")
                self.assertEqual(copy["hint"], "")
                self.assertNotIn("synthetic", copy["body"].lower())
                self.assertNotIn("real", copy["body"].lower())

        for role in ("viewer", False, "", None):
            with self.subTest(role=role):
                copy = self.copy(0, role)
                self.assertEqual(copy["title"], "No events yet")
                self.assertIn("read-only", copy["body"].lower())
                self.assertEqual(copy["href"], "")
                self.assertEqual(copy["label"], "")
                self.assertNotIn("upload a log", copy["body"].lower())
                self.assertNotIn("synthetic", copy["body"].lower())

    def test_any_stored_event_hides_the_empty_state(self):
        for events_total in (1, 40, None, "0"):
            with self.subTest(events_total=events_total):
                self.assertIsNone(self.copy(events_total, "analyst"))
                self.assertIsNone(self.copy(events_total, "viewer"))


class EmptyDashboardUiTests(unittest.TestCase):
    def test_the_empty_store_hides_the_map_and_the_saved_view_form(self):
        src = read("dashboard.js")
        self.assertNotIn("Loading saved dashboard views", src)
        self.assertNotIn("dash-load-demo", src)

        mount = method_body(src, "mount")
        self.assertLess(mount.index('id: "dash-empty"'), mount.index('id: "soc"'))
        self.assertIn('id: "dashboard-view-bar", hidden: true', mount)
        self.assertIn('id: "soc", hidden: true', mount)

        update = method_body(src, "update")
        self.assertLess(update.index("this.renderEmpty()"), update.index("fillFeed"))

        render = method_body(src, "renderEmpty")
        self.assertIn('emptyDashboard(this.data.events_total, dashboardRole())', render)
        self.assertIn("soc.hidden = true", render)
        self.assertIn("bar.hidden = true", render)
        self.assertLess(render.index("copy.href"), render.index('id: "dash-next"'))
        self.assertIn('href: "#ingest"', function_body(src, "emptyDashboard"))

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

    def test_seeded_data_exposes_the_queue_and_keeps_ownership_fallback_and_focus(self):
        src = read("dashboard.js")
        bar = method_body(src, "renderViewBar")
        self.assertLess(bar.index("emptyDashboard"), bar.index('id: "dash-queue", href: "#alerts"'))
        self.assertIn("selected.layout", bar)

        norm = function_body(src, "normIncidents")
        self.assertIn("assignee: ownerName(i.assignee)", norm)
        board = function_body(src, "incidentBoard")
        self.assertIn("owner: ownerName(i.assignee)", board)
        self.assertIn("owner: ownerName(a.assignee)", board)
        self.assertIn("c.owner", board)
        self.assertIn("boardTags(i.tactics, i.top_technique)", board)
        self.assertIn('class: "tag tech"', board)
        self.assertIn("INCIDENTS UNAVAILABLE · SHOWING ALERTS", src)
        self.assertIn("INCIDENTS PENDING · SHOWING ALERTS", src)
        self.assertIn("incidentFallbackChip(inc.state)", method_body(src, "renderBoard"))
        self.assertIn("onfocusin: () => this.focusFeed(true)", src)
        self.assertIn("focusFeed(on) { this.feedFocused = on; this.syncPause(); }", src)

        html = read("index.html")
        self.assertIn(">Sign in<", html)
        self.assertIn("All data is synthetic.", html)
