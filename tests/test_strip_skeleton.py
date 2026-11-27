"""Status strip shows skeletons, not em dashes, until /api/dashboard returns."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
SKELETON = (
    '<span class="skel-bar" aria-hidden="true"></span>'
    '<span class="sr-only">Loading</span>'
)
TILES = ("k-open", "k-crit", "k-inc", "k-events")


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


class StripSkeletonTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        dash = read("dashboard.js")
        fmt = re.search(r"^const fmtN = .*;$", dash, re.M)
        self.assertIsNotNone(fmt)
        self.script = "\n".join([
            fmt.group(0),
            function_body(dash, "boardColumn"),
            function_body(dash, "stripDashboardTiles"),
            function_body(dash, "stripIncidentTile"),
            """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const tiles = stripDashboardTiles(input.summary);
const incidents = stripIncidentTile(input.incidents);
process.stdout.write(JSON.stringify({ tiles, incidents }));
""",
        ])

    def run_tiles(self, summary, incidents):
        out = subprocess.run(
            [self.node, "-e", self.script],
            input=json.dumps({"summary": summary, "incidents": incidents}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_missing_dashboard_is_three_skeletons_and_not_em_dashes(self):
        for summary in (None,):
            got = self.run_tiles(summary, {"state": "loading"})
            for name in ("open", "critical", "stored"):
                self.assertTrue(got["tiles"][name]["loading"])
                self.assertNotIn("text", got["tiles"][name])
            self.assertFalse(got["tiles"]["critical"]["hot"])
            self.assertTrue(got["incidents"]["loading"])
            self.assertFalse(got["incidents"]["dim"])
            self.assertNotIn("—", json.dumps(got))

    def test_dashboard_numbers_replace_the_skeletons_and_critical_can_run_hot(self):
        summary = {
            "alerts_open": 4,
            "alerts_investigating": 1,
            "alerts_critical_open": 2,
            "events_total": 40,
        }
        got = self.run_tiles(summary, {
            "state": "ok",
            "list": [{"status": "open"}, {"status": "resolved"}, {"status": "investigating"}],
        })
        self.assertEqual(got["tiles"]["open"], {"loading": False, "text": "5"})
        self.assertEqual(got["tiles"]["critical"]["text"], "2")
        self.assertTrue(got["tiles"]["critical"]["hot"])
        self.assertEqual(got["tiles"]["stored"]["text"], "40")
        self.assertEqual(got["incidents"], {"loading": False, "text": "2", "dim": False, "title": ""})

        quiet = self.run_tiles({
            "alerts_open": 0, "alerts_investigating": 0,
            "alerts_critical_open": 0, "events_total": 0,
        }, {"state": "pending"})
        self.assertFalse(quiet["tiles"]["critical"]["hot"])
        self.assertEqual(quiet["tiles"]["open"]["text"], "0")
        self.assertEqual(quiet["incidents"]["text"], "pending")
        self.assertTrue(quiet["incidents"]["dim"])
        self.assertIn("/api/incidents", quiet["incidents"]["title"])

    def test_an_incidents_error_keeps_the_last_value(self):
        got = self.run_tiles(None, {"state": "error", "error": "offline"})
        self.assertTrue(got["incidents"]["keep"])
        self.assertTrue(got["incidents"]["dim"])
        self.assertNotIn("text", got["incidents"])


class StripSkeletonMarkupTests(unittest.TestCase):
    def test_the_four_em_dash_tiles_start_as_skeletons(self):
        html = read("index.html")
        for tile_id in TILES:
            with self.subTest(tile_id=tile_id):
                token = f'id="{tile_id}"'
                start = html.index(token)
                end = html.index("</span>", html.index("</span>", start) + 1)
                chunk = html[html.rindex("<span", 0, start):end + len("</span>")]
                self.assertIn('class="tv skel"', chunk)
                self.assertIn('aria-busy="true"', chunk)
                self.assertIn(SKELETON, chunk)
                self.assertNotIn("—", chunk)
        # Events / min is a live counter, not one of the em dashes.
        epm = html[html.index('id="k-epm"') - 40:html.index('id="k-epm"') + 20]
        self.assertIn(">0<", epm)
        self.assertNotIn("skel", epm)

    def test_render_strip_paints_skeletons_until_the_dashboard_returns(self):
        src = read("dashboard.js")
        body = method_body(src, "renderStrip")
        self.assertIn("const tiles = stripDashboardTiles(d);", body)
        self.assertIn('applyStripTile($("#k-open"), tiles.open);', body)
        self.assertIn('applyStripTile($("#k-crit"), tiles.critical);', body)
        self.assertIn('applyStripTile($("#k-events"), tiles.stored);', body)
        self.assertIn('applyStripTile($("#k-inc"), stripIncidentTile(this.incidents));', body)
        self.assertIn('classList.toggle("hot", !!tiles.critical.hot)', body)
        apply = function_body(src, "applyStripTile")
        self.assertIn('setAttribute("aria-busy", "true")', apply)
        self.assertIn('removeAttribute("aria-busy")', apply)
        self.assertIn('classList.toggle("skel", tile.loading === true)', apply)
        self.assertIn("node.textContent = tile.text", apply)
        self.assertLess(apply.index("if (tile.keep)"), apply.index("node.textContent = tile.text"))
        css = read("style.css")
        self.assertIn(".tv.skel { display: flex; align-items: center; min-height: 1.1em; }", css)
        self.assertIn(".skel-bar { display: block;", css)
        self.assertIn("background: rgb(255 255 255 / .18);", css)
        motion = css.index("@media (prefers-reduced-motion: no-preference)")
        self.assertLess(css.index(".skel-bar { display: block;"), motion)


if __name__ == "__main__":
    unittest.main()
