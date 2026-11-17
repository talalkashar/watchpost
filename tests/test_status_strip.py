"""Phone status strip: Events/min, open alerts, critical, and incidents share two columns."""

import re
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"


def read(name):
    return (STATIC / name).read_text()


def media_bodies(css, query):
    """Bodies of @media rules whose prelude contains query. One level of nesting is enough."""
    bodies = []
    for match in re.finditer(r"@media\s*([^{]+)\{", css):
        if query not in match.group(1):
            continue
        start = match.end()
        depth = 1
        i = start
        while i < len(css) and depth:
            if css[i] == "{":
                depth += 1
            elif css[i] == "}":
                depth -= 1
            i += 1
        bodies.append(css[start:i - 1])
    return bodies


class StatusStripPhoneTests(unittest.TestCase):
    def test_the_grid_holds_events_open_alerts_critical_and_incidents(self):
        html = read("index.html")
        start = html.index('<div class="strip-kpis">')
        stored = html.index('<span class="tl">Stored</span>', start)
        chunk = html[start:stored]
        self.assertEqual(
            re.findall(r'class="tl">([^<]+)', chunk),
            ["Events / min", "Open alerts", "Critical", "Incidents"])
        self.assertEqual(chunk.count("<div"), chunk.count("</div>") + 1)
        self.assertIn('id="k-epm"', chunk)
        self.assertIn('id="k-open"', chunk)
        self.assertIn('id="k-crit"', chunk)
        self.assertIn('id="k-inc"', chunk)
        self.assertNotIn('id="k-events"', chunk)

    def test_wider_screens_keep_the_tiles_in_the_strip_flex_row(self):
        css = read("style.css")
        outside = css
        for body in media_bodies(css, ""):
            outside = outside.replace(body, "", 1)
        self.assertIn(".strip-kpis { display: contents; }", outside)
        self.assertNotIn("grid-template-columns: minmax(0, 1fr) minmax(0, 1fr)", outside)

    def test_under_390px_the_four_kpis_are_two_equal_columns(self):
        bodies = media_bodies(read("style.css"), "max-width: 390px")
        self.assertEqual(len(bodies), 1)
        body = bodies[0]
        self.assertIn("display: grid", body)
        self.assertIn("grid-template-columns: minmax(0, 1fr) minmax(0, 1fr)", body)
        self.assertIn("flex: 1 0 100%", body)
        self.assertIn(".strip-kpis > .tile { min-width: 0;", body)
        self.assertIn(".strip-kpis .tl { white-space: normal; }", body)
        self.assertIn(".strip-kpis .tv { overflow-wrap: anywhere; }", body)
        # The 112px spark must shrink inside its column instead of widening the row.
        self.assertIn(".strip-kpis .t-epm { grid-template-columns: auto minmax(0, 1fr); }", body)
        self.assertIn(".strip-kpis .t-epm .spark svg { display: block; width: 100%; height: 28px; }", body)
        self.assertIn("min-width: 0", body)


if __name__ == "__main__":
    unittest.main()
