"""Entity page: alerts per UTC day across the entity's stored event window."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema, iso, parse_iso

STATIC = Path(__file__).resolve().parent.parent / "static"
ANCHOR = "2026-09-15T12:00:00.000Z"


def day(offset):
    return iso(parse_iso(ANCHOR) + timedelta(days=offset))


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class AlertDayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = connect(os.path.join(self.tmp.name, "t.db"))
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_counts_each_alert_on_its_newest_evidence_day_and_keeps_gaps(self):
        early = add_event(self.conn, day(-2), src_ip="203.0.113.45")
        later = add_event(self.conn, ANCHOR, src_ip="203.0.113.45")
        add_event(self.conn, day(-1), src_ip="203.0.113.45")  # stored day with no alert
        add_alert(self.conn, "high", day(-2), [early])
        add_alert(self.conn, "critical", ANCHOR, [early, later])  # spans two days; counts on the later one
        add_alert(self.conn, "low", ANCHOR, [later])
        other = add_event(self.conn, ANCHOR, src_ip="198.51.100.7")
        add_alert(self.conn, "high", ANCHOR, [other])

        series = entities.get_entity(self.conn, "src_ip", "203.0.113.45")["alerts_by_day"]
        self.assertEqual(series["start"], "2026-09-13")
        self.assertEqual(series["end"], "2026-09-15")
        self.assertEqual(series["days"], [
            {"day": "2026-09-13", "count": 1},
            {"day": "2026-09-14", "count": 0},
            {"day": "2026-09-15", "count": 2},
        ])
        self.assertEqual(sum(d["count"] for d in series["days"]), 3)

    def test_accounts_match_case_insensitively(self):
        event = add_event(self.conn, ANCHOR, user="Alice")
        add_alert(self.conn, "medium", ANCHOR, [event])
        series = entities.get_entity(self.conn, "user", "ALICE")["alerts_by_day"]
        self.assertEqual(series["days"], [{"day": "2026-09-15", "count": 1}])

    def test_unknown_entity_has_no_days(self):
        series = entities.get_entity(self.conn, "host", "missing")["alerts_by_day"]
        self.assertEqual(series, {"start": None, "end": None, "days": [], "omitted": 0})

    def test_a_long_window_keeps_the_newest_month(self):
        old = add_event(self.conn, day(-40), host="web01")
        fresh = add_event(self.conn, ANCHOR, host="web01")
        add_alert(self.conn, "low", day(-40), [old])
        add_alert(self.conn, "high", ANCHOR, [fresh])
        series = entities.get_entity(self.conn, "host", "web01")["alerts_by_day"]
        self.assertEqual(len(series["days"]), entities._DAY_BARS)
        self.assertEqual(series["end"], "2026-09-15")
        self.assertEqual(series["days"][0]["day"], "2026-08-16")
        self.assertEqual(series["days"][-1], {"day": "2026-09-15", "count": 1})
        self.assertNotIn("2026-08-06", [d["day"] for d in series["days"]])
        self.assertEqual(sum(d["count"] for d in series["days"]), 1)
        self.assertEqual(series["omitted"], 1)


class DemoEntityDayTests(ServerTestCase):
    def test_demo_entity_bars_sum_to_its_alerts(self):
        self.assertEqual(self.client("admin").post("/api/demo/load", {})[0], 200)
        viewer = self.client("viewer")
        status, detail, _ = viewer.get("/api/entities/src_ip/203.0.113.45")
        self.assertEqual(status, 200)
        series = detail["alerts_by_day"]
        self.assertEqual(series["days"], [{"day": series["start"], "count": len(detail["alerts"])}])
        self.assertGreater(series["days"][0]["count"], 0)
        self.assertTrue(detail["synthetic"])
        # ops-admin's office mornings span three stored days; the outside alert sits on the last one.
        account = viewer.get("/api/entities/user/ops-admin")[1]
        days = account["alerts_by_day"]["days"]
        self.assertEqual(len(days), 3)
        self.assertEqual(sum(d["count"] for d in days), len(account["alerts"]))
        self.assertGreater(days[-1]["count"], 0)
        self.assertEqual(days[0]["count"], 0)


class AlertDayBarTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def bars(self, series):
        script = function_body(self.app, "entityAlertBars") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(entityAlertBars(input)));
"""
        out = subprocess.run(
            [self.node, "-e", script], input=json.dumps(series),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_bars_scale_to_the_busiest_day_and_name_the_window(self):
        model = self.bars({"days": [
            {"day": "2026-09-13", "count": 1},
            {"day": "2026-09-14", "count": 0},
            {"day": "2026-09-15", "count": 2},
        ]})
        self.assertFalse(model["empty"])
        self.assertEqual([b["count"] for b in model["bars"]], [1, 0, 2])
        self.assertEqual([b["share"] for b in model["bars"]], [0.5, 0, 1])
        self.assertEqual(model["note"], "3 alerts across 3 days, 2026-09-13 to 2026-09-15.")
        self.assertIn("2026-09-14 0", model["label"])

    def test_one_alert_on_one_day_uses_the_singular(self):
        model = self.bars({"days": [{"day": "2026-09-15", "count": 1}]})
        self.assertEqual(model["note"], "1 alert across 1 day, 2026-09-15.")
        self.assertEqual(model["bars"][0]["share"], 1)

    def test_older_alerts_outside_the_drawn_window_are_named(self):
        model = self.bars({"omitted": 2, "days": [{"day": "2026-09-15", "count": 1}]})
        self.assertIn("2 older alerts are outside this window.", model["note"])

    def test_a_missing_series_is_an_empty_chart(self):
        for series in (None, {}, {"days": []}, {"days": [{"day": "nope", "count": 4}]}):
            model = self.bars(series)
            self.assertTrue(model["empty"])
            self.assertEqual(model["note"], "No stored events for this entity.")
            self.assertEqual(model["bars"], [])

    def test_the_entity_page_draws_the_chart_from_the_payload(self):
        detail = function_body(self.app, "entityDetail")
        self.assertIn("entityDayChart(e.alerts_by_day)", detail)
        chart = function_body(self.app, "entityDayChart")
        self.assertIn('id: "entity-days"', chart)
        self.assertIn('class: "sr-only"', chart)
        self.assertIn('"aria-label": model.label', chart)
        self.assertIn("day-chart", chart)
        self.assertIn("e.alerts_by_day", self.app)


if __name__ == "__main__":
    unittest.main()
