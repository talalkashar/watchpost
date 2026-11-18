"""The alerts queue opens on open critical and high, names that filter, and resets in one click."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.queries import QueryError, list_alerts

STATIC = Path(__file__).resolve().parent.parent / "static"
NOW = "2026-09-15T10:00:00.000Z"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


def add_alert(conn, alert_id, severity, status):
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
        (alert_id, "synthetic_rule", f"g{alert_id}", severity, "synthetic alert", "synthetic", status,
         NOW, NOW, NOW, NOW))


class AlertListFilterTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_alert(self.conn, 1, "critical", "open")
        add_alert(self.conn, 2, "high", "open")
        add_alert(self.conn, 3, "medium", "open")
        add_alert(self.conn, 4, "low", "open")
        add_alert(self.conn, 5, "critical", "investigating")
        add_alert(self.conn, 6, "critical", "resolved")
        add_alert(self.conn, 7, "high", "resolved")

    def ids(self, **params):
        return [row["id"] for row in list_alerts(self.conn, params)]

    def test_open_critical_and_high_is_the_working_queue(self):
        self.assertEqual(self.ids(status="open", severity="critical,high"), [1, 2])

    def test_a_single_severity_still_matches_every_status(self):
        self.assertEqual(self.ids(severity="high"), [2, 7])

    def test_a_comma_list_keeps_spaces_and_rejects_an_unknown_level(self):
        self.assertEqual(set(self.ids(severity=" high , critical ")), {1, 2, 5, 6, 7})
        for bad in ("urgent", "critical,urgent", "critical,", ","):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryError):
                    list_alerts(self.conn, {"severity": bad})


class AlertQueueLabelTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def run_js(self, payload):
        words = re.search(r"^const ALERT_STATUS_WORDS = \{.*?^\};$", self.app, re.S | re.M)
        defaults = "\n".join(
            line for line in self.app.splitlines() if line.startswith("const ALERT_QUEUE_"))
        self.assertIsNotNone(words)
        self.assertIn("ALERT_QUEUE_DEFAULT", defaults)
        script = defaults + "\n" + words.group(0) + "\n" + "\n".join(
            function_body(self.app, name) for name in (
                "alertQueueParams", "alertQueueLabel", "alertQueueCanReset")) + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const params = alertQueueParams(input.saved);
process.stdout.write(JSON.stringify({
  query: params.toString(),
  label: alertQueueLabel(params),
  reset: alertQueueCanReset(params),
}));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps(payload),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_first_visit_names_open_critical_and_high_and_can_reset(self):
        shown = self.run_js({"saved": None})
        self.assertEqual(shown["query"], "status=open&severity=critical%2Chigh")
        self.assertEqual(shown["label"], "Showing open critical and high")
        self.assertTrue(shown["reset"])
        self.assertEqual(self.run_js({"saved": ""})["label"],
                         "Showing open critical and high")

    def test_reset_shows_every_alert_and_hides_the_button(self):
        shown = self.run_js({"saved": "all"})
        self.assertEqual(shown["query"], "")
        self.assertEqual(shown["label"], "Showing all alerts")
        self.assertFalse(shown["reset"])

    def test_other_filters_stay_visible(self):
        active = self.run_js({"saved": "status=open,investigating&severity=critical,high"})
        self.assertEqual(active["label"], "Showing active critical, high")
        self.assertTrue(active["reset"])
        resolved = self.run_js({"saved": "status=resolved"})
        self.assertEqual(resolved["label"], "Showing resolved")
        ruled = self.run_js({"saved": "rule_id=brute_force_ip"})
        self.assertEqual(ruled["label"], "Showing rule brute_force_ip")
        self.assertTrue(ruled["reset"])


class AlertQueueViewTests(unittest.TestCase):
    def test_the_page_paints_the_label_and_a_reset_before_the_table(self):
        app = read("app.js")
        body = function_body(app, "alerts")
        self.assertIn("alertQueueParams(alertQueueSaved())", body)
        self.assertIn("alertQueueLabel(params)", body)
        self.assertIn('id: "alert-filter"', body)
        self.assertIn('id: "alert-filter-reset"', body)
        self.assertIn('"Reset"', body)
        self.assertIn('["critical,high", "Critical and high"]', body)
        self.assertIn("storeAlertFilter(ALERT_QUEUE_ALL)", body)
        self.assertIn("storeAlertFilter(p.toString() || ALERT_QUEUE_ALL)", body)
        self.assertLess(body.index('id: "alert-filter"'), body.index('name: "status"'))
        self.assertIn("filterNote", body)
        self.assertLess(body.index("filterNote"), body.index("list.map"))
        css = read("style.css")
        self.assertIn("#alert-filter {", css)
        self.assertIn("#alert-filter-reset {", css)
