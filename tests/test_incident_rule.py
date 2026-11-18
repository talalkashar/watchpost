"""Incident detail states the correlation rule beside the source IP, account, and host lists."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from watchpost import correlate, incidents
from watchpost.db import connect, init_schema

STATIC = Path(__file__).resolve().parent.parent / "static"
RULE = (
    "Alerts that share a source IP, account, or host within "
    "30 minutes are grouped into this incident."
)


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class CorrelationRuleTests(unittest.TestCase):
    def test_the_default_window_is_thirty_minutes_in_plain_text(self):
        self.assertEqual(correlate.DEFAULT_WINDOW_SECONDS, 30 * 60)
        self.assertEqual(correlate.rule_summary(), RULE)
        self.assertEqual(
            correlate.rule_summary(600),
            "Alerts that share a source IP, account, or host within 10 minutes are grouped into this incident.")

    def test_incident_detail_carries_that_sentence_with_the_entities(self):
        conn = connect(":memory:")
        init_schema(conn)
        now = "2026-09-15T10:00:00.000Z"
        conn.execute(
            "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
            " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("Synthetic probe", "high", "open", now, now,
             json.dumps({"src_ip": ["203.0.113.10"], "user": ["erin"], "host": ["web01"]}),
             json.dumps(["Initial Access"]), 2, 1, now, now))
        detail = incidents.get_incident(conn, 1)
        conn.close()
        self.assertEqual(detail["correlation_rule"], RULE)
        self.assertEqual(detail["entities"]["src_ip"], ["203.0.113.10"])
        self.assertEqual(detail["entities"]["user"], ["erin"])
        self.assertEqual(detail["entities"]["host"], ["web01"])


class CorrelationRulePageTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def rule(self, incident):
        script = function_body(self.app, "correlationRule") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(correlationRule(input)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps(incident),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_server_sentence_is_shown_and_a_blank_one_falls_back(self):
        self.assertEqual(self.rule({"correlation_rule": RULE}), RULE)
        self.assertEqual(self.rule({"correlation_rule": "  " + RULE + "  "}), RULE)
        for missing in ({}, {"correlation_rule": ""}, {"correlation_rule": "   "}, {"correlation_rule": 30}, None):
            self.assertEqual(self.rule(missing), RULE)

    def test_the_sentence_sits_above_the_entity_list(self):
        detail = function_body(self.app, "incidentDetail")
        rule = detail.index('id: "correlation-rule"')
        note = detail.index("correlationRule(i)")
        ips = detail.index('["Source IPs"')
        accounts = detail.index('["Accounts"')
        hosts = detail.index('["Hosts"')
        assignee = detail.index('["Assignee"')
        self.assertLess(detail.index('["Last seen"'), rule)
        self.assertLess(rule, note)
        self.assertLess(note, ips)
        self.assertLess(ips, accounts)
        self.assertLess(accounts, hosts)
        self.assertLess(hosts, assignee)
        css = read("style.css")
        self.assertIn(".entity-rule { margin: 10px 0 8px; font-size: 13px; line-height: 1.45; }", css)


if __name__ == "__main__":
    unittest.main()
