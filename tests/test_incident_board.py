"""Incident cards name the earliest ATT&CK technique next to the tactic tags."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from watchpost import attack, incidents
from watchpost.db import connect, init_schema

STATIC = Path(__file__).resolve().parent.parent / "static"
NOW = "2026-09-15T10:00:00.000Z"


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class TopTechniqueTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.add_rule("scan", [attack.technique("T1595.003"), attack.technique("T1190")])
        self.add_rule("later", [attack.technique("T1048")])
        self.add_rule("empty", [])
        self.add_incident(1, "open")
        self.add_alert(1, "scan", 1)
        self.add_alert(2, "later", 1)
        self.add_incident(2, "investigating")
        self.add_alert(3, "empty", 2)

    def tearDown(self):
        self.conn.close()

    def add_rule(self, rule_id, techniques):
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
            " updated_by, techniques) VALUES (?,?,?,?,1,'{}',1,?,?,?)",
            (rule_id, rule_id, "synthetic", "medium", NOW, "test", json.dumps(techniques)))

    def add_incident(self, incident_id, status):
        self.conn.execute(
            "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
            " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,1,1,?,?)",
            (incident_id, f"Synthetic incident {incident_id}", "high", status, NOW, NOW,
             json.dumps({"src_ip": [], "user": [], "host": []}),
             json.dumps(["Reconnaissance", "Initial Access", "Exfiltration"]), NOW, NOW))

    def add_alert(self, alert_id, rule_id, incident_id):
        self.conn.execute(
            "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
            " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
            (alert_id, rule_id, f"g{alert_id}", "high", "synthetic alert", "synthetic", "open",
             NOW, NOW, NOW, NOW))
        self.conn.execute(
            "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
            (alert_id, incident_id, NOW))

    def test_earliest_kill_chain_technique_wins_and_id_breaks_ties(self):
        # T1595.003 and T1190 share the scan rule; T1190 is Initial Access, after Reconnaissance.
        # T1048 is Exfiltration. The card leads with the recon id.
        listed = {item["id"]: item["top_technique"] for item in incidents.list_incidents(self.conn, {})}
        self.assertEqual(listed[1], {
            "id": "T1595.003",
            "name": "Active Scanning: Wordlist Scanning",
            "tactic": "Reconnaissance",
        })
        self.assertIsNone(listed[2])

    def test_same_tactic_picks_the_lower_technique_id(self):
        self.add_rule("peer", [attack.technique("T1595.002")])
        self.add_alert(4, "peer", 1)
        top = incidents.top_techniques(self.conn, [1])[1]
        self.assertEqual(top["id"], "T1595.002")


class IncidentBoardTagTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.source = (STATIC / "dashboard.js").read_text()

    def tags(self, tactics, technique):
        script = function_body(self.source, "techniqueRef") + "\n" + function_body(self.source, "boardTags") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(boardTags(input.tactics, input.technique)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"tactics": tactics, "technique": technique}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_technique_id_sits_ahead_of_four_tactic_tags(self):
        tags = self.tags(
            ["Reconnaissance", "Initial Access", "Persistence", "Privilege Escalation", "Exfiltration"],
            {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance"})
        self.assertEqual(tags[0], {
            "kind": "tech", "id": "T1595.002",
            "name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance"})
        self.assertEqual([t["text"] for t in tags[1:]],
                         ["Reconnaissance", "Initial Access", "Persistence", "Privilege Escalation"])
        self.assertNotIn("Exfiltration", [t.get("text") for t in tags])

    def test_missing_technique_leaves_tactic_tags_only(self):
        self.assertEqual(self.tags(["Impact"], None), [{"kind": "tactic", "text": "Impact"}])
        self.assertEqual(self.tags([], {}), [])

    def test_card_renders_the_technique_tag_beside_tactics(self):
        board = function_body(self.source, "incidentBoard")
        self.assertIn("boardTags(i.tactics, i.top_technique)", board)
        self.assertIn('class: "tag tech"', board)
        self.assertIn("techniqueTagTitle(t)", board)
        css = (STATIC / "style.css").read_text() + (STATIC / "views.css").read_text()
        self.assertIn(".tag.tech", css)


if __name__ == "__main__":
    unittest.main()
