import json
import unittest

from tests.pdfparse import ParsedPDF
from watchpost import engine, incidents, queries, report, simulate
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload


def demo_conn():
    conn = connect(":memory:")
    init_schema(conn)
    engine.seed_rules(conn)
    for name, events in simulate.build(seed=7).items():
        normalized, rejections = parse_payload(json.dumps(events), "json", f"demo:{name}")
        engine.ingest(conn, normalized, rejections, f"demo:{name}", "json", "test", synthetic=True)
    return conn


def alert_id(conn, rule_id, group_key=None):
    sql, args = "SELECT id FROM alerts WHERE rule_id = ?", [rule_id]
    if group_key:
        sql, args = sql + " AND group_key = ?", args + [group_key]
    return conn.execute(sql + " ORDER BY id LIMIT 1", args).fetchone()[0]


def incident_for(conn, alert):
    return conn.execute("SELECT incident_id FROM incident_alerts WHERE alert_id = ?", (alert,)).fetchone()[0]


class AlertReportTests(unittest.TestCase):
    def setUp(self):
        self.conn = demo_conn()
        self.id = alert_id(self.conn, "success_after_failures", "dave|192.0.2.77")
        queries.add_note(self.conn, self.id, "analyst", "Reset dave's password | checked <VPN> logs.")

    def tearDown(self):
        self.conn.close()

    def test_model(self):
        m = report.build_from_alert(self.conn, self.id)
        self.assertEqual((m["kind"], m["id"], m["severity"]), ("alert", self.id, "critical"))
        self.assertTrue(m["synthetic"])
        self.assertIn("dave", m["entities"]["users"])
        self.assertIn("192.0.2.77", m["entities"]["ips"])
        self.assertEqual(len(m["alerts"]), 1)
        self.assertEqual(len(m["alerts"][0]["evidence"]), 8)
        self.assertTrue(any(e["is_evidence"] for e in m["timeline"]))
        self.assertEqual(m["timeline"], sorted(m["timeline"], key=lambda e: (e["ts"], e["id"])))
        self.assertEqual(len(m["notes"]), 1)
        self.assertIn("1 alert(s) from 1 detection rule(s)", m["summary"])
        # ATT&CK techniques from the rule metadata, tactics in kill-chain order.
        self.assertEqual({k: [t["id"] for t in v] for k, v in m["techniques_by_tactic"].items()},
                         {"Initial Access": ["T1078"], "Credential Access": ["T1110"]})
        self.assertEqual(list(m["techniques_by_tactic"]), ["Initial Access", "Credential Access"])
        self.assertEqual({t["name"] for t in m["alerts"][0]["techniques"]}, {"Valid Accounts", "Brute Force"})
        self.assertEqual([a["technique"] for a in m["actions"][:3]], ["T1078", "T1078", "T1110"])
        self.assertEqual(m["actions"][-1]["action"], report.FALLBACK_ACTIONS[-1])

    def test_markdown(self):
        text = report.to_markdown(report.build_from_alert(self.conn, self.id))
        self.assertTrue(text.startswith("# Alert report: "))
        for expected in ("SYNTHETIC DATA", "## Summary", "## Entities", "## MITRE ATT&CK techniques",
                         "## Timeline", "## Alerts and evidence", "## Analyst notes", "## Recommended actions",
                         "`success\\_after\\_failures`", "192.0.2.77", "Why it fired:"):
            self.assertIn(expected, text)
        # Log- and analyst-supplied text cannot break tables or inject HTML.
        self.assertIn("Reset dave's password \\| checked \\<VPN\\> logs.", text)
        self.assertNotIn("<VPN>", text)

    def test_pdf(self):
        m = report.build_from_alert(self.conn, self.id)
        data = report.to_pdf_bytes(m)
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        pdf = ParsedPDF(data)
        text = pdf.text()
        self.assertIn(m["title"], text)
        self.assertIn("SYNTHETIC DATA", text)
        self.assertIn("Recommended actions", text)
        self.assertIn(f"Page 1 of {len(pdf.pages())}", text)

    def test_long_report_paginates(self):
        bf = alert_id(self.conn, "brute_force_ip", "203.0.113.45")
        for i in range(60):
            queries.add_note(self.conn, bf, "analyst", f"note {i} " + "detail " * 40)
        m = report.build_from_alert(self.conn, bf)
        pdf = ParsedPDF(report.to_pdf_bytes(m))
        self.assertGreater(len(pdf.pages()), 2)
        self.assertIn("note 59", pdf.text())

    def test_real_data_has_no_banner(self):
        self.conn.execute("UPDATE alerts SET synthetic = 0")
        m = report.build_from_alert(self.conn, self.id)
        self.assertFalse(m["synthetic"])
        self.assertNotIn("SYNTHETIC DATA", report.to_markdown(m))
        self.assertNotIn("SYNTHETIC DATA", ParsedPDF(report.to_pdf_bytes(m)).text())

    def test_missing_alert(self):
        with self.assertRaises(report.ReportError) as ctx:
            report.build_from_alert(self.conn, 999999)
        self.assertEqual(ctx.exception.status, 404)


class IncidentReportTests(unittest.TestCase):
    """Reports built from incidents the correlation engine created during ingestion."""

    def setUp(self):
        self.conn = demo_conn()
        # The cloud intrusion: IAM change, audit trail stopped, then bulk data access by one new principal,
        # five tactics. The logging_disabled alert joins it because it shares the principal and source IP.
        self.exfil = alert_id(self.conn, "data_exfil_volume")
        self.id = incident_for(self.conn, self.exfil)
        self.incident = incidents.get_incident(self.conn, self.id)

    def tearDown(self):
        self.conn.close()

    def test_model_matches_incident(self):
        m = report.build(self.conn, self.id)
        i = self.incident
        self.assertEqual((m["kind"], m["id"], m["title"], m["status"], m["severity"]),
                         ("incident", i["id"], i["title"], "open", "critical"))
        self.assertEqual((m["first_seen"], m["last_seen"]), (i["first_seen"], i["last_seen"]))
        self.assertEqual([a["id"] for a in m["alerts"]], [a["id"] for a in i["alerts"]])
        self.assertIn(self.exfil, [a["id"] for a in m["alerts"]])
        self.assertTrue(m["synthetic"])
        self.assertEqual(m["stages"], ["Initial Access", "Persistence", "Defense Evasion", "Collection",
                                       "Exfiltration"])
        self.assertTrue(m["escalated"])
        self.assertIn("svc-deploy-tmp", m["entities"]["users"])
        self.assertIn("203.0.113.150", m["entities"]["ips"])
        self.assertEqual(len({e["id"] for e in m["timeline"]}), len(m["timeline"]))
        self.assertIn("3 alert(s) from 3 detection rule(s)", m["summary"])
        self.assertIn("Escalated: the alerts span 5 ATT&CK tactics.", m["summary"])

    def test_techniques_by_tactic_from_rule_metadata(self):
        m = report.build(self.conn, self.id)
        by_tactic = m["techniques_by_tactic"]
        # Tactics follow the incident's kill-chain stages; techniques come from the merged rule metadata.
        self.assertEqual(list(by_tactic), self.incident["stages"])
        self.assertEqual({k: [t["id"] for t in v] for k, v in by_tactic.items()},
                         {g["tactic"]: [t["id"] for t in g["techniques"]] for g in self.incident["techniques_by_tactic"]})
        self.assertEqual([t["id"] for t in by_tactic["Exfiltration"]], ["T1048"])
        self.assertEqual(by_tactic["Exfiltration"][0]["alert_ids"], [self.exfil])
        self.assertEqual(by_tactic["Collection"][0]["name"], "Data from Cloud Storage")
        mapped = {a["technique"] for a in m["actions"] if a["technique"]}
        self.assertTrue({"T1078.004", "T1098.001", "T1562.008", "T1530", "T1048"} <= mapped)

    def test_markdown(self):
        text = report.to_markdown(report.build(self.conn, self.id))
        self.assertTrue(text.startswith("# Incident report: Initial Access"))
        for expected in ("SYNTHETIC DATA", f"- **Incident:** #{self.id}",
                         "**Kill-chain stages:** Initial Access -> Persistence -> Defense Evasion -> Collection"
                         " -> Exfiltration"
                         " (escalated: 3 or more tactics)",
                         f"- **Exfiltration:** T1048 Exfiltration Over Alternative Protocol (alert #{self.exfil})",
                         "- **Collection:** T1530 Data from Cloud Storage", "### Alert #", "**T1048:**"):
            self.assertIn(expected, text)
        # Tactic lines appear in kill-chain order.
        positions = [text.index(f"- **{t}:**") for t in self.incident["stages"]]
        self.assertEqual(positions, sorted(positions))

    def test_pdf(self):
        m = report.build(self.conn, self.id)
        pdf = ParsedPDF(report.to_pdf_bytes(m))
        text = pdf.text()
        # Non-Latin-1 characters in the title (arrows, ellipsis) become ASCII in the PDF.
        self.assertIn("Initial Access -> ... -> Exfiltration (5 tactics)", text)
        for expected in ("SYNTHETIC DATA", "MITRE ATT&CK techniques", "T1048", "Exfiltration Over Alternative",
                         f"#{self.exfil}", "escalated: 3 or more tactics", "Recommended actions"):
            self.assertIn(expected, " ".join(text.split()))  # five stages wrap the stage line
        self.assertIn(f"Page 1 of {len(pdf.pages())}", text)

    def test_status_change_and_alert_notes_flow_through(self):
        incidents.update_status(self.conn, self.id, "analyst", "investigating")
        queries.add_note(self.conn, self.exfil, "analyst", "Keys revoked for svc-deploy-tmp.")
        m = report.build(self.conn, self.id)
        self.assertEqual((m["status"], m["assignee"]), ("investigating", "analyst"))
        self.assertIn("Status: investigating.", m["summary"])
        self.assertEqual([(n["body"], n["alert_id"]) for n in m["notes"]],
                         [("Keys revoked for svc-deploy-tmp.", self.exfil)])

    def test_single_tactic_incident_is_not_escalated(self):
        bf = incident_for(self.conn, alert_id(self.conn, "brute_force_ip", "203.0.113.45"))
        m = report.build(self.conn, bf)
        self.assertEqual((m["stages"], m["escalated"]), (["Credential Access"], False))
        self.assertNotIn("escalated", report.to_markdown(m))

    def test_real_data_has_no_banner(self):
        self.conn.execute("UPDATE incidents SET synthetic = 0")
        self.conn.execute("UPDATE alerts SET synthetic = 0")
        m = report.build(self.conn, self.id)
        self.assertFalse(m["synthetic"])
        self.assertNotIn("SYNTHETIC DATA", report.to_markdown(m))

    def test_missing_incident(self):
        with self.assertRaises(report.ReportError) as ctx:
            report.build(self.conn, 999999)
        self.assertEqual((ctx.exception.status, str(ctx.exception)), (404, "incident not found"))

    def test_action_lookup_falls_back_to_parent_technique(self):
        rows = report.actions_for([{"id": "T1110.999", "name": "", "tactic": "Credential Access"}])
        self.assertEqual(rows[0]["technique"], "T1110.999")
        self.assertIn(report.ACTIONS["T1110"][0], [r["action"] for r in rows])


if __name__ == "__main__":
    unittest.main()
