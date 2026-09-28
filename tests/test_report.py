import json
import unittest

from tests.pdfparse import ParsedPDF
from watchpost import engine, queries, report, simulate
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


def add_incident_tables(conn):
    """The shape the correlation workstream adds; reports must work against it when present."""
    conn.executescript("""
        CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, severity TEXT NOT NULL,
            status TEXT NOT NULL, first_seen TEXT, last_seen TEXT, entities TEXT, kill_chain TEXT,
            created_at TEXT, updated_at TEXT);
        CREATE TABLE incident_alerts (incident_id INTEGER NOT NULL, alert_id INTEGER NOT NULL,
            PRIMARY KEY (incident_id, alert_id));
    """)


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
        # No ATT&CK mapping on the rules yet: generic fallback actions.
        self.assertEqual(m["techniques_by_tactic"], {})
        self.assertEqual([a["action"] for a in m["actions"]], report.FALLBACK_ACTIONS)

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
    def setUp(self):
        self.conn = demo_conn()

    def tearDown(self):
        self.conn.close()

    def test_without_incident_tables_is_404(self):
        self.assertFalse(report.incidents_available(self.conn))
        with self.assertRaises(report.ReportError) as ctx:
            report.build(self.conn, 1)
        self.assertEqual(ctx.exception.status, 404)

    def test_incident_with_techniques(self):
        add_incident_tables(self.conn)
        self.conn.execute("ALTER TABLE rules ADD COLUMN techniques TEXT")
        self.conn.execute("UPDATE rules SET techniques = ? WHERE id = 'success_after_failures'", (json.dumps(
            [{"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
             {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}]),))
        self.conn.execute("UPDATE rules SET techniques = ? WHERE id = 'brute_force_ip'", (json.dumps(
            [{"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}]),))
        ids = [alert_id(self.conn, "brute_force_ip", "203.0.113.45"),
               alert_id(self.conn, "success_after_failures", "dave|192.0.2.77")]
        incident = self.conn.execute(
            "INSERT INTO incidents(title, severity, status, first_seen, last_seen, kill_chain) VALUES"
            " ('Credential attack on dave', 'critical', 'open', NULL, NULL, ?)",
            (json.dumps(["Credential Access", "Initial Access"]),)).lastrowid
        self.conn.executemany("INSERT INTO incident_alerts(incident_id, alert_id) VALUES (?, ?)",
                              [(incident, a) for a in ids])
        queries.add_note(self.conn, ids[0], "analyst", "Blocked at the edge.")

        m = report.build(self.conn, incident)
        self.assertEqual((m["kind"], m["title"], m["status"], m["severity"]),
                         ("incident", "Credential attack on dave", "open", "critical"))
        self.assertEqual([a["id"] for a in m["alerts"]], ids)
        self.assertEqual(set(m["techniques_by_tactic"]), {"Initial Access", "Credential Access"})
        self.assertEqual(m["stages"], ["Credential Access", "Initial Access"])
        self.assertIn("203.0.113.45", m["entities"]["ips"])
        self.assertEqual(len({e["id"] for e in m["timeline"]}), len(m["timeline"]))
        techniques = {a["technique"] for a in m["actions"]}
        self.assertTrue({"T1078", "T1110.001"} <= techniques)
        self.assertIn("2 alert(s) from 2 detection rule(s)", m["summary"])

        text = report.to_markdown(m)
        self.assertTrue(text.startswith("# Incident report: Credential attack on dave"))
        self.assertIn("**Credential Access:** T1110.001 Password Guessing", text)
        self.assertIn("Blocked at the edge.", text)
        pdf = ParsedPDF(report.to_pdf_bytes(m))
        self.assertIn("Credential attack on dave", pdf.text())
        self.assertIn("T1078", pdf.text())

        with self.assertRaises(report.ReportError):
            report.build(self.conn, incident + 100)

    def test_action_lookup_falls_back_to_parent_technique(self):
        rows = report.actions_for([{"id": "T1110.999", "name": "", "tactic": "Credential Access"}])
        self.assertEqual(rows[0]["technique"], "T1110.999")
        self.assertIn(report.ACTIONS["T1110"][0], [r["action"] for r in rows])


if __name__ == "__main__":
    unittest.main()
