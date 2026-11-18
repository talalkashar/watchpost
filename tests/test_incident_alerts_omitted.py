"""Incident detail pages the earliest 200 linked alerts and says how many were left out.

`alerts` and `timeline` stay the earliest 200 by first_seen, then id. A later first_seen
on a lower id is the one past the cap. alerts_omitted is 0 when the incident has 200 or
fewer, including none. Techniques, stages, and severity still come from every linked alert.
The case export and the incident report still list the alert the page left out.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import attack, case_record, report
from watchpost.db import connect, init_schema, iso
from watchpost.engine import seed_rules
from watchpost.incidents import INCIDENT_ALERT_LIMIT, get_incident

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
EARLY = iso(BASE)
LATER = iso(BASE + timedelta(hours=2))
STAGES = ["Reconnaissance", "Initial Access", "Exfiltration"]


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_rule(conn, rule_id, technique_id):
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
        " updated_by, techniques) VALUES (?,?,?,?,1,'{}',1,?,?,?)",
        (rule_id, rule_id, "synthetic", "medium", EARLY, "test",
         json.dumps([attack.technique(technique_id)])))


def add_alert(conn, rule_id, first_seen, severity="medium"):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,0,1,?,?)",
        (rule_id, 1, "web01", severity, "[SYNTHETIC] alert", "synthetic", "open",
         first_seen, first_seen, first_seen, first_seen))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_incident(conn, alert_ids, severity="critical"):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("Synthetic probe", severity, "open", EARLY, LATER,
         json.dumps({"src_ip": [], "user": [], "host": ["web01"]}),
         json.dumps(STAGES), len(alert_ids), 1, EARLY, EARLY))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, EARLY) for alert_id in alert_ids])
    return incident_id


class IncidentAlertsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        # Real rules, so the case export can grade techniques. web_scanner names T1190.
        # data_exfil_volume names T1048.
        seed_rules(self.conn)

    def test_a_later_alert_with_a_lower_id_is_the_one_left_out(self):
        # Lower id, later first_seen. Order is first_seen, then id, so this row is past the cap.
        late_id = add_alert(self.conn, "data_exfil_volume", LATER, severity="critical")
        early_ids = [add_alert(self.conn, "web_scanner", EARLY) for _ in range(INCIDENT_ALERT_LIMIT)]
        incident_id = add_incident(self.conn, [late_id] + early_ids)

        detail = get_incident(self.conn, incident_id)
        self.assertEqual([row["id"] for row in detail["alerts"]], early_ids)
        self.assertEqual([row["alert_id"] for row in detail["timeline"]], early_ids)
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["alerts"]})
        self.assertEqual(detail["timeline"][0]["techniques"], ["T1595.002", "T1595.003", "T1190"])
        self.assertEqual(detail["timeline"][0]["tactics"], ["Reconnaissance", "Initial Access"])

        # The page dropped the exfil alert. Its technique, the stored stages, and the severity stay.
        exfil = next(row for row in detail["techniques"] if row["id"] == "T1048")
        self.assertEqual(exfil["alert_ids"], [late_id])
        self.assertEqual(exfil["tactic"], "Exfiltration")
        access = next(row for row in detail["techniques"] if row["id"] == "T1190")
        self.assertEqual(access["alert_ids"], early_ids)
        by_tactic = {group["tactic"]: [t["id"] for t in group["techniques"]]
                     for group in detail["techniques_by_tactic"]}
        self.assertEqual(by_tactic["Exfiltration"], ["T1048"])
        self.assertEqual(by_tactic["Initial Access"], ["T1190"])
        self.assertEqual(detail["stages"], STAGES)
        self.assertEqual(detail["severity"], "critical")
        self.assertTrue(detail["escalated"])

        case = case_record.build(self.conn, incident_id)
        self.assertEqual([row["id"] for row in case["alerts"]], early_ids + [late_id])
        self.assertIn(late_id, {item["alert_id"] for item in case["timeline"] if item["type"] == "alert_added"})

        model = report.build(self.conn, incident_id)
        self.assertEqual([row["id"] for row in model["alerts"]], early_ids + [late_id])
        self.assertEqual(model["severity"], "critical")
        self.assertEqual(model["stages"], STAGES)

    def test_the_same_first_seen_keeps_the_lower_ids(self):
        ids = [add_alert(self.conn, "web_scanner", EARLY) for _ in range(INCIDENT_ALERT_LIMIT + 1)]
        detail = get_incident(self.conn, add_incident(self.conn, ids))
        self.assertEqual([row["id"] for row in detail["alerts"]], ids[:INCIDENT_ALERT_LIMIT])
        self.assertEqual([row["alert_id"] for row in detail["timeline"]], ids[:INCIDENT_ALERT_LIMIT])
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertNotIn(ids[-1], {row["id"] for row in detail["alerts"]})
        access = next(row for row in detail["techniques"] if row["id"] == "T1190")
        self.assertEqual(access["alert_ids"], ids)

    def test_a_short_incident_an_exact_cap_and_none_omit_nothing(self):
        one = add_incident(self.conn, [add_alert(self.conn, "web_scanner", EARLY)])
        exact_ids = [add_alert(self.conn, "web_scanner", EARLY) for _ in range(INCIDENT_ALERT_LIMIT)]
        exact = add_incident(self.conn, exact_ids)
        empty = add_incident(self.conn, [])

        short = get_incident(self.conn, one)
        self.assertEqual(len(short["alerts"]), 1)
        self.assertEqual(len(short["timeline"]), 1)
        self.assertEqual(short["alerts_omitted"], 0)
        self.assertIn("T1190", [row["id"] for row in short["techniques"]])

        exact_detail = get_incident(self.conn, exact)
        self.assertEqual(len(exact_detail["alerts"]), INCIDENT_ALERT_LIMIT)
        self.assertEqual(len(exact_detail["timeline"]), INCIDENT_ALERT_LIMIT)
        self.assertEqual(exact_detail["alerts_omitted"], 0)

        none = get_incident(self.conn, empty)
        self.assertEqual(none["alerts"], [])
        self.assertEqual(none["timeline"], [])
        self.assertEqual(none["alerts_omitted"], 0)
        self.assertEqual(none["techniques"], [])
        self.assertEqual(none["severity"], "critical")
        self.assertEqual(none["stages"], STAGES)

    def test_the_docs_name_the_cap_and_say_the_rest_still_count(self):
        text = API.read_text()
        self.assertIn(
            "`alerts` (the earliest 200 linked alerts by `first_seen`, then `id`, each with `techniques`),"
            " `alerts_omitted` (how many linked alerts were past that cap;"
            " 0 when the incident has 200 or fewer, including none)",
            text)
        self.assertIn(
            "`timeline` (one entry per shown alert, the same earliest 200, with tactics and technique ids),"
            " `techniques` (from every linked alert, including ones left out of `alerts`)",
            text)
        self.assertIn(
            "`severity` and `stages` stay the incident's, from every linked alert, not only the 200 shown",
            text)
        reference = REFERENCE.read_text()
        self.assertIn("earliest 200 linked alerts", reference)
        self.assertIn("That page is `ORDER BY a.first_seen, a.id LIMIT`", reference)
        self.assertIn("not from the page", reference)
        self.assertIn("case export and the incident report still list every linked alert", reference)
        row = next(line for line in text.splitlines() if line.startswith("| `GET /api/incidents/{id}`"))
        self.assertIn("The alert page is `ORDER BY a.first_seen, a.id LIMIT`", row)
        self.assertIn("Technique `alert_ids` still name every linked alert", row)

    def test_the_page_query_uses_limit_and_techniques_read_every_link(self):
        # Two alerts both fit on the page. The page statement is still LIMIT, and the
        # technique statement has no LIMIT, so an alert past the page is still read.
        late_id = add_alert(self.conn, "data_exfil_volume", LATER)
        early_id = add_alert(self.conn, "web_scanner", EARLY)
        incident_id = add_incident(self.conn, [late_id, early_id])
        calls = []
        real = self.conn.execute

        def execute(sql, params=()):
            calls.append((" ".join(sql.split()), params))
            return real(sql, params)

        self.conn.execute = execute
        try:
            detail = get_incident(self.conn, incident_id)
        finally:
            self.conn.execute = real

        pages = [call for call in calls if call[0].startswith("SELECT a.*")]
        self.assertEqual(len(pages), 1)
        self.assertIn("ORDER BY a.first_seen, a.id LIMIT ?", pages[0][0])
        self.assertEqual(pages[0][1], (incident_id, INCIDENT_ALERT_LIMIT))
        links = [call for call in calls if call[0].startswith("SELECT a.id, a.rule_id")]
        self.assertEqual(len(links), 1)
        self.assertNotIn("LIMIT", links[0][0])
        self.assertIn("ORDER BY a.first_seen, a.id", links[0][0])
        self.assertEqual(links[0][1], (incident_id,))
        self.assertEqual([row["id"] for row in detail["alerts"]], [early_id, late_id])
        self.assertEqual(detail["alerts_omitted"], 0)
        exfil = next(row for row in detail["techniques"] if row["id"] == "T1048")
        self.assertEqual(exfil["alert_ids"], [late_id])
        access = next(row for row in detail["techniques"] if row["id"] == "T1190")
        self.assertEqual(access["alert_ids"], [early_id])
        source = Path(__file__).resolve().parent.parent.joinpath("watchpost", "incidents.py").read_text()
        self.assertNotIn("alerts[:INCIDENT_ALERT_LIMIT]", source)


class IncidentAlertsOmittedApiTests(ServerTestCase):
    def test_incident_detail_reports_the_dropped_alert(self):
        conn = connect(self.db_path)
        try:
            add_rule(conn, "access", "T1190")
            add_rule(conn, "exfil", "T1048")
            late_id = add_alert(conn, "exfil", LATER, severity="critical")
            early_ids = [add_alert(conn, "access", EARLY) for _ in range(INCIDENT_ALERT_LIMIT)]
            incident_id = add_incident(conn, [late_id] + early_ids)
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/incidents/{incident_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["alerts"]], early_ids)
        self.assertEqual([row["alert_id"] for row in detail["timeline"]], early_ids)
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(detail["severity"], "critical")
        self.assertEqual(detail["stages"], STAGES)
        exfil = next(row for row in detail["techniques"] if row["id"] == "T1048")
        self.assertEqual(exfil["alert_ids"], [late_id])
        self.assertEqual(detail["alerts"][0]["title"], "[SYNTHETIC] alert")
        self.assertEqual(detail["alerts"][0]["synthetic"], 1)

        denied, body, _ = self.client().get(f"/api/incidents/{incident_id}")
        self.assertEqual(denied, 401)
        self.assertNotIn("alerts_omitted", body)
