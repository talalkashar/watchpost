"""Incident rollups name catalog techniques, and assets past the evidence page."""

import json
import unittest

from watchpost import assets, attack, correlate, incidents
from watchpost.db import connect, init_schema

NOW = "2026-09-15T10:00:00.000Z"
LATER = "2026-09-15T11:00:00.000Z"

# Stored before the catalog moved T1562.008. The name and tactic are the old ones on purpose.
_OLD_CLOUD_LOG = {
    "id": "T1562.008",
    "name": "Impair Defenses: Disable or Modify Cloud Logs",
    "tactic": "Defense Evasion",
}


class IncidentBlitzTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def add_rule(self, rule_id, techniques):
        raw = techniques if isinstance(techniques, str) else json.dumps(techniques)
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
            " updated_by, techniques) VALUES (?,?,?,?,1,'{}',1,?,?,?)",
            (rule_id, rule_id, "synthetic", "medium", NOW, "test", raw))

    def add_incident(self, incident_id):
        self.conn.execute(
            "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
            " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,0,1,?,?)",
            (incident_id, f"Synthetic incident {incident_id}", "high", "open", NOW, LATER,
             json.dumps({"src_ip": [], "user": [], "host": []}),
             json.dumps(["Defense Impairment"]), NOW, NOW))

    def add_alert(self, alert_id, rule_id, incident_id, first_seen):
        self.conn.execute(
            "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
            " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
            (alert_id, rule_id, f"g{alert_id}", "high", "synthetic alert", "synthetic", "open",
             first_seen, first_seen, NOW, NOW))
        self.conn.execute(
            "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
            (alert_id, incident_id, NOW))

    def add_event(self, alert_id, dest_ip, ts):
        self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, dest_ip, synthetic)"
            " VALUES (?,?,?,?,?,?,?,1)",
            (ts, ts, "syslog", "other", "connection", "low", dest_ip))
        event_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        self.conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, event_id))
        return event_id

    def add_asset(self, name, addresses):
        assets.save_asset(self.conn, {"name": name, "addresses": list(addresses), "synthetic": 1}, "test")

    def test_upgraded_incident_keeps_the_canonical_technique_and_the_late_asset(self):
        # One rule still stores the revoked alias twice, the current id under the old name,
        # an orphan, an integer, and a malformed tag. A second rule's JSON does not parse.
        self.add_rule("legacy", [
            _OLD_CLOUD_LOG,
            dict(_OLD_CLOUD_LOG),
            {"id": "T1685.002", "name": "stored current", "tactic": "Defense Evasion"},
            {"id": "T9999", "name": "Orphan", "tactic": "Impact"},
            {"id": 1562, "name": "Numeric", "tactic": "Impact"},
            "attack.t1562.008",
            {"name": "no id"},
            {"id": ""},
            {"id": True, "name": "Bool"},
        ])
        self.add_rule("damaged", "{not-json")
        self.add_asset("shown-dest", ["10.0.0.1"])
        self.add_asset("late-dest", ["10.0.0.10"])
        self.add_incident(1)
        self.add_alert(2, "legacy", 1, NOW)
        self.add_alert(3, "damaged", 1, NOW)
        self.add_alert(4, "legacy", 1, LATER)
        self.add_event(2, "10.0.0.1", NOW)
        late_event = self.add_event(2, "10.0.0.10", LATER)

        previous = incidents.INCIDENT_EVENT_LIMIT
        incidents.INCIDENT_EVENT_LIMIT = 1
        try:
            detail = incidents.get_incident(self.conn, 1)
        finally:
            incidents.INCIDENT_EVENT_LIMIT = previous

        canonical = attack.technique("T1685.002")
        self.assertEqual(attack.technique("T1562.008"), canonical)
        self.assertEqual(detail["techniques"], [{**canonical, "alert_ids": [2, 4]}])
        self.assertEqual([row["id"] for row in detail["techniques"]], ["T1685.002"])
        self.assertEqual(detail["techniques_by_tactic"], [
            {"tactic": "Defense Impairment", "techniques": [{**canonical, "alert_ids": [2, 4]}]},
        ])
        self.assertEqual([row["techniques"] for row in detail["timeline"]], [
            ["T1685.002"], [], ["T1685.002"],
        ])
        self.assertEqual(detail["timeline"][0]["tactics"], ["Defense Impairment"])
        self.assertEqual(detail["alerts"][0]["techniques"], [canonical])
        self.assertEqual(detail["alerts"][1]["techniques"], [])
        self.assertEqual(detail["alerts"][1]["rule_name"], "damaged")

        # The second evidence row is past the page. Its destination asset still belongs to the incident.
        self.assertEqual([event["dest_ip"] for event in detail["events"]], ["10.0.0.1"])
        self.assertNotIn(late_event, {event["id"] for event in detail["events"]})
        self.assertEqual(detail["events_omitted"], 1)
        self.assertEqual([asset["name"] for asset in detail["assets"]], ["late-dest", "shown-dest"])

        # The rest of the incident stays readable, including the alert whose rule metadata is damaged.
        self.assertEqual(detail["title"], "Synthetic incident 1")
        self.assertEqual([alert["id"] for alert in detail["alerts"]], [2, 3, 4])
        self.assertEqual(detail["correlation_rule"], correlate.rule_summary())
        listed, omitted = incidents.list_incidents(self.conn, {})
        self.assertEqual(omitted, 0)
        self.assertEqual(listed[0]["top_technique"], canonical)
        self.assertEqual(listed[0]["correlation_rule"], detail["correlation_rule"])


if __name__ == "__main__":
    unittest.main()
