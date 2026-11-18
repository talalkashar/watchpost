"""Incident rollups name catalog techniques, assets past the evidence page, and status edges."""

import json
import unittest

from watchpost import assets, attack, correlate, incidents
from watchpost.db import connect, init_schema
from watchpost.queries import QueryError

NOW = "2026-09-15T10:00:00.000Z"
LATER = "2026-09-15T11:00:00.000Z"
LAST = "2026-09-15T12:00:00.000Z"

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

    def add_incident(self, incident_id, entities=None, stages=None, status="open"):
        if not isinstance(entities, str):
            entities = json.dumps(entities if entities is not None else {"src_ip": [], "user": [], "host": []})
        if not isinstance(stages, str):
            stages = json.dumps(stages if stages is not None else ["Reconnaissance"])
        self.conn.execute(
            "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
            " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,0,1,?,?)",
            (incident_id, f"Synthetic incident {incident_id}", "high", status, NOW, NOW,
             entities, stages, NOW, NOW))

    def add_alert(self, alert_id, rule_id, incident_id, first_seen=NOW):
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

    def add_asset(self, name, addresses=()):
        assets.save_asset(self.conn, {"name": name, "addresses": list(addresses), "synthetic": 1}, "test")

    def row(self, incident_id):
        return self.conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()

    def last_note(self):
        row = self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'incident_status_changed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return json.loads(row["detail"])["note"]

    def test_corrupt_techniques_do_not_break_list_or_detail(self):
        self.add_rule("good", [{"id": "T1190", "name": "Exploit", "tactic": "Initial Access"}])
        self.add_rule("bad", "{not-json")
        self.add_rule("obj", '{"id": "T1190"}')
        self.add_rule("empty", "null")
        self.add_incident(1)
        self.add_alert(1, "good", 1)
        self.add_incident(2)
        self.add_alert(2, "bad", 2)
        self.add_incident(3)
        self.add_alert(3, "obj", 3)
        self.add_incident(4)
        self.add_alert(4, "empty", 4)

        rows, _omitted = incidents.list_incidents(self.conn, {})
        listed = {item["id"]: item["top_technique"] for item in rows}
        self.assertEqual(listed[1]["id"], "T1190")
        self.assertIsNone(listed[2])
        self.assertIsNone(listed[3])
        self.assertIsNone(listed[4])
        self.assertEqual(rows[0]["correlation_rule"], correlate.rule_summary())

        detail = incidents.get_incident(self.conn, 2)
        self.assertEqual(detail["techniques"], [])
        self.assertEqual(detail["timeline"][0]["techniques"], [])
        self.assertEqual(detail["timeline"][0]["tactics"], [])
        self.assertEqual(detail["alerts"][0]["rule_name"], "bad")
        self.assertEqual(detail["correlation_rule"], correlate.rule_summary())

    def test_alert_ids_follow_first_seen_then_id_past_the_page(self):
        self.add_rule("paged", [{"id": "T1190", "name": "Exploit", "tactic": "Initial Access"}])
        self.add_incident(1, stages=["Initial Access"])
        self.add_alert(2, "paged", 1, NOW)
        self.add_alert(1, "paged", 1, LATER)
        previous = incidents.INCIDENT_ALERT_LIMIT
        incidents.INCIDENT_ALERT_LIMIT = 1
        try:
            detail = incidents.get_incident(self.conn, 1)
        finally:
            incidents.INCIDENT_ALERT_LIMIT = previous
        self.assertEqual([a["id"] for a in detail["alerts"]], [2])
        self.assertEqual(detail["alerts_omitted"], 1)
        self.assertEqual(detail["techniques"][0]["alert_ids"], [2, 1])
        self.assertEqual(detail["timeline"][0]["alert_id"], 2)

    def test_same_tactic_lower_string_id_wins(self):
        self.add_rule("later", [{"id": "T1595.003", "name": "Wordlist", "tactic": "Reconnaissance"}])
        self.add_rule("earlier", [{"id": "T1595.002", "name": "Vulnerability", "tactic": "Reconnaissance"}])
        self.add_incident(1)
        self.add_alert(1, "later", 1)
        self.add_alert(2, "earlier", 1)
        self.assertEqual(incidents.top_techniques(self.conn, [1])[1]["id"], "T1595.002")

    def test_assets_include_dest_ips_past_the_event_page_and_string_entities(self):
        self.add_asset("web01")
        self.add_asset("shown-dest", ["10.0.0.1"])
        self.add_asset("hidden-dest", ["10.0.0.10"])
        self.add_asset("entity-src", ["10.0.0.20"])
        self.add_asset("db01")
        self.add_asset("list-src", ["10.2.2.2"])
        self.add_asset("list-dest", ["10.9.9.9"])
        self.add_rule("reach", [{"id": "T1190", "name": "Exploit", "tactic": "Initial Access"}])
        self.add_incident(1, {"src_ip": "10.0.0.20", "user": [], "host": "web01"})
        self.add_alert(1, "reach", 1)
        self.add_event(1, "10.0.0.1", NOW)
        self.add_event(1, "10.0.0.10", LATER)
        self.add_event(1, "", LAST)
        self.add_incident(2, {"src_ip": ["10.2.2.2", "", 5], "user": [], "host": ["db01", "", 5]})
        self.add_alert(2, "reach", 2)
        self.add_event(2, "10.9.9.9", NOW)

        previous_limit = incidents.INCIDENT_EVENT_LIMIT
        previous_match = incidents.assets.for_entities
        seen = []

        def wrapped(conn, hosts, ips):
            hosts, ips = list(hosts), list(ips)  # ips may be a one-pass iterator
            seen.append((hosts, ips))
            return previous_match(conn, hosts, ips)

        incidents.INCIDENT_EVENT_LIMIT = 1
        incidents.assets.for_entities = wrapped
        try:
            string_entities = incidents.get_incident(self.conn, 1)
            list_entities = incidents.get_incident(self.conn, 2)
        finally:
            incidents.INCIDENT_EVENT_LIMIT = previous_limit
            incidents.assets.for_entities = previous_match

        self.assertEqual(string_entities["entities"]["host"], "web01")
        self.assertEqual(string_entities["entities"]["src_ip"], "10.0.0.20")
        self.assertEqual([event["dest_ip"] for event in string_entities["events"]], ["10.0.0.1"])
        self.assertEqual(string_entities["events_omitted"], 2)
        self.assertEqual(seen[0][0], ["web01"])
        self.assertEqual(sorted(seen[0][1]), ["10.0.0.1", "10.0.0.10", "10.0.0.20"])
        self.assertEqual(
            {asset["name"] for asset in string_entities["assets"]},
            {"web01", "shown-dest", "hidden-dest", "entity-src"})
        self.assertEqual(seen[1][0], ["db01"])
        self.assertEqual(sorted(seen[1][1]), ["10.2.2.2", "10.9.9.9"])
        self.assertEqual(
            {asset["name"] for asset in list_entities["assets"]},
            {"db01", "list-src", "list-dest"})

    def test_blank_note_is_audited_as_null_and_a_padded_note_is_stripped(self):
        self.add_incident(1)
        incidents.update_status(self.conn, 1, "analyst", "investigating", note="")
        self.assertIsNone(self.last_note())
        incidents.update_status(self.conn, 1, "analyst", "investigating", note="   ")
        self.assertIsNone(self.last_note())
        incidents.update_status(self.conn, 1, "analyst", "investigating", note=" " * 5000)
        self.assertIsNone(self.last_note())
        incidents.update_status(self.conn, 1, "analyst", "resolved", note="  contained  ")
        self.assertEqual(self.last_note(), "contained")
        self.assertEqual(self.row(1)["status"], "resolved")

    def test_rejected_status_and_note_leave_the_incident_unchanged(self):
        self.add_incident(1)
        with self.assertRaises(QueryError) as caught:
            incidents.update_status(self.conn, 1, "analyst", "Open", note="nope")
        self.assertEqual(caught.exception.status, 400)
        with self.assertRaises(QueryError):
            incidents.update_status(self.conn, 1, "analyst", "resolved", note={"text": "x"})
        with self.assertRaises(QueryError):
            incidents.update_status(self.conn, 1, "analyst", "resolved", note=" " * 5001)
        row = self.row(1)
        self.assertEqual(row["status"], "open")
        self.assertIsNone(row["resolved_at"])
        self.assertIsNone(row["assignee"])
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM audit_log WHERE action = 'incident_status_changed'").fetchone())

    def test_resolve_again_keeps_the_first_resolved_at(self):
        self.add_incident(1)
        incidents.update_status(self.conn, 1, "analyst", "open")
        self.assertIsNone(self.row(1)["assignee"])
        incidents.update_status(self.conn, 1, "analyst", "investigating")
        self.assertEqual(self.row(1)["assignee"], "analyst")
        incidents.update_status(self.conn, 1, "other", "investigating")
        self.assertEqual(self.row(1)["assignee"], "other")
        incidents.update_status(self.conn, 1, "other", "resolved", note="first")
        self.conn.execute(
            "UPDATE incidents SET resolved_at = ?, updated_at = ? WHERE id = 1",
            ("2020-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z"))
        updated = incidents.update_status(self.conn, 1, "other", "resolved", note="later")
        self.assertEqual(updated["resolved_at"], "2020-01-01T00:00:00.000Z")
        self.assertNotEqual(updated["updated_at"], "2020-01-01T00:00:00.000Z")
        self.assertEqual(self.last_note(), "later")
        reopened = incidents.update_status(self.conn, 1, "other", "open")
        self.assertIsNone(reopened["resolved_at"])
        self.assertEqual(reopened["assignee"], "other")
        resolved = incidents.update_status(self.conn, 1, "other", "resolved")
        self.assertIsNotNone(resolved["resolved_at"])
        self.assertNotEqual(resolved["resolved_at"], "2020-01-01T00:00:00.000Z")

    def test_bad_entities_and_stages_fall_back_to_empty(self):
        self.add_incident(1, "null", "null")
        self.add_incident(2, "not-json", "not-json")
        self.add_incident(3, "[\"web01\"]", "{\"tactic\": \"Impact\"}")
        rows, _omitted = incidents.list_incidents(self.conn, {})
        self.assertEqual(len(rows), 3)
        for item in rows:
            self.assertEqual(item["entities"], {})
            self.assertEqual(item["stages"], [])
            detail = incidents.get_incident(self.conn, item["id"])
            self.assertEqual(detail["entities"], {})
            self.assertEqual(detail["stages"], [])
            self.assertEqual(detail["techniques_by_tactic"], [])
            self.assertFalse(detail["escalated"])

    def test_valid_entities_and_duplicate_stages_stay_as_stored(self):
        entities = {"src_ip": ["10.1.1.1"], "user": ["ada"], "host": ["web01"], "extra": 1}
        stages = ["Reconnaissance", "Initial Access", "Reconnaissance"]
        self.add_rule("scan", [{"id": "T1595.002", "name": "Vulnerability", "tactic": "Reconnaissance"}])
        self.add_rule("exploit", [{"id": "T1190", "name": "Exploit", "tactic": "Initial Access"}])
        self.add_incident(1, entities, stages)
        self.add_alert(1, "scan", 1, NOW)
        self.add_alert(2, "exploit", 1, LATER)
        detail = incidents.get_incident(self.conn, 1)
        self.assertEqual(detail["entities"], entities)
        self.assertEqual(detail["stages"], stages)
        self.assertEqual([group["tactic"] for group in detail["techniques_by_tactic"]], stages)
        self.assertEqual([t["id"] for t in detail["techniques_by_tactic"][0]["techniques"]], ["T1595.002"])
        self.assertEqual([t["id"] for t in detail["techniques_by_tactic"][2]["techniques"]], ["T1595.002"])
        self.assertTrue(detail["escalated"])
        self.assertEqual(detail["correlation_rule"], correlate.rule_summary())
        listed, omitted = incidents.list_incidents(self.conn, {})
        self.assertEqual(omitted, 0)
        self.assertEqual(listed[0]["entities"], entities)
        self.assertEqual(listed[0]["stages"], stages)
        self.assertEqual(listed[0]["top_technique"]["id"], "T1595.002")
        self.assertEqual(listed[0]["correlation_rule"], correlate.rule_summary())

    def test_missing_incident_is_not_found(self):
        with self.assertRaises(QueryError) as caught:
            incidents.get_incident(self.conn, 404)
        self.assertEqual(caught.exception.status, 404)

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
        self.add_incident(1, stages=["Defense Impairment"])
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
