"""Edge cases for the incident case record.

An incident_alerts row can outlive its alert (the schema has no foreign key). Mixed ISO
timestamps must follow real time, then type, then id. Missing text must not render as the
word None. Notes, activity, and status changes stay the newest 100 by id. Evidence keeps
the incident's own cap.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone

from watchpost import __version__, case_record
from watchpost.db import connect, init_schema, iso
from watchpost.incidents import INCIDENT_EVENT_LIMIT
from watchpost.queries import QueryError
from watchpost.rules import DEFAULT_RULES

BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)
EARLY = "2026-10-07T12:00:00Z"
# One hundred milliseconds later. As text this sorts before EARLY, because '.' < 'Z'.
EARLY_MS = "2026-10-07T12:00:00.100Z"
MID = "2026-10-07T15:00:00Z"
LATER = "2026-10-08T12:00:00Z"
BAD_TS = "not-a-timestamp"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes, message="[SYNTHETIC] case"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, rule_id="synthetic_rule", title="synthetic alert", event_ids=()):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        (rule_id, 1, "web01", "high", title, "synthetic", "open", SEEN, SEEN, len(event_ids), SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


def add_incident(conn, alert_ids, title="Synthetic probe", synthetic=0, created_at=EARLY):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (title, "high", "open", SEEN, SEEN,
         json.dumps({"src_ip": [], "user": [], "host": ["web01"]}),
         json.dumps(["Initial Access"]), len(alert_ids), synthetic, created_at, created_at))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, EARLY_MS) for alert_id in alert_ids])
    return incident_id


def add_orphan_link(conn, incident_id, alert_id=999999):
    conn.execute(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        (alert_id, incident_id, EARLY))


def kinds(case, kind):
    return [item for item in case["timeline"] if item["type"] == kind]


class CaseRecordBlitzTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_orphan_alert_link_does_not_crash_the_case(self):
        alert_id = add_alert(self.conn)
        incident_id = add_incident(self.conn, [alert_id])
        add_orphan_link(self.conn, incident_id)
        self.conn.execute(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
            (999999, "analyst", "[SYNTHETIC] orphan note", LATER))
        dangling = add_incident(self.conn, [])
        add_orphan_link(self.conn, dangling, alert_id=888888)

        case = case_record.build(self.conn, incident_id)
        self.assertEqual([alert["id"] for alert in case["alerts"]], [alert_id])
        self.assertEqual([item["alert_id"] for item in kinds(case, "alert_added")], [alert_id])
        self.assertEqual(kinds(case, "analyst_note"), [])

        empty = case_record.build(self.conn, dangling)
        self.assertEqual(empty["alerts"], [])
        self.assertEqual([item["type"] for item in empty["timeline"]], ["incident_created"])

    def test_timeline_follows_real_time_then_type_then_id(self):
        event_id = add_event(self.conn, 0)
        # Pin this event to the mixed stamp. iso() would have written milliseconds already.
        self.conn.execute("UPDATE events SET ts = ? WHERE id = ?", (EARLY_MS, event_id))
        first = add_alert(self.conn, event_ids=(event_id,))
        second = add_alert(self.conn)
        incident_id = add_incident(self.conn, [second, first], created_at=EARLY)
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (first, "analyst", "assigned", "nobody -> analyst", EARLY_MS))
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (first, "analyst", "note_added", None, EARLY_MS))
        self.conn.execute(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
            (first, "analyst", "[SYNTHETIC] later note", LATER))
        self.conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (MID, "analyst", "incident_status_changed", str(incident_id),
             json.dumps({"from": "open", "to": "investigating", "note": "real change"})))
        self.conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (BAD_TS, "analyst", "incident_status_changed", str(incident_id), None))
        self.conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (EARLY, "analyst", "case_exported", str(incident_id), "{}"))
        self.conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (LATER, "analyst", "incident_status_changed", str(incident_id + 50),
             json.dumps({"from": "open", "to": "resolved"})))

        case = case_record.build(self.conn, incident_id)
        self.assertEqual([item["type"] for item in case["timeline"]], [
            "incident_created",
            "evidence",
            "alert_added",
            "alert_added",
            "assigned",
            "incident_status_changed",
            "analyst_note",
            "incident_status_changed",
        ])
        added = kinds(case, "alert_added")
        self.assertEqual([item["alert_id"] for item in added], sorted(item["alert_id"] for item in added))
        self.assertLess(added[0]["alert_id"], added[1]["alert_id"])
        self.assertEqual(kinds(case, "evidence")[0]["event"]["id"], event_id)
        self.assertEqual(kinds(case, "analyst_note")[0]["ts"], LATER)
        self.assertEqual(kinds(case, "note_added"), [])
        self.assertEqual(case["timeline"][-1]["ts"], BAD_TS)
        self.assertEqual([item["sequence"] for item in case["timeline"]],
                         list(range(1, len(case["timeline"]) + 1)))
        stored = [item["ts"] for item in case["timeline"]]
        self.assertIn(EARLY, stored)
        self.assertIn(EARLY_MS, stored)

    def test_missing_text_is_not_the_word_none(self):
        alert_id = add_alert(self.conn, title="called *bob* about a|b <x>")
        incident_id = add_incident(self.conn, [alert_id], title="a|b *c* <d>")
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "analyst", "assigned", None, LATER))
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "analyst", "status_changed", "open -> investigating", MID))
        self.conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (LATER, "analyst", "incident_status_changed", str(incident_id), None))

        case = case_record.build(self.conn, incident_id)
        text = case_record.to_markdown_bytes(case).decode("utf-8")
        self.assertNotIn("None", text)
        self.assertIn("by analyst:", text)
        self.assertIn(r"open -\> investigating", text)
        self.assertIn("analyst: - → -", text)
        self.assertIn(r"a\|b \*c\* \<d\>", text)
        self.assertIn(r"\*bob\*", text)
        self.assertIn(r"a\|b", text)
        self.assertIn("**Assignee:** -", text)
        self.assertNotIn("SYNTHETIC DATA", text)
        self.assertNotIn("left out", text)

    def test_newest_hundred_notes_leave_the_oldest_id_out(self):
        alert_id = add_alert(self.conn)
        incident_id = add_incident(self.conn, [alert_id])
        self.conn.executemany(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
            [(alert_id, "analyst", f"[SYNTHETIC] note {i}", LATER if i == 0 else EARLY)
             for i in range(case_record.CASE_ROW_LIMIT + 1)])

        case = case_record.build(self.conn, incident_id)
        notes = kinds(case, "analyst_note")
        self.assertEqual(len(notes), case_record.CASE_ROW_LIMIT)
        self.assertEqual(case["notes_omitted"], 1)
        self.assertEqual(case["activity_omitted"], 0)
        self.assertEqual(case["status_changes_omitted"], 0)
        self.assertNotIn("[SYNTHETIC] note 0", {item["body"] for item in notes})
        self.assertEqual(notes[-1]["body"], f"[SYNTHETIC] note {case_record.CASE_ROW_LIMIT}")
        text = case_record.to_markdown_bytes(case).decode("utf-8")
        self.assertIn("_1 note left out._", text)
        self.assertNotIn("notes left out", text)

    def test_evidence_omitted_count_is_copied(self):
        event_ids = [add_event(self.conn, i) for i in range(INCIDENT_EVENT_LIMIT + 1)]
        alert_id = add_alert(self.conn, event_ids=event_ids)
        incident_id = add_incident(self.conn, [alert_id])

        case = case_record.build(self.conn, incident_id)
        evidence = kinds(case, "evidence")
        self.assertEqual(case["events_omitted"], 1)
        self.assertEqual(len(evidence), INCIDENT_EVENT_LIMIT)
        self.assertEqual(evidence[0]["event"]["id"], event_ids[0])
        self.assertNotIn(event_ids[-1], {item["event"]["id"] for item in evidence})
        text = case_record.to_markdown_bytes(case).decode("utf-8")
        self.assertIn("_1 evidence event left out._", text)

    def test_unknown_technique_stays_mapped(self):
        rule = next(item for item in DEFAULT_RULES if item["id"] == "brute_force_ip")
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
            " updated_by, techniques) VALUES (?,?,?,?,1,?,1,?,?,?)",
            (rule["id"], rule["name"], rule["description"], rule["severity"], json.dumps(rule["params"]),
             SEEN, "system", json.dumps([{"id": "T9999", "name": "n|m", "tactic": "Impact"}])))
        alert_id = add_alert(self.conn, rule_id=rule["id"])
        incident_id = add_incident(self.conn, [alert_id], synthetic=1)

        case = case_record.build(self.conn, incident_id)
        self.assertEqual(case["techniques"], [{
            "id": "T9999", "name": "n|m", "tactic": "Impact", "level": "mapped", "alert_ids": [alert_id],
        }])
        self.assertTrue(case["synthetic"])
        self.assertEqual(case["format"], "watchpost-incident-case")
        self.assertEqual(case["format_version"], 1)
        self.assertEqual(case["generator"], f"Watchpost {__version__}")
        self.assertRegex(case["generated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        text = case_record.to_markdown_bytes(case).decode("utf-8")
        self.assertIn("SYNTHETIC DATA", text)
        self.assertIn(f"| T9999 | n\\|m | Impact | mapped | \\#{alert_id} |", text)

    def test_missing_incident_raises(self):
        with self.assertRaises(QueryError) as caught:
            case_record.build(self.conn, 999999)
        self.assertEqual(caught.exception.status, 404)

    def test_markdown_of_a_partial_case_names_only_real_drops(self):
        case = {
            "id": 7, "title": "Partial", "synthetic": False, "status": "open", "severity": "low",
            "assignee": None, "first_seen": EARLY, "last_seen": LATER, "generated_at": SEEN,
            "techniques": [], "timeline": [],
            "events_omitted": 1, "notes_omitted": 0, "activity_omitted": 2,
        }
        text = case_record.to_markdown_bytes(case).decode("utf-8")
        self.assertIn("No ATT&CK technique is recorded for the rules on this incident.", text)
        self.assertIn("_1 evidence event left out._", text)
        self.assertIn("_2 activity rows left out._", text)
        self.assertNotIn("note", text.lower().split("chronological")[-1])
        self.assertNotIn("status change", text)
        self.assertNotIn("SYNTHETIC DATA", text)
        self.assertTrue(text.startswith("# Incident case #7:"))
        self.assertTrue(text.endswith("\n"))

        raw = case_record.to_json_bytes({"b": 1, "a": None})
        self.assertEqual(json.loads(raw.decode("utf-8")), {"a": None, "b": 1})
        self.assertLess(raw.index(b'"a"'), raw.index(b'"b"'))
