"""Case export copies the incident event cap and caps notes, activity, and status changes.

Notes, activity other than note_added, and incident status changes stay the newest 100 by id.
A later created_at on a lower id is the row left out. Timeline order stays by ts. A list that
fits returns 0. Evidence is the incident's already-capped events, and events_omitted is copied.
Markdown names a count only when it is not 0.
"""

import json
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import case_record
from watchpost.db import connect, init_schema, iso
from watchpost.incidents import INCIDENT_EVENT_LIMIT, get_incident

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)
EARLY = "2026-10-07T12:00:00Z"
LATER = "2026-10-08T12:00:00Z"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, minutes):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", "web01", "auth", "low", "[SYNTHETIC] case cap"))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_ids=()):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        ("synthetic_rule", 1, "web01", "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, len(event_ids), SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


def add_incident(conn, alert_ids):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("Synthetic probe", "high", "open", SEEN, SEEN,
         json.dumps({"src_ip": [], "user": [], "host": ["web01"]}),
         json.dumps(["Initial Access"]), len(alert_ids), 1, SEEN, SEEN))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, SEEN) for alert_id in alert_ids])
    return incident_id


def add_notes(conn, alert_id, count, created_at=EARLY):
    conn.executemany(
        "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
        [(alert_id, "analyst", f"[SYNTHETIC] note {i}", created_at) for i in range(count)])


def add_activity(conn, alert_id, count, created_at=EARLY, action="status_changed"):
    conn.executemany(
        "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
        [(alert_id, "analyst", action, f"[SYNTHETIC] step {i}", created_at) for i in range(count)])


def add_status(conn, incident_id, count, created_at=EARLY):
    conn.executemany(
        "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
        [(created_at, "analyst", "incident_status_changed", str(incident_id),
          json.dumps({"from": "open", "to": "investigating", "note": f"[SYNTHETIC] change {i}"}))
         for i in range(count)])


def kinds(case, kind):
    return [item for item in case["timeline"] if item["type"] == kind]


class CaseOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_past_each_cap(self):
        alert_id = add_alert(self.conn)
        incident_id = add_incident(self.conn, [alert_id])
        # Highest id, earliest time: newest is id, so this row stays and the first insert is dropped.
        add_notes(self.conn, alert_id, 1, created_at=LATER)
        add_notes(self.conn, alert_id, case_record.CASE_ROW_LIMIT, created_at=EARLY)
        add_activity(self.conn, alert_id, 1, created_at=LATER)
        add_activity(self.conn, alert_id, case_record.CASE_ROW_LIMIT, created_at=EARLY)
        add_status(self.conn, incident_id, 1, created_at=LATER)
        add_status(self.conn, incident_id, case_record.CASE_ROW_LIMIT, created_at=EARLY)

        case = case_record.build(self.conn, incident_id)
        notes = kinds(case, "analyst_note")
        activity = kinds(case, "status_changed")
        changes = kinds(case, "incident_status_changed")
        self.assertEqual(len(notes), case_record.CASE_ROW_LIMIT)
        self.assertEqual(len(activity), case_record.CASE_ROW_LIMIT)
        self.assertEqual(len(changes), case_record.CASE_ROW_LIMIT)
        self.assertEqual(case["notes_omitted"], 1)
        self.assertEqual(case["activity_omitted"], 1)
        self.assertEqual(case["status_changes_omitted"], 1)
        self.assertNotIn(LATER, {item["ts"] for item in notes})
        self.assertNotIn(LATER, {item["ts"] for item in activity})
        self.assertNotIn(LATER, {item["ts"] for item in changes})
        self.assertEqual(notes[0]["body"], "[SYNTHETIC] note 0")
        self.assertEqual(changes[-1]["note"], "[SYNTHETIC] change 99")

    def test_note_added_is_not_an_activity_row(self):
        alert_id = add_alert(self.conn)
        incident_id = add_incident(self.conn, [alert_id])
        add_activity(self.conn, alert_id, case_record.CASE_ROW_LIMIT + 5, action="note_added")
        add_activity(self.conn, alert_id, 1, action="assigned")

        case = case_record.build(self.conn, incident_id)
        self.assertEqual(case["activity_omitted"], 0)
        self.assertEqual([item["type"] for item in kinds(case, "assigned")], ["assigned"])
        self.assertEqual(kinds(case, "note_added"), [])

    def test_notes_on_every_linked_alert_share_one_cap(self):
        first = add_alert(self.conn)
        second = add_alert(self.conn)
        other = add_alert(self.conn)
        incident_id = add_incident(self.conn, [first, second])
        add_incident(self.conn, [other])
        # Lowest id, later time, on the first alert: this is the one left out.
        add_notes(self.conn, first, 1, created_at=LATER)
        add_notes(self.conn, second, case_record.CASE_ROW_LIMIT, created_at=EARLY)
        add_notes(self.conn, other, 5, created_at=LATER)
        add_status(self.conn, incident_id + 1, 3, created_at=LATER)
        self.conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (LATER, "analyst", "case_exported", str(incident_id), "{}"))

        case = case_record.build(self.conn, incident_id)
        notes = kinds(case, "analyst_note")
        self.assertEqual(case["notes_omitted"], 1)
        self.assertEqual(case["status_changes_omitted"], 0)
        self.assertEqual({item["alert_id"] for item in notes}, {second})
        self.assertNotIn(LATER, {item["ts"] for item in notes})
        self.assertEqual(len(notes), case_record.CASE_ROW_LIMIT)

    def test_a_short_list_and_an_exact_cap_omit_nothing(self):
        one_alert = add_alert(self.conn)
        one = add_incident(self.conn, [one_alert])
        add_notes(self.conn, one_alert, 1)
        add_activity(self.conn, one_alert, 1)
        add_status(self.conn, one, 1)
        exact_alert = add_alert(self.conn)
        exact = add_incident(self.conn, [exact_alert])
        add_notes(self.conn, exact_alert, case_record.CASE_ROW_LIMIT)
        add_activity(self.conn, exact_alert, case_record.CASE_ROW_LIMIT)
        add_status(self.conn, exact, case_record.CASE_ROW_LIMIT)
        empty = add_incident(self.conn, [add_alert(self.conn)])

        short = case_record.build(self.conn, one)
        filled = case_record.build(self.conn, exact)
        none = case_record.build(self.conn, empty)
        self.assertEqual(short["notes_omitted"], 0)
        self.assertEqual(short["activity_omitted"], 0)
        self.assertEqual(short["status_changes_omitted"], 0)
        self.assertEqual(len(kinds(short, "analyst_note")), 1)
        self.assertEqual(filled["notes_omitted"], 0)
        self.assertEqual(filled["activity_omitted"], 0)
        self.assertEqual(filled["status_changes_omitted"], 0)
        self.assertEqual(len(kinds(filled, "analyst_note")), case_record.CASE_ROW_LIMIT)
        self.assertEqual(none["notes_omitted"], 0)
        self.assertEqual(none["activity_omitted"], 0)
        self.assertEqual(none["status_changes_omitted"], 0)
        self.assertEqual(none["events_omitted"], 0)

    def test_timeline_order_stays_by_time(self):
        alert_id = add_alert(self.conn)
        incident_id = add_incident(self.conn, [alert_id])
        add_status(self.conn, incident_id, 1, created_at=LATER)
        add_notes(self.conn, alert_id, 1, created_at=EARLY)

        case = case_record.build(self.conn, incident_id)
        note = kinds(case, "analyst_note")[0]
        change = kinds(case, "incident_status_changed")[0]
        self.assertLess(note["sequence"], change["sequence"])
        self.assertEqual(note["ts"], EARLY)
        self.assertEqual(change["ts"], LATER)

    def test_events_omitted_is_copied_and_evidence_is_not_capped_again(self):
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(INCIDENT_EVENT_LIMIT)]
        incident_id = add_incident(self.conn, [add_alert(self.conn, [late_id] + early_ids)])

        incident = get_incident(self.conn, incident_id)
        case = case_record.build(self.conn, incident_id)
        evidence = [item["event"]["id"] for item in kinds(case, "evidence")]
        self.assertEqual(case["events_omitted"], incident["events_omitted"])
        self.assertEqual(case["events_omitted"], 1)
        self.assertEqual(evidence, early_ids)
        self.assertNotIn(late_id, evidence)
        self.assertEqual(len(evidence), len(incident["events"]))

    def test_markdown_names_a_count_only_when_it_is_not_zero(self):
        alert_id = add_alert(self.conn)
        incident_id = add_incident(self.conn, [alert_id])
        add_notes(self.conn, alert_id, 1, created_at=LATER)
        add_notes(self.conn, alert_id, case_record.CASE_ROW_LIMIT, created_at=EARLY)
        text = case_record.to_markdown_bytes(case_record.build(self.conn, incident_id)).decode()
        self.assertIn("_1 note left out._", text)
        self.assertNotIn("activity row", text)
        self.assertNotIn("status change", text)
        self.assertNotIn("evidence event", text)

        named = {"id": 7, "title": "probe", "synthetic": True, "status": "open", "severity": "high",
                 "assignee": None, "first_seen": "t0", "last_seen": "t1", "generated_at": "t2",
                 "timeline": [], "techniques": [], "events_omitted": 2, "notes_omitted": 1,
                 "activity_omitted": 3, "status_changes_omitted": 4}
        both = case_record.to_markdown_bytes(named).decode()
        self.assertIn("_2 evidence events left out._", both)
        self.assertIn("_1 note left out._", both)
        self.assertIn("_3 activity rows left out._", both)
        self.assertIn("_4 status changes left out._", both)
        quiet = dict(named, events_omitted=0, notes_omitted=0, activity_omitted=0, status_changes_omitted=0)
        self.assertNotIn("left out", case_record.to_markdown_bytes(quiet).decode())

    def test_the_docs_name_the_caps(self):
        api = API.read_text()
        self.assertIn(
            "`events_omitted` is copied from the incident and evidence is not capped again", api)
        self.assertIn(
            "`notes_omitted`, `activity_omitted`, and `status_changes_omitted` are how many of those"
            " rows were past that cap (0 when each fits, including none)", api)
        self.assertIn("A left-out count is named only when it is not 0", api)
        reference = REFERENCE.read_text()
        self.assertIn("The case copies `events_omitted` and does not", reference)
        self.assertIn("Markdown names a count only when it is not", reference)


class CaseOmittedApiTests(ServerTestCase):
    def test_case_json_reports_the_dropped_note(self):
        conn = connect(self.db_path)
        try:
            alert_id = add_alert(conn)
            incident_id = add_incident(conn, [alert_id])
            add_notes(conn, alert_id, 1, created_at=LATER)
            add_notes(conn, alert_id, case_record.CASE_ROW_LIMIT, created_at=EARLY)
            conn.commit()
        finally:
            conn.close()

        status, raw, _ = _raw(self, incident_id)
        self.assertEqual(status, 200, raw[:200])
        case = json.loads(raw)
        self.assertEqual(case["notes_omitted"], 1)
        self.assertEqual(case["activity_omitted"], 0)
        self.assertEqual(case["status_changes_omitted"], 0)
        self.assertEqual(case["events_omitted"], 0)
        notes = [item for item in case["timeline"] if item["type"] == "analyst_note"]
        self.assertEqual(len(notes), case_record.CASE_ROW_LIMIT)
        self.assertNotIn(LATER, {item["ts"] for item in notes})
        self.assertEqual(notes[0]["body"], "[SYNTHETIC] note 0")
        text = _raw(self, incident_id, "md")[1].decode()
        self.assertIn("_1 note left out._", text)
        self.assertNotIn("_0 ", text)


def _raw(test, incident_id, fmt="json"):
    client = test.client("viewer")
    path = f"/api/incidents/{incident_id}/case.{fmt}"
    try:
        with client.opener.open(urllib.request.Request(test.base + path), timeout=30) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read(), exc.headers
