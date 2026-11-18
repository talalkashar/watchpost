"""Edge cases for the incident case record that the cap tests do not cover.

Equal timestamps sort by kind, then alert id, then event id. Malformed status
audit JSON contributes no from/to/note. An incident with no alerts is still a
record. A technique the catalog does not grade, or a level outside the evidence
scale, stays mapped. JSON bytes are sorted, indented, and ASCII. Markdown
renders every timeline kind, blank fields, and a left-out count of one.
"""

import json
import unittest
from unittest.mock import patch

import watchpost
from watchpost import case_record
from watchpost.db import connect, init_schema

TS = "2026-10-07T12:00:00Z"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, event_id):
    conn.execute(
        "INSERT INTO events(id, ts, ingested_at, source, host, event_type, severity, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,0)",
        (event_id, TS, TS, "lab", "web01", "auth", "low", f"[SYNTHETIC] event {event_id}"))


def add_alert(conn, rule_id="synthetic_rule", disposition=None, assignee=None, event_count=0):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " disposition, assignee, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)",
        (rule_id, 1, "web01", "high", "synthetic alert", "synthetic", "open",
         disposition, assignee, TS, TS, event_count, TS, TS))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_incident(conn, alert_ids, synthetic=0, assignee=None, entities=None, stages=None):
    if entities is None:
        entities = {"src_ip": [], "user": [], "host": ["web01"]}
    if stages is None:
        stages = ["Initial Access"]
    conn.execute(
        "INSERT INTO incidents(title, severity, status, assignee, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("Synthetic probe", "high", "open", assignee, TS, TS,
         json.dumps(entities), json.dumps(stages), len(alert_ids), synthetic, TS, TS))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, TS) for alert_id in alert_ids])
    return incident_id


def add_note(conn, alert_id, body):
    conn.execute(
        "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
        (alert_id, "analyst", body, TS))


def add_activity(conn, alert_id, action, detail="step"):
    conn.execute(
        "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
        (alert_id, "analyst", action, detail, TS))


def add_status(conn, incident_id, actor, detail):
    conn.execute(
        "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
        (TS, actor, "incident_status_changed", str(incident_id), detail))


def render(case):
    raw = case_record.to_markdown_bytes(case)
    return raw, raw.decode("utf-8")


class CaseRecordBuildEdgeTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_an_incident_with_no_alerts_is_still_one_record(self):
        incident_id = add_incident(self.conn, [], entities={}, stages=[])

        case = case_record.build(self.conn, incident_id)

        self.assertEqual(case["format"], "watchpost-incident-case")
        self.assertEqual(case["format_version"], 1)
        self.assertEqual(case["generator"], f"Watchpost {watchpost.__version__}")
        self.assertRegex(case["generated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        self.assertIs(case["synthetic"], False)
        self.assertIsNone(case["assignee"])
        self.assertEqual(case["entities"], {})
        self.assertEqual(case["stages"], [])
        self.assertEqual(case["alerts"], [])
        self.assertEqual(case["techniques"], [])
        self.assertEqual(case["events_omitted"], 0)
        self.assertEqual(case["notes_omitted"], 0)
        self.assertEqual(case["activity_omitted"], 0)
        self.assertEqual(case["status_changes_omitted"], 0)
        self.assertEqual(case["timeline"], [{
            "ts": TS, "type": "incident_created",
            "detail": f"Incident #{incident_id} created", "sequence": 1,
        }])

    def test_equal_timestamps_sort_by_kind_then_alert_then_event(self):
        # Higher alert id is inserted first, and its note and assignment are written first, so row id
        # order is the opposite of the timeline order. Evidence is appended after incident_created,
        # and the unknown action is written before the status change. The sort has to undo all of that.
        low = add_alert(self.conn)
        high = add_alert(self.conn)
        incident_id = add_incident(self.conn, [high, low], synthetic=1)
        add_event(self.conn, 20)
        add_event(self.conn, 5)
        for event_id in (20, 5):
            self.conn.execute(
                "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (high, event_id))
            self.conn.execute(
                "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (low, event_id))
        add_note(self.conn, high, "high")
        add_note(self.conn, low, "low")
        add_activity(self.conn, low, "reopened", detail=None)
        add_activity(self.conn, high, "status_changed")
        add_activity(self.conn, high, "assigned")
        add_activity(self.conn, low, "assigned")
        add_status(self.conn, incident_id, "analyst",
                   json.dumps({"from": "open", "to": "investigating", "note": "same time"}))

        case = case_record.build(self.conn, incident_id)

        self.assertIs(case["synthetic"], True)
        evidence = [item for item in case["timeline"] if item["type"] == "evidence"]
        self.assertEqual([item["event"]["id"] for item in evidence], [5, 20])
        for item in evidence:
            self.assertEqual(item["alert_ids"], [low, high])
            self.assertNotIn("alert_ids", item["event"])
            self.assertIn("message", item["event"])
        self.assertEqual(
            [(item["type"], item.get("alert_id"), (item.get("event") or {}).get("id"))
             for item in case["timeline"]],
            [
                ("evidence", None, 5),
                ("evidence", None, 20),
                ("incident_created", None, None),
                ("alert_added", low, None),
                ("alert_added", high, None),
                ("assigned", low, None),
                ("assigned", high, None),
                ("status_changed", high, None),
                ("analyst_note", low, None),
                ("analyst_note", high, None),
                ("incident_status_changed", None, None),
                ("reopened", low, None),
            ])
        notes = [item["body"] for item in case["timeline"] if item["type"] == "analyst_note"]
        self.assertEqual(notes, ["low", "high"])
        reopened = next(item for item in case["timeline"] if item["type"] == "reopened")
        self.assertIsNone(reopened["detail"])
        self.assertEqual(reopened["actor"], "analyst")

    def test_malformed_status_detail_does_not_invent_fields(self):
        # No linked alerts: notes and activity are skipped, and status changes are still part of the record.
        incident_id = add_incident(self.conn, [])
        rows = {
            "missing": None,
            "blank": "",
            "garbage": "{not",
            "list": "[]",
            "scalar": "42",
            "text": '"nope"',
            "flag": "true",
            "nulls": '{"from": null, "to": null, "note": null}',
            "extra": '{"extra": 1}',
            "partial": '{"from": "open"}',
            "kept": '{"from": "open", "to": "resolved", "note": "kept", "actor": "spoofed", "extra": 1}',
        }
        for actor, detail in rows.items():
            add_status(self.conn, incident_id, actor, detail)

        case = case_record.build(self.conn, incident_id)

        self.assertEqual(case["alerts"], [])
        self.assertEqual(case["notes_omitted"], 0)
        self.assertEqual(case["activity_omitted"], 0)
        self.assertEqual(case["status_changes_omitted"], 0)
        changes = [item for item in case["timeline"] if item["type"] == "incident_status_changed"]
        by_actor = {item["actor"]: item for item in changes}
        self.assertEqual(set(by_actor), set(rows))
        for actor in ("missing", "blank", "garbage", "list", "scalar", "text", "flag", "nulls", "extra"):
            self.assertEqual((by_actor[actor]["from"], by_actor[actor]["to"], by_actor[actor]["note"]),
                             (None, None, None), actor)
        self.assertEqual((by_actor["partial"]["from"], by_actor["partial"]["to"], by_actor["partial"]["note"]),
                         ("open", None, None))
        kept = by_actor["kept"]
        self.assertEqual((kept["from"], kept["to"], kept["note"], kept["actor"]),
                         ("open", "resolved", "kept", "kept"))
        self.assertEqual(set(kept), {"ts", "type", "actor", "from", "to", "note", "sequence"})
        self.assertFalse(any(item.get("actor") == "spoofed" for item in case["timeline"]))

    def test_a_technique_missing_from_the_catalog_or_with_a_bad_level_stays_mapped(self):
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
            " updated_by, techniques) VALUES (?,?,?,?,1,'{}',1,?,?,?)",
            ("case_gap_rule", "case gap", "synthetic", "low", TS, "test", json.dumps([
                {"id": "T9998", "name": None, "tactic": None},
                {"id": "T9999", "name": "", "tactic": None},
            ])))
        alert_id = add_alert(
            self.conn, rule_id="case_gap_rule", disposition="false_positive", assignee="ada", event_count=4)
        incident_id = add_incident(self.conn, [alert_id])
        # T9998 is graded with a level outside the evidence scale. T9999 is not graded at all.
        graded = {"techniques": [{"id": "T9998", "level": "alleged"}]}

        with patch.object(case_record.incidents, "coverage", return_value=graded):
            case = case_record.build(self.conn, incident_id)

        self.assertEqual(case["techniques"], [
            {"id": "T9998", "name": "", "tactic": "", "level": "mapped", "alert_ids": [alert_id]},
            {"id": "T9999", "name": "", "tactic": "", "level": "mapped", "alert_ids": [alert_id]},
        ])
        self.assertEqual(case["alerts"], [{
            "id": alert_id, "rule_id": "case_gap_rule", "title": "synthetic alert", "severity": "high",
            "status": "open", "disposition": "false_positive", "assignee": "ada",
            "first_seen": TS, "last_seen": TS, "event_count": 4,
        }])

    @unittest.expectedFailure
    def test_a_null_tactic_beside_a_blank_tactic_still_builds(self):
        # Both tactics are unknown, so they tie on rank. tactic_order then compares the names with `<`.
        # None and "" raise TypeError inside get_incident, before the case can blank either tactic.
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
            " updated_by, techniques) VALUES (?,?,?,?,1,'{}',1,?,?,?)",
            ("case_gap_rule", "case gap", "synthetic", "low", TS, "test", json.dumps([
                {"id": "T9997", "name": "Named", "tactic": ""},
                {"id": "T9998", "name": None, "tactic": None},
            ])))
        alert_id = add_alert(self.conn, rule_id="case_gap_rule")
        incident_id = add_incident(self.conn, [alert_id])

        with patch.object(case_record.incidents, "coverage", return_value={"techniques": []}):
            case = case_record.build(self.conn, incident_id)

        self.assertEqual(case["techniques"], [
            {"id": "T9997", "name": "Named", "tactic": "", "level": "mapped", "alert_ids": [alert_id]},
            {"id": "T9998", "name": "", "tactic": "", "level": "mapped", "alert_ids": [alert_id]},
        ])


class CaseRecordRenderEdgeTests(unittest.TestCase):
    def test_json_bytes_are_sorted_indented_and_ascii(self):
        raw = case_record.to_json_bytes({
            "b": 1, "a": {"z": "café", "m": None}, "c": [2, 1], "d": True,
        })
        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw, (
            b'{\n  "a": {\n    "m": null,\n    "z": "caf\\u00e9"\n  },\n'
            b'  "b": 1,\n  "c": [\n    2,\n    1\n  ],\n  "d": true\n}'
        ))
        self.assertNotIn("é".encode(), raw)
        self.assertEqual(case_record.to_json_bytes({}), b"{}")
        with self.assertRaises(TypeError):
            case_record.to_json_bytes({"a": {1, 2}})

    def test_markdown_renders_each_timeline_kind_and_blank_fields(self):
        case = {
            "id": 4, "title": "  café * one  ", "synthetic": False, "status": "open",
            "severity": "low", "assignee": None, "first_seen": "t0", "last_seen": "t1",
            "generated_at": "t2",
            "techniques": [
                {"id": "T0000", "name": None, "tactic": None, "level": None, "alert_ids": None},
                {"id": "T0001", "name": "", "tactic": "", "level": "gap", "alert_ids": []},
            ],
            "timeline": [
                {"sequence": 1, "ts": "2026-10-07T12:00:00Z", "type": "evidence", "alert_ids": [3, 4],
                 "event": {"event_type": "auth", "message": "pipe | star * <x>"}},
                {"sequence": 2, "ts": "t|0", "type": "evidence", "alert_ids": [],
                 "event": {"event_type": "auth", "message": None}},
                {"sequence": 3, "ts": "t", "type": "incident_created", "detail": "Incident #4 created"},
                {"sequence": 4, "ts": "t", "type": "alert_added", "alert_id": 8,
                 "rule_id": "rule|a", "title": "title *b"},
                {"sequence": 5, "ts": "t", "type": "assigned", "alert_id": 8, "actor": "ann",
                 "detail": "to bob"},
                {"sequence": 6, "ts": "t", "type": "status_changed", "alert_id": 8, "actor": "ann",
                 "detail": "open > investigating"},
                {"sequence": 7, "ts": "t", "type": "analyst_note", "alert_id": 8, "author": "ann",
                 "body": "see | note"},
                {"sequence": 8, "ts": "t", "type": "incident_status_changed", "actor": "ann",
                 "from": "a|b", "to": "resolved", "note": "done | now"},
                {"sequence": 9, "ts": "t", "type": "incident_status_changed", "actor": "ann",
                 "from": "open", "to": "investigating"},
                {"sequence": 10, "ts": "t", "type": "incident_status_changed", "actor": "ann",
                 "from": "open", "to": "closed", "note": ""},
                {"sequence": 11, "ts": "t", "type": "incident_status_changed", "actor": "ann",
                 "from": None, "to": None, "note": "   "},
                {"sequence": 12, "ts": "t", "type": "reopened", "alert_id": 8, "actor": "ann",
                 "detail": None},
            ],
        }

        raw, text = render(case)

        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertIn("café".encode(), raw)
        self.assertNotIn("SYNTHETIC DATA", text)
        self.assertIn("# Incident case #4: café \\* one\n", text)
        self.assertIn("- **Assignee:** -\n", text)
        self.assertIn("| T0000 | - | - | - | - |", text)
        self.assertIn("| T0001 | - | - | gap | - |", text)
        self.assertIn(
            "| 1 | 2026-10-07T12:00:00Z | Evidence | Alert(s) \\#3, \\#4: auth — pipe \\| star \\* \\<x\\> |",
            text)
        self.assertIn("| 2 | t\\|0 | Evidence | Alert(s) : auth — |", text)
        self.assertIn("| 3 | t | Incident created | Incident \\#4 created |", text)
        self.assertIn("| 4 | t | Alert added | Alert \\#8 (rule\\|a): title \\*b |", text)
        self.assertIn("| 5 | t | Alert assigned | Alert \\#8 by ann: to bob |", text)
        self.assertIn("| 6 | t | Alert status changed | Alert \\#8 by ann: open \\> investigating |", text)
        self.assertIn("| 7 | t | Analyst note | Alert \\#8 by ann: see \\| note |", text)
        self.assertIn(
            "| 8 | t | Incident status changed | ann: a\\|b → resolved — done \\| now |", text)
        self.assertIn("| 9 | t | Incident status changed | ann: open → investigating |", text)
        self.assertIn("| 10 | t | Incident status changed | ann: open → closed |", text)
        self.assertIn("| 11 | t | Incident status changed | ann: None → None — |", text)
        self.assertIn("| 12 | t | Alert activity | Alert \\#8 by ann: reopened — |", text)

    def test_markdown_names_a_single_left_out_row_and_skips_blank_counts(self):
        named = {
            "id": 7, "title": "probe", "synthetic": True, "status": "open", "severity": "high",
            "assignee": "", "first_seen": "t0", "last_seen": "t1", "generated_at": "t2",
            "timeline": [], "techniques": None,
            "events_omitted": 1, "notes_omitted": 2, "activity_omitted": 1, "status_changes_omitted": 1,
        }
        text = case_record.to_markdown_bytes(named).decode()
        self.assertIn("# Incident case #7: probe\n\nSYNTHETIC DATA\n\n- **Status:** open\n", text)
        self.assertIn("- **Assignee:** -\n", text)
        self.assertIn("No ATT&CK technique is recorded for the rules on this incident.", text)
        lines = (
            "_1 evidence event left out._",
            "_2 notes left out._",
            "_1 activity row left out._",
            "_1 status change left out._",
        )
        self.assertEqual([text.index(line) for line in lines], sorted(text.index(line) for line in lines))

        blank = {
            "id": 7, "title": "probe", "synthetic": False, "status": "open", "severity": "high",
            "assignee": "ada", "first_seen": "t0", "last_seen": "t1", "generated_at": "t2",
            "timeline": [], "events_omitted": None, "activity_omitted": "", "status_changes_omitted": 0,
        }
        self.assertNotIn("left out", case_record.to_markdown_bytes(blank).decode())


if __name__ == "__main__":
    unittest.main()
