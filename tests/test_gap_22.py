"""get_alert: a missing id is 404, and a hit carries techniques, evidence, notes, activity, and timeline.

Evidence is the earliest 500 linked events. Notes and activity are this alert's rows.
The timeline is events that share a source IP, user, or host inside the alert window.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone

from watchpost.db import connect, init_schema, iso
from watchpost.queries import EVIDENCE_LIMIT, QueryError, get_alert

BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)
TECHNIQUES = [{"id": "T1110", "name": "Brute Force", "tactic": "credential-access"}]


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_rule(conn, rule_id, techniques):
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by,"
        " techniques) VALUES (?,?,?,?,1,?,1,?,?,?)",
        (rule_id, "Synthetic rule", "synthetic", "high", "{}", SEEN, "system", json.dumps(techniques)))


def add_event(conn, minutes, user="alice", src_ip="192.0.2.10", host="web01", message="[SYNTHETIC] evidence"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", host, "auth", "low", user, src_ip, message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_events(conn, count, minutes):
    """`count` events that share one timestamp. Ids are the rows just inserted, in id order."""
    before = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.executemany(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?,1)",
        [(ts, ts, "lab", "web01", "auth", "low", "alice", "192.0.2.10", "[SYNTHETIC] evidence")
         for _ in range(count)])
    return list(range(before + 1, before + 1 + count))


def add_alert(conn, event_ids, rule_id="synthetic_rule"):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        (rule_id, 1, "alice", "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, len(event_ids), SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


class GetAlertTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_a_missing_id_raises_query_error_404(self):
        add_rule(self.conn, "synthetic_rule", TECHNIQUES)
        present = add_alert(self.conn, [])
        with self.assertRaises(QueryError) as caught:
            get_alert(self.conn, present + 1)
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(str(caught.exception), "alert not found")

    def test_detail_includes_the_rules_techniques_notes_activity_and_timeline(self):
        add_rule(self.conn, "synthetic_rule", TECHNIQUES)
        add_rule(self.conn, "other_rule", [{"id": "T9999", "name": "Other", "tactic": "impact"}])
        evidence_id = add_event(self.conn, 0, message="[SYNTHETIC] evidence")
        # Same user, different host and address: the timeline matches the user.
        related_id = add_event(
            self.conn, 5, user="alice", src_ip="192.0.2.20", host="db01", message="[SYNTHETIC] related")
        # No shared source IP, user, or host.
        add_event(
            self.conn, 6, user="mallory", src_ip="198.51.100.9", host="other", message="[SYNTHETIC] unrelated")
        # Same user, past the 30-minute pad around first_seen and last_seen.
        add_event(self.conn, 40, message="[SYNTHETIC] outside window")
        alert_id = add_alert(self.conn, [evidence_id])
        other = add_alert(self.conn, [], rule_id="other_rule")
        self.conn.execute(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
            (alert_id, "analyst", "[SYNTHETIC] note", SEEN))
        self.conn.execute(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
            (other, "analyst", "[SYNTHETIC] other note", SEEN))
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "analyst", "status_changed", "[SYNTHETIC] opened", SEEN))
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (other, "analyst", "assigned", "[SYNTHETIC] other activity", SEEN))

        detail = get_alert(self.conn, alert_id)
        self.assertEqual(detail["rule"]["techniques"], TECHNIQUES)
        self.assertEqual(detail["rule"]["id"], "synthetic_rule")
        self.assertEqual([row["body"] for row in detail["notes"]], ["[SYNTHETIC] note"])
        self.assertEqual(detail["notes_omitted"], 0)
        self.assertEqual(
            [(row["action"], row["detail"]) for row in detail["activity"]],
            [("status_changed", "[SYNTHETIC] opened")])
        self.assertEqual(detail["activity_omitted"], 0)
        self.assertEqual([row["id"] for row in detail["evidence"]], [evidence_id])
        self.assertEqual(
            [(row["id"], row["is_evidence"]) for row in detail["timeline"]],
            [(evidence_id, True), (related_id, False)])

    def test_evidence_is_at_most_500_rows(self):
        self.assertEqual(EVIDENCE_LIMIT, 500)
        add_rule(self.conn, "synthetic_rule", TECHNIQUES)
        # Lower id, later time: order is ts, then id, so this row is the one past the cap.
        late_id = add_event(self.conn, minutes=10, message="[SYNTHETIC] late evidence")
        early_ids = add_events(self.conn, EVIDENCE_LIMIT, minutes=0)
        alert_id = add_alert(self.conn, [late_id] + early_ids)
        # Another alert's event is not this alert's evidence and is not omitted.
        extra_id = add_event(self.conn, minutes=0, message="[SYNTHETIC] other alert")
        add_alert(self.conn, [extra_id])

        detail = get_alert(self.conn, alert_id)
        self.assertEqual(len(detail["evidence"]), 500)
        self.assertEqual([row["id"] for row in detail["evidence"]], early_ids)
        self.assertEqual(detail["evidence_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["evidence"]})
        self.assertNotIn(extra_id, {row["id"] for row in detail["evidence"]})
