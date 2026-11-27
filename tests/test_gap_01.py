"""engine._apply_finding keeps one open alert per rule and group key.

Same event ids already linked to any alert of that rule and group key,
including a resolved alert, return unchanged. New ids on an open in-window
alert return updated and write evidence_added. New ids when the only prior
alert is resolved return created and leave that row alone.
"""

import unittest
from datetime import datetime, timedelta, timezone

from watchpost.assets import index as asset_index
from watchpost.db import connect, init_schema, iso
from watchpost.engine import _apply_finding

RULE_ID = "brute_force_ip"
GROUP = "203.0.113.50"
WINDOW = 3600
FIRST = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


def at(delta):
    return iso(FIRST + delta)


class ApplyFindingTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.rule = {
            "id": RULE_ID,
            "version": 3,
            "severity": "high",
            "params": {"window_seconds": WINDOW},
        }
        self.assets = asset_index([])

    def add_events(self, *timestamps):
        ids = []
        for ts in timestamps:
            cur = self.conn.execute(
                "INSERT INTO events(ts, ingested_at, source, event_type, severity, src_ip)"
                " VALUES (?,?,?,?,?,?)",
                (ts, ts, "lab", "auth_failure", "medium", GROUP),
            )
            ids.append(cur.lastrowid)
        return ids

    def add_alert(self, event_ids, *, first_seen, last_seen, status="open", rule_id=RULE_ID,
                  group_key=GROUP):
        resolved = status == "resolved"
        cur = self.conn.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
            " status, disposition, first_seen, last_seen, event_count, synthetic, created_at,"
            " updated_at, resolved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rule_id, 1, group_key, "high", "old title", "old explanation", status,
             "false_positive" if resolved else None, first_seen, last_seen, len(event_ids), 0,
             first_seen, last_seen, last_seen if resolved else None),
        )
        alert_id = cur.lastrowid
        self.conn.executemany(
            "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
            [(alert_id, event_id) for event_id in event_ids],
        )
        self.conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at)"
            " VALUES (?,?,?,?,?)",
            (alert_id, "analyst", "status_changed", status, first_seen),
        )
        return alert_id

    def apply(self, event_ids, **overrides):
        seen = at(timedelta(0))
        finding = {
            "event_ids": list(event_ids),
            "group_key": GROUP,
            "first_seen": seen,
            "last_seen": seen,
            "title": "repeated failures",
            "explanation": "more failures from one address",
        }
        finding.update(overrides)
        return _apply_finding(self.conn, self.rule, finding, False, self.assets)

    def snapshot(self, alert_id):
        row = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        links = tuple(r["event_id"] for r in self.conn.execute(
            "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id", (alert_id,)))
        activity = tuple(tuple(r) for r in self.conn.execute(
            "SELECT actor, action, detail, created_at FROM alert_activity"
            " WHERE alert_id = ? ORDER BY id", (alert_id,)))
        return (tuple(row), links, activity)

    def alert_ids(self):
        return [r["id"] for r in self.conn.execute("SELECT id FROM alerts ORDER BY id")]

    def links(self, alert_id):
        return [r["event_id"] for r in self.conn.execute(
            "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id", (alert_id,))]

    def evidence_added(self, alert_id):
        return [(r["actor"], r["action"], r["detail"]) for r in self.conn.execute(
            "SELECT actor, action, detail FROM alert_activity"
            " WHERE alert_id = ? AND action = 'evidence_added' ORDER BY id", (alert_id,))]

    def test_same_ids_on_a_resolved_alert_return_unchanged(self):
        seen = at(timedelta(0))
        event_id = self.add_events(seen)[0]
        alert_id = self.add_alert([event_id], status="resolved", first_seen=seen, last_seen=seen)
        before = self.snapshot(alert_id)
        finding_ids = [event_id]
        self.assertEqual(self.apply(finding_ids, first_seen=seen, last_seen=seen), "unchanged")
        self.assertEqual(self.apply(finding_ids, first_seen=seen, last_seen=seen), "unchanged")
        self.assertEqual(self.snapshot(alert_id), before)
        self.assertEqual(self.alert_ids(), [alert_id])
        self.assertEqual(self.evidence_added(alert_id), [])

    def test_same_ids_on_an_open_alert_return_unchanged(self):
        seen = at(timedelta(0))
        event_id = self.add_events(seen)[0]
        alert_id = self.add_alert([event_id], first_seen=seen, last_seen=seen)
        before = self.snapshot(alert_id)
        self.assertEqual(self.apply([event_id], first_seen=seen, last_seen=seen), "unchanged")
        self.assertEqual(self.snapshot(alert_id), before)
        self.assertEqual(self.evidence_added(alert_id), [])

    def test_new_ids_on_an_open_in_window_alert_return_updated(self):
        seen = at(timedelta(0))
        later = at(timedelta(minutes=20))
        old_id, new_id = self.add_events(seen, later)
        alert_id = self.add_alert([old_id], first_seen=seen, last_seen=seen)
        outcome = self.apply([old_id, new_id], first_seen=seen, last_seen=later)
        self.assertEqual(outcome, "updated")
        self.assertEqual(self.alert_ids(), [alert_id])
        row = dict(self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())
        self.assertEqual(row["status"], "open")
        self.assertEqual(row["event_count"], 2)
        self.assertEqual(row["first_seen"], seen)
        self.assertEqual(row["last_seen"], later)
        self.assertEqual(self.links(alert_id), [old_id, new_id])
        self.assertEqual(self.evidence_added(alert_id), [
            ("detection", "evidence_added", "now 2 related events"),
        ])

    def test_open_alert_exactly_one_window_back_is_still_updated(self):
        # last_seen == first_seen - window_seconds is still inside the window.
        last = at(timedelta(seconds=-WINDOW))
        seen = at(timedelta(0))
        old_id, new_id = self.add_events(last, seen)
        alert_id = self.add_alert([old_id], first_seen=last, last_seen=last)
        outcome = self.apply([new_id], first_seen=seen, last_seen=seen)
        self.assertEqual(outcome, "updated")
        self.assertEqual(self.alert_ids(), [alert_id])
        self.assertEqual(self.links(alert_id), [old_id, new_id])
        self.assertEqual(self.evidence_added(alert_id), [
            ("detection", "evidence_added", "now 2 related events"),
        ])

    def test_open_alert_outside_the_window_is_left_alone(self):
        last = at(timedelta(seconds=-WINDOW, milliseconds=-1))
        seen = at(timedelta(0))
        old_id, new_id = self.add_events(last, seen)
        alert_id = self.add_alert([old_id], first_seen=last, last_seen=last)
        before = self.snapshot(alert_id)
        outcome = self.apply([new_id], first_seen=seen, last_seen=seen)
        self.assertEqual(outcome, "created")
        self.assertEqual(self.snapshot(alert_id), before)
        self.assertEqual(self.evidence_added(alert_id), [])
        created_id = next(i for i in self.alert_ids() if i != alert_id)
        created = dict(self.conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (created_id,)).fetchone())
        self.assertEqual(created["status"], "open")
        self.assertEqual(created["event_count"], 1)
        self.assertEqual(self.links(created_id), [new_id])
        self.assertEqual(self.links(alert_id), [old_id])

    def test_new_ids_when_the_only_prior_alert_is_resolved_return_created(self):
        # The resolved row is still inside the window. Status, not age, keeps it closed.
        seen = at(timedelta(0))
        later = at(timedelta(minutes=10))
        old_id, new_id = self.add_events(seen, later)
        resolved_id = self.add_alert([old_id], status="resolved", first_seen=seen, last_seen=seen)
        before = self.snapshot(resolved_id)
        outcome = self.apply([new_id], first_seen=later, last_seen=later)
        self.assertEqual(outcome, "created")
        self.assertEqual(self.snapshot(resolved_id), before)
        self.assertEqual(self.links(resolved_id), [old_id])
        self.assertEqual(self.evidence_added(resolved_id), [])
        created_id = next(i for i in self.alert_ids() if i != resolved_id)
        created = dict(self.conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (created_id,)).fetchone())
        self.assertEqual(created["status"], "open")
        self.assertEqual(created["rule_id"], RULE_ID)
        self.assertEqual(created["group_key"], GROUP)
        self.assertEqual(created["rule_version"], 3)
        self.assertEqual(created["event_count"], 1)
        self.assertEqual(self.links(created_id), [new_id])
        actions = [r["action"] for r in self.conn.execute(
            "SELECT action FROM alert_activity WHERE alert_id = ? ORDER BY id", (created_id,))]
        self.assertEqual(actions, ["created"])

    def test_a_new_id_beside_resolved_evidence_still_creates(self):
        seen = at(timedelta(0))
        later = at(timedelta(minutes=10))
        old_id, new_id = self.add_events(seen, later)
        resolved_id = self.add_alert([old_id], status="resolved", first_seen=seen, last_seen=seen)
        before = self.snapshot(resolved_id)
        outcome = self.apply([old_id, new_id], first_seen=seen, last_seen=later)
        self.assertEqual(outcome, "created")
        self.assertEqual(self.snapshot(resolved_id), before)
        created_id = next(i for i in self.alert_ids() if i != resolved_id)
        self.assertEqual(self.links(resolved_id), [old_id])
        self.assertEqual(self.links(created_id), [old_id, new_id])
        created = dict(self.conn.execute(
            "SELECT event_count, status FROM alerts WHERE id = ?", (created_id,)).fetchone())
        self.assertEqual((created["event_count"], created["status"]), (2, "open"))

    def test_same_ids_on_another_rule_do_not_block_a_new_alert(self):
        seen = at(timedelta(0))
        event_id = self.add_events(seen)[0]
        other_id = self.add_alert(
            [event_id], rule_id="password_spray", first_seen=seen, last_seen=seen)
        before = self.snapshot(other_id)
        self.assertEqual(self.apply([event_id], first_seen=seen, last_seen=seen), "created")
        self.assertEqual(self.snapshot(other_id), before)
        self.assertEqual(len(self.alert_ids()), 2)
        created_id = next(i for i in self.alert_ids() if i != other_id)
        self.assertEqual(self.links(created_id), [event_id])
        self.assertEqual(self.links(other_id), [event_id])

    def test_same_ids_on_another_group_key_do_not_block_a_new_alert(self):
        seen = at(timedelta(0))
        event_id = self.add_events(seen)[0]
        other_id = self.add_alert(
            [event_id], group_key="198.51.100.8", first_seen=seen, last_seen=seen)
        before = self.snapshot(other_id)
        self.assertEqual(self.apply([event_id], first_seen=seen, last_seen=seen), "created")
        self.assertEqual(self.snapshot(other_id), before)
        self.assertEqual(len(self.alert_ids()), 2)
        created_id = next(i for i in self.alert_ids() if i != other_id)
        created = dict(self.conn.execute(
            "SELECT group_key FROM alerts WHERE id = ?", (created_id,)).fetchone())
        self.assertEqual(created["group_key"], GROUP)
        self.assertEqual(self.links(other_id), [event_id])
