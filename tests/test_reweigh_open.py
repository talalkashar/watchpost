"""Open-alert reweigh reads evidence once, grouped by alert id.

A resolved alert stays out. An alert whose events match an asset and an alert whose events
match none keep the severity, base_severity, assets, and severity_note weigh() already returns.
"""

import json
import unittest

from watchpost import assets
from watchpost.db import connect, init_schema

TS = "2026-09-15T12:00:00.000Z"
UPDATED = "2026-09-01T00:00:00.000Z"


def add_event(conn, host, src_ip, dest_ip):
    cur = conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, src_ip, dest_ip, synthetic)"
        " VALUES (?, ?, 'demo', ?, 'auth_failure', 'medium', ?, ?, 1)",
        (TS, TS, host, src_ip, dest_ip))
    return cur.lastrowid


def add_alert(conn, status, severity, base, group_key, assets_json="[]", note=None):
    cur = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " base_severity, assets, severity_note, first_seen, last_seen, event_count, synthetic,"
        " created_at, updated_at)"
        " VALUES ('brute_force_ip', 1, ?, ?, 'synthetic alert', 'why', ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)",
        (group_key, severity, status, base, assets_json, note, TS, TS, TS, UPDATED))
    return cur.lastrowid


def link(conn, alert_id, event_id):
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)", (alert_id, event_id))


class ReweighOpenTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.idx = assets.index([
            {"id": 1, "name": "db01", "kind": "database", "criticality": "critical",
             "data_tags": ["pci"], "addresses": [], "synthetic": 1},
            {"id": 2, "name": "pay-gw", "kind": "server", "criticality": "high",
             "data_tags": [], "addresses": ["198.51.100.10"], "synthetic": 1},
        ])
        db_host = add_event(self.conn, "db01", "203.0.113.77", None)
        pay = add_event(self.conn, "jump01", None, "198.51.100.10")
        quiet_host = add_event(self.conn, "kiosk07", "203.0.113.78", "203.0.113.79")
        closed = add_event(self.conn, "db01", "203.0.113.80", None)
        self.matched = add_alert(self.conn, "open", "high", "high", "matched")
        self.unmatched = add_alert(self.conn, "investigating", "high", "high", "unmatched")
        self.none = add_alert(self.conn, "open", "medium", "medium", "none")
        self.resolved = add_alert(self.conn, "resolved", "critical", "high", "closed",
                                  '["sentinel"]', "kept")
        link(self.conn, self.matched, db_host)
        link(self.conn, self.matched, pay)
        link(self.conn, self.unmatched, quiet_host)
        link(self.conn, self.resolved, closed)

    def row(self, alert_id):
        return self.conn.execute(
            "SELECT severity, base_severity, assets, severity_note, updated_at FROM alerts WHERE id = ?",
            (alert_id,)).fetchone()

    def test_one_grouped_query_keeps_match_and_miss(self):
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append(sql)
            return real_execute(sql, args)

        self.conn.execute = execute
        changed = assets.rescore_open_alerts(self.conn, self.idx)
        grouped = [sql for sql in captured if "alert_events" in sql]
        self.assertEqual(len(grouped), 1)
        self.assertIn("GROUP BY a.id", grouped[0])
        self.assertIn("json_group_array", grouped[0])
        self.assertNotIn("alert_id = ?", grouped[0])
        self.assertEqual(changed, 1)

        matched = self.row(self.matched)
        self.assertEqual(matched["severity"], "critical")
        self.assertEqual(matched["base_severity"], "high")
        self.assertEqual([a["name"] for a in json.loads(matched["assets"])], ["db01", "pay-gw"])
        self.assertEqual(
            matched["severity_note"],
            "raised 2 level(s): db01 is a critical-criticality asset; sensitive data on db01 (pci)")
        self.assertNotEqual(matched["updated_at"], UPDATED)
        activity = self.conn.execute(
            "SELECT action, detail FROM alert_activity WHERE alert_id = ?", (self.matched,)).fetchone()
        self.assertEqual(activity["action"], "severity_changed")
        self.assertIn("high -> critical", activity["detail"])

        unmatched = self.row(self.unmatched)
        self.assertEqual((unmatched["severity"], unmatched["base_severity"]), ("high", "high"))
        self.assertEqual(unmatched["assets"], "[]")
        self.assertIsNone(unmatched["severity_note"])
        self.assertEqual(unmatched["updated_at"], UPDATED)

        quiet = self.row(self.none)
        self.assertEqual((quiet["severity"], quiet["base_severity"], quiet["assets"]), ("medium", "medium", "[]"))
        self.assertIsNone(quiet["severity_note"])
        self.assertEqual(quiet["updated_at"], UPDATED)

        resolved = self.row(self.resolved)
        self.assertEqual(resolved["severity"], "critical")
        self.assertEqual(resolved["base_severity"], "high")
        self.assertEqual(resolved["assets"], '["sentinel"]')
        self.assertEqual(resolved["severity_note"], "kept")
        self.assertEqual(resolved["updated_at"], UPDATED)
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM alert_activity WHERE alert_id = ?", (self.resolved,)).fetchone())
