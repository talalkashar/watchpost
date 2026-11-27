"""rescore_open_alerts updates unresolved alerts whose weighed severity differs.

The return value is that count. Each of those alerts gets one severity_changed
activity row, read back with GET /api/alerts/{id} (the row the asset rescore
writes, actor "assets"). A resolved alert keeps the severity it closed with.
"""

import unittest

from tests.helpers import ServerTestCase
from watchpost import assets
from watchpost.db import connect

STAMP = "2026-11-01T12:00:00.000Z"


def insert_alert(conn, status, severity, base, host, group_key):
    """One alert linked to one event on `host`, stamped so a later write is visible."""
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
        " VALUES (?, ?, 'lab', ?, 'auth_failure', 'medium', 'Failed password', 1)",
        (STAMP, STAMP, host))
    event_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    resolved_at = STAMP if status == "resolved" else None
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, base_severity, assets,"
        " title, explanation, status, first_seen, last_seen, event_count, synthetic, created_at,"
        " updated_at, resolved_at)"
        " VALUES ('brute_force_ip', 1, ?, ?, ?, '[]', 'synthetic alert', 'why', ?, ?, ?, 1, 1, ?, ?, ?)",
        (group_key, severity, base, status, STAMP, STAMP, STAMP, STAMP, resolved_at))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)", (alert_id, event_id))
    return alert_id


class RescoreOpenAlertsTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.analyst = self.client("analyst")
        self.conn = connect(self.db_path)
        self.addCleanup(self.conn.close)
        # Critical host: medium rises two levels to critical, high rises to critical and stops there.
        assets.save_asset(self.conn, {"name": "db01", "kind": "database", "criticality": "critical"}, "admin")
        self.ids = {
            "raised": insert_alert(self.conn, "open", "medium", "medium", "db01", "raised"),
            "capped": insert_alert(self.conn, "investigating", "high", "high", "db01", "capped"),
            "held": insert_alert(self.conn, "open", "critical", "high", "db01", "held"),
            "lowered": insert_alert(self.conn, "open", "critical", "medium", "kiosk07", "lowered"),
            "resolved": insert_alert(self.conn, "resolved", "medium", "medium", "db01", "resolved"),
        }

    def alert(self, key):
        status, data, _ = self.analyst.get(f"/api/alerts/{self.ids[key]}")
        self.assertEqual(status, 200, data)
        return data

    def severity_changed(self, key):
        """severity_changed rows as the alert detail API returns them."""
        return [row for row in self.alert(key)["activity"]
                if row["action"] == "severity_changed" and row["actor"] == "assets"]

    def test_unresolved_severity_changes_are_counted_and_resolved_alerts_stay(self):
        resolved_before = self.alert("resolved")
        changed = assets.rescore_open_alerts(self.conn)
        # raised medium->critical, capped high->critical, lowered critical->medium.
        # held is already critical. resolved is not re-weighed.
        self.assertEqual(changed, 3)

        raised = self.alert("raised")
        self.assertEqual((raised["status"], raised["severity"], raised["base_severity"]),
                         ("open", "critical", "medium"))
        self.assertEqual([item["name"] for item in raised["assets"]], ["db01"])
        self.assertIn("db01 is a critical-criticality asset", raised["severity_note"])
        self.assertNotEqual(raised["updated_at"], STAMP)
        raised_rows = self.severity_changed("raised")
        self.assertEqual(len(raised_rows), 1)
        self.assertTrue(raised_rows[0]["detail"].startswith("medium -> critical"))

        capped = self.alert("capped")
        self.assertEqual((capped["status"], capped["severity"], capped["base_severity"]),
                         ("investigating", "critical", "high"))
        self.assertEqual([item["name"] for item in capped["assets"]], ["db01"])
        self.assertNotEqual(capped["updated_at"], STAMP)
        capped_rows = self.severity_changed("capped")
        self.assertEqual(len(capped_rows), 1)
        self.assertTrue(capped_rows[0]["detail"].startswith("high -> critical"))

        held = self.alert("held")
        self.assertEqual((held["severity"], held["base_severity"], held["updated_at"]),
                         ("critical", "high", STAMP))
        self.assertEqual([item["name"] for item in held["assets"]], ["db01"])
        self.assertEqual(self.severity_changed("held"), [])

        lowered = self.alert("lowered")
        self.assertEqual((lowered["status"], lowered["severity"], lowered["base_severity"]),
                         ("open", "medium", "medium"))
        self.assertEqual(lowered["assets"], [])
        self.assertIsNone(lowered["severity_note"])
        self.assertNotEqual(lowered["updated_at"], STAMP)
        lowered_rows = self.severity_changed("lowered")
        self.assertEqual(len(lowered_rows), 1)
        self.assertTrue(lowered_rows[0]["detail"].startswith("critical -> medium"))

        resolved = self.alert("resolved")
        for field in ("severity", "base_severity", "assets", "severity_note", "status",
                      "updated_at", "resolved_at"):
            self.assertEqual(resolved[field], resolved_before[field], field)
        self.assertEqual(resolved["severity"], "medium")
        self.assertEqual(resolved["assets"], [])
        self.assertEqual(self.severity_changed("resolved"), [])

        # A second pass finds nothing new and does not write another activity row.
        self.assertEqual(assets.rescore_open_alerts(self.conn), 0)
        self.assertEqual(len(self.severity_changed("raised")), 1)
        self.assertEqual(len(self.severity_changed("capped")), 1)
        self.assertEqual(len(self.severity_changed("lowered")), 1)
        self.assertEqual(self.severity_changed("resolved"), [])


if __name__ == "__main__":
    unittest.main()
