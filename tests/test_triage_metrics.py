"""Milestone 12: acknowledge timestamps, alert assignment, and triage metrics (MTTA/MTTR, SLA breaches)."""

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import ServerTestCase
from watchpost import queries, triage
from watchpost.db import SCHEMA_VERSION, connect, init_schema, iso, verify_chain

T0 = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)


def at(minutes):
    return iso(T0 + timedelta(minutes=minutes))


def add_alert(conn, severity="critical", created=0, acked=None, resolved=None, status=None, synthetic=0):
    """Insert an alert with fixed timestamps (minutes after T0). Returns its id."""
    status = status or ("resolved" if resolved is not None else "investigating" if acked is not None else "open")
    return conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status, disposition,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at, acknowledged_at, resolved_at)"
        " VALUES ('brute_force_ip', 1, 'k', ?, 't', 'e', ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        (severity, status, "true_positive" if status == "resolved" else None, at(created), at(created), synthetic,
         at(created), at(created), None if acked is None else at(acked), None if resolved is None else at(resolved)),
    ).lastrowid


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = connect(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def severity(self, result, name):
        return next(s for s in result["severities"] if s["severity"] == name)


class PercentileTests(unittest.TestCase):
    def test_median_and_p90(self):
        values = list(range(1, 11))
        self.assertEqual(triage.median(values), 5.5)
        self.assertEqual(triage.percentile(values, 0.9), 9)  # nearest rank: ceil(0.9 * 10) = 9th value
        self.assertEqual(triage.median([7, 1, 3]), 3)
        self.assertEqual(triage.percentile([5, 1, 3], 0.9), 5)
        self.assertEqual(triage.percentile([4], 0.9), 4)
        self.assertIsNone(triage.median([]))
        self.assertIsNone(triage.percentile([], 0.9))

    def test_summary_is_empty_without_samples(self):
        self.assertEqual(triage.summarize([]), {"samples": 0, "mean_minutes": None, "median_minutes": None,
                                                "p90_minutes": None})


class TriageMathTests(DbTestCase):
    def test_mtta_and_mttr_with_fixed_timestamps(self):
        add_alert(self.conn, created=0, acked=5, resolved=60)
        add_alert(self.conn, created=0, acked=10, resolved=120)
        add_alert(self.conn, created=0, acked=30, resolved=300)
        result = triage.triage_metrics(self.conn, "all", now=T0 + timedelta(days=1))
        crit = self.severity(result, "critical")
        self.assertEqual(crit["count"], 3)
        self.assertEqual(crit["open"], 0)
        self.assertEqual(crit["mtta"], {"samples": 3, "mean_minutes": 15.0, "median_minutes": 10.0, "p90_minutes": 30.0})
        self.assertEqual(crit["mttr"], {"samples": 3, "mean_minutes": 160.0, "median_minutes": 120.0,
                                        "p90_minutes": 300.0})
        # Critical targets: ack 15m, resolve 240m. Only the 30m ack and the 300m resolve are late.
        self.assertEqual(crit["sla"], {"ack_target_minutes": 15, "resolve_target_minutes": 240,
                                       "ack_breaches": 1, "resolve_breaches": 1})
        self.assertEqual(self.severity(result, "high")["count"], 0)
        self.assertIsNone(self.severity(result, "high")["mtta"]["mean_minutes"])

    def test_open_and_unacknowledged_alerts_count_against_the_clock(self):
        now = T0 + timedelta(minutes=20)
        add_alert(self.conn, created=0)        # open 20m: past the 15m ack target, inside 4h resolve
        add_alert(self.conn, created=10)       # open 10m: inside both
        add_alert(self.conn, created=0, acked=15)  # acked exactly at the target: not a breach
        result = triage.triage_metrics(self.conn, "all", now=now)
        crit = self.severity(result, "critical")
        self.assertEqual((crit["count"], crit["open"], crit["unresolved"]), (3, 2, 3))
        self.assertEqual(crit["mtta"]["samples"], 1)  # only measured acks feed MTTA
        self.assertEqual((crit["sla"]["ack_breaches"], crit["sla"]["resolve_breaches"]), (1, 0))
        later = triage.triage_metrics(self.conn, "all", now=T0 + timedelta(hours=5))
        self.assertEqual(self.severity(later, "critical")["sla"]["resolve_breaches"], 3)

    def test_breaches_for_a_single_alert(self):
        alert = {"severity": "high", "status": "open", "created_at": at(0), "acknowledged_at": None, "resolved_at": None}
        self.assertEqual(triage.breaches(alert, T0 + timedelta(minutes=60)), [])
        self.assertEqual(triage.breaches(alert, T0 + timedelta(minutes=61)), ["ack"])
        self.assertEqual(triage.breaches(alert, T0 + timedelta(days=2)), ["ack", "resolve"])
        # Acknowledged late, then resolved in time: the late ack stays a breach in the history.
        done = {**alert, "status": "resolved", "acknowledged_at": at(90), "resolved_at": at(120)}
        self.assertEqual(triage.breaches(done, T0 + timedelta(days=9)), ["ack"])
        # A row from before acknowledged_at existed: its ack time is unknown, so it is never judged.
        legacy = {**alert, "status": "investigating"}
        self.assertEqual(triage.breaches(legacy, T0 + timedelta(minutes=90)), [])
        self.assertEqual(triage.breaches({**alert, "severity": "unknown"}, T0 + timedelta(days=9)), [])

    def test_legacy_rows_without_an_ack_time_are_reported_not_guessed(self):
        add_alert(self.conn, created=0, status="investigating")  # pre-migration: left open, no ack time recorded
        crit = self.severity(triage.triage_metrics(self.conn, "all", now=T0 + timedelta(hours=1)), "critical")
        self.assertEqual((crit["ack_unknown"], crit["mtta"]["samples"], crit["sla"]["ack_breaches"]), (1, 0, 0))

    def test_window_filters_on_creation_time_and_is_validated(self):
        now = datetime.now(timezone.utc)
        recent = add_alert(self.conn)
        old = add_alert(self.conn)
        self.conn.execute("UPDATE alerts SET created_at = ? WHERE id = ?", (iso(now - timedelta(hours=1)), recent))
        self.conn.execute("UPDATE alerts SET created_at = ? WHERE id = ?", (iso(now - timedelta(days=10)), old))
        self.assertEqual(self.severity(triage.triage_metrics(self.conn, "7d"), "critical")["count"], 1)
        self.assertEqual(self.severity(triage.triage_metrics(self.conn, "30d"), "critical")["count"], 2)
        self.assertEqual(self.severity(triage.triage_metrics(self.conn, "all"), "critical")["count"], 2)
        self.assertEqual(triage.triage_metrics(self.conn, None)["window"], triage.DEFAULT_WINDOW)
        for bad in ("8d", "7", "-1d", "all; DROP"):
            with self.subTest(window=bad), self.assertRaises(queries.QueryError):
                triage.triage_metrics(self.conn, bad)

    def test_synthetic_label(self):
        self.assertEqual(triage.triage_metrics(self.conn, "all")["synthetic"], "none")
        add_alert(self.conn, synthetic=1)
        result = triage.triage_metrics(self.conn, "all")
        self.assertEqual((result["synthetic"], result["synthetic_alerts"]), ("all", 1))
        add_alert(self.conn, synthetic=0)
        result = triage.triage_metrics(self.conn, "all")
        self.assertEqual((result["synthetic"], result["synthetic_alerts"]), ("some", 1))

    def test_sla_targets_cover_every_severity(self):
        from watchpost.normalize import SEVERITIES
        self.assertEqual(set(triage.SLA_TARGETS), set(SEVERITIES))
        for sev, target in triage.SLA_TARGETS.items():
            self.assertLess(target["ack"], target["resolve"], sev)
        self.assertEqual(triage.SLA_TARGETS["critical"], {"ack": 15, "resolve": 240})


class AcknowledgeTests(DbTestCase):
    def ack(self, alert_id):
        return self.conn.execute("SELECT acknowledged_at FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]

    def test_acknowledged_at_is_set_once_and_never_overwritten(self):
        alert_id = add_alert(self.conn)
        self.assertIsNone(self.ack(alert_id))
        queries.update_status(self.conn, alert_id, "alice", "investigating")
        self.assertIsNotNone(self.ack(alert_id))
        self.conn.execute("UPDATE alerts SET acknowledged_at = ? WHERE id = ?", (at(3), alert_id))
        queries.update_status(self.conn, alert_id, "bob", "resolved", "benign")
        queries.update_status(self.conn, alert_id, "bob", "open")       # reopen
        queries.update_status(self.conn, alert_id, "bob", "investigating")
        queries.update_status(self.conn, alert_id, "bob", "resolved", "true_positive")
        self.assertEqual(self.ack(alert_id), at(3))

    def test_resolving_straight_from_open_acknowledges_at_the_same_time(self):
        alert_id = add_alert(self.conn)
        row = queries.update_status(self.conn, alert_id, "alice", "resolved", "false_positive")
        self.assertEqual(row["acknowledged_at"], row["resolved_at"])

    def test_a_row_that_already_left_open_is_not_backfilled(self):
        alert_id = add_alert(self.conn, status="investigating")
        queries.update_status(self.conn, alert_id, "alice", "resolved", "benign")
        self.assertIsNone(self.ack(alert_id))

    def test_status_changes_are_audited(self):
        alert_id = add_alert(self.conn)
        queries.update_status(self.conn, alert_id, "alice", "investigating")
        row = self.conn.execute("SELECT actor, target, detail FROM audit_log WHERE action = 'alert_status_changed'"
                                " ORDER BY id DESC").fetchone()
        self.assertEqual((row["actor"], row["target"]), ("alice", str(alert_id)))
        self.assertIn('"to": "investigating"', row["detail"])
        self.assertTrue(verify_chain(self.conn)["ok"])


class TriageApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        with sqlite3.connect(self.db_path) as db:
            self.alert_id = add_alert(db, synthetic=1)
            self.old_id = add_alert(db, severity="high")
            db.execute("UPDATE alerts SET created_at = ? WHERE id = ?",
                       (iso(datetime.now(timezone.utc) - timedelta(hours=2)), self.old_id))
            db.execute("UPDATE alerts SET created_at = ? WHERE id = ?",
                       (iso(datetime.now(timezone.utc)), self.alert_id))

    def test_viewer_reads_metrics_but_cannot_assign_or_acknowledge(self):
        viewer = self.client("viewer")
        status, data, _ = viewer.get("/api/metrics/triage")
        self.assertEqual(status, 200, data)
        self.assertEqual({s["severity"] for s in data["severities"]}, set(triage.SLA_TARGETS))
        self.assertEqual(viewer.post(f"/api/alerts/{self.alert_id}/assign", {"assignee": "analyst"})[0], 403)
        self.assertEqual(viewer.post(f"/api/alerts/{self.alert_id}/status", {"status": "investigating"})[0], 403)
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT status, assignee, acknowledged_at FROM alerts WHERE id = ?",
                             (self.alert_id,)).fetchone()
        self.assertEqual(row, ("open", None, None))

    def test_metrics_endpoint_validates_the_window_and_labels_synthetic_data(self):
        analyst = self.client("analyst")
        status, data, _ = analyst.get("/api/metrics/triage?window=7d")
        self.assertEqual((status, data["window"], data["synthetic"], data["synthetic_alerts"]), (200, "7d", "some", 1))
        self.assertEqual(data["sla_targets_minutes"]["critical"], {"ack": 15, "resolve": 240})
        self.assertEqual(analyst.get("/api/metrics/triage?window=1y")[0], 400)

    def test_analyst_assigns_to_an_analyst_or_admin_with_an_audit_entry(self):
        analyst = self.client("analyst")
        status, data, _ = analyst.post(f"/api/alerts/{self.alert_id}/assign", {"assignee": "admin"})
        self.assertEqual((status, data["assignee"]), (200, "admin"), data)
        self.assertEqual(data["status"], "open")  # assigning hands over ownership; it is not an acknowledgement
        self.assertIsNone(data["acknowledged_at"])
        for bad in ("viewer", "nobody", "", None, 5):
            with self.subTest(assignee=bad):
                self.assertEqual(analyst.post(f"/api/alerts/{self.alert_id}/assign", {"assignee": bad})[0], 400)
        self.assertEqual(analyst.post("/api/alerts/9999/assign", {"assignee": "admin"})[0], 404)
        entries = [a for a in self.client("admin").get("/api/audit")[1] if a["action"] == "alert_assigned"]
        self.assertEqual(len(entries), 1)
        self.assertEqual((entries[0]["actor"], entries[0]["target"]), ("analyst", str(self.alert_id)))
        activity = analyst.get(f"/api/alerts/{self.alert_id}")[1]["activity"]
        self.assertEqual(activity[-1]["action"], "assigned")

    def test_alert_list_flags_open_alerts_past_their_sla(self):
        alerts = {a["id"]: a for a in self.client("viewer").get("/api/alerts")[1]}
        self.assertEqual(alerts[self.alert_id]["sla_breach"], [])            # critical, just created
        self.assertEqual(alerts[self.old_id]["sla_breach"], ["ack"])         # high, open for 2h (ack target 1h)
        self.client("analyst").post(f"/api/alerts/{self.old_id}/status", {"status": "investigating"})
        alerts = {a["id"]: a for a in self.client("viewer").get("/api/alerts")[1]}
        self.assertEqual(alerts[self.old_id]["sla_breach"], [])              # acknowledged: no longer pending ack


class MigrationTests(unittest.TestCase):
    def test_v6_database_gains_acknowledged_at_and_keeps_rows_null(self):
        self.assertEqual(SCHEMA_VERSION, 7)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v6.db")
            conn = connect(path)
            init_schema(conn)
            conn.execute("ALTER TABLE alerts DROP COLUMN acknowledged_at")  # what a 6.x database looked like
            conn.execute("UPDATE meta SET value = '6' WHERE key = 'schema_version'")
            conn.execute(
                "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
                " first_seen, last_seen, event_count, created_at, updated_at) VALUES"
                " ('r', 1, 'k', 'high', 't', 'e', 'investigating', ?, ?, 1, ?, ?)", (at(0), at(0), at(0), at(0)))
            chain = [tuple(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
            conn.close()

            conn = connect(path)
            self.addCleanup(conn.close)
            init_schema(conn)
            self.assertIn("acknowledged_at", {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")})
            self.assertEqual(conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "7")
            self.assertEqual(conn.execute("SELECT acknowledged_at FROM alerts").fetchall()[0][0], None)
            self.assertEqual([tuple(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")], chain)
            self.assertTrue(verify_chain(conn)["ok"])
            crit = triage.triage_metrics(conn, "all")
            self.assertEqual(next(s for s in crit["severities"] if s["severity"] == "high")["ack_unknown"], 1)


if __name__ == "__main__":
    unittest.main()
