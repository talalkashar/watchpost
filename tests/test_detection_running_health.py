"""A detection run still marked running is not a successful health check.

A row younger than 5 minutes is degraded and is not called succeeded.
A row older than 5 minutes stays the stuck message.
A finished ok run with no failed batches stays ok.
A failed run stays failing.
Zero enabled rules stays the existing degraded message.
The row is inserted. Detection is not started.
"""

import sqlite3
import unittest
from datetime import timedelta

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.engine import seed_rules
from watchpost.health import check_detection


def memory():
    conn = connect(":memory:")
    init_schema(conn)
    seed_rules(conn)
    return conn


def insert_run(conn, status, started, error=None):
    conn.execute(
        "INSERT INTO detection_runs(started_at, trigger, status, error) VALUES (?,?,?,?)",
        (started, "test", status, error),
    )


class DetectionRunningHealthTests(unittest.TestCase):
    def test_a_young_running_scan_is_degraded(self):
        conn = memory()
        insert_run(conn, "running", iso(utcnow() - timedelta(minutes=1)))
        status, message, _, details = check_detection(conn)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "a detection run is still in progress")
        self.assertNotIn("succeeded", message)
        self.assertEqual(details["last_run"]["status"], "running")

    def test_a_run_older_than_five_minutes_stays_stuck(self):
        conn = memory()
        insert_run(conn, "running", iso(utcnow() - timedelta(minutes=6)))
        status, message, _, _ = check_detection(conn)
        self.assertEqual((status, message), (
            "degraded", "a detection run has been running for more than 5 minutes"))

    def test_a_finished_ok_run_stays_ok(self):
        conn = memory()
        insert_run(conn, "ok", iso(utcnow() - timedelta(minutes=1)))
        status, message, guidance, _ = check_detection(conn)
        self.assertEqual((status, message, guidance), ("ok", "last detection run succeeded", None))

    def test_a_failed_run_stays_failing(self):
        conn = memory()
        insert_run(conn, "failed", iso(utcnow()), "RuleConfigError: bad")
        status, message, _, _ = check_detection(conn)
        self.assertEqual(status, "failing")
        self.assertIn("last detection run failed: RuleConfigError: bad", message)

    def test_zero_enabled_rules_keeps_its_message(self):
        conn = memory()
        conn.execute("UPDATE rules SET enabled = 0")
        insert_run(conn, "running", iso(utcnow()))
        status, message, _, _ = check_detection(conn)
        self.assertEqual((status, message), ("degraded", "no detection rules are enabled"))


class DetectionRunningHealthApiTests(ServerTestCase):
    def test_details_names_the_in_progress_run(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO detection_runs(started_at, trigger, status) VALUES (?,?,'running')",
                (iso(utcnow()), "test"),
            )
        status, body, _ = self.client("admin").get("/api/health/details")
        self.assertEqual(status, 200)
        detection = next(c for c in body["checks"] if c["name"] == "detection")
        self.assertEqual(detection["status"], "degraded")
        self.assertEqual(detection["message"], "a detection run is still in progress")
        self.assertEqual(body["status"], "degraded")
        public = self.client().get("/api/health")
        self.assertEqual(public[0], 200)
        self.assertEqual(public[1]["checks"]["detection"], "degraded")
        self.assertNotIn("message", public[1])
        self.assertEqual(self.client().get("/api/health/details")[0], 401)
