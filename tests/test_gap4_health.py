"""Boundaries for the health checks the other suites leave open.

Reject rate and the 24-hour window, the five-minute detection run, disk space
and integrity text, and which function a register or unregister call affects.
"""

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from watchpost import health
from watchpost.db import connect, init_schema, iso

FROZEN = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def schema():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def enable_rule(conn, enabled=1):
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, updated_at, updated_by)"
        " VALUES ('one', 'One', 'd', 'low', ?, '{}', '2026-01-01T00:00:00.000Z', 't')",
        (enabled,),
    )


def open_seeded():
    conn = schema()
    enable_rule(conn)
    return conn


def batch(conn, created_at, received, rejected, batch_id="b", accepted=None,
          detection_status="pending"):
    if accepted is None:
        accepted = received - rejected
    conn.execute(
        "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted, rejected,"
        " errors, synthetic, submitted_by, detection_status)"
        " VALUES (?, ?, 'api', 'json', ?, ?, ?, '[]', 0, 't', ?)",
        (batch_id, created_at, received, accepted, rejected, detection_status),
    )


def ingestion_error(conn, created_at, component="ingestion"):
    conn.execute(
        "INSERT INTO error_log(created_at, component, message) VALUES (?, ?, 'boom')",
        (created_at, component),
    )


def detection_run(conn, started, status="running", error=None, correlation=None):
    conn.execute(
        "INSERT INTO detection_runs(started_at, trigger, status, error, correlation)"
        " VALUES (?, 'manual', ?, ?, ?)",
        (started, status, error, correlation),
    )


class _Quick:
    """Connection stand-in whose integrity probe returns a fixed string."""

    def __init__(self, value):
        self.value = value

    def execute(self, sql, params=()):
        if sql != "PRAGMA quick_check":
            raise AssertionError(sql)
        return self

    def fetchone(self):
        return (self.value,)


class Gap4HealthTests(unittest.TestCase):
    def setUp(self):
        self._checks = dict(health._COMPONENT_CHECKS)
        health._COMPONENT_CHECKS.clear()

    def tearDown(self):
        health._COMPONENT_CHECKS.clear()
        health._COMPONENT_CHECKS.update(self._checks)

    def ingest(self, conn):
        with mock.patch("watchpost.health.utcnow", return_value=FROZEN):
            return health.check_ingestion(conn)

    def detect(self, conn):
        with mock.patch("watchpost.health.utcnow", return_value=FROZEN):
            return health.check_detection(conn)

    def test_no_batches_is_ok_and_omits_the_reject_rate(self):
        conn = schema()
        self.addCleanup(conn.close)
        status, message, guidance, details = self.ingest(conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "no data ingested yet")
        self.assertIn("POST events", guidance)
        self.assertNotIn("reject_rate_24h", details)
        self.assertIsNone(details["last_batch_at"])
        self.assertEqual(details["batches_24h"], 0)
        self.assertEqual(details["received_24h"], 0)
        self.assertEqual(details["rejected_24h"], 0)
        self.assertEqual(details["server_errors_24h"], 0)

    def test_reject_rate_needs_twenty_records_and_more_than_a_quarter(self):
        samples = (
            (19, 19, "ok", 1.0),
            (20, 5, "ok", 0.25),
            (20, 6, "degraded", 0.3),
        )
        for received, rejected, want, rate in samples:
            with self.subTest(received=received, rejected=rejected):
                conn = schema()
                self.addCleanup(conn.close)
                batch(conn, iso(FROZEN), received, rejected, batch_id=f"b{received}-{rejected}")
                status, message, _, details = self.ingest(conn)
                self.assertEqual(status, want)
                self.assertEqual(details["reject_rate_24h"], rate)
                if want == "ok":
                    self.assertEqual(message, "ingestion is accepting events")
                else:
                    self.assertIn("30%", message)

    def test_a_zero_received_total_does_not_divide_by_zero(self):
        conn = schema()
        self.addCleanup(conn.close)
        batch(conn, iso(FROZEN), 0, 10, accepted=0)
        status, message, _, details = self.ingest(conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "ingestion is accepting events")
        self.assertEqual(details["reject_rate_24h"], 0.0)
        self.assertEqual(details["rejected_24h"], 10)

    def test_a_server_error_outranks_the_reject_rate(self):
        conn = schema()
        self.addCleanup(conn.close)
        batch(conn, iso(FROZEN), 20, 20)
        ingestion_error(conn, iso(FROZEN))
        ingestion_error(conn, iso(FROZEN), component="api")
        status, message, _, details = self.ingest(conn)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "1 ingestion request(s) failed server-side in the last 24h")
        self.assertEqual(details["server_errors_24h"], 1)
        self.assertEqual(details["reject_rate_24h"], 1.0)

    def test_the_24h_window_includes_the_cutoff_instant(self):
        cutoff = iso(FROZEN - timedelta(hours=24))
        before = iso(FROZEN - timedelta(hours=24, milliseconds=1))
        inside = iso(FROZEN - timedelta(hours=1))

        older = schema()
        self.addCleanup(older.close)
        batch(older, before, 20, 20, "old")
        status, _, _, details = self.ingest(older)
        self.assertEqual(status, "ok")
        self.assertEqual(details["batches_24h"], 0)
        self.assertEqual(details["last_batch_at"], before)
        self.assertEqual(details["reject_rate_24h"], 0.0)

        edged = schema()
        self.addCleanup(edged.close)
        batch(edged, cutoff, 20, 20, "edge")
        status, message, _, details = self.ingest(edged)
        self.assertEqual(status, "degraded")
        self.assertIn("100%", message)
        self.assertEqual(details["batches_24h"], 1)
        self.assertEqual(details["last_batch_at"], cutoff)

        quiet = schema()
        self.addCleanup(quiet.close)
        batch(quiet, inside, 20, 0, "quiet")
        ingestion_error(quiet, before)
        status, message, _, details = self.ingest(quiet)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "ingestion is accepting events")
        self.assertEqual(details["server_errors_24h"], 0)

        loud = schema()
        self.addCleanup(loud.close)
        batch(loud, inside, 20, 0, "loud")
        ingestion_error(loud, cutoff)
        status, message, _, details = self.ingest(loud)
        self.assertEqual(status, "degraded")
        self.assertIn("server-side", message)
        self.assertEqual(details["server_errors_24h"], 1)

    @unittest.expectedFailure
    def test_a_server_error_with_no_stored_batch_is_degraded(self):
        """Ingest can log a server error and store no batch (the batch was not stored).

        check_ingestion returns ok as soon as ingest_batches is empty, so that
        error never degrades the check.
        """
        conn = schema()
        self.addCleanup(conn.close)
        ingestion_error(conn, iso(FROZEN))
        status, message, _, details = self.ingest(conn)
        self.assertEqual(status, "degraded")
        self.assertIn("server-side", message)
        self.assertEqual(details["server_errors_24h"], 1)
        self.assertIsNone(details["last_batch_at"])

    def test_detection_that_has_not_run_is_ok(self):
        conn = schema()
        self.addCleanup(conn.close)
        enable_rule(conn)
        status, message, guidance, details = health.check_detection(conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "detection has not run yet (no data)")
        self.assertIsNone(guidance)
        self.assertIsNone(details["last_run"])
        self.assertIsNone(details["last_successful_run_at"])
        self.assertEqual(details["enabled_rules"], 1)
        self.assertEqual(details["unprocessed_failed_batches"], 0)

    def test_disabled_rules_outrank_a_failed_run(self):
        conn = schema()
        self.addCleanup(conn.close)
        enable_rule(conn, enabled=0)
        detection_run(conn, iso(FROZEN), status="failed", error="RuleConfigError: threshold")
        status, message, _, details = self.detect(conn)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "no detection rules are enabled")
        self.assertEqual(details["enabled_rules"], 0)
        self.assertEqual(details["last_run"]["status"], "failed")

        conn.execute("UPDATE rules SET enabled = 1")
        status, message, _, _ = self.detect(conn)
        self.assertEqual(status, "failing")
        self.assertEqual(message, "last detection run failed: RuleConfigError: threshold")

    def test_a_running_check_sticks_only_after_five_minutes(self):
        samples = (
            (timedelta(minutes=-5, milliseconds=-1), "degraded"),
            (timedelta(minutes=-5), "ok"),
            (timedelta(minutes=-5, milliseconds=1), "ok"),
        )
        for delta, want in samples:
            with self.subTest(delta=delta):
                conn = schema()
                self.addCleanup(conn.close)
                enable_rule(conn)
                detection_run(conn, iso(FROZEN + delta))
                status, message, _, _ = self.detect(conn)
                self.assertEqual(status, want)
                if want == "degraded":
                    self.assertIn("more than 5 minutes", message)
                else:
                    self.assertEqual(message, "last detection run succeeded")

        blank = schema()
        self.addCleanup(blank.close)
        enable_rule(blank)
        detection_run(blank, "")
        status, message, _, _ = self.detect(blank)
        self.assertEqual(status, "degraded")
        self.assertIn("more than 5 minutes", message)

        garbage = schema()
        self.addCleanup(garbage.close)
        enable_rule(garbage)
        detection_run(garbage, "zzz")
        status, message, _, _ = self.detect(garbage)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "last detection run succeeded")

    def test_a_stuck_run_outranks_correlation_failure_and_failed_batches(self):
        stuck = schema()
        self.addCleanup(stuck.close)
        enable_rule(stuck)
        detection_run(
            stuck, iso(FROZEN - timedelta(minutes=5, milliseconds=1)),
            correlation="failed",
        )
        batch(stuck, iso(FROZEN), 1, 0, "stuck-batch", detection_status="failed")
        status, message, _, _ = self.detect(stuck)
        self.assertEqual(status, "degraded")
        self.assertIn("more than 5 minutes", message)

        grouped = schema()
        self.addCleanup(grouped.close)
        enable_rule(grouped)
        detection_run(grouped, iso(FROZEN), correlation="failed")
        batch(grouped, iso(FROZEN), 1, 0, "group-batch", detection_status="failed")
        status, message, _, _ = self.detect(grouped)
        self.assertEqual(status, "degraded")
        self.assertIn("could not group", message)

        backlog = schema()
        self.addCleanup(backlog.close)
        enable_rule(backlog)
        detection_run(backlog, iso(FROZEN))
        batch(backlog, iso(FROZEN), 1, 0, "backlog-batch", detection_status="failed")
        status, message, _, details = self.detect(backlog)
        self.assertEqual(status, "degraded")
        self.assertIn("1 batch", message)
        self.assertEqual(details["unprocessed_failed_batches"], 1)

    def test_the_write_probe_rolls_back_and_memory_skips_disk(self):
        conn = schema()
        self.addCleanup(conn.close)
        with mock.patch("watchpost.health.shutil.disk_usage") as disk:
            status, message, guidance, details = health.check_storage(conn, ":memory:")
        self.assertEqual(status, "ok")
        self.assertEqual(message, "read/write probe and integrity check passed")
        self.assertIsNone(guidance)
        self.assertNotIn("free_disk_mb", details)
        self.assertNotIn("db_size_mb", details)
        self.assertFalse(disk.called)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0], 0)
        self.assertFalse(conn.in_transaction)

    def test_disk_free_degrades_only_below_100_mb(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "siem.db")
        conn = connect(path)
        self.addCleanup(conn.close)
        init_schema(conn)
        exact = health.LOW_DISK_BYTES

        with mock.patch("watchpost.health.shutil.disk_usage", return_value=mock.Mock(free=exact)):
            status, _, _, details = health.check_storage(conn, path)
        self.assertEqual(status, "ok")
        self.assertEqual(details["free_disk_mb"], 100)
        self.assertIn("db_size_mb", details)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0], 0)
        self.assertFalse(conn.in_transaction)

        with mock.patch("watchpost.health.shutil.disk_usage", return_value=mock.Mock(free=exact - 1)):
            status, message, guidance, details = health.check_storage(conn, path)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "less than 100 MB of disk space left")
        self.assertIn("SIEM_DB", guidance)
        self.assertEqual(details["free_disk_mb"], 100)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0], 0)
        self.assertFalse(conn.in_transaction)

    def test_integrity_failure_keeps_the_first_120_characters(self):
        quick = ("A" * 120) + "TAIL"
        status, message, guidance, details = health.check_storage(_Quick(quick), "ignored.db")
        self.assertEqual(status, "failing")
        self.assertEqual(message, "database integrity check failed: " + ("A" * 120))
        self.assertNotIn("TAIL", message)
        self.assertIn("known-good", guidance)
        self.assertEqual(details, {})

        for malformed in ("OK", "ok ", ""):
            with self.subTest(quick=malformed):
                status, message, _, details = health.check_storage(_Quick(malformed), "ignored.db")
                self.assertEqual(status, "failing")
                self.assertEqual(message, f"database integrity check failed: {malformed}")
                self.assertEqual(details, {})

    def test_register_and_unregister_follow_function_identity_and_order(self):
        def check_a():
            return "ok", "a", None, {}

        def check_b():
            return "degraded", "b", "look", {"k": 1}

        def other():
            return "failing", "other", None, {}

        health.register_check("alpha", check_a)
        health.register_check("beta", check_b)
        report = health.run_health_checks(open_seeded, ":memory:")
        self.assertEqual(
            [c["name"] for c in report["checks"]],
            ["storage", "ingestion", "detection", "dependencies", "alpha", "beta"],
        )
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["checks"][-1]["details"], {"k": 1})

        health.unregister_check("beta", other)
        health.unregister_check("missing")
        health.unregister_check("missing", check_a)
        report = health.run_health_checks(open_seeded, ":memory:")
        self.assertEqual([c["name"] for c in report["checks"]][-2:], ["alpha", "beta"])

        health.register_check("alpha", other)
        health.unregister_check("alpha", check_a)
        report = health.run_health_checks(open_seeded, ":memory:")
        self.assertEqual(report["checks"][-2]["status"], "failing")
        self.assertEqual(report["checks"][-1]["name"], "beta")
        self.assertEqual(report["status"], "failing")

        health.unregister_check("beta", check_b)
        health.unregister_check("alpha")
        report = health.run_health_checks(open_seeded, ":memory:")
        self.assertEqual(
            [c["name"] for c in report["checks"]],
            ["storage", "ingestion", "detection", "dependencies"],
        )
        self.assertEqual(report["status"], "ok")

    def test_a_bad_registered_check_does_not_drop_later_checks(self):
        def boom():
            raise RuntimeError("disk")

        def later():
            return "ok", "up", None, {"ok": True}

        health.register_check("boom", boom)
        health.register_check("short", lambda: ("ok",))
        health.register_check("later", later)
        report = health.run_health_checks(open_seeded, ":memory:")
        by_name = {c["name"]: c for c in report["checks"]}
        self.assertEqual([c["name"] for c in report["checks"]][-3:], ["boom", "short", "later"])
        self.assertEqual(by_name["boom"]["status"], "failing")
        self.assertEqual(by_name["short"]["status"], "failing")
        self.assertEqual(by_name["later"]["status"], "ok")
        self.assertEqual(by_name["later"]["details"], {"ok": True})
        self.assertEqual(report["status"], "failing")

    def test_an_unopenable_database_still_runs_registered_checks(self):
        health.register_check("widget", lambda: ("degraded", "slow", "wait", {"n": 1}))

        def open_conn():
            raise sqlite3.OperationalError("unable to open database file")

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "siem.db")
        report = health.run_health_checks(open_conn, path)
        self.assertEqual([c["name"] for c in report["checks"]], ["storage", "dependencies", "widget"])
        self.assertEqual(report["checks"][0]["status"], "failing")
        self.assertEqual(report["checks"][0]["latency_ms"], 0)
        self.assertEqual(report["checks"][1]["status"], "ok")
        self.assertEqual(report["checks"][2]["status"], "degraded")
        self.assertEqual(report["checks"][2]["details"], {"n": 1})
        self.assertEqual(report["status"], "failing")

    @unittest.expectedFailure
    def test_a_status_outside_the_scale_still_returns_a_report(self):
        """max() over STATUS_ORDER crashes when a registered check returns another status.

        The rank lookup is None, and None cannot be ordered against ok/degraded/failing,
        so one optional check takes down the whole report.
        """
        health.register_check("widget", lambda: ("bogus", "no", None, {}))
        report = health.run_health_checks(open_seeded, ":memory:")
        self.assertIn(report["status"], ("ok", "degraded", "failing"))
        self.assertEqual(report["checks"][-1]["name"], "widget")
        self.assertEqual(report["checks"][-1]["status"], "bogus")


if __name__ == "__main__":
    unittest.main()
