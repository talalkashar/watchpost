"""Health-check edge cases: disk path, ingest faults, and detection run state."""

import os
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from watchpost.db import connect, init_schema, iso, now_iso, utcnow
from watchpost.health import (
    LOW_DISK_BYTES,
    check_dependencies,
    check_detection,
    check_ingestion,
    check_storage,
    register_check,
    run_health_checks,
    unregister_check,
)

FROZEN = datetime(2026, 6, 1, 12, 0, 0, 400000, tzinfo=timezone.utc)


class _EmptyCursor:
    def fetchone(self):
        return None


class _ValueCursor:
    def __init__(self, value):
        self._value = value

    def fetchone(self):
        return (self._value,)


class _HealthCase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self._n = 0
        self.conn.execute(
            "INSERT INTO rules (id, name, description, severity, enabled, params, version, updated_at, updated_by)"
            " VALUES ('r1', 'rule', 'desc', 'low', 1, '{}', 1, ?, 'test')",
            (now_iso(),),
        )

    def _enable(self, enabled):
        self.conn.execute("UPDATE rules SET enabled = ?", (1 if enabled else 0,))

    def _run(self, *, status="ok", started_at=None, finished_at=None, error=None, correlation=None):
        self.conn.execute(
            "INSERT INTO detection_runs (started_at, finished_at, trigger, status, error, correlation)"
            " VALUES (?, ?, 'manual', ?, ?, ?)",
            (started_at if started_at is not None else now_iso(), finished_at, status, error, correlation),
        )

    def _batch(self, *, created_at=None, received=1, rejected=0, accepted=None, detection_status="ok"):
        self._n += 1
        if accepted is None:
            accepted = received - rejected if received >= rejected else 0
        self.conn.execute(
            "INSERT INTO ingest_batches (id, created_at, source, format, received, accepted, rejected, errors,"
            " synthetic, submitted_by, detection_status) VALUES (?, ?, 'src', 'json', ?, ?, ?, '[]', 0, 'test', ?)",
            (f"b{self._n}", created_at or now_iso(), received, accepted, rejected, detection_status),
        )

    def _error(self, *, created_at=None, component="ingestion", message="boom"):
        self.conn.execute(
            "INSERT INTO error_log (created_at, component, message) VALUES (?, ?, ?)",
            (created_at or now_iso(), component, message),
        )

    def _file_db(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "wp.db")
        conn = connect(path)
        init_schema(conn)
        self.addCleanup(conn.close)
        return path, conn

    def _open_memory(self):
        def open_conn():
            conn = connect(":memory:")
            init_schema(conn)
            conn.execute(
                "INSERT INTO rules (id, name, description, severity, enabled, params, version, updated_at, updated_by)"
                " VALUES ('r1', 'rule', 'desc', 'low', 1, '{}', 1, ?, 'test')",
                (now_iso(),),
            )
            return conn

        return open_conn


class StorageTests(_HealthCase):
    def test_probe_is_rolled_back_and_memory_skips_disk(self):
        status, message, _, details = check_storage(self.conn, ":memory:")
        self.assertEqual(status, "ok")
        self.assertEqual(message, "read/write probe and integrity check passed")
        self.assertEqual(details["events"], 0)
        self.assertNotIn("free_disk_mb", details)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0], 0)
        self.assertFalse(self.conn.in_transaction)

    def test_probe_must_read_back_the_row_just_written(self):
        real = self.conn.execute

        def execute(sql, *args, **kwargs):
            if isinstance(sql, str) and "SELECT written_at FROM health_probe" in sql:
                real(sql, *args, **kwargs)
                return _EmptyCursor()
            return real(sql, *args, **kwargs)

        self.conn.execute = execute
        try:
            status, message, guidance, _ = check_storage(self.conn, ":memory:")
        finally:
            self.conn.execute = real
        self.assertEqual(status, "failing")
        self.assertIn("read probe", message)
        self.assertIn("known-good", guidance)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0], 0)
        self.assertFalse(self.conn.in_transaction)

    def test_quick_check_failure_is_failing_and_truncated(self):
        long = "corrupt " + ("x" * 200)
        real = self.conn.execute

        def execute(sql, *args, **kwargs):
            if isinstance(sql, str) and sql.strip().upper().startswith("PRAGMA QUICK_CHECK"):
                return _ValueCursor(long)
            return real(sql, *args, **kwargs)

        self.conn.execute = execute
        try:
            status, message, guidance, _ = check_storage(self.conn, ":memory:")
        finally:
            self.conn.execute = real
        prefix = "database integrity check failed: "
        self.assertEqual(status, "failing")
        self.assertTrue(message.startswith(prefix))
        self.assertEqual(message[len(prefix):], long[:120])
        self.assertIn("known-good", guidance)
        self.assertFalse(self.conn.in_transaction)

    def test_quick_check_without_a_row_does_not_crash(self):
        real = self.conn.execute

        def execute(sql, *args, **kwargs):
            if isinstance(sql, str) and sql.strip().upper().startswith("PRAGMA QUICK_CHECK"):
                return _EmptyCursor()
            return real(sql, *args, **kwargs)

        self.conn.execute = execute
        try:
            status, message, _, _ = check_storage(self.conn, ":memory:")
        finally:
            self.conn.execute = real
        self.assertEqual(status, "failing")
        self.assertIn("no result", message)

    def test_free_disk_boundary_floors_the_reported_megabytes(self):
        path, conn = self._file_db()
        base = shutil.disk_usage(Path(path).parent)
        low = base._replace(free=LOW_DISK_BYTES - 1)
        exact = base._replace(free=LOW_DISK_BYTES)
        with patch("watchpost.health.shutil.disk_usage", return_value=low):
            status, message, _, details = check_storage(conn, path)
        self.assertEqual(status, "degraded")
        self.assertIn("100 MB", message)
        self.assertEqual(details["free_disk_mb"], 99)
        with patch("watchpost.health.shutil.disk_usage", return_value=exact):
            status, _, _, details = check_storage(conn, path)
        self.assertEqual(status, "ok")
        self.assertEqual(details["free_disk_mb"], 100)

    def test_a_file_database_with_space_reports_free_disk(self):
        path, conn = self._file_db()
        status, _, _, details = check_storage(conn, path)
        self.assertEqual(status, "ok")
        self.assertGreaterEqual(details["free_disk_mb"], 100)
        self.assertEqual(details["db_size_mb"], round(Path(path).stat().st_size / 1024 / 1024, 2))

    def test_symlinked_database_uses_the_target_volume(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        real = Path(tmp.name) / "real"
        links = Path(tmp.name) / "links"
        real.mkdir()
        links.mkdir()
        target = real / "wp.db"
        conn = connect(str(target))
        init_schema(conn)
        self.addCleanup(conn.close)
        link = links / "wp.db"
        link.symlink_to(target)
        seen = []
        real_usage = shutil.disk_usage

        def fake_usage(path):
            resolved = Path(path).resolve()
            seen.append(resolved)
            base = real_usage(resolved)
            if resolved == real.resolve():
                return base._replace(free=LOW_DISK_BYTES - 1)
            return base._replace(free=LOW_DISK_BYTES * 50)

        with patch("watchpost.health.shutil.disk_usage", side_effect=fake_usage):
            status, _, _, details = check_storage(conn, str(link))
        self.assertEqual(status, "degraded")
        self.assertEqual(seen, [real.resolve()])
        self.assertEqual(details["free_disk_mb"], 99)
        self.assertEqual(details["db_size_mb"], round(target.stat().st_size / 1024 / 1024, 2))


class IngestionTests(_HealthCase):
    def test_no_batches_and_no_errors_is_ok(self):
        status, message, guidance, details = check_ingestion(self.conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "no data ingested yet")
        self.assertIn("/api/ingest", guidance)
        self.assertNotIn("reject_rate_24h", details)

    def test_server_error_with_no_batches_is_degraded(self):
        self._error()
        status, message, _, details = check_ingestion(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("server-side", message)
        self.assertNotIn("reject_rate_24h", details)

    def test_old_server_error_with_no_batches_stays_ok(self):
        self._error(created_at=iso(utcnow() - timedelta(hours=25)))
        status, message, _, _ = check_ingestion(self.conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "no data ingested yet")

    def test_reject_rate_threshold_is_strictly_above_one_quarter(self):
        self._batch(received=20, rejected=5)
        status, message, _, details = check_ingestion(self.conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "ingestion is accepting events")
        self.assertEqual(details["reject_rate_24h"], 0.25)

        self.conn.execute("DELETE FROM ingest_batches")
        self._batch(received=20, rejected=6)
        status, message, _, _ = check_ingestion(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("rejected", message)

    def test_rejections_with_zero_received_count_as_rejected(self):
        self._batch(received=0, rejected=30, accepted=0)
        status, message, _, details = check_ingestion(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("rejected", message)
        self.assertEqual(details["reject_rate_24h"], 1.0)

    def test_server_error_wins_over_a_high_reject_rate(self):
        self._batch(received=20, rejected=10)
        self._error()
        status, message, _, details = check_ingestion(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("server-side", message)
        self.assertNotIn("of records were rejected", message)
        self.assertEqual(details["reject_rate_24h"], 0.5)

    def test_quiet_history_does_not_claim_events_are_being_accepted(self):
        self._batch(created_at=iso(utcnow() - timedelta(hours=25)), received=10, rejected=0)
        status, message, guidance, _ = check_ingestion(self.conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "no batches in the last 24h")
        self.assertIsNone(guidance)
        self.assertNotIn("accepting", message)


class DetectionTests(_HealthCase):
    def test_no_run_yet_is_ok_and_disabled_rules_are_degraded(self):
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "detection has not run yet (no data)")
        self._enable(False)
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "no detection rules are enabled")

    def test_a_failed_run_stays_failing_when_rules_are_disabled(self):
        self._enable(False)
        self._run(status="failed", error=None, finished_at=now_iso())
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "failing")
        self.assertNotIn("None", message)
        self.assertIn("no error was recorded", message)

        self.conn.execute("DELETE FROM detection_runs")
        self._run(status="failed", error="rule boom", finished_at=now_iso())
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "failing")
        self.assertIn("rule boom", message)

    def test_a_fresh_running_scan_is_in_progress(self):
        self._run(status="running", started_at=now_iso())
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "ok")
        self.assertIn("in progress", message)
        self.assertNotIn("succeeded", message)

        self.conn.execute("DELETE FROM detection_runs")
        self._run(status="running", started_at=iso(utcnow() - timedelta(minutes=1)))
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "ok")
        self.assertIn("in progress", message)

    def test_a_fresh_running_scan_still_reports_skipped_batches(self):
        self._run(status="running", started_at=now_iso())
        self._batch(detection_status="failed")
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("batch", message)
        self.assertNotIn("in progress", message)

    def test_a_fresh_running_scan_with_rules_off_still_says_no_rules(self):
        self._enable(False)
        self._run(status="running", started_at=now_iso())
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("no detection rules", message)

    def test_a_canonical_stuck_run_is_degraded(self):
        self._run(status="running", started_at=iso(utcnow() - timedelta(minutes=6)))
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("5 minutes", message)

    def test_stuck_beats_disabled_rules(self):
        self._enable(False)
        self._run(status="running", started_at=iso(utcnow() - timedelta(minutes=6)))
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("5 minutes", message)
        self.assertNotIn("no detection rules", message)

    def test_noncanonical_timestamp_is_compared_as_an_instant(self):
        with patch("watchpost.health.utcnow", return_value=FROZEN):
            self._run(status="running", started_at="2026-06-01T11:55:00Z")
            status, message, _, _ = check_detection(self.conn)
            self.assertEqual(status, "degraded")
            self.assertIn("5 minutes", message)

            self.conn.execute("DELETE FROM detection_runs")
            self._run(status="running", started_at=iso(FROZEN - timedelta(minutes=5)))
            status, message, _, _ = check_detection(self.conn)
            self.assertEqual(status, "ok")
            self.assertIn("in progress", message)
            self.assertNotIn("5 minutes", message)

            self.conn.execute("DELETE FROM detection_runs")
            self._run(status="running", started_at="2026-06-01T11:00:00")
            status, message, _, _ = check_detection(self.conn)
            self.assertEqual(status, "degraded")
            self.assertIn("5 minutes", message)

    def test_unreadable_start_time_is_not_reported_as_success(self):
        self._run(status="running", started_at="not-a-timestamp")
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("cannot be read", message)
        self.assertNotIn("succeeded", message)

        self.conn.execute("DELETE FROM detection_runs")
        self._run(status="running", started_at="")
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("cannot be read", message)

    def test_unexpected_status_is_not_success(self):
        self._run(status="aborted", finished_at=now_iso())
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("aborted", message)
        self.assertNotIn("succeeded", message)

    def test_correlation_failure_and_skipped_batches_stay_degraded(self):
        self._run(status="ok", finished_at=now_iso(), correlation="failed")
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("could not group", message)

        self.conn.execute("DELETE FROM detection_runs")
        self._run(status="ok", finished_at=now_iso())
        self._batch(detection_status="failed")
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "degraded")
        self.assertIn("batch", message)

    def test_a_finished_run_is_success(self):
        self._run(status="ok", finished_at=now_iso())
        status, message, _, _ = check_detection(self.conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "last detection run succeeded")


class DependencyTests(_HealthCase):
    def test_memory_database_dependencies_are_ok(self):
        status, message, _, details = check_dependencies(":memory:")
        self.assertEqual(status, "ok")
        self.assertIn("runtime", message)
        self.assertTrue(details["static_assets"])

    def test_a_file_used_as_the_database_directory_is_not_writable(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        parent = Path(tmp.name) / "not-a-dir"
        parent.write_text("x")
        path = str(parent / "wp.db")
        self.assertTrue(os.access(parent, os.W_OK))
        self.assertFalse(parent.is_dir())
        status, message, _, _ = check_dependencies(path)
        self.assertEqual(status, "failing")
        self.assertIn("not writable", message)

    def test_symlink_writability_follows_the_target_directory(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory mode")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        real = Path(tmp.name) / "real"
        links = Path(tmp.name) / "links"
        real.mkdir()
        links.mkdir()
        target = real / "wp.db"
        conn = connect(str(target))
        init_schema(conn)
        conn.close()
        link = links / "wp.db"
        link.symlink_to(target)
        os.chmod(real, 0o555)
        self.addCleanup(os.chmod, real, 0o755)
        self.assertTrue(os.access(links, os.W_OK))
        status, message, _, _ = check_dependencies(str(link))
        self.assertEqual(status, "failing")
        self.assertIn("not writable", message)

    def test_missing_console_files_are_degraded_until_the_directory_is_unwritable(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch("watchpost.health.STATIC_DIR", Path(tmp.name)):
            status, message, _, details = check_dependencies(":memory:")
        self.assertEqual(status, "degraded")
        self.assertIn("web UI", message)
        self.assertFalse(details["static_assets"])

        parent = Path(tmp.name) / "not-a-dir"
        parent.write_text("x")
        with patch("watchpost.health.STATIC_DIR", Path(tmp.name) / "empty"):
            status, message, _, _ = check_dependencies(str(parent / "wp.db"))
        self.assertEqual(status, "failing")
        self.assertIn("not writable", message)
        self.assertIn("web UI", message)


class ReportTests(_HealthCase):
    def test_healthy_report_order(self):
        report = run_health_checks(self._open_memory(), ":memory:")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(
            [c["name"] for c in report["checks"]],
            ["storage", "ingestion", "detection", "dependencies"],
        )
        self.assertTrue(all(c["status"] == "ok" for c in report["checks"]))

    def test_unopenable_database_fails_on_storage_first(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        blocked = os.path.join(tmp.name, "blocked")
        with open(blocked, "w") as handle:
            handle.write("not a directory")
        path = os.path.join(blocked, "sub", "x.db")
        report = run_health_checks(lambda: connect(path), path)
        self.assertEqual(report["status"], "failing")
        storage = report["checks"][0]
        self.assertEqual(storage["name"], "storage")
        self.assertEqual(storage["status"], "failing")
        self.assertIn("SIEM_DB", storage["guidance"])

    def test_unknown_component_status_fails_the_report(self):
        def warning():
            return "warning", "look", None, {}

        def banana():
            return "banana", "nope", "keep-me", {}

        def missing():
            return None, "missing", None, {}

        register_check("blitz-warning", warning)
        register_check("blitz-banana", banana)
        register_check("blitz-missing", missing)
        self.addCleanup(unregister_check, "blitz-warning", warning)
        self.addCleanup(unregister_check, "blitz-banana", banana)
        self.addCleanup(unregister_check, "blitz-missing", missing)
        report = run_health_checks(self._open_memory(), ":memory:")
        self.assertEqual(report["status"], "failing")
        by_name = {c["name"]: c for c in report["checks"]}
        self.assertEqual(by_name["blitz-warning"]["status"], "failing")
        self.assertEqual(by_name["blitz-warning"]["message"].count("unknown status"), 1)
        self.assertIn("'warning'", by_name["blitz-warning"]["message"])
        self.assertIn("ok, degraded, or failing", by_name["blitz-warning"]["guidance"])
        self.assertEqual(by_name["blitz-banana"]["guidance"], "keep-me")
        self.assertIn("'banana'", by_name["blitz-banana"]["message"])
        self.assertIn("None", by_name["blitz-missing"]["message"])

    def test_a_raising_component_does_not_crash_the_report(self):
        def boom():
            raise RuntimeError("disk")

        register_check("blitz-boom", boom)
        self.addCleanup(unregister_check, "blitz-boom", boom)
        report = run_health_checks(self._open_memory(), ":memory:")
        self.assertEqual(report["status"], "failing")
        boom_check = next(c for c in report["checks"] if c["name"] == "blitz-boom")
        self.assertEqual(boom_check["status"], "failing")
        self.assertIn("health check raised", boom_check["message"])
        self.assertIn("RuntimeError", boom_check["message"])

    def test_unregister_uses_identity_and_builtins_are_not_replaced(self):
        def first():
            return "ok", "from-a", None, {}

        def second():
            return "ok", "from-b", None, {}

        def hijack():
            return "ok", "hijacked storage", None, {}

        register_check("blitz-lane", first)
        register_check("blitz-lane", second)
        self.addCleanup(unregister_check, "blitz-lane", second)
        unregister_check("blitz-lane", first)
        register_check("storage", hijack)
        self.addCleanup(unregister_check, "storage", hijack)
        report = run_health_checks(self._open_memory(), ":memory:")
        by_name = {c["name"]: c for c in report["checks"]}
        self.assertEqual(by_name["blitz-lane"]["message"], "from-b")
        storages = [c for c in report["checks"] if c["name"] == "storage"]
        self.assertEqual(len(storages), 1)
        self.assertIn("read/write probe", storages[0]["message"])

    def test_a_check_can_register_another_without_deadlock(self):
        def inner():
            return "ok", "inner", None, {}

        def outer():
            register_check("blitz-inner", inner)
            return "ok", "outer", None, {}

        register_check("blitz-outer", outer)
        self.addCleanup(unregister_check, "blitz-outer", outer)
        self.addCleanup(unregister_check, "blitz-inner", inner)
        holder = {}

        def go():
            try:
                holder["report"] = run_health_checks(self._open_memory(), ":memory:")
            except Exception as exc:
                holder["error"] = exc

        thread = threading.Thread(target=go, daemon=True)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive(), "health checks deadlocked on the registry lock")
        self.assertNotIn("error", holder)
        names = [c["name"] for c in holder["report"]["checks"]]
        self.assertIn("blitz-outer", names)
        self.assertNotIn("blitz-inner", names)
        again = run_health_checks(self._open_memory(), ":memory:")
        self.assertIn("blitz-inner", [c["name"] for c in again["checks"]])


if __name__ == "__main__":
    unittest.main()
