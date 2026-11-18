"""check_storage: integrity failure, probe rollback, low disk, memory skip."""

import os
import tempfile
import unittest
from unittest import mock

from watchpost.db import connect, init_schema
from watchpost.health import LOW_DISK_BYTES, check_storage

def opened(path=":memory:"):
    conn = connect(path)
    init_schema(conn)
    return conn


class CheckStorageTests(unittest.TestCase):
    def test_quick_check_other_than_ok_is_failing(self):
        verdicts = ("database disk image is malformed", "x" * 180)
        for verdict in verdicts:
            conn = mock.Mock()
            conn.execute.return_value.fetchone.return_value = (verdict,)
            status, message, guidance, details = check_storage(conn, ":memory:")
            self.assertEqual(status, "failing")
            shown = verdict[:120]
            self.assertEqual(message, f"database integrity check failed: {shown}")
            self.assertIn("restore from a known-good copy", guidance)
            self.assertEqual(details, {})
            conn.execute.assert_called_once_with("PRAGMA quick_check")

    def test_health_probe_insert_is_rolled_back(self):
        conn = opened()
        self.addCleanup(conn.close)
        conn.execute("INSERT INTO health_probe(id, written_at) VALUES (1, 'sentinel')")
        seen = []
        conn.set_trace_callback(seen.append)
        status, _, _, details = check_storage(conn, ":memory:")
        self.assertEqual(status, "ok")
        self.assertEqual(details, {"events": 0})
        prefix = "INSERT OR REPLACE INTO health_probe"
        inserts = [sql for sql in seen if sql.startswith(prefix)]
        self.assertEqual(len(inserts), 1)
        self.assertNotIn("sentinel", inserts[0])
        insert_at = seen.index(inserts[0])
        self.assertLess(seen.index("BEGIN IMMEDIATE"), insert_at)
        self.assertLess(insert_at, seen.index("ROLLBACK"))
        row = conn.execute(
            "SELECT written_at FROM health_probe WHERE id = 1").fetchone()
        self.assertEqual(row["written_at"], "sentinel")
        count = conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0]
        self.assertEqual(count, 1)

    def test_free_disk_under_low_disk_bytes_is_degraded(self):
        self.assertEqual(LOW_DISK_BYTES, 100 * 1024 * 1024)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "events.db")
        conn = opened(path)
        self.addCleanup(conn.close)

        def usage(target):
            self.assertEqual(os.path.realpath(target), os.path.realpath(tmp.name))
            return mock.Mock(free=LOW_DISK_BYTES - 1)

        with mock.patch("watchpost.health.shutil.disk_usage", side_effect=usage):
            status, message, guidance, details = check_storage(conn, path)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "less than 100 MB of disk space left")
        self.assertIn("SIEM_DB", guidance)
        self.assertEqual(details["events"], 0)
        low_mb = round((LOW_DISK_BYTES - 1) / 1024 / 1024)
        self.assertEqual(details["free_disk_mb"], low_mb)
        self.assertIn("db_size_mb", details)

        enough = mock.Mock(free=LOW_DISK_BYTES)
        with mock.patch("watchpost.health.shutil.disk_usage", return_value=enough):
            status, message, guidance, details = check_storage(conn, path)
        self.assertEqual(status, "ok")
        self.assertIsNone(guidance)
        self.assertIn("integrity check passed", message)
        self.assertEqual(details["free_disk_mb"], round(LOW_DISK_BYTES / 1024 / 1024))

    def test_memory_database_skips_the_disk_check(self):
        conn = opened()
        self.addCleanup(conn.close)
        boom = AssertionError("disk checked")
        with mock.patch("watchpost.health.shutil.disk_usage", side_effect=boom):
            status, message, guidance, details = check_storage(conn, ":memory:")
        self.assertEqual(status, "ok")
        self.assertIsNone(guidance)
        self.assertIn("integrity check passed", message)
        self.assertEqual(details, {"events": 0})


if __name__ == "__main__":
    unittest.main()
