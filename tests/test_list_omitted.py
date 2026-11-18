"""Clipped health, audit, and batch lists say how many rows were left out.

Health details keeps the newest error_log rows by id (20) and the newest
detection runs by id (10), and names the rest in the body. Audit (200) and
ingest batches (50) stay bare arrays. Their leftover count is
X-Watchpost-Omitted, including 0 when the table fits. A later timestamp on an
older id is still the row past the id cap. Batches drop the oldest created_at.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"


def _insert(db, sql, rows):
    db.executemany(sql, rows)


class ListOmittedTests(ServerTestCase):
    def _fill_errors(self, db):
        db.execute("DELETE FROM error_log")
        _insert(db,
                "INSERT INTO error_log(created_at, component, message) VALUES (?,?,?)",
                [("2026-08-01T00:00:00", "api", "old-id")] +
                [("2026-01-01T00:00:00", "api", f"row-{i}") for i in range(20)])

    def _fill_runs(self, db):
        db.execute("DELETE FROM detection_runs")
        _insert(db,
                "INSERT INTO detection_runs(started_at, trigger, status) VALUES (?,?,'ok')",
                [("2026-08-01T00:00:00", "old-id")] +
                [("2026-01-01T00:00:00", f"run-{i}") for i in range(10)])

    def _fill_batches(self, db, count):
        db.execute("DELETE FROM ingest_batches")
        rows = []
        for i in range(count):
            stamp = f"2026-06-01T{i // 60:02d}:{i % 60:02d}:00"
            rows.append((f"batch-{i}", stamp, f"batch-{i}"))
        if count:
            rows.append(("oldest", "2026-01-01T00:00:00", "oldest"))
        _insert(db,
                "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted,"
                " rejected, errors, submitted_by, detection_status)"
                " VALUES (?,?,?,'json',1,1,0,'[]','admin','ok')",
                rows)

    def _fill_audit(self, db, count):
        db.execute("DELETE FROM audit_log")
        rows = [("2026-08-01T00:00:00", "admin", "old-id")] if count else []
        rows += [("2026-01-01T00:00:00", "admin", f"act-{i}") for i in range(max(0, count - 1))]
        _insert(db, "INSERT INTO audit_log(created_at, actor, action) VALUES (?,?,?)", rows)

    def test_a_lower_id_is_the_error_and_run_past_the_cap(self):
        with sqlite3.connect(self.db_path) as db:
            self._fill_errors(db)
            self._fill_runs(db)
        status, body, headers = self.client("viewer").get("/api/health/details")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["recent_errors_omitted"], 1)
        self.assertEqual([row["message"] for row in body["recent_errors"]],
                         [f"row-{i}" for i in range(19, -1, -1)])
        self.assertNotIn("old-id", [row["message"] for row in body["recent_errors"]])
        self.assertEqual(body["recent_detection_runs_omitted"], 1)
        self.assertEqual([row["trigger"] for row in body["recent_detection_runs"]],
                         [f"run-{i}" for i in range(9, -1, -1)])
        self.assertNotIn("old-id", [row["trigger"] for row in body["recent_detection_runs"]])

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/health/details")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["recent_errors"], [])
        self.assertEqual(body["recent_errors_omitted"], 0)
        self.assertEqual(body["recent_detection_runs"], [])
        self.assertEqual(body["recent_detection_runs_omitted"], 0)
        with sqlite3.connect(self.db_path) as db:
            self._fill_errors(db)
            self._fill_runs(db)
            db.execute("DELETE FROM error_log WHERE message = 'old-id'")
            db.execute("DELETE FROM detection_runs WHERE trigger = 'old-id'")
        body = viewer.get("/api/health/details")[1]
        self.assertEqual(body["recent_errors_omitted"], 0)
        self.assertEqual(len(body["recent_errors"]), 20)
        self.assertEqual(body["recent_detection_runs_omitted"], 0)
        self.assertEqual(len(body["recent_detection_runs"]), 10)

    def test_audit_stays_an_array_and_names_the_leftover_in_a_header(self):
        admin = self.client("admin")
        with sqlite3.connect(self.db_path) as db:
            self._fill_audit(db, 201)
        status, body, headers = admin.get("/api/audit")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual([row["action"] for row in body],
                         [f"act-{i}" for i in range(199, -1, -1)])
        self.assertNotIn("old-id", [row["action"] for row in body])
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM audit_log WHERE action = 'old-id'")
        status, fitted, headers = admin.get("/api/audit")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 200)
        self.assertEqual(headers[OMITTED], "0")
        with sqlite3.connect(self.db_path) as db:
            self._fill_audit(db, 0)
        status, empty, headers = admin.get("/api/audit")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")
        denied = self.client("viewer").get("/api/audit")
        self.assertEqual(denied[0], 403)
        self.assertIsNone(denied[2].get(OMITTED))

    def test_batches_stay_an_array_and_drop_the_oldest_created_at(self):
        viewer = self.client("viewer")
        status, empty, headers = viewer.get("/api/ingest/batches")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")
        with sqlite3.connect(self.db_path) as db:
            self._fill_batches(db, 50)
        status, body, headers = viewer.get("/api/ingest/batches")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(len(body), 50)
        self.assertEqual(body[0]["id"], "batch-49")
        self.assertNotIn("oldest", [row["id"] for row in body])
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM ingest_batches WHERE id = 'oldest'")
        fitted, headers = viewer.get("/api/ingest/batches")[1:]
        self.assertEqual(len(fitted), 50)
        self.assertEqual(headers[OMITTED], "0")
        self.assertEqual(fitted[-1]["id"], "batch-0")

    def test_the_docs_name_the_omitted_counts(self):
        api = API.read_text()
        self.assertIn(
            "`recent_errors_omitted` is how many were past that cap (0 when the table fits)",
            api)
        self.assertIn(
            "`recent_detection_runs_omitted` is how many were past that cap (0 when the table fits)",
            api)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many entries were past that cap (0 when the table fits)",
            api)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many batches were past that cap (0 when the table fits)",
            api)
        self.assertIn("The body stays a bare array", api)


if __name__ == "__main__":
    unittest.main()
