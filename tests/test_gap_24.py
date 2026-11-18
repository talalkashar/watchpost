"""check_ingestion: empty store, a recent ingestion error, and a high reject rate.

The high reject rate is already covered through run_health_checks. These tests
call check_ingestion itself.
"""

import unittest

from watchpost.db import connect, init_schema, now_iso
from watchpost.health import check_ingestion


def memory():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def batch(conn, received, rejected):
    conn.execute(
        "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted,"
        " rejected, errors, submitted_by, detection_status)"
        " VALUES (?,?,?,'json',?,?,?,'[]','test','ok')",
        ("b1", now_iso(), "src", received, received - rejected, rejected),
    )


class CheckIngestionTests(unittest.TestCase):
    def test_no_ingest_batches_row_is_ok(self):
        conn = memory()
        self.addCleanup(conn.close)
        status, message, guidance, details = check_ingestion(conn)
        self.assertEqual(status, "ok")
        self.assertEqual(message, "no data ingested yet")
        self.assertIn("/api/ingest", guidance)
        self.assertIsNone(details["last_batch_at"])
        self.assertEqual(details["batches_24h"], 0)
        self.assertEqual(details["received_24h"], 0)
        self.assertEqual(details["rejected_24h"], 0)
        self.assertEqual(details["server_errors_24h"], 0)
        self.assertNotIn("reject_rate_24h", details)

    def test_ingestion_error_in_24h_is_degraded_when_reject_rate_is_low(self):
        conn = memory()
        self.addCleanup(conn.close)
        # 1/40 is well under 0.25, and received is past the sample floor.
        batch(conn, received=40, rejected=1)
        conn.execute(
            "INSERT INTO error_log(created_at, component, message) VALUES (?,?,?)",
            (now_iso(), "detection", "unrelated"),
        )
        status, _, _, details = check_ingestion(conn)
        self.assertEqual(status, "ok")
        self.assertEqual(details["server_errors_24h"], 0)
        self.assertLess(details["reject_rate_24h"], 0.25)

        conn.execute(
            "INSERT INTO error_log(created_at, component, message) VALUES (?,?,?)",
            (now_iso(), "ingestion", "request failed"),
        )
        status, message, guidance, details = check_ingestion(conn)
        self.assertEqual(status, "degraded")
        self.assertEqual(message, "1 ingestion request(s) failed server-side in the last 24h")
        self.assertEqual(details["server_errors_24h"], 1)
        self.assertEqual(details["reject_rate_24h"], round(1 / 40, 3))
        self.assertLess(details["reject_rate_24h"], 0.25)
        self.assertIn("Errors", guidance)

    def test_reject_rate_over_a_quarter_with_at_least_20_received_is_degraded(self):
        conn = memory()
        self.addCleanup(conn.close)
        # 6/20 = 0.30, just over 0.25 at the minimum received count.
        batch(conn, received=20, rejected=6)
        status, message, guidance, details = check_ingestion(conn)
        self.assertEqual(status, "degraded")
        self.assertEqual(details["received_24h"], 20)
        self.assertEqual(details["rejected_24h"], 6)
        self.assertEqual(details["reject_rate_24h"], 0.3)
        self.assertEqual(message, "30% of records were rejected in the last 24h")
        self.assertIn("rejection", guidance)


if __name__ == "__main__":
    unittest.main()
