"""GET /api/rule-suppression-windows stays a bare array and names the rows past 100.

The order stays newest id first. A later created_at on a lower id is the one
left out. upcoming, active, expired, and ended stay on the kept rows.
X-Watchpost-Omitted is that count, including 0 when the list fits. A 401
sends no header. Ending a window past the cap still returns that row.
"""

import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.improve import end_rule_suppression_window, list_rule_suppression_windows

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
PAST = "2020-01-01T00:00:00.000Z"
FUTURE = "2099-01-01T00:00:00.000Z"
INSERT = (
    "INSERT INTO rule_suppression_windows(rule_id, starts_at, expires_at, reason,"
    " proposed_by, approved_by, created_at)"
    " VALUES ('brute_force_ip', ?, ?, 'synthetic maintenance', 'analyst', 'admin', ?)"
)


def _insert(db, specs):
    """specs: created_at. Ids follow insert order. The window stays active."""
    db.executemany(INSERT, [(PAST, FUTURE, stamp) for stamp in specs])


def _fill(count, stamp="2026-01-01T00:00:00.000Z"):
    return [stamp for _ in range(count)]


class RuleWindowsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_left_out(self):
        _insert(self.conn, ["2026-09-01T00:00:00.000Z"] + _fill(100))
        self.conn.execute(
            "UPDATE rule_suppression_windows SET expires_at = ? WHERE id = 101",
            ("2020-06-01T00:00:00.000Z",),
        )
        self.conn.execute(
            "UPDATE rule_suppression_windows SET ended_at = ?, ended_by = ? WHERE id = 100",
            ("2026-06-01T00:00:00.000Z", "admin"),
        )
        self.conn.execute(
            "UPDATE rule_suppression_windows SET starts_at = ? WHERE id = 99",
            ("2098-01-01T00:00:00.000Z",),
        )
        rows, omitted = list_rule_suppression_windows(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["id"], 101)
        self.assertEqual([row["id"] for row in rows], list(range(101, 1, -1)))
        self.assertNotIn(1, [row["id"] for row in rows])
        self.assertEqual(
            self.conn.execute(
                "SELECT created_at FROM rule_suppression_windows WHERE id = 1"
            ).fetchone()[0],
            "2026-09-01T00:00:00.000Z",
        )
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id[101]["state"], "expired")
        self.assertFalse(by_id[101]["active"])
        self.assertEqual(by_id[100]["state"], "ended")
        self.assertFalse(by_id[100]["active"])
        self.assertEqual(by_id[100]["ended_by"], "admin")
        self.assertEqual(by_id[99]["state"], "upcoming")
        self.assertFalse(by_id[99]["active"])
        self.assertEqual(by_id[98]["state"], "active")
        self.assertTrue(by_id[98]["active"])

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, _fill(100))
        rows, omitted = list_rule_suppression_windows(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertTrue(all(row["state"] == "active" and row["active"] for row in rows))
        self.assertIn(1, [row["id"] for row in rows])
        self.conn.execute("DELETE FROM rule_suppression_windows")
        rows, omitted = list_rule_suppression_windows(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)

    def test_ending_a_window_past_the_cap_still_returns_it(self):
        _insert(self.conn, _fill(101))
        ended = end_rule_suppression_window(self.conn, 1, "admin")
        self.assertEqual(ended["id"], 1)
        self.assertEqual(ended["state"], "ended")
        self.assertFalse(ended["active"])
        self.assertEqual(ended["ended_by"], "admin")
        rows, omitted = list_rule_suppression_windows(self.conn)
        self.assertEqual(omitted, 1)
        self.assertNotIn(1, [row["id"] for row in rows])


class RuleWindowsOmittedApiTests(ServerTestCase):
    def _load(self, stamps):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM rule_suppression_windows")
            if stamps:
                _insert(db, stamps)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load(["2026-09-01T00:00:00.000Z"] + _fill(100))
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/rule-suppression-windows")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(body[0]["id"], 101)
        self.assertNotIn(1, [row["id"] for row in body])
        self.assertEqual(body[0]["state"], "active")
        self.assertTrue(body[0]["active"])
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load(_fill(100))
        status, fitted, headers = viewer.get("/api/rule-suppression-windows")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = viewer.get("/api/rule-suppression-windows")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(_fill(101))
        status, _body, headers = self.client().get("/api/rule-suppression-windows")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(
            row
            for row in API.read_text().splitlines()
            if row.startswith("| `GET /api/rule-suppression-windows`")
        )
        self.assertIn("The body stays a bare array", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many windows were past that cap (0 when the list fits)",
            line,
        )
        self.assertIn("`upcoming`, `active`, `expired`, and `ended`", line)


if __name__ == "__main__":
    unittest.main()
