"""GET /api/rules/{id}/history stays a bare array and names versions past 50.

The order stays newest version first. A later changed_at on a lower version
is the one left out. Another rule's rows are not counted. X-Watchpost-Omitted
is that count, including 0 when the history fits. An unknown rule is an empty
array and omitted 0. A 401 sends no header.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.improve import list_rule_history

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
INSERT = ("INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, note)"
          " VALUES (?, ?, 1, ?, ?, 'analyst', 'tune')")


def _insert(db, rule_id, specs):
    """specs: (version, changed_at). Params stay a JSON object."""
    db.executemany(INSERT, [
        (rule_id, version, json.dumps({"threshold": version}), stamp)
        for version, stamp in specs
    ])


def _fill(count, start=1, stamp="2026-01-01T00:00:00.000Z"):
    return [(version, stamp) for version in range(start, start + count)]


class RuleHistoryOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_the_lowest_version_is_the_one_left_out(self):
        _insert(self.conn, "brute_force_ip",
                [(1, "2026-09-01T00:00:00.000Z")] + _fill(50, start=2))
        _insert(self.conn, "password_spray", _fill(10))
        rows, omitted = list_rule_history(self.conn, "brute_force_ip")
        self.assertEqual(len(rows), 50)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["version"], 51)
        self.assertEqual([row["version"] for row in rows], list(range(51, 1, -1)))
        self.assertNotIn(1, [row["version"] for row in rows])
        self.assertEqual(rows[0]["params"], {"threshold": 51})
        self.assertEqual(rows[0]["grouping"], [])
        self.assertEqual(
            self.conn.execute(
                "SELECT changed_at FROM rule_history WHERE rule_id = 'brute_force_ip' AND version = 1"
            ).fetchone()[0],
            "2026-09-01T00:00:00.000Z")
        spray, spray_omitted = list_rule_history(self.conn, "password_spray")
        self.assertEqual(len(spray), 10)
        self.assertEqual(spray_omitted, 0)

    def test_an_exact_cap_an_empty_table_and_an_unknown_rule_return_zero(self):
        _insert(self.conn, "brute_force_ip", _fill(50))
        rows, omitted = list_rule_history(self.conn, "brute_force_ip")
        self.assertEqual(len(rows), 50)
        self.assertEqual(omitted, 0)
        self.assertIn(1, [row["version"] for row in rows])
        self.conn.execute("DELETE FROM rule_history")
        rows, omitted = list_rule_history(self.conn, "brute_force_ip")
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)
        _insert(self.conn, "password_spray", _fill(51))
        rows, omitted = list_rule_history(self.conn, "not_a_rule")
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class RuleHistoryOmittedApiTests(ServerTestCase):
    def _load(self, rule_id, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM rule_history WHERE rule_id = ?", (rule_id,))
            if specs:
                _insert(db, rule_id, specs)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load("brute_force_ip", [(1, "2026-09-01T00:00:00.000Z")] + _fill(50, start=2))
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/rules/brute_force_ip/history")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 50)
        self.assertEqual(body[0]["version"], 51)
        self.assertEqual(body[0]["params"]["threshold"], 51)
        self.assertNotIn(1, [row["version"] for row in body])
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self._load("brute_force_ip", _fill(50))
        status, fitted, headers = viewer.get("/api/rules/brute_force_ip/history")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 50)
        self.assertEqual(headers[OMITTED], "0")
        self._load("brute_force_ip", [])
        status, empty, headers = viewer.get("/api/rules/brute_force_ip/history")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")
        status, unknown, headers = viewer.get("/api/rules/not_a_rule/history")
        self.assertEqual(status, 200)
        self.assertEqual(unknown, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load("brute_force_ip", _fill(51))
        status, _body, headers = self.client().get("/api/rules/brute_force_ip/history")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/rules/{id}/history`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn("An unknown rule is an empty array", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many versions were past that cap (0 when the history fits)",
            line)


if __name__ == "__main__":
    unittest.main()
