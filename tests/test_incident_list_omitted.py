"""GET /api/incidents stays a bare array and names the rows past the limit.

The order stays not-resolved first, then severity, then last_seen. A newer
low incident is the one left out when two open critical incidents fill the page.
X-Watchpost-Omitted is that count, including 0 when the list fits. A filter
counts only its matches. The default cap is 100.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.incidents import list_incidents

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
STAMP = "2026-01-01T00:00:00.000Z"
ENTITIES = json.dumps({"src_ip": ["203.0.113.5"], "user": ["erin"], "host": ["db01"]})
STAGES = json.dumps(["Initial Access"])


def _insert(db, specs):
    """specs: (title, severity, status, last_seen)."""
    db.executemany(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,1,1,?,?)",
        [(title, severity, status, STAMP, last_seen, ENTITIES, STAGES, STAMP, STAMP)
         for title, severity, status, last_seen in specs])


ORDERED = [
    ("crit-new", "critical", "open", "2026-06-01T00:00:00.000Z"),
    ("crit-old", "critical", "open", "2026-01-01T00:00:00.000Z"),
    ("low-new", "low", "open", "2026-09-01T00:00:00.000Z"),
    ("resolved-new", "critical", "resolved", "2026-12-01T00:00:00.000Z"),
]


class IncidentListOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        _insert(self.conn, ORDERED)

    def test_the_row_past_the_cap_sorts_after_severity(self):
        rows, omitted = list_incidents(self.conn, {"limit": "2"})
        self.assertEqual([row["title"] for row in rows], ["crit-new", "crit-old"])
        self.assertEqual(omitted, 2)
        self.assertNotIn("low-new", [row["title"] for row in rows])
        self.assertNotIn("resolved-new", [row["title"] for row in rows])

    def test_a_filter_counts_only_its_matches(self):
        rows, omitted = list_incidents(self.conn, {"status": "open", "limit": "2"})
        self.assertEqual([row["title"] for row in rows], ["crit-new", "crit-old"])
        self.assertEqual(omitted, 1)
        rows, omitted = list_incidents(self.conn, {"status": "resolved"})
        self.assertEqual([row["title"] for row in rows], ["resolved-new"])
        self.assertEqual(omitted, 0)
        rows, omitted = list_incidents(self.conn, {"severity": "info"})
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        rows, omitted = list_incidents(self.conn, {"limit": "4"})
        self.assertEqual(len(rows), 4)
        self.assertEqual(omitted, 0)
        self.conn.execute("DELETE FROM incidents")
        rows, omitted = list_incidents(self.conn, {})
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)

    def test_the_default_cap_is_100(self):
        self.conn.execute("DELETE FROM incidents")
        specs = [
            (f"row-{i}", "medium", "open", f"2026-03-{(i // 60) + 1:02d}T00:{i % 60:02d}:00.000Z")
            for i in range(101)]
        _insert(self.conn, specs)
        rows, omitted = list_incidents(self.conn, {})
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual(rows[0]["title"], "row-100")
        self.assertNotIn("row-0", [row["title"] for row in rows])


class IncidentListOmittedApiTests(ServerTestCase):
    def _load(self, specs):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM incidents")
            _insert(db, specs)

    def test_the_response_stays_an_array_and_names_the_leftover(self):
        self._load(ORDERED)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/incidents?limit=2")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual([row["title"] for row in body], ["crit-new", "crit-old"])
        self.assertEqual(headers[OMITTED], "2")
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, opened, headers = viewer.get("/api/incidents?status=open&limit=2")
        self.assertEqual(status, 200, opened)
        self.assertEqual([row["title"] for row in opened], ["crit-new", "crit-old"])
        self.assertEqual(headers[OMITTED], "1")
        status, fitted, headers = viewer.get("/api/incidents?limit=4")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 4)
        self.assertEqual(headers[OMITTED], "0")
        self._load([])
        status, empty, headers = viewer.get("/api/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(ORDERED)
        status, _body, headers = self.client().get("/api/incidents")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        status, _body, headers = self.client("viewer").get("/api/incidents?severity=nope")
        self.assertEqual(status, 400)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_default_page_drops_the_oldest_last_seen(self):
        specs = [
            (f"row-{i}", "medium", "open", f"2026-03-{(i // 60) + 1:02d}T00:{i % 60:02d}:00.000Z")
            for i in range(101)]
        self._load(specs)
        status, body, headers = self.client("viewer").get("/api/incidents")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(body[0]["title"], "row-100")
        self.assertNotIn("row-0", [row["title"] for row in body])
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM incidents WHERE title = 'row-0'")
        status, fitted, headers = self.client("viewer").get("/api/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 100)
        self.assertEqual(headers[OMITTED], "0")

    def test_the_docs_name_the_header(self):
        api = API.read_text()
        self.assertIn(
            "`X-Watchpost-Omitted` is how many matched incidents were past that cap (0 when the list fits)",
            api)
        self.assertIn("The body stays a bare array", api)


if __name__ == "__main__":
    unittest.main()
