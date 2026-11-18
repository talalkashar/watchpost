"""The dashboard alert board says how many alerts the cap dropped.

The rows stay not-resolved first, then severity, then last_seen. A newer low
alert is the one left out when 60 open critical alerts fill the board. A
resolved critical sorts after that low alert. A list that fits, including an
empty table, returns board_omitted 0.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import BOARD_LIMIT, dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
STAMP = "2026-01-01T00:00:00.000Z"
LOW = "low-new"
RESOLVED = "resolved-new"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alert(conn, title, severity="critical", status="open", last_seen=STAMP):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("synthetic_rule", 1, title, severity, title, "synthetic", status, STAMP, last_seen, 1, 1,
         STAMP, STAMP))


def fill_critical(conn, n, minute=0):
    """n open critical alerts, newest last_seen first among January minutes."""
    for i in range(n):
        add_alert(conn, f"crit-{i:02d}", last_seen=f"2026-01-01T00:{minute + i:02d}:00.000Z")


class BoardOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def board(self):
        body = dashboard(self.conn)
        return body["board_omitted"], [row["title"] for row in body["alerts"]]

    def test_a_newer_low_alert_is_the_one_past_the_cap(self):
        fill_critical(self.conn, BOARD_LIMIT)
        add_alert(self.conn, LOW, severity="low", last_seen="2026-09-01T00:00:00.000Z")
        add_alert(self.conn, RESOLVED, status="resolved", last_seen="2026-12-01T00:00:00.000Z")
        omitted, titles = self.board()
        self.assertEqual(omitted, 2)
        self.assertEqual(len(titles), BOARD_LIMIT)
        self.assertNotIn(LOW, titles)
        self.assertNotIn(RESOLVED, titles)
        self.assertEqual(titles[0], f"crit-{BOARD_LIMIT - 1:02d}")
        self.assertEqual(titles[-1], "crit-00")

    def test_a_resolved_critical_sorts_after_a_newer_low_alert(self):
        fill_critical(self.conn, BOARD_LIMIT - 1)
        add_alert(self.conn, LOW, severity="low", last_seen="2026-09-01T00:00:00.000Z")
        add_alert(self.conn, RESOLVED, status="resolved", last_seen="2026-12-01T00:00:00.000Z")
        omitted, titles = self.board()
        self.assertEqual(omitted, 1)
        self.assertEqual(titles[-1], LOW)
        self.assertNotIn(RESOLVED, titles)
        self.assertEqual(titles[0], f"crit-{BOARD_LIMIT - 2:02d}")

    def test_not_resolved_then_severity_then_last_seen(self):
        add_alert(self.conn, "crit-new", last_seen="2026-06-01T00:00:00.000Z")
        add_alert(self.conn, "invest-old", status="investigating", last_seen="2026-03-01T00:00:00.000Z")
        add_alert(self.conn, "crit-old", last_seen="2026-01-02T00:00:00.000Z")
        add_alert(self.conn, LOW, severity="low", last_seen="2026-09-01T00:00:00.000Z")
        add_alert(self.conn, RESOLVED, status="resolved", last_seen="2026-12-01T00:00:00.000Z")
        omitted, titles = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(titles, ["crit-new", "invest-old", "crit-old", LOW, RESOLVED])

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        self.assertEqual(self.board(), (0, []))
        add_alert(self.conn, "only")
        self.assertEqual(self.board(), (0, ["only"]))
        self.conn.execute("DELETE FROM alerts")
        fill_critical(self.conn, BOARD_LIMIT)
        omitted, titles = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(len(titles), BOARD_LIMIT)

    def test_the_docs_name_board_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`board_omitted` is how many alerts were past that cap"
            " (0 when there are 60 or fewer)",
            api)
        self.assertIn("not resolved first, then severity, then last_seen", api)
        self.assertIn("the first 60", api)


class BoardOmittedApiTests(ServerTestCase):
    def test_the_dashboard_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(BOARD_LIMIT):
                add_alert(db, f"crit-{i:02d}", last_seen=f"2026-01-01T00:{i:02d}:00.000Z")
            add_alert(db, LOW, severity="low", last_seen="2026-09-01T00:00:00.000Z")
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["board_omitted"], 1)
        self.assertEqual(len(body["alerts"]), BOARD_LIMIT)
        self.assertNotIn(LOW, [row["title"] for row in body["alerts"]])
        self.assertEqual(body["alerts"][0]["title"], f"crit-{BOARD_LIMIT - 1:02d}")
        self.assertTrue(all(row["severity"] == "critical" for row in body["alerts"]))

    def test_an_empty_dashboard_and_a_rejected_request(self):
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["board_omitted"], 0)
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("board_omitted", denied)
