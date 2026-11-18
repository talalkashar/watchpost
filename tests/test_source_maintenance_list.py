"""GET /api/sources/health names every active maintenance window on the source row.

The list is capped at 5 in starts_at DESC, id DESC order. maintenance_omitted is the
rest (0 when the active set fits, including none). A window that does not cover the
row is not in the list or the count. Detection still uses every window, including
the one the row left out. ASCII case still matches. A 401 has no field.
"""

import sqlite3
import unittest
from datetime import timedelta
from pathlib import Path

from watchpost import engine, sources
from watchpost.db import connect, init_schema, iso, utcnow

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
INSERT = ("INSERT INTO maintenance_windows(source, host, starts_at, ends_at, reason, proposed_by, approved_by,"
          " created_at, ended_at) VALUES (?,?,?,?,?,?,?,?,?)")


def _window(conn, source, host, start, end, reason, ended_at=None):
    conn.execute(INSERT, (source, host, start, end, reason, "a", "b", start, ended_at))


def _store(conn, source, host, arrivals):
    for when in arrivals:
        stamp = iso(when)
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
            " VALUES (?,?,?,?,'other','info','heartbeat',0)", (stamp, stamp, source, host))


class MaintenanceListTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.now = utcnow()

    def _alerts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM alerts WHERE rule_id = 'log_source_silent' ORDER BY id")]

    def _row(self, source, host):
        rows = sources.inventory(self.conn)["sources"]
        return next(r for r in rows if r["source"] == source and r["host"] == host)

    def test_six_active_windows_keep_five_and_the_oldest_start_is_left_out(self):
        now = self.now
        # A learned cadence that has been quiet for about three hours.
        _store(self.conn, "fw", "fw01",
               [now - timedelta(hours=6) + timedelta(minutes=i) for i in range(180)])
        _store(self.conn, "web", "web01", [now - timedelta(minutes=i) for i in range(30)])
        long_start = iso(now - timedelta(hours=4))
        _window(self.conn, "fw", "fw01", long_start, iso(now + timedelta(hours=1)), "covers the silence")
        short_start = iso(now - timedelta(seconds=20))
        for i in range(5):
            _window(self.conn, "FW", "FW01", short_start, iso(now + timedelta(hours=2)), f"short {i}")
        engine.run_detection(self.conn)
        self.assertEqual(self._alerts(), [])
        row = self._row("fw", "fw01")
        self.assertEqual(row["status"], "healthy")
        self.assertGreater(row["silence_seconds"], 3600)
        self.assertLess(row["quiet_seconds"], 60)
        self.assertEqual([w["id"] for w in row["maintenance"]], [6, 5, 4, 3, 2])
        self.assertEqual([w["reason"] for w in row["maintenance"]],
                         ["short 4", "short 3", "short 2", "short 1", "short 0"])
        self.assertTrue(all(w["active"] for w in row["maintenance"]))
        self.assertEqual(row["maintenance_omitted"], 1)
        self.assertNotIn("covers the silence", [w["reason"] for w in row["maintenance"]])
        quiet = self._row("web", "web01")
        self.assertEqual(quiet["maintenance"], [])
        self.assertEqual(quiet["maintenance_omitted"], 0)

    def test_a_window_that_does_not_cover_is_not_counted(self):
        now = self.now
        _store(self.conn, "fw", "fw01", [now - timedelta(minutes=i) for i in range(20)])
        _store(self.conn, "démo", "Érin-host", [now - timedelta(minutes=i) for i in range(20)])
        _store(self.conn, "démo", "érin-host", [now - timedelta(minutes=i) for i in range(20)])
        start, end = iso(now - timedelta(hours=1)), iso(now + timedelta(hours=1))
        _window(self.conn, "fw", None, start, end, "every host")
        _window(self.conn, "fw", "fw02", start, end, "other host")
        _window(self.conn, "other", "fw01", start, end, "other source")
        _window(self.conn, "fw", "fw01", start, end, "ended", ended_at=iso(now - timedelta(minutes=5)))
        _window(self.conn, "fw", "fw01", iso(now + timedelta(hours=1)), iso(now + timedelta(hours=2)), "not started")
        _window(self.conn, "démo", "érin-host", start, end, "accented host")
        fw = self._row("fw", "fw01")
        self.assertEqual([w["reason"] for w in fw["maintenance"]], ["every host"])
        self.assertEqual(fw["maintenance_omitted"], 0)
        self.assertIsNone(fw["maintenance"][0]["host"])
        accent = self._row("démo", "érin-host")
        self.assertEqual([w["reason"] for w in accent["maintenance"]], ["accented host"])
        self.assertEqual(accent["maintenance_omitted"], 0)
        other = self._row("démo", "Érin-host")
        self.assertEqual(other["maintenance"], [])
        self.assertEqual(other["maintenance_omitted"], 0)

    def test_an_exact_five_and_the_same_start_keep_the_higher_id_first(self):
        now = self.now
        _store(self.conn, "fw", "fw01", [now - timedelta(minutes=i) for i in range(20)])
        start, end = iso(now - timedelta(minutes=10)), iso(now + timedelta(hours=1))
        for i in range(5):
            _window(self.conn, "fw", "fw01", start, end, f"tied {i}")
        row = self._row("fw", "fw01")
        self.assertEqual([w["id"] for w in row["maintenance"]], [5, 4, 3, 2, 1])
        self.assertEqual(row["maintenance_omitted"], 0)
        self.assertEqual([w["reason"] for w in row["maintenance"]],
                         ["tied 4", "tied 3", "tied 2", "tied 1", "tied 0"])


class MaintenanceListApiTests(ServerTestCase):
    def test_get_returns_the_list_and_a_401_has_no_field(self):
        now = utcnow()
        with sqlite3.connect(self.db_path) as db:
            stamp = iso(now)
            db.execute(
                "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
                " VALUES (?,?,?,?, 'other','info','heartbeat',0)", (stamp, stamp, "fw", "fw01"))
            start, end = iso(now - timedelta(minutes=5)), iso(now + timedelta(hours=1))
            for i in range(6):
                db.execute(INSERT, ("fw", "fw01", start, end, f"w{i}", "a", "b", start, None))
        status, body, headers = self.client("viewer").get("/api/sources/health")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        row = next(r for r in body["sources"] if r["source"] == "fw")
        self.assertEqual([w["id"] for w in row["maintenance"]], [6, 5, 4, 3, 2])
        self.assertEqual(row["maintenance_omitted"], 1)
        self.assertNotIn(1, [w["id"] for w in row["maintenance"]])
        status, denied, _ = self.client().get("/api/sources/health")
        self.assertEqual(status, 401)
        self.assertNotIn("maintenance_omitted", denied)

    def test_the_docs_row_names_maintenance_omitted(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `GET /api/sources/health`"))
        self.assertIn("maintenance_omitted", row)
        self.assertIn("at most 5", row)
        self.assertIn("every window", row)
