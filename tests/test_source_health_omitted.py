"""GET /api/sources/health caps source pairs and future maintenance windows.

sources stays the first 100 after silent, then source, then host. sources_omitted
is the rest (0 when the inventory fits, including none). summary counts every pair.
maintenance_windows stays the first 100 whose effective end is still ahead, in
starts_at descending then id descending order. maintenance_windows_omitted is the
rest. An ended window is not a row and is not omitted. The per-source maintenance
list stays the cap of 5. A 401 has neither field.
"""

import sqlite3
import unittest
from datetime import timedelta
from pathlib import Path

from watchpost import sources
from watchpost.db import connect, init_schema, iso, utcnow

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
EVENT = ("INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
         " VALUES (?,?,?,?,'other','info','heartbeat',1)")
WINDOW = ("INSERT INTO maintenance_windows(source, host, starts_at, ends_at, reason, proposed_by, approved_by,"
          " created_at, ended_at) VALUES (?,?,?,?,?,?,?,?,?)")


def _silent_arrivals(now):
    """Eleven arrivals spanning two hours, ending four hours ago: a learned source that is silent."""
    start = now - timedelta(hours=6)
    return [start + timedelta(minutes=12 * j) for j in range(11)]


def _event_rows(source, host, arrivals):
    return [(iso(when), iso(when), source, host) for when in arrivals]


class SourceHealthOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        self.now = utcnow()

    def _body(self):
        return sources.inventory(self.conn, now=iso(self.now))

    def test_silent_rows_stay_and_the_last_source_is_left_out(self):
        now = self.now
        silent = _silent_arrivals(now)
        rows = []
        for i in range(98):
            rows.extend(_event_rows(f"zzz-{i:02d}", "host", silent))
        # The newest event is the learning source that sorts last.
        rows.extend(_event_rows("aaa", "host", [now - timedelta(hours=1)]))
        rows.extend(_event_rows("mmm", "host", [now - timedelta(minutes=30)]))
        rows.extend(_event_rows("zzz", "host", [now]))
        self.conn.executemany(EVENT, rows)
        body = self._body()
        self.assertEqual(body["sources_omitted"], 1)
        self.assertEqual(len(body["sources"]), 100)
        self.assertEqual(body["sources"][0]["source"], "zzz-00")
        self.assertTrue(all(r["status"] == "silent" for r in body["sources"][:98]))
        self.assertEqual([(r["source"], r["status"]) for r in body["sources"][98:]],
                         [("aaa", "learning"), ("mmm", "learning")])
        self.assertNotIn("zzz", [r["source"] for r in body["sources"]])
        self.assertEqual(body["summary"], {"silent": 98, "late": 0, "healthy": 0, "learning": 3})

    def test_the_same_source_leaves_out_the_last_host_even_when_it_is_newest(self):
        now = self.now
        rows = []
        for i in range(100):
            rows.extend(_event_rows("learn", f"h{i:03d}", [now - timedelta(hours=1)]))
        rows.extend(_event_rows("learn", "h100", [now]))
        self.conn.executemany(EVENT, rows)
        body = self._body()
        hosts = [r["host"] for r in body["sources"]]
        self.assertEqual(body["sources_omitted"], 1)
        self.assertEqual(hosts[0], "h000")
        self.assertEqual(hosts[-1], "h099")
        self.assertNotIn("h100", hosts)
        self.assertEqual(body["summary"]["learning"], 101)

    def test_an_exact_hundred_and_an_empty_table_return_0(self):
        now = self.now
        self.assertEqual(self._body()["sources_omitted"], 0)
        self.assertEqual(self._body()["sources"], [])
        self.assertEqual(self._body()["summary"], {"silent": 0, "late": 0, "healthy": 0, "learning": 0})
        rows = [_event_rows(f"s{i:03d}", "host", [now])[0] for i in range(100)]
        self.conn.executemany(EVENT, rows)
        body = self._body()
        self.assertEqual(body["sources_omitted"], 0)
        self.assertEqual(len(body["sources"]), 100)
        self.assertEqual(body["summary"]["learning"], 100)

    def test_ascii_case_is_one_pair_and_accented_hosts_stay_two(self):
        now = self.now
        rows = [_event_rows(f"s{i:03d}", "host", [now])[0] for i in range(98)]
        rows.append(_event_rows("Demo", "WEB01", [now])[0])
        rows.append(_event_rows("demo", "web01", [now])[0])
        self.conn.executemany(EVENT, rows)
        body = self._body()
        self.assertEqual(body["sources_omitted"], 0)
        self.assertEqual(len(body["sources"]), 99)
        folded = [r for r in body["sources"] if r["source"] == "demo"]
        self.assertEqual([(r["host"], r["events"]) for r in folded], [("web01", 2)])
        self.conn.executemany(EVENT, [
            _event_rows("z", "Érin-host", [now])[0],
            _event_rows("z", "érin-host", [now])[0],
        ])
        body = self._body()
        self.assertEqual(body["sources_omitted"], 1)
        kept = [r["host"] for r in body["sources"] if r["source"] == "z"]
        self.assertEqual(kept, ["Érin-host"])
        self.assertEqual(body["summary"]["learning"], 101)

    def test_the_earliest_start_is_the_one_left_out_of_the_windows(self):
        now = self.now
        later = iso(now - timedelta(hours=1))
        end = iso(now + timedelta(hours=2))
        earlier = iso(now - timedelta(days=1))
        windows = [("fw", "fw01", later, end, f"late {i}", "a", "b", later, None) for i in range(100)]
        windows.append(("fw", "fw01", earlier, end, "earliest", "a", "b", earlier, None))
        self.conn.executemany(WINDOW, windows)
        body = self._body()
        ids = [w["id"] for w in body["maintenance_windows"]]
        self.assertEqual(body["maintenance_windows_omitted"], 1)
        self.assertEqual(ids, list(range(100, 0, -1)))
        self.assertNotIn(101, ids)
        self.assertNotIn("earliest", [w["reason"] for w in body["maintenance_windows"]])

    def test_the_same_start_keeps_the_higher_ids(self):
        now = self.now
        start, end = iso(now - timedelta(minutes=5)), iso(now + timedelta(hours=1))
        windows = [("fw", None, start, end, f"tied {i}", "a", "b", start, None) for i in range(101)]
        self.conn.executemany(WINDOW, windows)
        body = self._body()
        self.assertEqual(body["maintenance_windows_omitted"], 1)
        self.assertEqual([w["id"] for w in body["maintenance_windows"]], list(range(101, 1, -1)))

    def test_an_ended_window_is_not_counted_and_an_upcoming_one_stays(self):
        now = self.now
        start, end = iso(now - timedelta(hours=1)), iso(now + timedelta(hours=2))
        windows = [("fw", "fw01", start, end, f"open {i}", "a", "b", start, None) for i in range(100)]
        windows.append(("fw", "fw01", iso(now - timedelta(hours=3)), end, "ended", "a", "b", start,
                        iso(now - timedelta(minutes=1))))
        windows.append(("fw", "fw01", iso(now + timedelta(hours=1)), iso(now + timedelta(hours=3)),
                        "upcoming", "a", "b", start, None))
        self.conn.executemany(WINDOW, windows)
        body = self._body()
        reasons = [w["reason"] for w in body["maintenance_windows"]]
        self.assertEqual(body["maintenance_windows_omitted"], 1)
        self.assertEqual(reasons[0], "upcoming")
        self.assertNotIn("ended", reasons)
        self.assertNotIn("open 0", reasons)
        self.assertIn("open 99", reasons)
        self.assertEqual(len(body["maintenance_windows"]), 100)

    def test_an_exact_hundred_windows_and_none_return_0(self):
        self.assertEqual(self._body()["maintenance_windows_omitted"], 0)
        self.assertEqual(self._body()["maintenance_windows"], [])
        now = self.now
        start, end = iso(now - timedelta(minutes=5)), iso(now + timedelta(hours=1))
        windows = [("fw", "fw01", start, end, f"fit {i}", "a", "b", start, None) for i in range(100)]
        self.conn.executemany(WINDOW, windows)
        body = self._body()
        self.assertEqual(body["maintenance_windows_omitted"], 0)
        self.assertEqual(len(body["maintenance_windows"]), 100)

    def test_a_source_row_still_names_only_five_windows(self):
        now = self.now
        self.conn.execute(EVENT, (iso(now), iso(now), "fw", "fw01"))
        start, end = iso(now - timedelta(minutes=5)), iso(now + timedelta(hours=1))
        windows = [("fw", "fw01", start, end, f"w{i}", "a", "b", start, None) for i in range(6)]
        self.conn.executemany(WINDOW, windows)
        row = self._body()["sources"][0]
        self.assertEqual([w["id"] for w in row["maintenance"]], [6, 5, 4, 3, 2])
        self.assertEqual(row["maintenance_omitted"], 1)
        self.assertEqual(self._body()["maintenance_windows_omitted"], 0)


class SourceHealthOmittedApiTests(ServerTestCase):
    def test_get_returns_both_counts_and_a_401_has_neither(self):
        now = utcnow()
        stamp = iso(now)
        with sqlite3.connect(self.db_path) as db:
            db.executemany(EVENT, [(stamp, stamp, f"s{i:03d}", "host") for i in range(101)])
            start, end = iso(now - timedelta(minutes=5)), iso(now + timedelta(hours=1))
            db.executemany(WINDOW, [("fw", "fw01", start, end, f"w{i}", "a", "b", start, None)
                                    for i in range(101)])
        status, body, headers = self.client("viewer").get("/api/sources/health")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["sources_omitted"], 1)
        self.assertEqual(len(body["sources"]), 100)
        self.assertEqual(body["summary"]["learning"], 101)
        self.assertNotIn("s100", [r["source"] for r in body["sources"]])
        self.assertEqual(body["maintenance_windows_omitted"], 1)
        self.assertEqual(len(body["maintenance_windows"]), 100)
        self.assertNotIn(1, [w["id"] for w in body["maintenance_windows"]])
        status, denied, _ = self.client().get("/api/sources/health")
        self.assertEqual(status, 401)
        self.assertNotIn("sources_omitted", denied)
        self.assertNotIn("maintenance_windows_omitted", denied)

    def test_the_docs_row_names_both_omitted_counts(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `GET /api/sources/health`"))
        self.assertIn("sources_omitted", row)
        self.assertIn("maintenance_windows_omitted", row)
        self.assertIn("summary", row)
        self.assertIn("at most 5", row)
