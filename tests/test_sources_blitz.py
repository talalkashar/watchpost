"""Bugs and contracts in log source health: clock, maintenance writes, and the future-window list."""

import unittest
from datetime import datetime, timedelta, timezone

from watchpost import sources
from watchpost.db import AuditKeyError, connect, init_schema, iso, transaction, utcnow

T0 = datetime(2026, 9, 15, tzinfo=timezone.utc).timestamp()


def steady(count, every, start=T0):
    return [start + i * every for i in range(count)]


def arrival(i, when, source="fw", host="fw01"):
    stamp = iso(datetime.fromtimestamp(when, tz=timezone.utc))
    return {"id": i, "ts": stamp, "ingested_at": stamp, "source": source, "host": host}


def run(events, now=None, maintenance=()):
    params = {"window_seconds": 3600, "maintenance": list(maintenance)}
    if now is not None:
        params["now"] = iso(datetime.fromtimestamp(now, tz=timezone.utc))
    return sources.log_source_silent(events, params)


def minute_series():
    """Every minute for four hours: a learned 60s cadence whose silent floor is one hour."""
    times = steady(4 * 60, 60)
    events = [arrival(i, t) for i, t in enumerate(times, start=1)]
    return times, events


class CadenceContractTests(unittest.TestCase):
    def test_quiet_seconds_counts_an_overlapping_window_once(self):
        self.assertEqual(sources.quiet_seconds(0, 100, [(10, 30), (20, 50), (90, 200)]), 50)

    def test_late_and_silent_are_strictly_past_the_floor(self):
        times = steady(4 * 60, 60)
        last = times[-1]
        self.assertEqual(sources.judge(times, T0, last + 900)["status"], "healthy")
        self.assertEqual(sources.judge(times, T0, last + 901)["status"], "late")
        self.assertEqual(sources.judge(times, T0, last + 3600)["status"], "late")
        self.assertEqual(sources.judge(times, T0, last + 3601)["status"], "silent")

    def test_exactly_ten_gaps_over_exactly_two_hours_is_learned(self):
        times = [T0 + i * 720 for i in range(11)]
        base, why = sources.baseline(times, 10, times[0])
        self.assertIsNone(why)
        self.assertEqual(base["samples"], 10)
        short = [T0 + i * 719 for i in range(11)]
        base, why = sources.baseline(short, 10, short[0])
        self.assertIsNone(base)
        self.assertIn("history needed", why)


class RuleClockTests(unittest.TestCase):
    def test_an_arrival_after_the_clock_does_not_finish_the_gap(self):
        times, events = minute_series()
        last = times[-1]
        future = arrival(len(events) + 1, last + 5 * 3600)
        # Thirty minutes is under the one-hour silent floor. The five-hour arrival has not happened yet.
        self.assertEqual(run(events + [future], now=last + 1800), [])
        found = run(events + [future], now=last + 2 * 3600)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["event_ids"], [events[-1]["id"]])
        self.assertIn("so far", found[0]["explanation"])
        self.assertIn("2h", found[0]["explanation"])
        self.assertNotIn("before it resumed", found[0]["explanation"])

    def test_a_clock_before_every_arrival_judges_nothing(self):
        times, events = minute_series()
        events.append(arrival(len(events) + 1, times[-1] + 6 * 3600))
        self.assertEqual(run(events, now=times[0] - 60), [])

    def test_no_clock_still_reports_a_silence_that_ended(self):
        times, events = minute_series()
        events.append(arrival(len(events) + 1, times[-1] + 5 * 3600))
        found = run(events)
        self.assertEqual(len(found), 1)
        self.assertIn("before it resumed", found[0]["explanation"])
        self.assertEqual(found[0]["event_ids"], [len(events) - 1])
        after = run(events, now=times[-1] + 7 * 3600)
        self.assertEqual(len(after), 1)
        self.assertIn("before it resumed", after[0]["explanation"])

    def test_maintenance_excuses_only_the_matching_pair(self):
        times, events = minute_series()
        last = times[-1]
        cover = {"source": "FW", "host": None, "start": last, "end": last + 4 * 3600}
        self.assertEqual(run(events, now=last + 2 * 3600, maintenance=[cover]), [])
        other = {**cover, "host": "fw02"}
        self.assertEqual(len(run(events, now=last + 2 * 3600, maintenance=[other])), 1)

    def test_ascii_fold_is_one_stream_and_non_ascii_stays_two(self):
        times = steady(4 * 60, 60)
        last = times[-1]
        mixed = [arrival(i, t, "Demo" if i % 2 else "demo", "WEB01" if i % 2 else "web01")
                 for i, t in enumerate(times, start=1)]
        found = run(mixed, now=last + 2 * 3600)
        self.assertEqual([(f["group_key"], f["event_ids"]) for f in found], [("demo|web01", [mixed[-1]["id"]])])
        accent_a = [arrival(i, t, "démo", "Érin-host") for i, t in enumerate(times, start=1)]
        accent_b = [arrival(1000 + i, t, "DÉMO", "érin-host") for i, t in enumerate(times, start=1)]
        keys = sorted(f["group_key"] for f in run(accent_a + accent_b, now=last + 2 * 3600))
        self.assertEqual(keys, ["dÉmo|érin-host", "démo|Érin-host"])


class WindowWriteTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:", audit_key="original-key")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        self.wall = utcnow()

    def payload(self, start, end, host="fw01"):
        body = {"start": iso(start), "end": iso(end)}
        if host is not None:
            body["host"] = host
        return body

    def test_validate_window_accepts_a_zoned_future_span(self):
        clock = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
        now = iso(clock)
        start = clock + timedelta(hours=1)
        end = clock + timedelta(hours=3)
        host, got_start, got_end = sources.validate_window("fw", self.payload(start, end, host=None), now=now)
        self.assertIsNone(host)
        self.assertTrue(got_start.endswith("Z") and got_end.endswith("Z"))
        with self.assertRaises(sources.WindowError) as bad:
            sources.validate_window("has space", self.payload(start, end), now=now)
        self.assertIn("1-64", str(bad.exception))
        with self.assertRaises(sources.WindowError) as past:
            sources.validate_window(
                "fw", self.payload(clock - timedelta(hours=2), clock - timedelta(minutes=1)), now=now)
        self.assertIn("past", str(past.exception))
        with self.assertRaises(sources.WindowError) as naive:
            sources.validate_window(
                "fw", {"start": "2026-09-15T13:00:00", "end": "2026-09-15T15:00:00"}, now=now)
        self.assertIn("time zone", str(naive.exception))
        too_long = start + timedelta(days=sources.MAX_WINDOW_DAYS, seconds=1)
        with self.assertRaises(sources.WindowError) as span:
            sources.validate_window("fw", self.payload(start, too_long), now=now)
        self.assertIn("30", str(span.exception))
        with self.assertRaises(sources.WindowError) as empty:
            sources.validate_window("fw", {"host": "", "start": iso(start), "end": iso(end)}, now=now)
        self.assertIn("1-255", str(empty.exception))
        with self.assertRaises(sources.WindowError) as missing:
            sources.validate_window("fw", {"host": "fw01"}, now=now)
        self.assertIn("start and end", str(missing.exception))

    def test_add_window_commits_the_row_and_the_audit(self):
        window_id = sources.add_window(
            self.conn, "fw", self.payload(self.wall + timedelta(hours=1), self.wall + timedelta(hours=2)),
            "patch", "pro", "app", None)
        self.assertFalse(self.conn.in_transaction)
        row = self.conn.execute(
            "SELECT source, host FROM maintenance_windows WHERE id = ?", (window_id,)).fetchone()
        self.assertEqual((row["source"], row["host"]), ("fw", "fw01"))
        added = self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'maintenance_window_added'").fetchone()[0]
        self.assertEqual(added, 1)

    def test_a_failed_audit_leaves_no_window(self):
        self.conn.audit_key = "other-key"
        with self.assertRaises(AuditKeyError):
            sources.add_window(
                self.conn, "fw", self.payload(self.wall + timedelta(hours=1), self.wall + timedelta(hours=2)),
                "patch", "pro", "app", None)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM maintenance_windows").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'maintenance_window_added'").fetchone()[0], 0)
        self.assertFalse(self.conn.in_transaction)

    def test_a_caller_transaction_still_owns_commit_and_rollback(self):
        with transaction(self.conn):
            window_id = sources.add_window(
                self.conn, "fw", self.payload(self.wall + timedelta(hours=3), self.wall + timedelta(hours=4)),
                "patch", "pro", "app", 7)
            self.assertTrue(self.conn.in_transaction)
        self.assertFalse(self.conn.in_transaction)
        stored = self.conn.execute(
            "SELECT change_request_id FROM maintenance_windows WHERE id = ?", (window_id,)).fetchone()[0]
        self.assertEqual(stored, 7)
        with self.assertRaises(RuntimeError):
            with transaction(self.conn):
                sources.add_window(
                    self.conn, "fw",
                    self.payload(self.wall + timedelta(hours=5), self.wall + timedelta(hours=6)),
                    "nope", "pro", "app", None)
                raise RuntimeError("caller changed its mind")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM maintenance_windows").fetchone()[0], 1)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'maintenance_window_added'").fetchone()[0], 1)
        self.assertFalse(self.conn.in_transaction)

    def test_a_window_ended_before_it_starts_is_not_listed_as_upcoming(self):
        soon = sources.add_window(
            self.conn, "fw", self.payload(self.wall + timedelta(hours=2), self.wall + timedelta(hours=4)),
            "soon", "pro", "app", None)
        later = sources.add_window(
            self.conn, "fw", self.payload(self.wall + timedelta(hours=6), self.wall + timedelta(hours=8)),
            "later", "pro", "app", None)
        ended = sources.end_window(self.conn, later, "admin")
        self.assertEqual(ended["effective_end"], ended["starts_at"])
        self.assertFalse(ended["active"])
        past_start = iso(self.wall - timedelta(hours=5))
        self.conn.execute(
            "INSERT INTO maintenance_windows(source, host, starts_at, ends_at, reason, proposed_by, approved_by,"
            " created_at, ended_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("fw", "fw01", past_start, iso(self.wall + timedelta(hours=1)), "gone", "pro", "app", past_start,
             iso(self.wall - timedelta(minutes=1))))
        body = sources.inventory(self.conn, now=iso(self.wall))
        self.assertEqual([w["id"] for w in body["maintenance_windows"]], [soon])
        self.assertEqual(body["maintenance_windows_omitted"], 0)


class InventoryClockTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def test_active_follows_the_clock_passed_to_inventory(self):
        clock = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
        self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
            " VALUES (?,?,?,'fw01','other','info','heartbeat',0)",
            (iso(clock), iso(clock), "fw"))
        start, end = clock + timedelta(hours=1), clock + timedelta(hours=3)
        self.conn.execute(
            "INSERT INTO maintenance_windows(source, host, starts_at, ends_at, reason, proposed_by, approved_by,"
            " created_at) VALUES ('fw','fw01',?,?,?,?,?,?)",
            (iso(start), iso(end), "upgrade", "pro", "app", iso(clock)))
        early = sources.inventory(self.conn, now=iso(clock))
        self.assertEqual(early["sources"][0]["maintenance"], [])
        self.assertEqual(len(early["maintenance_windows"]), 1)
        self.assertFalse(early["maintenance_windows"][0]["active"])
        later = sources.inventory(self.conn, now=iso(clock + timedelta(minutes=90)))
        self.assertEqual(len(later["sources"][0]["maintenance"]), 1)
        self.assertTrue(later["sources"][0]["maintenance"][0]["active"])
        self.assertTrue(later["maintenance_windows"][0]["active"])
