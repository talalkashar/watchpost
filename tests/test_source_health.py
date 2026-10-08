"""Milestone 17: log source health (inventory, cadence, statuses) and the log_source_silent rule."""

import json
import sqlite3
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from watchpost import attack, engine, improve, rules, simulate, sources, storyline
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.normalize import parse_payload

from .helpers import ServerTestCase
from .test_assets import second_admin

T0 = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc).timestamp()
DEFAULTS = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}


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


class CadenceTests(unittest.TestCase):
    def test_cadence_is_the_median_gap_and_thresholds_follow_it(self):
        times = steady(16, 60) + [T0 + 15 * 60 + 600]  # fifteen 60 s gaps, then one 600 s gap
        times = [t + 3 * 3600 for t in times]
        base, why = sources.baseline(times, len(times) - 1, first_seen=T0)
        self.assertIsNone(why)
        self.assertEqual((base["cadence"], base["longest_gap"], base["samples"]), (60, 600, 16))
        self.assertEqual(base["late_after"], max(3 * 60, 900, 600))
        self.assertEqual(base["silent_after"], max(6 * 60, 3600, 1200))
        # A slow, steady source: the multipliers dominate the floors.
        base, _ = sources.baseline(steady(20, 1800), 19, T0)
        self.assertEqual((base["cadence"], base["late_after"], base["silent_after"]), (1800, 5400, 10800))

    def test_a_small_sample_or_a_short_history_is_learning(self):
        base, why = sources.baseline(steady(sources.MIN_GAPS, 600), sources.MIN_GAPS - 1, T0)
        self.assertIsNone(base)
        self.assertIn(f"{sources.MIN_GAPS - 1} gap(s)", why)
        burst = steady(40, 4)  # 40 events in under 3 minutes: a burst, not a cadence
        base, why = sources.baseline(burst, 39, T0)
        self.assertIsNone(base)
        self.assertIn("history needed", why)

    def test_only_the_recent_window_and_sample_count(self):
        old = steady(30, 10)  # a fast burst more than a day before the slow recent arrivals
        recent = steady(15, 1200, start=T0 + 2 * 86400)
        base, _ = sources.baseline(old + recent, len(old + recent) - 1, T0)
        self.assertEqual((base["cadence"], base["samples"]), (1200, 14))
        many = steady(500, 30)
        self.assertEqual(sources.baseline(many, 499, T0)[0]["samples"], sources.CADENCE_SAMPLE)

    def test_quiet_seconds_subtracts_maintenance(self):
        self.assertEqual(sources.quiet_seconds(0, 100), 100)
        self.assertEqual(sources.quiet_seconds(0, 100, [(10, 30), (20, 50), (90, 200)]), 50)
        self.assertEqual(sources.quiet_seconds(0, 100, [(-50, 500)]), 0)


class StatusTests(unittest.TestCase):
    times = steady(4 * 60, 60)  # every minute for four hours
    last = times[-1]

    def status(self, after, windows=(), times=None):
        return sources.judge(times or self.times, T0, self.last + after, windows)

    def test_transitions(self):
        self.assertEqual(self.status(30)["status"], "healthy")
        self.assertEqual(self.status(900)["status"], "healthy")  # the 15-minute floor, not 3x60 s
        self.assertEqual(self.status(901)["status"], "late")
        self.assertEqual(self.status(3600)["status"], "late")
        silent = self.status(3601)
        self.assertEqual(silent["status"], "silent")
        self.assertEqual((silent["cadence_seconds"], silent["silent_after_seconds"]), (60, 3600))
        self.assertIn("silent threshold", silent["reasons"][0])
        learning = sources.judge(steady(5, 60), T0, T0 + 86400)
        self.assertEqual(learning["status"], "learning")
        self.assertIsNone(learning["cadence_seconds"])

    def test_silence_is_measured_against_the_clock_given(self):
        # A clock behind the last arrival (skew) is no silence at all.
        self.assertEqual(self.status(-300)["silence_seconds"], 0)

    def test_maintenance_window_keeps_a_quiet_source_healthy(self):
        window = [(self.last + 60, self.last + 4 * 3600)]
        inside = self.status(3 * 3600, window)
        self.assertEqual((inside["status"], inside["quiet_seconds"]), ("healthy", 60))
        self.assertIn("inside a maintenance window", inside["reasons"][0])
        # After the window the clock runs again: 60 s before it plus the time since it ended.
        after = self.status(4 * 3600 + 3600, window)
        self.assertEqual((after["status"], after["quiet_seconds"]), ("silent", 3660))


class RuleTests(unittest.TestCase):
    def events(self):
        return [arrival(i, t) for i, t in enumerate(StatusTests.times, start=1)]

    def test_fires_on_current_silence_with_the_last_event_as_evidence(self):
        events = self.events()
        found = run(events, now=StatusTests.last + 2 * 3600)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["group_key"], found[0]["event_ids"]), ("fw|fw01", [events[-1]["id"]]))
        self.assertIn("so far", found[0]["explanation"])
        self.assertEqual(run(events, now=StatusTests.last + 1800), [])  # late is not an alert
        self.assertEqual(run(events), [])  # no clock: only silences that ended are judged

    def test_a_silence_that_ended_is_judged_against_the_cadence_before_it(self):
        events = self.events()
        events.append(arrival(len(events) + 1, StatusTests.last + 5 * 3600))
        found = run(events)
        self.assertEqual([f["event_ids"] for f in found], [[len(events) - 1]])
        self.assertIn("before it resumed", found[0]["explanation"])

    def test_learning_and_bursty_sources_never_alert(self):
        burst = [arrival(i, T0 + i * 4) for i in range(1, 41)]
        self.assertEqual(run(burst, now=T0 + 86400), [])
        nightly = [arrival(i, T0 + d * 86400 + k * 150) for i, (d, k) in
                   enumerate(((d, k) for d in range(4) for k in range(12)), start=1)]
        self.assertEqual(run(nightly, now=T0 + 3 * 86400 + 23 * 3600), [])

    def test_maintenance_window_suppresses_and_host_scoping_holds(self):
        events = self.events()
        now = StatusTests.last + 3 * 3600
        window = {"source": "fw", "host": None, "start": StatusTests.last, "end": now + 3600}
        self.assertEqual(run(events, now=now, maintenance=[window]), [])
        other_host = {**window, "host": "fw02"}
        self.assertEqual(len(run(events, now=now, maintenance=[other_host])), 1)
        ended_early = {**window, "end": StatusTests.last + 600}
        self.assertEqual(len(run(events, now=now, maintenance=[ended_early])), 1)


class EngineTests(unittest.TestCase):
    """The rule in a real detection run: wall clock, arrivals by ingested_at, one alert per silence."""

    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def store(self, source, host, arrivals, synthetic=0):
        for when in arrivals:
            stamp = iso(when)
            self.conn.execute(
                "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
                " VALUES (?,?,?,?,'other','info','heartbeat',?)", (stamp, stamp, source, host, synthetic))

    def alerts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM alerts WHERE rule_id = 'log_source_silent' ORDER BY id")]

    def test_fires_once_per_silence_episode(self):
        now = utcnow()
        self.store("fw", "fw01", [now - timedelta(hours=6) + timedelta(minutes=i) for i in range(180)])
        self.store("web", "web01", [now - timedelta(hours=6) + timedelta(minutes=i) for i in range(361)])
        first = engine.run_detection(self.conn)
        self.assertEqual(first["status"], "ok")
        self.assertEqual([a["group_key"] for a in self.alerts()], ["fw|fw01"])
        self.assertIn("Log source silent", self.alerts()[0]["title"])
        for _ in range(2):  # rescans and later ingests add nothing to the same silence
            engine.run_detection(self.conn)
        self.assertEqual(len(self.alerts()), 1)
        self.conn.execute("UPDATE alerts SET status = 'resolved'")
        engine.run_detection(self.conn)
        self.assertEqual(len(self.alerts()), 1)  # resolved stays resolved for this episode
        # The source comes back: the finished gap carries the same evidence, so still one alert.
        self.store("fw", "fw01", [now - timedelta(minutes=30) + timedelta(minutes=i) for i in range(30)])
        engine.run_detection(self.conn)
        self.assertEqual(len(self.alerts()), 1)
        # It stops again; two hours later by the clock that is a new episode and a new alert.
        later = iso(now + timedelta(hours=2))
        with mock.patch.object(sources, "now_iso", return_value=later):
            engine.run_detection(self.conn)
            engine.run_detection(self.conn)
        self.assertEqual(len(self.alerts()), 2)
        self.assertEqual(self.alerts()[1]["status"], "open")

    def test_maintenance_window_in_the_database_suppresses(self):
        now = utcnow()
        self.store("fw", "fw01", [now - timedelta(hours=6) + timedelta(minutes=i) for i in range(180)])
        self.conn.execute(
            "INSERT INTO maintenance_windows(source, host, starts_at, ends_at, reason, proposed_by, approved_by,"
            " created_at) VALUES ('fw', 'fw01', ?, ?, 'firmware upgrade', 'a', 'b', ?)",
            (iso(now - timedelta(hours=3, minutes=30)), iso(now + timedelta(hours=1)), iso(now)))
        engine.run_detection(self.conn)
        self.assertEqual(self.alerts(), [])
        health = {(r["source"], r["host"]): r for r in sources.inventory(self.conn)["sources"]}
        self.assertEqual(health[("fw", "fw01")]["status"], "healthy")
        self.assertIsNotNone(health[("fw", "fw01")]["maintenance"])

    def test_replayed_old_data_is_one_arrival_and_learning(self):
        # Demo data is dated yesterday but arrives in one upload: no cadence, no alert.
        raw = json.dumps(simulate.build(["log_source_stops"])["log_source_stops"])
        events, rejections = parse_payload(raw, "json", "demo:log_source_stops")
        result = engine.ingest(self.conn, events, rejections, "demo:log_source_stops", "json", "test", synthetic=True)
        self.assertEqual(result["detection"]["status"], "ok")
        self.assertEqual(self.alerts(), [])
        rows = sources.inventory(self.conn)["sources"]
        self.assertEqual([r["status"] for r in rows], ["learning"])
        self.assertEqual(rows[0]["events_24h"], 165)


class NoiseLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = improve.evaluate(DEFAULTS)["rules"]

    def test_detects_the_stopped_source_and_not_the_badge_reader(self):
        r = self.result["log_source_silent"]
        self.assertEqual((r["tp"], r["fn"], r["fp"]), (1, 0, 0))
        self.assertEqual((r["detected"], r["lookalikes"], r["lookalikes_fired"]),
                         (["log_source_stops"], ["office_badge_reader"], []))
        self.assertEqual(r["group_keys"], ["demo:log_source_stops|dc01"])

    def test_the_lookalike_needs_the_longest_gap_term(self):
        # Without its overnight gap in the baseline the badge reader's evening would look like silence.
        events = simulate.build(["office_badge_reader"])["office_badge_reader"]
        today = [dict(e, id=i, ingested_at=e["ts"]) for i, e in enumerate(events[-20:], start=1)]
        times = sorted(sources._epoch(e["ts"]) for e in today)
        end_of_day = times[-1] + 6.5 * 3600
        self.assertEqual(sources.judge(times, times[0] - 86400, end_of_day)["status"], "silent")
        everything = sorted(sources._epoch(e["ts"]) for e in events)
        self.assertEqual(sources.judge(everything, everything[0], end_of_day)["status"], "healthy")

    def test_new_scenarios_trip_no_other_rule_and_old_ones_not_this_rule(self):
        new = {"log_source_stops", "office_badge_reader"}
        for rule_id, r in self.result.items():
            with self.subTest(rule=rule_id):
                fired = set(r["detected"]) | set(r["false_positives"])
                if rule_id == "log_source_silent":
                    self.assertEqual(fired, {"log_source_stops"})
                else:
                    self.assertEqual(fired & new, set())
        self.assertIn("log_source_stops", simulate.DEMO_SCENARIOS)
        self.assertNotIn("office_badge_reader", simulate.DEMO_SCENARIOS)

    def test_coverage_is_validated(self):
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        lab = improve.noise_lab(conn)["rules"]
        row = next(r for r in lab if r["rule_id"] == "log_source_silent")
        self.assertEqual(row["verdict"], "quiet")
        cov = attack.evidence(attack.coverage(engine.load_rules(conn, enabled_only=False), {}), lab,
                              simulate.SCENARIOS)
        t = next(t for t in cov["techniques"] if t["id"] == "T1562.006")
        self.assertEqual((t["level"], t["scenarios"]), ("validated", ["log_source_stops"]))


class StorylineTests(unittest.TestCase):
    def test_demo_loop_never_goes_silent(self):
        """The storyline replayed every 10 minutes (render.yaml) for 5 hours, judged every 3 minutes throughout."""
        timeline = storyline.build(seed=7)
        loop, events, next_id = 600, [], 1
        for run_no in range(30):
            start = T0 + run_no * loop
            for offset, event, _ in timeline:
                # One ingest batch per BATCH_SECONDS of story time, as Runner sends them.
                batch = start + (offset // storyline.BATCH_SECONDS) * storyline.BATCH_SECONDS
                events.append(arrival(next_id, batch, event["source"], event["host"]))
                next_id += 1
        for minute in range(0, 30 * 10 + 30, 3):
            now = T0 + minute * 60
            seen = [e for e in events if sources._epoch(e["ts"]) <= now]
            if seen:
                self.assertEqual(run(seen, now=now), [], minute)
        self.assertEqual(run(events), [])
        # Not vacuous: by the end every storyline host has a learned cadence and is healthy between runs.
        for (source, host), g in sources._arrivals(events).items():
            times = sorted(g["by_time"])
            self.assertEqual(sources.judge(times, g["first_seen"], times[-1] + 540)["status"], "healthy", host)

    def test_a_real_storyline_run_raises_no_silence_alert(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "story.db")
            conn = connect(path)
            init_schema(conn)
            engine.seed_rules(conn)
            conn.close()
            storyline.run_once_fast(lambda: connect(path), speed=1000.0)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = 'log_source_silent'")
                                 .fetchone()[0], 0)
                self.assertGreater(db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)


class ApiTests(ServerTestCase):
    def window(self, **over):
        now = utcnow()
        return {"source": "fw", "host": "fw01", "start": iso(now), "end": iso(now + timedelta(hours=2)),
                "reason": "firmware upgrade on fw01", **over}

    def test_viewer_reads_health_and_cannot_change_windows(self):
        viewer = self.client("viewer")
        status, data, _ = viewer.get("/api/sources/health")
        self.assertEqual(status, 200)
        self.assertEqual(set(data), {"checked_at", "thresholds", "sources", "summary", "maintenance_windows"})
        self.assertEqual(viewer.post("/api/sources/maintenance", self.window())[0], 403)
        self.assertEqual(viewer.post("/api/sources/maintenance/1/end")[0], 403)
        self.assertEqual(self.client("analyst").post("/api/sources/maintenance", self.window())[0], 403)

    def test_window_goes_through_review_and_can_end_early(self):
        admin = self.client("admin")
        status, change, _ = admin.post("/api/sources/maintenance", self.window())
        self.assertEqual((status, change["kind"], change["status"]), (201, "maintenance_add", "pending"))
        self.assertEqual(admin.get("/api/sources/health")[1]["maintenance_windows"], [])  # not before review
        self.assertEqual(admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 403)
        status, reviewed, _ = second_admin(self).post(f"/api/changes/{change['id']}/review", {"decision": "approve"})
        self.assertEqual((status, reviewed["status"]), (200, "approved"), reviewed)
        windows = admin.get("/api/sources/health")[1]["maintenance_windows"]
        self.assertEqual([(w["source"], w["host"], w["active"]) for w in windows], [("fw", "fw01", True)])
        status, ended, _ = admin.post(f"/api/sources/maintenance/{windows[0]['id']}/end")
        self.assertEqual((status, ended["active"]), (200, False))
        self.assertEqual(admin.post(f"/api/sources/maintenance/{windows[0]['id']}/end")[0], 409)
        actions = [a["action"] for a in admin.get("/api/audit")[1]]
        self.assertIn("maintenance_window_added", actions)
        self.assertIn("maintenance_window_ended", actions)

    def test_bad_windows_are_refused(self):
        admin = self.client("admin")
        now = utcnow()
        for bad in (self.window(source="bad source!"), self.window(end=iso(now - timedelta(hours=1))),
                    self.window(start=iso(now + timedelta(hours=3))), self.window(end="tomorrow"),
                    self.window(end=iso(now + timedelta(days=40))), self.window(host=""),
                    self.window(reason="x")):
            with self.subTest(body=bad):
                self.assertEqual(admin.post("/api/sources/maintenance", bad)[0], 400)

    def test_health_endpoint_has_no_sources_check(self):
        checks = self.client().get("/api/health")[1]["checks"]
        self.assertNotIn("sources", checks)


if __name__ == "__main__":
    unittest.main()
