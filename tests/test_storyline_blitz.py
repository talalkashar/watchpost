"""Focused tests for storyline timeline edges and runner lifetime. Not the HTTP suite."""

import os
import tempfile
import threading
import time
import unittest

from watchpost import engine, health, storyline
from watchpost.db import connect, init_schema

EXPECTED_RULES = (
    "web_scanner", "firewall_port_sweep", "password_spray", "brute_force_ip",
    "success_after_failures", "privilege_escalation_after_login",
    "cloud_iam_change_by_new_principal", "data_exfil_volume",
)


class TimelineTests(unittest.TestCase):
    def test_build_is_deterministic_ordered_and_labeled_synthetic(self):
        first, again = storyline.build(seed=7), storyline.build(seed=7)
        self.assertEqual(first, again)
        self.assertNotEqual(first, storyline.build(seed=8))
        offsets = [offset for offset, _, _ in first]
        self.assertEqual(offsets, sorted(offsets))
        self.assertLessEqual(offsets[-1], storyline.STORY_SECONDS)
        self.assertGreater(offsets[-1], 0)
        stages = {stage for _, _, stage in first}
        self.assertEqual(stages - {"baseline"}, {name for name, _, _ in storyline.STAGES})
        for _, event, _ in first:
            self.assertEqual(event["source"], storyline.SOURCE)
            self.assertIn("SYNTHETIC", event["message"])
            self.assertTrue(event["src_ip"].startswith(("203.0.113.", "198.51.100.", "10.0.")), event["src_ip"])

    def test_stage_boundaries_and_speed_limits(self):
        bounds = (
            (-1, "recon"), (0, "recon"), (19.999, "recon"), (20, "credential_attack"),
            (47.999, "credential_attack"), (48, "foothold"), (61.999, "foothold"), (62, "escalation"),
            (79.999, "escalation"), (80, "lateral_cloud"), (95.999, "lateral_cloud"), (96, "exfiltration"),
            (10_000, "exfiltration"),
        )
        for offset, name in bounds:
            self.assertEqual(storyline.stage_at(offset), name, offset)
        storyline.build(seed=1, speed=0.1)
        storyline.build(seed=1, speed=10_000)
        for bad in (0, 0.09, 10_000.1, float("nan"), float("inf"), -1, "fast"):
            with self.assertRaises(ValueError):
                storyline.build(seed=1, speed=bad)
        with self.assertRaises(TypeError):
            storyline.build(seed=1, speed=None)

    def test_outbound_transfers_record_the_destination_they_name(self):
        firewall = [event for _, event, stage in storyline.build(seed=7)
                    if stage == "exfiltration" and event["event_type"] == "fw_allow"]
        self.assertEqual(len(firewall), 4)
        for event in firewall:
            self.assertEqual(event["src_ip"], "10.0.0.10")
            self.assertIsNone(event["user"])
            self.assertEqual(event["dest_ip"], storyline.ATTACKER_VPN_IP)
            self.assertIn(f"-> {storyline.ATTACKER_VPN_IP}:443", event["message"])
            self.assertEqual(event["bytes"], 400_000_000)


class RunnerTests(unittest.TestCase):
    def tearDown(self):
        health.unregister_check("storyline")

    def fresh_db(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "story.db")
        conn = connect(path)
        try:
            init_schema(conn)
            engine.seed_rules(conn)
        finally:
            conn.close()
        return path

    def quiet(self, runner):
        runner.stop()
        runner.join(5)
        health.unregister_check("storyline", runner.health_check)

    def test_invalid_speed_or_seed_does_not_mark_the_run_started(self):
        def opened():
            raise AssertionError("connection opened for a run that should not start")

        runner = storyline.Runner(opened)
        self.addCleanup(self.quiet, runner)
        for speed in (0, 0.09, float("nan"), "fast"):
            with self.assertRaises(ValueError):
                runner.start(speed=speed, seed=1)
        with self.assertRaises(ValueError):
            runner.start(speed=1, seed="nope")
        with self.assertRaises(TypeError):
            runner.start(speed=None, seed=1)
        self.assertFalse(runner.status["running"])
        self.assertIsNone(runner.status["error"])
        self.assertIsNone(runner._thread)
        self.assertEqual(runner.health_check()[0], "ok")

    def test_idle_stop_does_not_stick_and_a_second_start_is_refused(self):
        runner = storyline.Runner(lambda: None)
        self.addCleanup(self.quiet, runner)
        runner.stop()
        self.assertTrue(runner.start(speed=0.1, seed=1, started_by="op"))
        self.assertFalse(runner.start(speed=1, seed=2))
        self.assertTrue(runner.status["running"])
        self.assertEqual(runner.status["speed"], 0.1)
        self.assertEqual(runner.status["seed"], 1)
        runner.stop()
        runner.join(5)
        self.assertFalse(runner.status["running"])
        self.assertTrue(runner.start(speed=0.1, seed=2))
        self.assertTrue(runner.status["running"])

    def test_a_failed_open_stays_degraded_until_the_next_start(self):
        def boom():
            raise RuntimeError("db down")

        runner = storyline.Runner(boom)
        self.addCleanup(self.quiet, runner)
        self.assertTrue(runner.start(speed=1000, seed=1))
        runner.join(5)
        snap = runner.snapshot()
        self.assertFalse(snap["running"])
        self.assertIn("db down", snap["error"])
        self.assertEqual(runner.health_check()[0], "degraded")
        registered = health._COMPONENT_CHECKS.get("storyline")
        self.assertIsNotNone(registered)
        self.assertEqual(registered()[0], "degraded")

    def test_fast_replay_finishes_synthetic_and_fires_the_attack_rules(self):
        path = self.fresh_db()
        snap = storyline.run_once_fast(lambda: connect(path), seed=7, speed=10_000)
        self.assertIsNone(snap["error"], snap)
        self.assertFalse(snap["running"])
        self.assertEqual(snap["progress"], 1.0)
        self.assertEqual(snap["stage"], "exfiltration")
        self.assertGreater(snap["events_sent"], 100)
        self.assertNotIn("storyline", health._COMPONENT_CHECKS)
        conn = connect(path)
        try:
            synthetic = conn.execute(
                "SELECT COUNT(*) FROM events WHERE source = ? AND synthetic = 1", (storyline.SOURCE,)
            ).fetchone()[0]
            real = conn.execute("SELECT COUNT(*) FROM events WHERE synthetic = 0").fetchone()[0]
            fired = {row[0] for row in conn.execute("SELECT DISTINCT rule_id FROM alerts")}
            exfil = {row[0] for row in conn.execute(
                "SELECT group_key FROM alerts WHERE rule_id = 'data_exfil_volume'")}
            actions = [row[0] for row in conn.execute(
                "SELECT action FROM audit_log WHERE action LIKE 'storyline_%'")]
        finally:
            conn.close()
        self.assertEqual(synthetic, snap["events_sent"])
        self.assertEqual(real, 0)
        for rule in EXPECTED_RULES:
            self.assertIn(rule, fired, sorted(fired))
        self.assertEqual(exfil, {storyline.ROGUE_PRINCIPAL, "10.0.0.10"})
        self.assertEqual(actions, ["storyline_finished"])

    def test_run_once_fast_stops_a_replay_that_outlasts_the_timeout(self):
        path = self.fresh_db()
        snap = storyline.run_once_fast(lambda: connect(path), seed=3, speed=0.1, timeout=0.05)
        self.assertFalse(snap["running"])
        self.assertIsNone(snap["error"], snap)
        self.assertLess(snap["events_sent"], 10)
        self.assertNotEqual(snap["progress"], 1.0)
        self.assertNotIn("storyline", health._COMPONENT_CHECKS)
        conn = connect(path)
        try:
            actions = [row[0] for row in conn.execute(
                "SELECT action FROM audit_log WHERE action LIKE 'storyline_%'")]
        finally:
            conn.close()
        self.assertEqual(actions, ["storyline_stopped"])


class DemoLoopTests(unittest.TestCase):
    def tearDown(self):
        health.unregister_check("storyline")

    def test_start_if_enabled_is_off_at_zero_or_below(self):
        class App:
            class config:
                demo_loop_minutes = 0
            storyline = None

        self.assertIsNone(storyline.start_if_enabled(App()))
        App.config.demo_loop_minutes = -5
        self.assertIsNone(storyline.start_if_enabled(App()))

    def test_zero_minutes_does_not_spin_and_a_bad_speed_is_degraded(self):
        calls = []

        class Counting:
            def __init__(self):
                self.status = {"running": False, "error": None}

            def start(self, **_kwargs):
                calls.append("start")
                return True

            def stop(self):
                calls.append("stop")

        idle = Counting()
        loop = storyline.DemoLoop(idle, minutes=0, speed=1)
        loop.start()
        loop._thread.join(1)
        self.assertFalse(loop._thread.is_alive())
        self.assertEqual(calls, [])

        def opened():
            raise AssertionError("bad speed must not open a connection")

        runner = storyline.Runner(opened)
        loop = storyline.DemoLoop(runner, minutes=30, speed=0)
        self.addCleanup(loop.stop)
        loop.start()
        deadline = time.time() + 2
        while time.time() < deadline and not runner.status["error"]:
            time.sleep(0.01)
        loop.stop()
        loop._thread.join(2)
        self.assertFalse(loop._thread.is_alive())
        self.assertFalse(runner.status["running"])
        self.assertIn("speed", runner.status["error"])
        self.assertEqual(runner.health_check()[0], "degraded")

    def test_stop_waits_until_the_overlapping_start_finishes(self):
        class Overlap:
            def __init__(self):
                self.entered = threading.Event()
                self.release = threading.Event()
                self.flag = threading.Event()
                self.status = {"running": False, "error": None}

            def start(self, **_kwargs):
                self.entered.set()
                if not self.release.wait(2):
                    raise AssertionError("start was not released")
                self.flag.clear()
                self.status["running"] = True
                return True

            def stop(self):
                self.flag.set()
                self.status["running"] = False

        runner = Overlap()
        loop = storyline.DemoLoop(runner, minutes=60, speed=1)
        self.addCleanup(loop.stop)
        self.addCleanup(runner.release.set)
        loop.start()
        self.assertTrue(runner.entered.wait(2))
        done = threading.Event()
        threading.Thread(target=lambda: (loop.stop(), done.set()), daemon=True).start()
        self.assertFalse(done.wait(0.2))
        runner.release.set()
        self.assertTrue(done.wait(2))
        loop._thread.join(2)
        self.assertFalse(loop._thread.is_alive())
        self.assertTrue(runner.flag.is_set())
