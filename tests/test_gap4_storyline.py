"""Edge cases for storyline.build, stage_at, Runner, DemoLoop, and start_if_enabled.

Existing tests cover a deterministic seed-7 timeline, three stage lookups, speed 0,
and a disabled demo loop. These tests cover the boundaries around that.
"""

import threading
import time
import unittest

from watchpost import health, storyline
from watchpost.db import connect, init_schema


class _Conn:
    """Sqlite connection created on the runner thread. audit() needs a real connection."""

    def __init__(self):
        self.raw = connect(":memory:")
        init_schema(self.raw)
        self.closed = False

    def close(self):
        self.closed = True
        self.raw.close()

    def __getattr__(self, name):
        return getattr(self.raw, name)


def _wait(fn, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return True
        time.sleep(0.01)
    return False


class BuildEdgeTests(unittest.TestCase):
    def test_inclusive_speed_bounds_do_not_change_the_timeline(self):
        baseline = storyline.build(seed=7, speed=1)
        self.assertEqual(storyline.build(seed=7, speed=0.1), baseline)
        self.assertEqual(storyline.build(seed=7, speed=10000), baseline)
        # float(True) is 1.0, so the library accepts it; the HTTP API rejects bools.
        self.assertEqual(storyline.build(seed=7, speed=True), baseline)

    def test_speed_rejects_out_of_range_and_non_numeric(self):
        for speed in (0.099999999999, -0.1, 10000.1, False, float("nan"), float("inf"), float("-inf")):
            with self.subTest(speed=speed):
                with self.assertRaises(ValueError):
                    storyline.build(seed=1, speed=speed)
        for speed in (None, "", "fast"):
            with self.subTest(speed=speed):
                with self.assertRaises((TypeError, ValueError)):
                    storyline.build(seed=1, speed=speed)

    def test_string_seed_is_deterministic_and_time_ordered(self):
        first = storyline.build(seed="alpha", speed=1)
        self.assertEqual(first, storyline.build(seed="alpha", speed=2))
        self.assertNotEqual(first, storyline.build(seed="beta"))
        offsets = [offset for offset, _, _ in first]
        self.assertEqual(offsets, sorted(offsets))
        self.assertGreaterEqual(offsets[0], 0)
        self.assertLessEqual(offsets[-1], storyline.STORY_SECONDS)
        for offset, _event, stage in first:
            if stage != "baseline":
                self.assertEqual(storyline.stage_at(offset), stage, offset)


class StageAtEdgeTests(unittest.TestCase):
    def test_negative_offset_and_exact_stage_boundaries(self):
        self.assertEqual(storyline.stage_at(-1), "recon")
        self.assertEqual(storyline.stage_at(-0.001), "recon")
        boundaries = {
            19.999: "recon",
            20: "credential_attack",
            47.999: "credential_attack",
            48: "foothold",
            61.999: "foothold",
            62: "escalation",
            79.999: "escalation",
            80: "lateral_cloud",
            95.999: "lateral_cloud",
            96: "exfiltration",
        }
        for offset, name in boundaries.items():
            with self.subTest(offset=offset):
                self.assertEqual(storyline.stage_at(offset), name)
        order = [name for name, _, _ in storyline.STAGES]
        seen = [order.index(storyline.stage_at(offset)) for offset in (-1, *boundaries)]
        self.assertEqual(seen, sorted(seen))

    def test_non_numeric_offset_raises(self):
        for offset in (None, "", "20"):
            with self.subTest(offset=offset):
                with self.assertRaises(TypeError):
                    storyline.stage_at(offset)


class RunnerEdgeTests(unittest.TestCase):
    def _runner(self, open_conn):
        runner = storyline.Runner(open_conn)
        self.addCleanup(self._halt, runner)
        self.addCleanup(health.unregister_check, "storyline", runner.health_check)
        return runner

    @staticmethod
    def _halt(runner):
        runner.stop()
        runner.join(timeout=5)

    def test_idle_health_and_snapshot_is_a_copy(self):
        runner = self._runner(lambda: _Conn())
        status, message, guidance, detail = runner.health_check()
        self.assertEqual((status, message, guidance), ("ok", "storyline idle", None))
        self.assertEqual(detail, {"running": False, "stage": None, "events_sent": 0})
        snap = runner.snapshot()
        self.assertEqual(snap, runner.status)
        self.assertIsNot(snap, runner.status)
        snap["running"] = True
        snap["events_sent"] = 9
        self.assertFalse(runner.status["running"])
        self.assertEqual(runner.status["events_sent"], 0)
        runner.join(timeout=0)

    def test_second_start_refused_and_stop_sends_nothing(self):
        hold = threading.Event()
        opened = {}

        def open_conn():
            hold.wait(timeout=5)
            opened["conn"] = _Conn()
            return opened["conn"]

        runner = self._runner(open_conn)
        self.assertTrue(runner.start(speed=0.1, seed=4, started_by="edge"))
        self.assertTrue(_wait(lambda: runner._thread is not None and runner._thread.is_alive()))
        self.assertFalse(runner.start(speed=0.1, seed=5))
        status, message, guidance, detail = runner.health_check()
        self.assertEqual((status, message, guidance), ("ok", "storyline running", None))
        self.assertEqual(detail["running"], True)
        self.assertEqual(detail["stage"], "recon")
        self.assertEqual(detail["events_sent"], 0)
        runner.join(timeout=0)
        self.assertTrue(runner._thread.is_alive())
        hold.set()
        runner.stop()
        runner.join(timeout=5)
        self.assertFalse(runner._thread.is_alive())
        self.assertFalse(runner.status["running"])
        self.assertEqual(runner.status["events_sent"], 0)
        self.assertEqual(runner.status["alerts_created"], 0)
        self.assertIsNone(runner.status["error"])
        self.assertLess(runner.status["progress"], 1)
        self.assertIsNotNone(runner.status["finished_at"])
        self.assertEqual(runner.status["seed"], 4)
        self.assertEqual(runner.status["started_by"], "edge")
        self.assertTrue(opened["conn"].closed)

    def test_bad_speed_degrades_health_and_next_start_clears_it(self):
        release = threading.Event()
        calls = {"n": 0}

        def open_conn():
            calls["n"] += 1
            if calls["n"] > 1:
                release.wait(timeout=5)
            return _Conn()

        runner = self._runner(open_conn)
        self.assertTrue(runner.start(speed=0.05, seed=3, started_by="edge"))
        runner.join(timeout=5)
        self.assertFalse(runner.status["running"])
        self.assertEqual(runner.status["error"], "ValueError: speed must be between 0.1 and 10000")
        status, message, guidance, detail = runner.health_check()
        self.assertEqual(status, "degraded")
        self.assertIn(runner.status["error"], message)
        self.assertIn("synthetic", guidance)
        self.assertEqual(detail, {"started_at": runner.status["started_at"]})

        self.assertTrue(runner.start(speed=0.1, seed=1.5))
        self.assertIsNone(runner.status["error"])
        self.assertEqual(runner.status["seed"], 1)
        self.assertEqual(runner.status["speed"], 0.1)
        self.assertTrue(runner.status["running"])
        runner.stop()
        release.set()
        runner.join(timeout=5)
        self.assertIsNone(runner.status["error"])
        self.assertEqual(runner.status["events_sent"], 0)

    def test_bad_speed_or_seed_raises_before_a_thread_starts(self):
        runner = self._runner(lambda: _Conn())
        with self.assertRaises(TypeError):
            runner.start(speed=None, seed=1)
        with self.assertRaises(ValueError):
            runner.start(speed="fast", seed=1)
        with self.assertRaises(ValueError):
            runner.start(speed=1, seed="nope")
        with self.assertRaises(TypeError):
            runner.start(speed=1, seed=None)
        self.assertFalse(runner.status["running"])
        self.assertIsNone(runner._thread)
        self.assertIsNone(runner.status["error"])
        self.assertIsNone(runner.status["started_at"])

    def test_open_conn_failure_finishes_with_an_error(self):
        def open_conn():
            raise RuntimeError("db down")

        runner = self._runner(open_conn)
        self.assertTrue(runner.start(speed=1, seed=1, started_by="edge"))
        runner.join(timeout=5)
        self.assertFalse(runner.status["running"])
        self.assertEqual(runner.status["error"], "RuntimeError: db down")
        self.assertIsNotNone(runner.status["finished_at"])
        self.assertEqual(runner.health_check()[0], "degraded")
        self.assertEqual(runner.status["events_sent"], 0)


class _FakeRunner:
    def __init__(self):
        self.starts = []
        self.stops = 0

    def start(self, speed=1.0, seed=7, started_by="system"):
        self.starts.append((speed, seed, started_by))
        return True

    def stop(self):
        self.stops += 1


class DemoLoopEdgeTests(unittest.TestCase):
    def _stop(self, loop):
        loop.stop()
        loop._thread.join(timeout=2)

    def test_stop_signals_the_runner_and_start_is_once(self):
        fake = _FakeRunner()
        loop = storyline.DemoLoop(fake, minutes=60, speed=2)
        self.addCleanup(self._stop, loop)
        self.assertIs(loop.start(), loop)
        self.assertTrue(_wait(lambda: fake.starts))
        with self.assertRaises(RuntimeError):
            loop.start()
        loop.stop()
        loop._thread.join(timeout=2)
        self.assertFalse(loop._thread.is_alive())
        self.assertEqual(fake.stops, 1)
        self.assertEqual(fake.starts, [(2, 7, "demo-loop")])

    def test_start_if_enabled_rejects_missing_or_non_positive_minutes(self):
        class Bare:
            storyline = None

        with self.assertRaises(AttributeError):
            storyline.start_if_enabled(Bare())

        class Missing:
            class config:
                pass

            storyline = None

        self.assertIsNone(storyline.start_if_enabled(Missing()))

        class Negative:
            class config:
                demo_loop_minutes = -3

            storyline = None

        self.assertIsNone(storyline.start_if_enabled(Negative()))

        class Text:
            class config:
                demo_loop_minutes = "5"

            storyline = None

        with self.assertRaises(TypeError):
            storyline.start_if_enabled(Text())

    def test_start_if_enabled_starts_a_loop_at_the_configured_speed(self):
        fake = _FakeRunner()

        class App:
            class config:
                demo_loop_minutes = 45
                demo_loop_speed = 8

            storyline = fake

        loop = storyline.start_if_enabled(App())
        self.addCleanup(self._stop, loop)
        self.assertIsInstance(loop, storyline.DemoLoop)
        self.assertEqual((loop.minutes, loop.speed), (45, 8))
        self.assertTrue(_wait(lambda: fake.starts))
        self.assertEqual(fake.starts[0], (8, 7, "demo-loop"))

    def test_start_if_enabled_defaults_speed_when_unset(self):
        fake = _FakeRunner()

        class App:
            class config:
                demo_loop_minutes = 45

            storyline = fake

        loop = storyline.start_if_enabled(App())
        self.addCleanup(self._stop, loop)
        self.assertEqual(loop.speed, 1.0)
        self.assertTrue(_wait(lambda: fake.starts))
        self.assertEqual(fake.starts[0], (1.0, 7, "demo-loop"))
