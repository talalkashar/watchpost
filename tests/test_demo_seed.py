"""Demo load and simulate refuse a JSON boolean seed.

Seed 7 stays. JSON true, JSON false, and a string seed are 400
seed must be an integer and store nothing. Storyline already refuses
a boolean seed.
"""

import inspect
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect
from watchpost.server import demo_load, demo_simulate, storyline_start

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
MESSAGE = "seed must be an integer"


class DemoSeedTests(ServerTestCase):
    def _counts(self):
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        batches = conn.execute("SELECT COUNT(*) FROM ingest_batches").fetchone()[0]
        loaded = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'demo_loaded'").fetchone()[0]
        started = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'storyline_started'").fetchone()[0]
        return events, batches, loaded, started

    def test_seed_seven_loads_and_one_scenario_replays(self):
        admin = self.client("admin")
        analyst = self.client("analyst")
        status, loaded, _ = admin.post("/api/demo/load", {"seed": 7})
        self.assertEqual(status, 200, loaded)
        accepted = sum(row["accepted"] for row in loaded.values())
        self.assertGreater(accepted, 0)
        events, batches, demo_rows, _ = self._counts()
        self.assertEqual(events, accepted)
        self.assertGreater(batches, 0)
        self.assertEqual(demo_rows, 1)

        before = events
        status, sim, _ = analyst.post("/api/demo/simulate", {"scenario": "brute_force", "seed": 7})
        self.assertEqual(status, 201, sim)
        self.assertGreater(sim["accepted"], 0)
        events, _, _, _ = self._counts()
        self.assertEqual(events, before + sim["accepted"])
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        plain = conn.execute("SELECT COUNT(*) FROM events WHERE synthetic = 0").fetchone()[0]
        self.assertEqual(plain, 0)

        status, omitted, _ = analyst.post("/api/demo/simulate", {"scenario": "noisy_scanner"})
        self.assertEqual(status, 201, omitted)
        self.assertGreater(omitted["accepted"], 0)

    def test_boolean_and_string_seeds_store_nothing(self):
        admin = self.client("admin")
        analyst = self.client("analyst")
        self.assertEqual(self._counts(), (0, 0, 0, 0))
        for seed in (True, False, "7"):
            with self.subTest(seed=seed):
                status, body, _ = admin.post("/api/demo/load", {"seed": seed, "force": True})
                self.assertEqual(status, 400, body)
                self.assertEqual(body["error"], MESSAGE)
                status, body, _ = analyst.post(
                    "/api/demo/simulate", {"scenario": "brute_force", "seed": seed})
                self.assertEqual(status, 400, body)
                self.assertEqual(body["error"], MESSAGE)
                status, body, _ = admin.post("/api/storyline/start", {"speed": 1, "seed": seed})
                self.assertEqual(status, 400, body)
                self.assertEqual(body["error"], MESSAGE)
        self.assertEqual(self._counts(), (0, 0, 0, 0))
        running = admin.get("/api/storyline/status")[1]
        self.assertFalse(running["running"])

        status, loaded, _ = admin.post("/api/demo/load", {"seed": 7})
        self.assertEqual(status, 200, loaded)
        events, batches, demo_rows, started = self._counts()
        self.assertGreater(events, 0)
        for seed in (True, False):
            status, body, _ = admin.post("/api/demo/load", {"seed": seed, "force": True})
            self.assertEqual(status, 400, body)
            self.assertEqual(body["error"], MESSAGE)
        self.assertEqual(self._counts(), (events, batches, demo_rows, started))

    def test_bool_is_excluded_before_build(self):
        for fn in (demo_load, demo_simulate, storyline_start):
            source = inspect.getsource(fn)
            self.assertIn("isinstance(seed, bool)", source)
            self.assertLess(
                source.index("isinstance(seed, bool)"),
                source.index('raise ApiError(400, "seed must be an integer")'))
        for fn in (demo_load, demo_simulate):
            source = inspect.getsource(fn)
            self.assertLess(source.index("isinstance(seed, bool)"), source.index("simulate.build"))
            self.assertNotIn("int(", source)

    def test_docs_name_the_boolean_seed(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("Seed `7`", text)
            self.assertIn("JSON `true`", text)
            self.assertIn("JSON `false`", text)
            self.assertIn("string seed", text)
            self.assertIn("`seed must be an integer`", text)
            self.assertIn("store nothing", text)
            self.assertIn("boolean seed", text)


if __name__ == "__main__":
    import unittest
    unittest.main()
