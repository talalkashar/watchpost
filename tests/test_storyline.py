import time
import unittest

from watchpost import storyline
from watchpost.db import connect
from .helpers import ServerTestCase


class TimelineTests(unittest.TestCase):
    def test_build_is_deterministic_ordered_and_synthetic_only(self):
        a, b = storyline.build(seed=7), storyline.build(seed=7)
        self.assertEqual(a, b)
        self.assertNotEqual(a, storyline.build(seed=8))
        offsets = [o for o, _, _ in a]
        self.assertEqual(offsets, sorted(offsets))
        self.assertLessEqual(offsets[-1], storyline.STORY_SECONDS)
        for _, event, _ in a:
            self.assertEqual(event["source"], storyline.SOURCE)
            self.assertTrue(event["src_ip"].startswith(("203.0.113.", "198.51.100.", "10.0.")), event["src_ip"])
        self.assertEqual({s for _, _, s in a} - {"baseline"}, {name for name, _, _ in storyline.STAGES})

    def test_stage_lookup_and_speed_validation(self):
        self.assertEqual(storyline.stage_at(0), "recon")
        self.assertEqual(storyline.stage_at(25), "credential_attack")
        self.assertEqual(storyline.stage_at(200), "exfiltration")
        with self.assertRaises(ValueError):
            storyline.build(seed=1, speed=0)


def _wait(fn, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(0.05)
    return False


class StorylineApiTests(ServerTestCase):
    def test_fast_replay_produces_alerts_and_one_multistage_incident(self):
        admin = self.client("admin")
        status, data, _ = admin.post("/api/storyline/start", {"speed": 2000})
        self.assertEqual(status, 202, data)
        self.assertTrue(data["running"])
        self.assertTrue(_wait(lambda: not admin.get("/api/storyline/status")[1]["running"]))
        status, final, _ = admin.get("/api/storyline/status")
        self.assertIsNone(final["error"], final)
        self.assertEqual(final["progress"], 1.0)
        self.assertEqual(final["stage"], "exfiltration")
        self.assertGreater(final["events_sent"], 100)
        self.assertTrue(final["synthetic"])
        self.assertEqual(len(final["stages"]), 6)

        _, alerts, _ = admin.get("/api/alerts?limit=200")
        fired = {a["rule_id"] for a in alerts}
        for rule in ("web_scanner", "firewall_port_sweep", "password_spray", "brute_force_ip",
                     "success_after_failures", "privilege_escalation_after_login",
                     "cloud_iam_change_by_new_principal", "data_exfil_volume"):
            self.assertIn(rule, fired, f"{rule} missing from {sorted(fired)}")

        _, incidents, _ = admin.get("/api/incidents")
        items = incidents if isinstance(incidents, list) else incidents["items"]
        self.assertTrue(any(len(i.get("stages") or []) >= 3 for i in items), [i["title"] for i in items])

        conn = connect(self.db_path)
        try:
            n_real = conn.execute("SELECT count(*) FROM events WHERE source = ? AND synthetic = 0",
                                  (storyline.SOURCE,)).fetchone()[0]
            n_syn = conn.execute("SELECT count(*) FROM events WHERE source = ? AND synthetic = 1",
                                 (storyline.SOURCE,)).fetchone()[0]
            actions = [r[0] for r in conn.execute("SELECT action FROM audit_log WHERE action LIKE 'storyline_%'")]
        finally:
            conn.close()
        self.assertEqual(n_real, 0)
        self.assertEqual(n_syn, final["events_sent"])
        self.assertEqual(sorted(actions), ["storyline_finished", "storyline_started"])

    def test_single_runner_stop_and_permissions(self):
        admin, analyst, viewer = self.client("admin"), self.client("analyst"), self.client("viewer")
        self.assertEqual(analyst.post("/api/storyline/start", {})[0], 403)
        self.assertEqual(viewer.post("/api/storyline/start", {})[0], 403)
        self.assertEqual(viewer.post("/api/storyline/stop", {})[0], 403)
        self.assertEqual(viewer.get("/api/storyline/status")[0], 200)
        self.assertEqual(admin.post("/api/storyline/start", {"speed": "fast"})[0], 400)
        self.assertEqual(admin.post("/api/storyline/start", {"speed": 1, "seed": 1.5})[0], 400)
        self.assertEqual(admin.post("/api/storyline/start", {"speed": 1})[0], 202)
        self.assertEqual(admin.post("/api/storyline/start", {"speed": 1})[0], 409)
        status, viewer_view, _ = analyst.get("/api/storyline/status")
        self.assertEqual(status, 200)
        self.assertTrue(viewer_view["running"])
        self.assertEqual(admin.post("/api/storyline/stop")[0], 200)
        self.assertTrue(_wait(lambda: not admin.get("/api/storyline/status")[1]["running"]))
        health = admin.get("/api/health")[1]
        self.assertEqual(health["checks"]["storyline"], "ok")
        # After a stop the runner is free again.
        self.assertEqual(admin.post("/api/storyline/start", {"speed": 5000})[0], 202)
        self.assertTrue(_wait(lambda: not admin.get("/api/storyline/status")[1]["running"]))


class DemoLoopTests(unittest.TestCase):
    def test_start_if_enabled_respects_config(self):
        class App:
            class config:
                demo_loop_minutes = 0
            storyline = None
        self.assertIsNone(storyline.start_if_enabled(App()))
