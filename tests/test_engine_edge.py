"""Open-alert matching: window edges, rescans, and the synthetic flag on an extended alert."""

import json
import unittest
from datetime import datetime, timedelta, timezone

from watchpost import engine
from watchpost.db import connect, init_schema, iso
from watchpost.normalize import parse_payload

RULE = "brute_force_ip"  # seeded threshold 10, window_seconds 300
IP = "203.0.113.50"
WINDOW = 300
T0 = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)


def burst(at, n=10, ip=IP, user="alice"):
    ts = iso(at)
    return [{"ts": ts, "type": "login_failed", "user": user, "src_ip": ip} for _ in range(n)]


class EngineEdgeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def ingest(self, events, synthetic=False):
        normalized, rejections = parse_payload(json.dumps(events), "json", "auth01")
        self.assertEqual(rejections, [])
        return engine.ingest(self.conn, normalized, rejections, "auth01", "json", "test", synthetic)

    def alerts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT id, first_seen, last_seen, event_count, synthetic, status FROM alerts"
            " WHERE rule_id = ? ORDER BY first_seen, id", (RULE,))]

    def test_later_open_alert_does_not_absorb_an_earlier_burst(self):
        self.ingest(burst(T0 + timedelta(hours=2)))
        self.ingest(burst(T0))
        rows = self.alerts()
        self.assertEqual([r["event_count"] for r in rows], [10, 10])
        self.assertEqual(rows[0]["first_seen"], iso(T0))
        self.assertEqual(rows[1]["first_seen"], iso(T0 + timedelta(hours=2)))
        # More failures beside the early burst extend that alert, not the newer one.
        self.ingest(burst(T0 + timedelta(seconds=30), n=5))
        rows = self.alerts()
        self.assertEqual([r["event_count"] for r in rows], [15, 10])
        self.assertEqual(rows[1]["first_seen"], iso(T0 + timedelta(hours=2)))

    def test_later_burst_after_an_earlier_alert_stays_separate(self):
        self.ingest(burst(T0))
        self.ingest(burst(T0 + timedelta(hours=2)))
        rows = self.alerts()
        self.assertEqual([r["event_count"] for r in rows], [10, 10])
        self.assertEqual(rows[0]["last_seen"], iso(T0))

    def test_gap_equal_to_window_still_merges(self):
        later = T0 + timedelta(seconds=WINDOW)
        self.ingest(burst(later))
        self.ingest(burst(T0))
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 20)
        self.assertEqual((rows[0]["first_seen"], rows[0]["last_seen"]), (iso(T0), iso(later)))

    def test_gap_just_over_window_stays_two_alerts(self):
        later = T0 + timedelta(seconds=WINDOW + 1)
        self.ingest(burst(later))
        self.ingest(burst(T0))
        rows = self.alerts()
        self.assertEqual([r["event_count"] for r in rows], [10, 10])
        self.assertEqual(rows[0]["last_seen"], iso(T0))
        self.assertEqual(rows[1]["first_seen"], iso(later))

    def test_nearby_burst_extends_the_open_alert(self):
        self.ingest(burst(T0 + timedelta(seconds=60)))
        self.ingest(burst(T0))
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 20)
        self.assertEqual(rows[0]["status"], "open")

    def test_rescan_does_not_duplicate_evidence(self):
        self.ingest(burst(T0))
        before = self.alerts()
        run = engine.run_detection(self.conn, trigger="rescan", start=iso(T0), end=iso(T0))
        self.assertEqual(run["status"], "ok")
        self.assertEqual((run["alerts_created"], run["alerts_updated"]), (0, 0))
        rows = self.alerts()
        self.assertEqual(rows, before)
        attached = self.conn.execute(
            "SELECT COUNT(*) FROM alert_events WHERE alert_id = ?", (rows[0]["id"],)).fetchone()[0]
        self.assertEqual(attached, 10)

    def test_resolved_alert_is_not_reopened_by_a_new_burst(self):
        # The new burst is inside the window, so the finding includes the old events.
        # Those stay on the resolved alert; detection opens a new one instead of extending it.
        self.ingest(burst(T0))
        self.conn.execute("UPDATE alerts SET status = 'resolved' WHERE rule_id = ?", (RULE,))
        self.ingest(burst(T0 + timedelta(seconds=60)))
        rows = self.alerts()
        self.assertEqual([(r["status"], r["event_count"]) for r in rows],
                         [("resolved", 10), ("open", 20)])

    def test_real_evidence_clears_synthetic_on_an_open_alert(self):
        self.ingest(burst(T0), synthetic=True)
        self.assertEqual(self.alerts()[0]["synthetic"], 1)
        self.ingest(burst(T0 + timedelta(seconds=60)), synthetic=False)
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 20)
        self.assertEqual(rows[0]["synthetic"], 0)

    def test_more_synthetic_evidence_keeps_the_flag(self):
        self.ingest(burst(T0), synthetic=True)
        self.ingest(burst(T0 + timedelta(seconds=60)), synthetic=True)
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["event_count"], rows[0]["synthetic"]), (20, 1))

    def test_synthetic_evidence_does_not_mark_a_real_alert(self):
        self.ingest(burst(T0), synthetic=False)
        self.ingest(burst(T0 + timedelta(seconds=60)), synthetic=True)
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["event_count"], rows[0]["synthetic"]), (20, 0))
