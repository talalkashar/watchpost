"""A detection run publishes at most the newest 100 alerts and 100 incidents by id.

Frames stay in id order. Health carries alerts_omitted and incidents_omitted
(0 when that set fits, and 0 on a failing run, which publishes neither).
The per-frame fields stay. A publish with no subscriber sends nothing.
A failed publish does not fail detection.
"""

import queue
import unittest
from pathlib import Path
from unittest import mock

from watchpost import stream
from watchpost.db import connect, init_schema
from watchpost.engine import STREAM_DETECTION_LIMIT, _publish_detection

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
STARTED = "2026-09-02T00:00:00.000Z"
TOUCHED = "2026-09-02T00:00:01.000Z"
OLD = "2026-09-01T00:00:00.000Z"
OK = {"status": "ok", "error": None}


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alert(conn, updated_at=TOUCHED, created_at=None):
    created_at = updated_at if created_at is None else created_at
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("lab_rule", 1, "203.0.113.10", "low", "[SYNTHETIC] lab alert", "[SYNTHETIC] drill",
         "open", TOUCHED, TOUCHED, 1, 1, created_at, updated_at))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_incident(conn, updated_at=TOUCHED):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("[SYNTHETIC] lab incident", "low", "open", TOUCHED, TOUCHED, "{}", "[]",
         1, 1, updated_at, updated_at))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


class DetectionStreamOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        self.sub = stream.BROKER.subscribe()
        self.addCleanup(stream.BROKER.unsubscribe, self.sub)

    def frames(self):
        out = []
        while True:
            try:
                out.append(self.sub.get(timeout=0.01))
            except queue.Empty:
                return out

    def test_the_lowest_alert_id_is_the_one_left_out(self):
        ids = [add_alert(self.conn) for _ in range(STREAM_DETECTION_LIMIT + 1)]
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][0], "health")
        self.assertEqual(frames[0][1], {
            "partial": True, "checks": {"detection": "ok"}, "error": None,
            "alerts_omitted": 1, "incidents_omitted": 0,
        })
        alerts = [data for kind, data in frames if kind == "alert"]
        self.assertEqual([row["id"] for row in alerts], ids[1:])
        self.assertNotIn(ids[0], [row["id"] for row in alerts])
        self.assertEqual(alerts[0]["change"], "created")
        self.assertEqual(alerts[0]["rule_id"], "lab_rule")
        self.assertEqual(alerts[0]["group_key"], "203.0.113.10")
        self.assertEqual(alerts[0]["status"], "open")
        self.assertIn("[SYNTHETIC]", alerts[0]["title"])
        self.assertTrue(alerts[0]["synthetic"])
        self.assertEqual([kind for kind, _ in frames if kind == "incident"], [])

    def test_an_updated_alert_keeps_change_when_a_lower_id_is_left_out(self):
        dropped = add_alert(self.conn)
        kept = [add_alert(self.conn) for _ in range(STREAM_DETECTION_LIMIT - 1)]
        updated = add_alert(self.conn, created_at=OLD)
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][1]["alerts_omitted"], 1)
        alerts = [data for kind, data in frames if kind == "alert"]
        self.assertEqual([row["id"] for row in alerts], kept + [updated])
        self.assertNotIn(dropped, [row["id"] for row in alerts])
        self.assertEqual(alerts[-1]["change"], "updated")
        self.assertEqual(alerts[0]["change"], "created")

    def test_an_untouched_alert_is_not_a_frame_and_is_not_omitted(self):
        kept = [add_alert(self.conn) for _ in range(STREAM_DETECTION_LIMIT)]
        older = add_alert(self.conn, updated_at=OLD, created_at=OLD)
        self.assertGreater(older, kept[-1])
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][1]["alerts_omitted"], 0)
        self.assertEqual(frames[0][1]["incidents_omitted"], 0)
        alerts = [data for kind, data in frames if kind == "alert"]
        self.assertEqual([row["id"] for row in alerts], kept)
        self.assertNotIn(older, [row["id"] for row in alerts])

    def test_a_short_alert_list_and_an_exact_cap_omit_zero(self):
        one = add_alert(self.conn)
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][1]["alerts_omitted"], 0)
        self.assertEqual(frames[0][1]["incidents_omitted"], 0)
        self.assertEqual([data["id"] for kind, data in frames if kind == "alert"], [one])
        self.conn.execute(
            "UPDATE alerts SET updated_at = ?, created_at = ? WHERE id = ?", (OLD, OLD, one))
        exact = [add_alert(self.conn) for _ in range(STREAM_DETECTION_LIMIT)]
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][1]["alerts_omitted"], 0)
        self.assertEqual(frames[0][1]["incidents_omitted"], 0)
        shown = [data["id"] for kind, data in frames if kind == "alert"]
        self.assertEqual(shown, exact)
        self.assertNotIn(one, shown)

    def test_the_lowest_incident_id_is_the_one_left_out(self):
        ids = [add_incident(self.conn) for _ in range(STREAM_DETECTION_LIMIT + 1)]
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][1]["alerts_omitted"], 0)
        self.assertEqual(frames[0][1]["incidents_omitted"], 1)
        incidents = [data for kind, data in frames if kind == "incident"]
        self.assertEqual([row["id"] for row in incidents], ids[1:])
        self.assertNotIn(ids[0], [row["id"] for row in incidents])
        self.assertEqual(incidents[0]["title"], "[SYNTHETIC] lab incident")
        self.assertEqual(incidents[0]["severity"], "low")
        self.assertEqual(incidents[0]["entities"], "{}")
        self.assertEqual(incidents[0]["stages"], "[]")
        self.assertEqual(incidents[0]["synthetic"], 1)
        self.assertEqual([kind for kind, _ in frames if kind == "alert"], [])

    def test_alerts_then_incidents_when_both_caps_leave_one_out(self):
        alerts = [add_alert(self.conn) for _ in range(STREAM_DETECTION_LIMIT + 1)]
        incidents = [add_incident(self.conn) for _ in range(STREAM_DETECTION_LIMIT + 1)]
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames[0][1]["alerts_omitted"], 1)
        self.assertEqual(frames[0][1]["incidents_omitted"], 1)
        kinds = [kind for kind, _ in frames]
        self.assertEqual(kinds[0], "health")
        self.assertEqual(kinds[1:STREAM_DETECTION_LIMIT + 1], ["alert"] * STREAM_DETECTION_LIMIT)
        self.assertEqual(kinds[STREAM_DETECTION_LIMIT + 1:], ["incident"] * STREAM_DETECTION_LIMIT)
        self.assertEqual([data["id"] for kind, data in frames if kind == "alert"], alerts[1:])
        self.assertEqual([data["id"] for kind, data in frames if kind == "incident"], incidents[1:])

    def test_an_empty_run_omits_zero_and_publishes_only_health(self):
        _publish_detection(self.conn, STARTED, OK)
        frames = self.frames()
        self.assertEqual(frames, [("health", {
            "partial": True, "checks": {"detection": "ok"}, "error": None,
            "alerts_omitted": 0, "incidents_omitted": 0,
        })])

    def test_a_failing_run_publishes_health_only_and_omits_zero(self):
        add_alert(self.conn)
        add_incident(self.conn)
        for _ in range(STREAM_DETECTION_LIMIT):
            add_alert(self.conn)
            add_incident(self.conn)
        _publish_detection(self.conn, STARTED, {"status": "failed", "error": "lab rule"})
        frames = self.frames()
        self.assertEqual(frames, [("health", {
            "partial": True, "checks": {"detection": "failing"}, "error": "lab rule",
            "alerts_omitted": 0, "incidents_omitted": 0,
        })])

    def test_no_subscriber_publishes_nothing(self):
        add_alert(self.conn)
        stream.BROKER.unsubscribe(self.sub)
        with mock.patch.object(stream.BROKER, "active", return_value=0), \
                mock.patch.object(stream.BROKER, "publish") as publish:
            _publish_detection(self.conn, STARTED, OK)
        publish.assert_not_called()

    def test_a_failed_publish_does_not_raise_and_records_the_stream_error(self):
        add_alert(self.conn)
        with mock.patch.object(stream.BROKER, "publish", side_effect=RuntimeError("stream down")):
            _publish_detection(self.conn, STARTED, OK)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
        row = self.conn.execute(
            "SELECT component, message FROM error_log WHERE component = 'stream'").fetchone()
        self.assertEqual(row["component"], "stream")
        self.assertIn("RuntimeError", row["message"])

    def test_the_docs_name_the_omitted_counts(self):
        api = API.read_text()
        self.assertIn(
            "`alerts_omitted` is how many alerts this run touched past the newest 100 by `id` "
            "(0 when the run fits, and 0 on a failing run)",
            api)
        self.assertIn(
            "`incidents_omitted` is the same count for incidents",
            api)
        self.assertIn("frames still in `id` order", api)
