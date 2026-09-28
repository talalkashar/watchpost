import json
import unittest
from datetime import timedelta

from watchpost import correlate, engine
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.normalize import parse_payload


def alert(aid, minute, ip=None, user=None, host=None, incident_id=None, severity="medium", length=1):
    first = f"2026-09-15T10:{minute:02d}:00.000Z"
    last = f"2026-09-15T10:{minute + length:02d}:00.000Z"
    return {"id": aid, "first_seen": first, "last_seen": last, "severity": severity, "incident_id": incident_id,
            "entities": {"src_ip": [ip] if ip else [], "user": [user] if user else [], "host": [host] if host else []}}


class CorrelateTests(unittest.TestCase):
    def test_shared_entities_chain_within_window(self):
        alerts = [alert(1, 0, ip="203.0.113.5"), alert(2, 10, ip="203.0.113.5", user="frank"),
                  alert(3, 20, user="FRANK"), alert(4, 25, ip="198.51.100.1")]
        groups = correlate.correlate(alerts, window_seconds=600)
        self.assertEqual([g["alert_ids"] for g in groups], [[1, 2, 3], [4]])
        self.assertTrue(all(g["incident_id"] is None for g in groups))

    def test_window_splits_distant_alerts(self):
        alerts = [alert(1, 0, ip="203.0.113.5"), alert(2, 50, ip="203.0.113.5")]
        self.assertEqual(len(correlate.correlate(alerts, window_seconds=600)), 2)
        self.assertEqual(len(correlate.correlate(alerts, window_seconds=3600)), 1)

    def test_sightings_keep_long_alerts_from_swallowing_a_busy_host(self):
        # A travel alert spans hours, but web01 only appears in its last event.
        travel = {**alert(1, 0, user="dave", host="web01", length=50),
                  "sightings": [("user", "dave", "2026-09-15T10:00:00.000Z"),
                                ("host", "files01", "2026-09-15T10:00:00.000Z"),
                                ("host", "web01", "2026-09-15T10:50:00.000Z")]}
        other = {**alert(2, 5, ip="203.0.113.9", host="web01"),
                 "sightings": [("host", "web01", "2026-09-15T10:05:00.000Z")]}
        self.assertEqual(len(correlate.correlate([travel, other], window_seconds=600)), 2)
        # Without sightings the whole span counts, and the two would be linked.
        plain = [{k: v for k, v in a.items() if k != "sightings"} for a in (travel, other)]
        self.assertEqual(len(correlate.correlate(plain, window_seconds=600)), 1)

    def test_new_alert_joins_existing_incident_and_incidents_never_merge(self):
        alerts = [alert(1, 0, ip="203.0.113.5", incident_id=7), alert(2, 1, user="erin", incident_id=9),
                  alert(3, 2, ip="203.0.113.5", user="erin")]
        groups = correlate.correlate(alerts)
        self.assertEqual([(g["incident_id"], g["alert_ids"], g["new_alert_ids"]) for g in groups],
                         [(7, [1, 3], [3]), (9, [2], [])])

    def test_summary_escalates_on_three_tactics(self):
        base = [{**alert(1, 0, ip="203.0.113.5"), "tactics": ["Credential Access"], "synthetic": 1},
                {**alert(2, 5, ip="203.0.113.5", user="frank", severity="high"),
                 "tactics": ["Initial Access"], "synthetic": 1}]
        two = correlate.summarize(base)
        self.assertEqual((two["severity"], two["escalated"]), ("high", False))
        self.assertEqual(two["stages"], ["Initial Access", "Credential Access"])
        self.assertEqual(two["title"], "Initial Access → Credential Access: 203.0.113.5, frank")
        three = correlate.summarize(base + [{**alert(3, 9, user="frank"), "tactics": ["Privilege Escalation"],
                                             "synthetic": 0}])
        self.assertEqual((three["severity"], three["escalated"], three["synthetic"]), ("critical", True, 0))
        self.assertEqual(three["alert_count"], 3)

    def test_should_open(self):
        self.assertFalse(correlate.should_open([alert(1, 0)]))
        self.assertTrue(correlate.should_open([alert(1, 0, severity="critical")]))
        self.assertTrue(correlate.should_open([alert(1, 0), alert(2, 1)]))


class EngineCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.start = utcnow() - timedelta(hours=3)

    def tearDown(self):
        self.conn.close()

    def ingest(self, records):
        events, rejections = parse_payload(json.dumps(records), "json", "test")
        self.assertEqual(rejections, [])
        return engine.ingest(self.conn, events, rejections, "test", "json", "tester")

    def at(self, seconds):
        return iso(self.start + timedelta(seconds=seconds))

    def intrusion(self):
        ip = "192.0.2.140"
        records = [{"ts": self.at(i), "event_type": "web_scan", "src_ip": ip, "message": f"GET /p{i} -> 404"}
                   for i in range(6)]
        records += [{"ts": self.at(60 + i * 20), "event_type": "auth_failure", "user": f"u{i}", "src_ip": ip}
                    for i in range(5)]
        records += [{"ts": self.at(200 + i * 10), "event_type": "auth_failure", "user": "frank", "src_ip": ip}
                    for i in range(3)]
        records += [{"ts": self.at(260), "event_type": "auth_success", "user": "frank", "src_ip": ip},
                    {"ts": self.at(600), "event_type": "privilege_escalation", "user": "frank", "host": "web01"}]
        return records

    def incidents(self):
        rows = self.conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()
        links = self.conn.execute("SELECT alert_id, incident_id FROM incident_alerts ORDER BY alert_id").fetchall()
        return [dict(r) for r in rows], [tuple(r) for r in links]

    def test_intrusion_becomes_one_escalated_incident_and_rerun_is_idempotent(self):
        result = self.ingest(self.intrusion())
        self.assertEqual(result["detection"]["correlation"]["status"], "ok")
        incidents, links = self.incidents()
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        rules_fired = {r[0] for r in self.conn.execute("SELECT rule_id FROM alerts")}
        self.assertEqual(rules_fired, {"web_scanner", "password_spray", "privilege_escalation_after_login"})
        self.assertEqual(json.loads(incident["stages"]),
                         ["Reconnaissance", "Initial Access", "Privilege Escalation", "Credential Access"])
        self.assertEqual(incident["severity"], "critical")
        self.assertEqual(incident["alert_count"], 3)
        self.assertIn("192.0.2.140", json.loads(incident["entities"])["src_ip"])

        again = engine.run_detection(self.conn, trigger="rerun")
        self.assertEqual(again["correlation"], {"status": "ok", "incidents_created": 0, "incidents_updated": 0})
        self.assertEqual(self.incidents(), (incidents, links))

    def test_new_alert_attaches_to_open_incident(self):
        self.ingest(self.intrusion())
        (incident,), _ = self.incidents()
        # Later exfiltration by the same account joins the open incident.
        self.ingest([{"ts": self.at(900 + i), "event_type": "cloud_data_access", "user": "frank",
                      "src_ip": "192.0.2.140", "bytes": 300_000_000} for i in range(4)])
        incidents, links = self.incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["alert_count"], 4)
        self.assertIn("Exfiltration", json.loads(incidents[0]["stages"]))
        self.assertEqual({i for _, i in links}, {incident["id"]})

    def test_resolved_incident_is_not_reopened(self):
        self.ingest(self.intrusion())
        self.conn.execute("UPDATE incidents SET status = 'resolved'")
        self.ingest([{"ts": self.at(900 + i), "event_type": "cloud_data_access", "user": "frank",
                      "src_ip": "192.0.2.140", "bytes": 300_000_000} for i in range(4)])
        incidents, _ = self.incidents()
        # The lone new alert (high, not critical) does not open an incident by itself.
        self.assertEqual([i["status"] for i in incidents], ["resolved"])

    def test_single_non_critical_alert_is_not_an_incident(self):
        self.ingest([{"ts": self.at(i), "event_type": "web_scan", "src_ip": "203.0.113.80"} for i in range(6)])
        self.assertEqual(self.incidents(), ([], []))

    def test_correlation_failure_leaves_alerts_and_is_reported(self):
        original = engine.correlate_alerts
        engine.correlate_alerts = lambda conn: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            result = self.ingest(self.intrusion())
        finally:
            engine.correlate_alerts = original
        self.assertEqual(result["detection"]["status"], "ok")
        self.assertEqual(result["detection"]["correlation"]["status"], "failed")
        self.assertGreater(result["detection"]["alerts_created"], 0)
        self.assertEqual(self.conn.execute("SELECT component FROM error_log").fetchone()[0], "correlation")
        from watchpost.health import check_detection
        self.assertEqual(check_detection(self.conn)[0], "degraded")
        # Recovery: the next run correlates the stored alerts.
        self.assertEqual(engine.run_detection(self.conn)["correlation"]["incidents_created"], 1)
        self.assertEqual(check_detection(self.conn)[0], "ok")


if __name__ == "__main__":
    unittest.main()
