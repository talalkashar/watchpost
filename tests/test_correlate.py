import json
import unittest
from datetime import timedelta

from watchpost import correlate, engine, incidents, report
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.normalize import parse_payload


def alert(aid, minute, ip=None, user=None, host=None, incident_id=None, severity="medium", length=1):
    first = f"2026-09-15T10:{minute:02d}:00.000Z"
    last = f"2026-09-15T10:{minute + length:02d}:00.000Z"
    return {"id": aid, "first_seen": first, "last_seen": last, "severity": severity, "incident_id": incident_id,
            "entities": {"src_ip": [ip] if ip else [], "user": [user] if user else [], "host": [host] if host else []}}


def _at(seconds):
    return f"2026-09-15T10:{seconds // 60:02d}:{seconds % 60:02d}.000Z"


def instant(aid, seconds, ip=None, user=None, host=None, tactics=None):
    """An alert whose span is a single instant, so window edges can be asserted exactly."""
    ts = _at(seconds)
    return {"id": aid, "first_seen": ts, "last_seen": ts, "severity": "medium", "incident_id": None,
            "tactics": tactics or [], "synthetic": 1,
            "entities": {"src_ip": [ip] if ip else [], "user": [user] if user else [],
                         "host": [host] if host else []}}


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

    def test_window_edge_is_inclusive_and_one_second_past_is_not(self):
        # The window is closed at the edge: a gap of exactly `window_seconds` still links,
        # one more second does not.
        ip = "203.0.113.5"
        self.assertEqual(len(correlate.correlate([instant(1, 0, ip=ip), instant(2, 600, ip=ip)],
                                                 window_seconds=600)), 1)
        self.assertEqual(len(correlate.correlate([instant(1, 0, ip=ip), instant(2, 601, ip=ip)],
                                                 window_seconds=600)), 2)

    def test_two_chains_link_only_through_a_third_alert(self):
        # 1-2 share an ip and 3-4 share a user; nothing links 1 to 4 except alert 3, which
        # carries both the host of 2 and the user of 4. The chain must reach all four.
        chained = [alert(1, 0, ip="203.0.113.5"), alert(2, 1, ip="203.0.113.5", host="web01"),
                   alert(3, 2, host="web01", user="frank"), alert(4, 3, user="FRANK")]
        self.assertEqual([g["alert_ids"] for g in correlate.correlate(chained, window_seconds=600)],
                         [[1, 2, 3, 4]])
        # Drop the bridge and the two pairs stay apart, so the test above is really chaining.
        self.assertEqual([g["alert_ids"] for g in correlate.correlate(chained[:2] + chained[3:],
                                                                     window_seconds=600)],
                         [[1, 2], [4]])

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
        # Not escalated by tactic count. The severity is critical all the same: a password attack followed by
        # a suspicious login from the same source completes the correlation rule attack_then_access.
        self.assertEqual((two["severity"], two["escalated"]), ("critical", False))
        self.assertEqual(two["patterns"], [{"id": "attack_then_access", "alert_ids": [1, 2]}])
        reverse = correlate.summarize([{**base[0], "tactics": ["Initial Access"]}, {**base[1], "tactics": ["Credential Access"]}])
        self.assertEqual((reverse["severity"], reverse["patterns"]), ("high", []))   # the other order is no rule
        self.assertEqual(two["stages"], ["Initial Access", "Credential Access"])
        self.assertEqual(two["title"], "Initial Access → Credential Access: 203.0.113.5, frank")
        three = correlate.summarize(base + [{**alert(3, 9, user="frank"), "tactics": ["Privilege Escalation"],
                                             "synthetic": 0}])
        self.assertEqual((three["severity"], three["escalated"], three["synthetic"]), ("critical", True, 0))
        self.assertEqual(three["alert_count"], 3)

    def test_escalation_needs_three_distinct_tactics(self):
        def summary(*tactics):
            return correlate.summarize([instant(i + 1, i * 5, ip="203.0.113.5", tactics=[t])
                                        for i, t in enumerate(tactics)])

        self.assertFalse(summary("Initial Access", "Credential Access")["escalated"])
        # Repeats are one tactic, not three: the count is distinct stages.
        repeated = summary("Initial Access", "Initial Access", "Initial Access")
        self.assertFalse(repeated["escalated"])
        self.assertEqual(repeated["stages"], ["Initial Access"])
        three = summary("Initial Access", "Credential Access", "Privilege Escalation")
        self.assertTrue(three["escalated"])
        self.assertEqual((three["severity"], three["escalated"]), ("high", True))

    def test_should_open(self):
        self.assertFalse(correlate.should_open([alert(1, 0)]))
        self.assertTrue(correlate.should_open([alert(1, 0, severity="critical")]))
        self.assertTrue(correlate.should_open([alert(1, 0), alert(2, 1)]))


def staged(aid, hour, minute=0, tactics=(), ip=None, user=None, host=None, users=None, incident_id=None, severity="medium"):
    """An alert at a time of day, hours apart from the others, raised by a rule with the given tactics."""
    ts = f"2026-09-15T{hour:02d}:{minute:02d}:00.000Z" if hour < 24 else f"2026-09-16T{hour - 24:02d}:{minute:02d}:00.000Z"
    return {"id": aid, "first_seen": ts, "last_seen": ts, "severity": severity, "incident_id": incident_id,
            "tactics": list(tactics), "synthetic": 1,
            "entities": {"src_ip": [ip] if ip else [], "user": users or ([user] if user else []), "host": [host] if host else []}}


class PatternTests(unittest.TestCase):
    """Correlation rules: named shapes over tactics that link alerts hours apart and raise the incident."""

    def groups(self, *alerts):
        return [g["alert_ids"] for g in correlate.correlate(list(alerts))]

    def test_rules_are_well_formed(self):
        tactics = {name for _, name in correlate.attack.TACTICS} | {"other"}
        self.assertEqual(len(correlate.PATTERN_INFO), len(correlate.PATTERNS))
        for pattern in correlate.PATTERNS:
            self.assertRegex(pattern["id"], r"^[a-z_]+$")
            self.assertIn(pattern["kind"], ("sequence", "together"))
            self.assertIn(pattern["severity"], ("high", "critical"))
            self.assertTrue(pattern["name"] and pattern["description"])
            self.assertLessEqual(set(pattern["shared"]), {"src_ip", "user"}, "a host is a place, not an actor")
            self.assertGreaterEqual(len(pattern["steps"]), 2)
            for step in pattern["steps"]:
                self.assertLessEqual(set(step), tactics, pattern["id"])

    def test_a_sequence_links_alerts_hours_apart_from_one_source(self):
        scan = staged(1, 9, tactics=["Reconnaissance"], ip="203.0.113.5", host="web01")
        attack = staged(2, 13, tactics=["Credential Access"], ip="203.0.113.5", user="frank")
        self.assertEqual(self.groups(scan, attack), [[1, 2]])                      # four hours: far past the plain window
        self.assertEqual(correlate.match_patterns([scan, attack]), [{"id": "scan_then_attack", "alert_ids": [1, 2]}])
        # The other order is not the rule, nor is another source, nor a gap of more than a day.
        self.assertEqual(self.groups(staged(1, 9, tactics=["Credential Access"], ip="203.0.113.5"),
                                     staged(2, 13, tactics=["Reconnaissance"], ip="203.0.113.5")), [[1], [2]])
        self.assertEqual(self.groups(scan, staged(2, 13, tactics=["Credential Access"], ip="198.51.100.9")), [[1], [2]])
        self.assertEqual(self.groups(scan, staged(2, 34, tactics=["Credential Access"], ip="203.0.113.5")), [[1], [2]])
        self.assertEqual(self.groups(scan, staged(2, 33, tactics=["Credential Access"], ip="203.0.113.5")), [[1, 2]])

    def test_a_shared_host_is_not_enough(self):
        login = staged(1, 9, tactics=["Initial Access"], user="erin", host="web01")
        escalation = staged(2, 12, tactics=["Privilege Escalation"], user="frank", host="web01")
        self.assertEqual(self.groups(login, escalation), [[1], [2]])
        self.assertEqual(correlate.match_patterns([login, escalation]), [])
        same_account = staged(3, 12, tactics=["Privilege Escalation"], user="ERIN", host="db01")
        self.assertEqual(self.groups(login, same_account), [[1, 3]])               # the account, whatever the host or case

    def test_an_alert_naming_many_accounts_ties_none_of_them_to_the_next_stage(self):
        spray = staged(1, 9, tactics=["Credential Access"], ip="198.51.100.23", users=["amy", "bob", "cal", "dee", "eve"])
        login = staged(2, 12, tactics=["Initial Access"], ip="192.0.2.77", user="dee")
        self.assertEqual(self.groups(spray, login), [[1], [2]])
        guessing = staged(1, 9, tactics=["Credential Access"], ip="198.51.100.23", users=["dee", "eve"])
        self.assertEqual(self.groups(guessing, login), [[1, 2]])                    # two accounts: specific enough
        from_same_source = staged(2, 12, tactics=["Initial Access"], ip="198.51.100.23", user="zed")
        self.assertEqual(self.groups(spray, from_same_source), [[1, 2]])            # the source still ties them

    def test_alerts_without_tactics_never_complete_a_rule(self):
        self.assertEqual(self.groups(staged(1, 9, ip="203.0.113.5"), staged(2, 13, ip="203.0.113.5")), [[1], [2]])
        self.assertEqual(self.groups(staged(1, 9, tactics=["Reconnaissance"], ip="203.0.113.5"), staged(2, 13, ip="203.0.113.5")),
                         [[1], [2]])

    def test_logging_impaired_matches_in_either_order_and_needs_another_kind_of_alert(self):
        off = staged(1, 12, tactics=["Defense Evasion"], user="svc-deploy")
        before = staged(2, 9, tactics=["Persistence"], user="svc-deploy")
        after = staged(3, 15, tactics=["Exfiltration"], user="svc-deploy")
        for other in (before, after):
            self.assertEqual(correlate.match_patterns([off, other])[0]["id"], "defenses_impaired")
            self.assertEqual(len(self.groups(off, other)), 1)
        again = staged(4, 14, tactics=["Defense Evasion"], user="svc-deploy")
        self.assertEqual(correlate.match_patterns([off, again]), [])
        self.assertEqual(self.groups(off, again), [[1], [4]])

    def test_a_rule_raises_the_incident_to_its_own_severity(self):
        login = staged(1, 9, tactics=["Initial Access"], user="erin", severity="medium")
        leaving = staged(2, 15, tactics=["Exfiltration"], user="erin", severity="medium")
        summary = correlate.summarize([login, leaving])
        self.assertEqual((summary["severity"], summary["escalated"]), ("critical", False))
        self.assertEqual(summary["patterns"], [{"id": "access_then_exfiltration", "alert_ids": [1, 2]}])
        plain = correlate.summarize([login, staged(2, 15, tactics=["Initial Access"], user="erin")])
        self.assertEqual((plain["severity"], plain["patterns"]), ("medium", []))
        three = correlate.summarize([login, staged(2, 11, tactics=["Privilege Escalation"], user="erin"),
                                     staged(3, 15, tactics=["Collection"], user="erin")])
        self.assertEqual([p["id"] for p in three["patterns"]], ["access_then_escalation", "access_then_exfiltration"])
        self.assertEqual(three["patterns"][1]["alert_ids"], [1, 2, 3])              # both ways into the last stage

    def test_existing_incidents_are_respected(self):
        scan = staged(1, 9, tactics=["Reconnaissance"], ip="203.0.113.5", incident_id=7)
        attack = staged(2, 13, tactics=["Credential Access"], ip="203.0.113.5")
        joined = correlate.correlate([scan, attack])
        self.assertEqual([(g["incident_id"], g["alert_ids"], g["new_alert_ids"]) for g in joined], [(7, [1, 2], [2])])
        other = staged(2, 13, tactics=["Credential Access"], ip="203.0.113.5", incident_id=8)
        self.assertEqual([g["incident_id"] for g in correlate.correlate([scan, other])], [7, 8])   # never merged


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

    def test_a_scan_and_an_attack_hours_apart_become_one_incident_with_the_rule_named(self):
        ip = "203.0.113.200"
        self.start = utcnow() - timedelta(hours=8)
        self.ingest([{"ts": self.at(i), "event_type": "fw_deny", "src_ip": ip, "dest_ip": "10.0.0.5", "dest_port": 1000 + i}
                     for i in range(12)])                                           # a port sweep, eight hours ago
        self.assertEqual(self.incidents(), ([], []))                                # one alert, not critical: no incident
        self.start = utcnow() - timedelta(hours=2)
        self.ingest([{"ts": self.at(i * 5), "event_type": "auth_failure", "user": f"u{i % 3}", "src_ip": ip}
                     for i in range(12)])                                           # the same source guesses passwords
        rows, links = self.incidents()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["patterns"])[0]["id"], "scan_then_attack")
        rules = {r[0] for r in self.conn.execute("SELECT rule_id FROM alerts WHERE id IN (SELECT alert_id FROM incident_alerts)")}
        self.assertEqual(rules, {"firewall_port_sweep", "brute_force_ip"})
        incident = incidents.get_incident(self.conn, rows[0]["id"])
        self.assertEqual([(p["id"], p["name"], p["severity"], len(p["alert_ids"])) for p in incident["patterns"]],
                         [("scan_then_attack", "Scan, then attack, from one source", "high", 2)])
        self.assertIn(incident["severity"], ("high", "critical"))
        self.assertEqual(engine.correlate_alerts(self.conn), {"incidents_created": 0, "incidents_updated": 0})   # idempotent
        self.assertIn("Correlation rules matched: Scan, then attack, from one source.",
                      report.build(self.conn, rows[0]["id"])["summary"])
        self.assertIn("**Correlation rule:** Scan, then attack, from one source.", report.to_markdown(report.build(self.conn, rows[0]["id"])))

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
