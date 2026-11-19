"""Withdrawn scored replays stay unknown, and the original demo still detects what it detected."""

import hashlib
import json
import unittest
from datetime import datetime, timezone

from watchpost import attack, engine, improve, incidents, simulate
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload

from .helpers import ServerTestCase

WITHDRAWN = ("credential_stuffing", "lateral_movement", "dns_exfil", "ransomware_precursors")
FIXED_NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
DEMO_HASH = "f41ec3b5073a60bd14e0968238cec8d8d25b27fafa70c3ab8e91f5bc82185d64"
ATTACKS = (
    "brute_force", "password_spray", "compromise", "off_hours_admin", "web_scan", "port_sweep",
    "impossible_travel", "privilege_escalation", "cloud_new_principal", "exfiltration", "shadow_it",
    "logging_disabled", "log_source_stops", "admin_new_source",
)
BENIGN_FIRES = (
    "noisy_scanner", "noisy_scanner_repeat", "stale_password_device", "password_expiry_nat",
    "oncall_admin", "authorized_port_scan", "typo_then_sudo", "nightly_backup",
)


def _ids(start, end):
    return list(range(start, end + 1))


# Alert evidence after ingesting simulate.build(seed=7) for 2026-11-18 12:00 UTC, in alert id order.
DEMO_EVIDENCE = (
    ("account_repeated_failures", "admin", _ids(21, 60)),
    ("brute_force_ip", "203.0.113.45", _ids(21, 60)),
    ("password_spray", "198.51.100.23", _ids(61, 72)),
    ("impossible_geo_login", "dave|10.0.1.23|192.0.2.77", [10, 80]),
    ("success_after_failures", "dave|192.0.2.77", _ids(73, 80)),
    ("off_hours_privileged_login", "root|10.0.9.9|2026-11-17", [81]),
    ("account_repeated_failures", "svc_scan", _ids(82, 93)),
    ("brute_force_ip", "10.0.50.5", _ids(82, 93)),
    ("account_repeated_failures", "svc_scan", _ids(94, 105)),
    ("brute_force_ip", "10.0.50.5", _ids(94, 105)),
    ("web_scanner", "203.0.113.80", _ids(106, 117)),
    ("firewall_port_sweep", "198.51.100.140", _ids(122, 141)),
    ("impossible_geo_login", "erin|10.0.1.24|203.0.113.150", [143, 144]),
    ("impossible_geo_login", "erin|203.0.113.150|10.0.1.24", [12, 144]),
    ("impossible_geo_login", "frank|10.0.1.25|192.0.2.140", [15, 148]),
    ("privilege_escalation_after_login", "frank|web01", _ids(145, 149)),
    ("cloud_iam_change_by_new_principal", "svc-deploy-tmp", _ids(156, 158)),
    ("data_exfil_volume", "svc-deploy-tmp", _ids(159, 198)),
    ("unsanctioned_cloud_service", "judy|personal-drive.example", _ids(209, 214)),
    ("cloud_logging_disabled", "svc-deploy-tmp", [219, 220]),
    ("admin_action_from_new_source", "ops-admin|198.51.100.77", [392, 393]),
)


class WithdrawnScenarioTests(unittest.TestCase):
    def test_a_withdrawn_name_is_an_unknown_scenario(self):
        for name in WITHDRAWN:
            self.assertNotIn(name, simulate.SCENARIOS)
            self.assertNotIn(name, simulate.DEMO_SCENARIOS)
            with self.assertRaises(ValueError) as caught:
                simulate.build([name])
            self.assertEqual(str(caught.exception), f"unknown scenario(s): {name}")

    def test_demo_sequence_and_evidence_ids_at_a_fixed_day(self):
        built = simulate.build(seed=7, now=FIXED_NOW)
        digest = hashlib.sha256(json.dumps(built, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, DEMO_HASH)
        self.assertEqual(list(built), list(simulate.DEMO_SCENARIOS))
        self.assertEqual(sum(len(events) for events in built.values()), 393)

        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        for name, events in built.items():
            normalized, rejections = parse_payload(json.dumps(events), "json", f"demo:{name}")
            self.assertEqual(rejections, [])
            engine.ingest(conn, normalized, rejections, f"demo:{name}", "json", "test", True)
        rows = []
        for alert in conn.execute("SELECT id, rule_id, group_key FROM alerts ORDER BY id"):
            ids = [row[0] for row in conn.execute(
                "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id", (alert["id"],))]
            rows.append((alert["rule_id"], alert["group_key"], ids))
        self.assertEqual(tuple(rows), DEMO_EVIDENCE)

    def test_the_lab_recovers_fourteen_attacks_and_eight_benign_fires(self):
        self.assertEqual([name for name, spec in simulate.SCENARIOS.items() if spec["malicious"]], list(ATTACKS))
        self.assertEqual(len(simulate.SCENARIOS), 31)
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        coverage = incidents.coverage(conn)
        lab = improve.cached_noise_lab(conn)
        scenarios = [{"name": name, "malicious": spec["malicious"], "expected_rules": list(spec["expected"])}
                     for name, spec in simulate.SCENARIOS.items()]
        strip = improve.lab_strip(lab["rules"], scenarios)
        self.assertEqual(strip["scenarios"], 31)
        self.assertEqual(strip["attacks"], 14)
        self.assertEqual(strip["detected_attacks"], 14)
        self.assertEqual(strip["missed"], [])
        self.assertEqual(strip["false_positives"], 8)
        self.assertEqual(tuple(strip["false_positive_scenarios"]), BENIGN_FIRES)
        self.assertEqual(coverage["summary"]["levels"]["validated"], 17)
        self.assertEqual(coverage["summary"]["levels"]["mapped"], 3)

        layer = attack.navigator_layer(coverage)
        for name in WITHDRAWN:
            self.assertNotIn(name, [row["name"] for row in lab["scenarios"]])
            for row in lab["rules"]:
                for key in ("detected", "missed", "lookalikes_fired", "other_benign_fired"):
                    self.assertNotIn(name, row[key], row["rule_id"])
            for technique in coverage["techniques"]:
                self.assertNotIn(name, technique["scenarios"])
                for rule in technique["rules"]:
                    self.assertNotIn(name, rule["proves"])
            for item in layer["techniques"]:
                self.assertNotIn(name, item["comment"])


class WithdrawnScenarioApiTests(ServerTestCase):
    def test_a_withdrawn_replay_name_is_rejected(self):
        analyst = self.client("analyst")
        status, listed, _ = analyst.get("/api/demo/scenarios")
        self.assertEqual(status, 200)
        names = [row["name"] for row in listed]
        self.assertIn("brute_force", names)
        for name in WITHDRAWN:
            self.assertNotIn(name, names)
            status, data, _ = analyst.post("/api/demo/simulate", {"scenario": name})
            self.assertEqual(status, 400, data)
            self.assertEqual(data["error"], f"scenario must be one of {', '.join(simulate.SCENARIOS)}")

    def test_persisted_replay_records_stay_readable(self):
        conn = connect(self.db_path)
        now = "2026-11-01T00:00:00.000Z"
        event_ids = {}
        for name in WITHDRAWN:
            event_ids[name] = conn.execute(
                "INSERT INTO events(ts, ingested_at, source, event_type, severity, message, synthetic)"
                " VALUES (?,?,?,?,?,?,1)",
                (now, now, f"demo:{name}", "auth_failure", "low", f"[SYNTHETIC] old replay {name}"),
            ).lastrowid
        alert_id = conn.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
            " VALUES ('brute_force_ip', 1, '203.0.113.45', 'high', 'Old replay', ?, 'open', ?, ?, 1, 1, ?, ?)",
            ("Stored from credential_stuffing", now, now, now, now),
        ).lastrowid
        conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)",
                     (alert_id, event_ids["credential_stuffing"]))
        conn.execute(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?, 'analyst', ?, ?)",
            (alert_id, "note from lateral_movement replay", now))
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
            (alert_id, "analyst", "noted", "dns_exfil", now))
        conn.execute(
            "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, note)"
            " VALUES ('brute_force_ip', 99, 1, '{}', ?, 'analyst', ?)",
            (now, "history from ransomware_precursors replay"))
        conn.close()

        analyst = self.client("analyst")
        status, alert, _ = analyst.get(f"/api/alerts/{alert_id}")
        self.assertEqual(status, 200, alert)
        self.assertEqual(alert["evidence"][0]["source"], "demo:credential_stuffing")
        self.assertEqual(alert["notes"][0]["body"], "note from lateral_movement replay")
        self.assertEqual(alert["activity"][0]["detail"], "dns_exfil")
        for name, event_id in event_ids.items():
            status, event, _ = analyst.get(f"/api/events/{event_id}")
            self.assertEqual(status, 200, event)
            self.assertEqual(event["source"], f"demo:{name}")
        status, history, _ = analyst.get("/api/rules/brute_force_ip/history")
        self.assertEqual(status, 200, history)
        self.assertEqual(history[0]["version"], 99)
        self.assertIn("ransomware_precursors", history[0]["note"])
