"""Labeled attacks added after the demo snapshot: stuffing, lateral movement, DNS exfil, precursors."""

import copy
import unittest
from datetime import datetime, time, timedelta, timezone

from watchpost import rules, simulate
from watchpost.db import iso
from watchpost.normalize import EVENT_TYPES

ALLOWED_PREFIXES = ("10.", "172.16.", "192.168.", "192.0.2.", "198.51.100.", "203.0.113.")
DEFAULTS = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}
NEW = ("credential_stuffing", "lateral_movement", "dns_exfil", "ransomware_precursors")


def _numbered(events):
    return [{"id": i, **e} for i, e in enumerate(events, start=1)]


def _findings(rule_id, events):
    params = dict(DEFAULTS[rule_id])
    if rule_id == "log_source_silent":
        # Same clock the noise lab uses: end of the scenario day, so a learned source would look silent.
        params["now"] = iso(datetime.combine(
            simulate.demo_day() + timedelta(days=1), time.min, tzinfo=timezone.utc))
    return rules.RULE_FUNCTIONS[rule_id](copy.deepcopy(_numbered(events)), params)


class NewScenarioTests(unittest.TestCase):
    def test_registered_outside_the_demo_dataset(self):
        self.assertEqual(list(simulate.build(seed=7)), simulate.DEMO_SCENARIOS)
        for name in NEW:
            spec = simulate.SCENARIOS[name]
            self.assertTrue(spec["malicious"], name)
            self.assertNotIn(name, simulate.DEMO_SCENARIOS)
            self.assertNotIn("lookalike_of", spec)
            self.assertTrue(spec["expected"])
            self.assertTrue(spec["techniques"])
            for rule_id in spec["expected"]:
                self.assertIn(rule_id, rules.RULE_FUNCTIONS)
            mapped = {t["id"] for rid in spec["expected"] for r in rules.DEFAULT_RULES if r["id"] == rid
                      for t in r["techniques"]}
            self.assertLessEqual(set(spec["techniques"]), mapped)

    def test_builders_do_not_shift_the_demo_events(self):
        full = simulate.build(list(simulate.SCENARIOS), seed=7)
        demo = simulate.build(seed=7)
        for name in simulate.DEMO_SCENARIOS:
            self.assertEqual(full[name], demo[name])

    def test_each_scenario_is_deterministic_and_labeled(self):
        for name in NEW:
            first = simulate.build([name], seed=7)[name]
            self.assertEqual(first, simulate.build([name], seed=7)[name])
            self.assertEqual(simulate.build([name], seed=7)[name], simulate.build([name], seed=11)[name])
            for event in first:
                self.assertIn("SYNTHETIC", event["message"])
                self.assertEqual(event["source"], f"demo:{name}")
                self.assertIn(event["event_type"], EVENT_TYPES)
                for ip in (event.get("src_ip"), event.get("dest_ip")):
                    self.assertTrue(ip and ip.startswith(ALLOWED_PREFIXES), ip)

    def test_only_the_expected_rules_fire(self):
        for name in NEW:
            spec = simulate.SCENARIOS[name]
            events = simulate.build([name], seed=7)[name]
            fired = {}
            for rule_id in rules.RULE_FUNCTIONS:
                found = _findings(rule_id, events)
                if found:
                    fired[rule_id] = [f["group_key"] for f in found]
            self.assertEqual(set(fired), set(spec["expected"]), fired)
            for rule_id, want in spec["expected"].items():
                self.assertEqual(fired[rule_id], [want])

    def test_credential_stuffing_is_distributed(self):
        events = simulate.build(["credential_stuffing"], seed=7)["credential_stuffing"]
        failures = [e for e in events if e["event_type"] == "auth_failure"]
        self.assertGreaterEqual(len({e["src_ip"] for e in failures}), 8)
        self.assertTrue(all(e["src_ip"].startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for e in failures))
        self.assertEqual({e["user"] for e in failures}, {"hr_admin"})
        self.assertGreaterEqual(len(failures), 8)
        self.assertEqual(max(sum(e["src_ip"] == ip for e in failures) for ip in {e["src_ip"] for e in failures}), 1)
        self.assertFalse(any(e["event_type"] in ("auth_success", "vpn_login") for e in events))

    def test_lateral_movement_hops_hosts(self):
        events = simulate.build(["lateral_movement"], seed=7)["lateral_movement"]
        hosts = {e["host"] for e in events}
        self.assertGreaterEqual(hosts, {"web01", "db01"})
        escalations = [e for e in events if e["event_type"] == "privilege_escalation"]
        self.assertEqual([e["host"] for e in escalations], ["db01"])
        self.assertEqual(sum(e["event_type"] == "auth_failure" for e in events), 3)
        self.assertTrue(any(e.get("dest_port") == 445 for e in events))

    def test_dns_exfil_stays_under_the_volume_rule(self):
        events = simulate.build(["dns_exfil"], seed=7)["dns_exfil"]
        queries = [e for e in events if e.get("dest_port") == 53 or "DNS" in e["message"]]
        self.assertGreaterEqual(len(queries), 8)
        self.assertTrue(all("DNS" in e["message"] for e in queries))
        self.assertLess(sum(e.get("bytes") or 0 for e in events), 1_000_000)
        self.assertFalse(any(e["event_type"] == "cloud_data_access" for e in events))
        self.assertFalse(any(e["event_type"] in ("auth_success", "vpn_login") for e in events))

    def test_ransomware_precursors_name_shadow_copies(self):
        events = simulate.build(["ransomware_precursors"], seed=7)["ransomware_precursors"]
        text = " ".join(e["message"].lower() for e in events)
        self.assertIn("vssadmin", text)
        self.assertTrue("shadow" in text or ".locked" in text)
        self.assertIn(".locked", text)
        self.assertEqual(sum(e["event_type"] == "auth_failure" for e in events), 4)
        self.assertEqual(sum(e["event_type"] == "privilege_escalation" for e in events), 1)


if __name__ == "__main__":
    unittest.main()
