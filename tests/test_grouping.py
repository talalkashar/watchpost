import unittest
from datetime import timedelta

from tests.helpers import ServerTestCase
from watchpost import grouping
from watchpost.db import iso, utcnow


class GroupingTests(unittest.TestCase):
    def test_grouping_changes_only_the_key_and_keeps_evidence(self):
        events = [{"id": 1, "user": "Alice", "src_ip": "1.1.1.1"},
                  {"id": 2, "user": "alice", "src_ip": "2.2.2.2"}]
        finding = {"group_key": "old", "event_ids": [1, 2], "first_seen": "a", "last_seen": "b"}
        changed = grouping.apply([finding], events, ["user", "src_ip"])[0]
        self.assertEqual(changed["group_key"], "alice|1.1.1.1,2.2.2.2")
        self.assertEqual(changed["event_ids"], [1, 2])
        self.assertEqual(finding["group_key"], "old")

    def test_large_multi_value_keys_are_bounded_and_stable(self):
        events = [{"id": i, "user": f"account-{i:04d}"} for i in range(1000)]
        finding = {"group_key": "old", "event_ids": list(range(1000))}
        first = grouping.apply([finding], events, ["user"])[0]
        second = grouping.apply([finding], list(reversed(events)), ["user"])[0]
        self.assertEqual(first["group_key"], second["group_key"])
        self.assertRegex(first["group_key"], r"^sha256:[0-9a-f]{64}$")

    def test_user_and_host_fold_ascii_only(self):
        events = [
            {"id": 1, "user": "ÉRIN", "host": "Érin-host", "src_ip": "2001:DB8::1",
             "dest_ip": "2001:DB8::2", "event_type": "AUTH_FAILURE", "source": "Demo"},
            {"id": 2, "user": "érin", "host": "érin-host", "src_ip": "2001:db8::1",
             "dest_ip": "2001:db8::2", "event_type": "auth_failure", "source": "demo"},
            {"id": 3, "user": "Alice", "host": "WEB01", "src_ip": "203.0.113.9",
             "dest_ip": "203.0.113.10", "event_type": "auth_failure", "source": "demo"},
            {"id": 4, "user": "alice", "host": "web01", "src_ip": "203.0.113.9",
             "dest_ip": "203.0.113.10", "event_type": "auth_failure", "source": "demo"},
            {"id": 5, "user": "ÉRIN", "host": "Érin-host"},
        ]
        findings = [{"group_key": "old", "event_ids": [i]} for i in (1, 2, 3, 4)]
        users = [item["group_key"] for item in grouping.apply(findings, events, ["user"])]
        self.assertEqual(users, ["Érin", "érin", "alice", "alice"])
        hosts = [item["group_key"] for item in grouping.apply(findings, events, ["host"])]
        self.assertEqual(hosts, ["Érin-host", "érin-host", "web01", "web01"])
        addresses = grouping.apply(findings[:2], events, ["src_ip", "dest_ip"])
        self.assertEqual(addresses[0]["group_key"], "2001:DB8::1|2001:DB8::2")
        self.assertEqual(addresses[1]["group_key"], "2001:db8::1|2001:db8::2")
        stored = grouping.apply(findings[:2], events, ["event_type", "source"])
        self.assertEqual(stored[0]["group_key"], "AUTH_FAILURE|Demo")
        self.assertEqual(stored[1]["group_key"], "auth_failure|demo")
        # Two spellings of one account in one finding still share one ASCII key.
        shared = grouping.apply([{"group_key": "old", "event_ids": [1, 5, 3, 4]}], events, ["user"])[0]
        self.assertEqual(shared["group_key"], "alice,Érin")


class GroupingApiTests(ServerTestCase):
    def test_reviewed_grouping_preview_applies_and_preserves_evidence(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        start = utcnow() - timedelta(minutes=5)
        events = [{"ts": iso(start + timedelta(seconds=i)), "type": "login_failed",
                   "user": "Alice", "src_ip": "203.0.113.9"} for i in range(12)]
        self.assertEqual(analyst.post("/api/ingest", events)[0], 201)
        status, change, _ = analyst.post("/api/rules/brute_force_ip/proposals",
                                          {"grouping": ["user"], "reason": "Deduplicate by account"})
        self.assertEqual(status, 201, change)
        preview = change["evaluation"]["grouping_preview"]
        self.assertEqual(preview["before"]["group_keys"], ["203.0.113.9"])
        self.assertEqual(preview["after"]["group_keys"], ["alice"])
        self.assertTrue(preview["evidence_ids_preserved"])
        status, reviewed, _ = admin.post(f"/api/changes/{change['id']}/review",
                                          {"decision": "approve", "evidence_digest": change["evidence_digest"]})
        self.assertEqual(status, 200, reviewed)
        rule = {r["id"]: r for r in analyst.get("/api/rules")[1]}["brute_force_ip"]
        self.assertEqual(rule["grouping"], ["user"])
        history = analyst.get("/api/rules/brute_force_ip/history")[1]
        self.assertEqual(history[0]["grouping"], ["user"])
        later = [{"ts": iso(start + timedelta(minutes=1, seconds=i)), "type": "login_failed",
                  "user": "Alice", "src_ip": "198.51.100.8"} for i in range(12)]
        self.assertEqual(analyst.post("/api/ingest", later)[0], 201)
        alerts = analyst.get("/api/alerts?rule_id=brute_force_ip")[1]
        regrouped = next(alert for alert in alerts if alert["group_key"] == "alice")
        self.assertEqual(regrouped["event_count"], 24)  # both IP findings deduplicate under the account key

    def test_grouping_validation(self):
        analyst = self.client("analyst")
        for value in ("user", ["unknown"], ["user", "user"], ["user", "host", "source", "src_ip"]):
            with self.subTest(value=value):
                self.assertEqual(analyst.post("/api/rules/brute_force_ip/proposals",
                                              {"grouping": value, "reason": "Validate grouping"})[0], 400)


if __name__ == "__main__":
    unittest.main()
