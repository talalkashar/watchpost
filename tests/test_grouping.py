import hashlib
import json
import unittest
from datetime import timedelta

from tests.helpers import ServerTestCase
from watchpost import engine, grouping
from watchpost.db import connect, init_schema, iso, now_iso, utcnow


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

    def test_separators_inside_values_do_not_alias_another_group(self):
        events = [
            {"id": 1, "user": "a,b", "src_ip": "9.9.9.9"},
            {"id": 2, "user": "a", "src_ip": "b"},
            {"id": 3, "user": "a|b", "src_ip": "9.9.9.9"},
            {"id": 4, "user": "a\\,b", "src_ip": "9.9.9.9"},
            {"id": 5, "user": "a", "src_ip": "b|9.9.9.9"},
        ]
        findings = [{"group_key": "old", "event_ids": [i]} for i in range(1, 6)]
        keys = [item["group_key"] for item in grouping.apply(findings, events, ["user", "src_ip"])]
        self.assertEqual(keys, [
            "a\\,b|9.9.9.9",
            "a|b",
            "a\\|b|9.9.9.9",
            "a\\\\\\,b|9.9.9.9",
            "a|b\\|9.9.9.9",
        ])
        self.assertEqual(len(set(keys)), len(keys))
        straight = grouping.apply(
            [{"group_key": "old", "event_ids": [1, 2]}], events, ["user"])[0]["group_key"]
        flipped = grouping.apply(
            [{"group_key": "old", "event_ids": [2, 1]}], list(reversed(events)), ["user"])[0]
        self.assertEqual(straight, "a,a\\,b")
        self.assertEqual(flipped["group_key"], straight)
        self.assertEqual(flipped["event_ids"], [2, 1])

    def test_a_stored_missing_marker_is_not_a_missing_value(self):
        events = [
            {"id": 1, "user": "(none)"},
            {"id": 2, "host": "web01"},
            {"id": 3, "user": ""},
            {"id": 4, "user": None},
            {"id": 5, "user": "(NONE)"},
        ]
        findings = [{"group_key": "old", "event_ids": [i]} for i in range(1, 6)]
        keys = [item["group_key"] for item in grouping.apply(findings, events, ["user"])]
        self.assertEqual(keys, ["\\(none)", "(none)", "(none)", "(none)", "\\(none)"])
        # source stays the stored spelling, so the marker is escaped and a gap is not.
        marked = [{"id": 6, "source": "(none)"}, {"id": 7}]
        stored = [item["group_key"] for item in grouping.apply(
            [{"group_key": "old", "event_ids": [6]}, {"group_key": "old", "event_ids": [7]}],
            marked, ["source"])]
        self.assertEqual(stored, ["\\(none)", "(none)"])

    def test_duplicate_event_ids_do_not_follow_list_order(self):
        finding = {"group_key": "old", "event_ids": [7]}
        forward = [{"id": 7, "user": "bob"}, {"id": 7, "user": "Alice"}]
        backward = list(reversed(forward))
        first = grouping.apply([finding], forward, ["user"])[0]
        second = grouping.apply([finding], backward, ["user"])[0]
        self.assertEqual(first["group_key"], "alice,bob")
        self.assertEqual(second["group_key"], first["group_key"])
        self.assertEqual(finding["group_key"], "old")

    def test_a_field_name_string_is_not_a_list_of_fields(self):
        events = [{"id": 1, "user": "alice"}]
        finding = {"group_key": "old", "event_ids": [1]}
        with self.assertRaises(ValueError):
            grouping.apply([finding], events, "user")
        self.assertEqual(finding["group_key"], "old")
        self.assertEqual(grouping.apply([finding], events, [])[0]["group_key"], "old")


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


class StoredGroupTests(unittest.TestCase):
    rule_id = "brute_force_ip"

    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.conn.execute("UPDATE rules SET enabled=(id=?)", (self.rule_id,))
        self.conn.execute("UPDATE rules SET grouping=? WHERE id=?", (json.dumps(["user"]), self.rule_id))
        self.now = now_iso()

    def events(self, names, ip="192.0.2.1"):
        return [self.conn.execute(
            "INSERT INTO events(ts,ingested_at,source,event_type,severity,user,src_ip) VALUES (?,?,?,'auth_failure','low',?,?)",
            (self.now, self.now, "fixture", name, ip)).lastrowid for name in names]

    def alert(self, key, ids, status="open", count=None):
        alert_id = self.conn.execute(
            "INSERT INTO alerts(rule_id,rule_version,group_key,severity,title,explanation,status,first_seen,"
            " last_seen,event_count,created_at,updated_at) VALUES (?,1,?,'low','fixture','fixture',?,?,?,?,?,?)",
            (self.rule_id, key, status, self.now, self.now, len(ids) if count is None else count,
             self.now, self.now)).lastrowid
        self.conn.executemany("INSERT INTO alert_events VALUES (?,?)", [(alert_id, n) for n in ids])
        return alert_id

    def suppress(self, key):
        return self.conn.execute(
            "INSERT INTO suppressions(rule_id,group_key,reason,expires_at,proposed_by,approved_by,created_at)"
            " VALUES (?,?,'fixture',?,'analyst','admin',?)",
            (self.rule_id, key, iso(utcnow()+timedelta(days=1)), self.now)).lastrowid

    def test_unresolved_sibling_keeps_delimiter_exception_in_review(self):
        ids = self.events(["a", "b"] * 5)
        self.alert("a,b", ids)
        incomplete = self.alert("a,b", ids[:2], count=10)
        missing = self.alert("a,b", [], count=10)
        exception = self.suppress("a,b")
        for _ in range(2):
            result = engine.run_detection(self.conn)
            self.assertEqual(result["status"], "ok", result)
            self.assertEqual(result["alerts_suppressed"], 0)
            self.assertEqual(result["alerts_created"], 0)
            self.assertNotIn((self.rule_id, "a,b"), engine.active_suppressions(self.conn))
            reviews = self.conn.execute(
                "SELECT detail FROM audit_log WHERE action='suppression_needs_review'").fetchall()
            self.assertEqual(len(reviews), 1)
            detail = json.loads(reviews[0][0])
            self.assertEqual(detail["suppression_id"], exception)
            self.assertEqual(detail["unresolved_alert_ids"], [incomplete, missing])
            self.assertEqual(result["suppression_reviews"], [detail])

    def test_proven_alias_only_suppresses_its_own_group(self):
        for name in ("a,b", "(none)", "long," + "x" * 300):
            with self.subTest(name=name[:8]):
                ids = self.events([name] * 10, "192.0.2." + str(len(name) % 100 + 2))
                key = name if len(name) <= 256 else "sha256:" + hashlib.sha256(name.encode()).hexdigest()
                self.alert(key, ids)
                self.suppress(key)
        self.events(["a", "b"] * 5)
        self.events([None] * 10, "192.0.2.99")
        for created in (2, 0):
            result = engine.run_detection(self.conn)
            self.assertEqual(result["status"], "ok", result)
            self.assertEqual((result["alerts_suppressed"], result["alerts_created"]), (3, created))

    def test_resolved_alias_and_current_escaped_alert_survive_replay(self):
        self.alert("a,b", self.events(["a,b"] * 10), status="resolved")
        self.alert(r"c\,d", self.events(["c,d"] * 10, "192.0.2.2"))
        for _ in range(2):
            result = engine.run_detection(self.conn)
            self.assertEqual((result["alerts_created"], result["alerts_updated"]), (0, 0))
        self.assertEqual([r[0] for r in self.conn.execute("SELECT status FROM alerts ORDER BY id")],
                         ["resolved", "open"])

    def test_historical_identity_is_read_outside_writer_and_only_once(self):
        ids = self.events(["a,b"] * 10)
        old = self.alert("a,b", ids)
        reads = []
        def trace(sql):
            if "FROM alert_events ae JOIN events e" in sql:
                reads.append(self.conn.in_transaction)
        self.conn.set_trace_callback(trace)
        first = engine.run_detection(self.conn)
        self.assertEqual((first["status"], first["alerts_created"]), ("ok", 0))
        self.assertEqual(reads, [False])
        self.events(["a,b"] * 10, "192.0.2.2")
        second = engine.run_detection(self.conn)
        self.assertEqual((second["status"], second["alerts_updated"]), ("ok", 1))
        self.assertEqual(reads, [False])
        self.assertEqual(self.conn.execute("SELECT event_count FROM alerts WHERE id=?", (old,)).fetchone()[0], 20)

    def test_later_alert_cannot_supply_missing_approval_provenance(self):
        exception = self.suppress("a,b")
        self.conn.execute("UPDATE suppressions SET created_at=? WHERE id=?",
                          (iso(utcnow() - timedelta(days=1)), exception))
        self.alert("a,b", self.events(["a,b"] * 10))
        for _ in range(2):
            result = engine.run_detection(self.conn)
            self.assertEqual(result["alerts_suppressed"], 0)
            self.assertEqual([r["suppression_id"] for r in result["suppression_reviews"]], [exception])

    def test_removing_grouping_does_not_retarget_an_old_exception(self):
        self.events(["192.0.2.1"] * 10)
        self.suppress("192.0.2.1")
        self.conn.execute("UPDATE rule_history SET grouping=? WHERE rule_id=?", (json.dumps(["user"]), self.rule_id))
        self.conn.execute("UPDATE rules SET grouping='[]',version=2 WHERE id=?", (self.rule_id,))
        result = engine.run_detection(self.conn)
        self.assertEqual((result["alerts_created"], result["alerts_suppressed"]), (1, 0))
        self.assertEqual(len(result["suppression_reviews"]), 1)

    def test_old_grouping_cannot_authorize_an_exception_after_fields_change(self):
        ids = self.events(["a,b"] * 10)
        self.alert("a,b", ids)
        self.suppress("a,b")
        self.conn.execute("UPDATE rule_history SET grouping=? WHERE rule_id=? AND version=1",
                          (json.dumps(["host"]), self.rule_id))
        self.conn.execute("UPDATE rules SET version=2 WHERE id=?", (self.rule_id,))
        result = engine.run_detection(self.conn)
        self.assertEqual((result["status"], result["alerts_suppressed"]), ("ok", 0))
        self.assertEqual(len(result["suppression_reviews"]), 1)


if __name__ == "__main__":
    unittest.main()
