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


RULE = "brute_force_ip"
TS = "2026-11-01T12:00:00.000Z"


def _current_user_key(user):
    return grouping.apply([{"group_key": "old", "event_ids": [1]}], [{"id": 1, "user": user}], ["user"])[0]["group_key"]


def _legacy_user_key(user):
    """Pre-#111 key: folded text, no escaping, hashed only after 256 characters."""
    if len(user) > 256:
        return "sha256:" + hashlib.sha256(user.encode()).hexdigest()
    return user


class GroupKeyReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.conn.execute("UPDATE rules SET enabled = 0 WHERE id != ?", (RULE,))
        self.set_grouping(["user"])

    def set_grouping(self, fields):
        self.conn.execute("UPDATE rules SET grouping = ? WHERE id = ?", (json.dumps(fields), RULE))

    def plant_events(self, ip, user="alice", n=10, users=None):
        names = users if users is not None else [user] * n
        now = now_iso()
        ids = []
        for name in names:
            cur = self.conn.execute(
                "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip)"
                " VALUES (?,?,?,?,?,?,?)",
                (TS, now, "auth01", "auth_failure", "low", name, ip),
            )
            ids.append(cur.lastrowid)
        return ids

    def plant_alert(self, group_key, event_ids, status="open"):
        now = now_iso()
        cur = self.conn.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (RULE, 1, group_key, "high", "title", "explanation", status, TS, TS, len(event_ids), now, now),
        )
        self.conn.executemany(
            "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
            [(cur.lastrowid, event_id) for event_id in event_ids],
        )
        return cur.lastrowid

    def plant_suppression(self, group_key):
        cur = self.conn.execute(
            "INSERT INTO suppressions(rule_id, group_key, reason, expires_at, proposed_by, approved_by, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (RULE, group_key, "reviewed exception", iso(utcnow() + timedelta(days=7)),
             "analyst", "admin", now_iso()),
        )
        return cur.lastrowid

    def alerts(self):
        return [dict(row) for row in self.conn.execute(
            "SELECT id, group_key, status, event_count FROM alerts WHERE rule_id = ? ORDER BY id", (RULE,))]

    def suppression_keys(self):
        return [row["group_key"] for row in self.conn.execute(
            "SELECT group_key FROM suppressions WHERE rule_id = ? ORDER BY id", (RULE,))]

    def reviews(self):
        return [json.loads(row["detail"]) for row in self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'suppression_needs_review' ORDER BY id")]

    def rewrites(self):
        return [row["detail"] for row in self.conn.execute(
            "SELECT detail FROM alert_activity WHERE action = 'group_key_reconciled' ORDER BY id")]

    def test_resolve_stored_and_ordinary_key(self):
        literal = [{"id": 1, "user": "a,b"}]
        split = [{"id": 1, "user": "a"}, {"id": 2, "user": "b"}]
        self.assertEqual(grouping.resolve_stored("a,b", literal, ["user"]), ("legacy", "a\\,b"))
        self.assertEqual(grouping.resolve_stored("a\\,b", literal, ["user"]), ("current", "a\\,b"))
        self.assertEqual(grouping.resolve_stored("a,b", split, ["user"]), ("current", "a,b"))
        self.assertEqual(grouping.resolve_stored("a\\,b", split, ["user"]), ("unresolved", None))
        marked = [{"id": 1, "user": "(none)"}]
        missing = [{"id": 1, "user": None}]
        self.assertEqual(grouping.resolve_stored("(none)", marked, ["user"]), ("legacy", "\\(none)"))
        self.assertEqual(grouping.resolve_stored("\\(none)", marked, ["user"]), ("current", "\\(none)"))
        self.assertEqual(grouping.resolve_stored("(none)", missing, ["user"]), ("current", "(none)"))
        both = [{"id": 7, "user": "bob"}, {"id": 7, "user": "Alice"}]
        self.assertEqual(grouping.resolve_stored("alice", both, ["user"]), ("legacy", "alice,bob"))
        self.assertEqual(grouping.resolve_stored("alice,bob", both, ["user"]), ("current", "alice,bob"))
        self.assertEqual(grouping.resolve_stored("bob", both, ["user"]), ("unresolved", None))
        slashed = [{"id": 1, "user": "a\\,b"}]
        self.assertEqual(grouping.resolve_stored("a\\,b", slashed, ["user"])[0], "legacy")
        long_user = "a," + ("b" * 300)
        legacy = _legacy_user_key(long_user)
        current = _current_user_key(long_user)
        self.assertNotEqual(legacy, current)
        self.assertEqual(grouping.resolve_stored(legacy, [{"id": 1, "user": long_user}], ["user"]),
                         ("legacy", current))
        plain = "u" * 300
        plain_hash = _legacy_user_key(plain)
        self.assertEqual(plain_hash, _current_user_key(plain))
        self.assertEqual(grouping.resolve_stored(plain_hash, [{"id": 1, "user": plain}], ["user"]),
                         ("current", plain_hash))
        self.assertTrue(grouping.ordinary_key("alice", 1))
        self.assertTrue(grouping.ordinary_key("alice|web01", 2))
        for key, count in (("a,b", 1), ("a\\,b", 1), ("(none)", 1), ("\\(none)", 1),
                           ("sha256:" + "ab" * 32, 1), ("alice", 0), ("a|b", 1), ("", 1)):
            self.assertFalse(grouping.ordinary_key(key, count), key)
        self.assertFalse(grouping.ordinary_key(None, 1))

    def test_legacy_delimiter_suppression_follows_the_same_entity(self):
        ids = self.plant_events("203.0.113.10", user="a,b")
        self.plant_alert("a,b", ids)
        self.plant_suppression("a,b")
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        self.assertEqual(first["alerts_suppressed"], 1)
        self.assertEqual(first["alerts_created"], 0)
        self.assertEqual([row["group_key"] for row in self.alerts()], ["a\\,b"])
        self.assertEqual(self.suppression_keys(), ["a\\,b"])
        self.assertEqual(self.rewrites(), ["a,b -> a\\,b"])
        self.assertEqual(self.reviews(), [])
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(second["alerts_suppressed"], 1)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.rewrites(), ["a,b -> a\\,b"])

    def test_legacy_delimiter_does_not_cover_the_colliding_group(self):
        literal = self.plant_events("203.0.113.10", user="a,b")
        self.plant_alert("a,b", literal)
        self.plant_suppression("a,b")
        self.plant_events("203.0.113.11", users=["a"] * 5 + ["b"] * 5)
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        rows = self.alerts()
        self.assertEqual(sorted(row["group_key"] for row in rows), ["a,b", "a\\,b"])
        self.assertEqual(self.suppression_keys(), ["a\\,b"])
        self.assertEqual(first["alerts_created"], 1)
        self.assertEqual(first["alerts_suppressed"], 1)
        open_keys = sorted(row["group_key"] for row in rows if row["status"] == "open")
        self.assertEqual(open_keys, ["a,b", "a\\,b"])
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(len(self.alerts()), 2)
        self.assertEqual(self.suppression_keys(), ["a\\,b"])

    def test_ordinary_key_stays_applied(self):
        ids = self.plant_events("203.0.113.12", user="alice")
        self.plant_alert("alice", ids)
        self.plant_suppression("alice")
        run = engine.run_detection(self.conn)
        self.assertEqual(run["alerts_suppressed"], 1)
        self.assertEqual(run["alerts_created"], 0)
        self.assertEqual([row["group_key"] for row in self.alerts()], ["alice"])
        self.assertEqual(self.suppression_keys(), ["alice"])
        self.assertEqual(self.reviews(), [])
        self.assertEqual(self.rewrites(), [])

    def test_colliding_keys_stay_put_and_are_reviewed_once(self):
        literal = self.plant_events("203.0.113.10", user="a,b")
        split = self.plant_events("203.0.113.11", users=["a"] * 5 + ["b"] * 5)
        self.plant_alert("a,b", literal)
        self.plant_alert("a,b", split)
        self.plant_suppression("a,b")
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        rows = self.alerts()
        self.assertEqual([row["group_key"] for row in rows], ["a,b", "a,b"])
        self.assertEqual([row["status"] for row in rows], ["open", "open"])
        self.assertEqual(self.suppression_keys(), ["a,b"])
        self.assertEqual(first["alerts_suppressed"], 0)
        self.assertEqual(first["alerts_created"], 0)
        self.assertEqual(len(self.reviews()), 1)
        self.assertEqual(self.reviews()[0]["group_key"], "a,b")
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(second["alerts_suppressed"], 0)
        self.assertEqual(len(self.alerts()), 2)
        self.assertEqual(len(self.reviews()), 1)
        self.assertEqual(self.rewrites(), [])

    def test_literal_missing_marker_is_not_a_gap(self):
        literal = self.plant_events("203.0.113.13", user="(none)")
        self.plant_alert("(none)", literal)
        self.plant_suppression("(none)")
        self.plant_events("203.0.113.14", user=None)
        run = engine.run_detection(self.conn)
        self.assertEqual(sorted(row["group_key"] for row in self.alerts()), ["(none)", "\\(none)"])
        self.assertEqual(self.suppression_keys(), ["\\(none)"])
        self.assertEqual(run["alerts_suppressed"], 1)
        self.assertEqual(run["alerts_created"], 1)
        gap = next(row for row in self.alerts() if row["group_key"] == "(none)")
        self.assertEqual(gap["status"], "open")

    def test_colliding_missing_marker_suppresses_neither(self):
        literal = self.plant_events("203.0.113.13", user="(none)")
        gap = self.plant_events("203.0.113.14", user=None)
        self.plant_alert("(none)", literal)
        self.plant_alert("(none)", gap)
        self.plant_suppression("(none)")
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        rows = self.alerts()
        self.assertEqual([row["group_key"] for row in rows], ["(none)", "(none)"])
        self.assertEqual(len({row["id"] for row in rows}), 2)
        self.assertEqual(self.suppression_keys(), ["(none)"])
        self.assertEqual(first["alerts_suppressed"], 0)
        self.assertEqual(first["alerts_created"], 0)
        self.assertEqual(len(self.reviews()), 1)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(len(self.reviews()), 1)
        self.assertEqual(len(self.alerts()), 2)

    def test_hashed_legacy_key_follows_evidence(self):
        user = "a," + ("b" * 300)
        legacy, current = _legacy_user_key(user), _current_user_key(user)
        self.assertNotEqual(legacy, current)
        self.assertTrue(legacy.startswith("sha256:") and current.startswith("sha256:"))
        ids = self.plant_events("203.0.113.15", user=user)
        self.plant_alert(legacy, ids)
        self.plant_suppression(legacy)
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        self.assertEqual([row["group_key"] for row in self.alerts()], [current])
        self.assertEqual(self.suppression_keys(), [current])
        self.assertEqual(first["alerts_created"], 0)
        self.assertEqual(first["alerts_suppressed"], 1)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.reviews(), [])

    def test_hashed_ordinary_key_still_suppresses(self):
        user = "u" * 300
        stored = _legacy_user_key(user)
        self.assertEqual(stored, _current_user_key(user))
        ids = self.plant_events("203.0.113.16", user=user)
        self.plant_alert(stored, ids)
        self.plant_suppression(stored)
        run = engine.run_detection(self.conn)
        self.assertEqual(run["alerts_suppressed"], 1)
        self.assertEqual(run["alerts_created"], 0)
        self.assertEqual(self.suppression_keys(), [stored])
        self.assertEqual([row["group_key"] for row in self.alerts()], [stored])
        self.assertEqual(self.reviews(), [])

    def test_resolved_alert_is_not_resurrected(self):
        ids = self.plant_events("203.0.113.17", user="a,b")
        self.plant_alert("a,b", ids, status="resolved")
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "resolved")
        self.assertEqual(rows[0]["group_key"], "a\\,b")
        self.assertEqual(first["alerts_created"], 0)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(self.rewrites(), ["a,b -> a\\,b"])

    def test_escaped_key_is_not_rewritten(self):
        ids = self.plant_events("203.0.113.18", user="a,b")
        self.plant_alert("a\\,b", ids)
        self.plant_suppression("a\\,b")
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        self.assertEqual([row["group_key"] for row in self.alerts()], ["a\\,b"])
        self.assertEqual(self.suppression_keys(), ["a\\,b"])
        self.assertEqual(first["alerts_suppressed"], 1)
        self.assertEqual(first["alerts_created"], 0)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.rewrites(), [])
        self.assertEqual(self.reviews(), [])

    def test_ambiguous_suppression_without_evidence_stays_visible(self):
        self.plant_suppression("a\\,b")
        self.plant_events("203.0.113.19", user="a,b")
        first = engine.run_detection(self.conn)
        second = engine.run_detection(self.conn)
        self.assertEqual(first["alerts_suppressed"], 0)
        self.assertEqual(first["alerts_created"], 1)
        self.assertEqual([row["group_key"] for row in self.alerts()], ["a\\,b"])
        self.assertEqual([row["status"] for row in self.alerts()], ["open"])
        self.assertEqual(self.suppression_keys(), ["a\\,b"])
        self.assertEqual(len(self.reviews()), 1)
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(second["alerts_suppressed"], 0)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(len(self.reviews()), 1)
        self.assertEqual(self.suppression_keys(), ["a\\,b"])

    def test_unresolved_native_key_is_not_rewritten(self):
        ids = self.plant_events("203.0.113.9", user="Alice")
        self.plant_alert("203.0.113.9", ids)
        engine.run_detection(self.conn)
        engine.run_detection(self.conn)
        rows = self.alerts()
        self.assertEqual(sorted(row["group_key"] for row in rows), ["203.0.113.9", "alice"])
        self.assertEqual(self.reviews(), [])
        self.assertEqual(self.rewrites(), [])


if __name__ == "__main__":
    unittest.main()
