"""Edge cases in rule export and import. The HTTP contract stays in test_portability.py."""

import copy
import json
import unittest
from unittest.mock import patch

from watchpost import improve, portability
from watchpost.db import connect, init_schema
from watchpost.engine import load_rules, seed_rules

RULE = "brute_force_ip"
OTHER = "password_spray"
SIGMA_ID = "sigma_round_trip"
SIGMA_PARAMS = {
    "title": "Round trip",
    "detection": {"op": "match", "field": "event_type", "mod": "eq", "all": False, "values": ["auth_failure"]},
}


def _insert(conn, rule_id, params, enabled=1, techniques="[]", grouping="[]"):
    raw = params if isinstance(params, str) else json.dumps(params)
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by,"
        " techniques, grouping) VALUES (?,?,?,?,?,?,1,?,?,?,?)",
        (rule_id, rule_id, "test rule", "low", enabled, raw, "2026-01-01T00:00:00Z", "system", techniques, grouping),
    )


class PortabilityBlitzTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        seed_rules(self.conn)

    def tearDown(self):
        self.conn.close()

    def exported(self):
        return portability.export_rules(self.conn)

    def rule(self, rule_id=RULE):
        return next(r for r in self.exported()["rules"] if r["id"] == rule_id)

    def plan(self, rules):
        doc = self.exported()
        doc["rules"] = rules
        return portability.plan_import(self.conn, doc)

    def item(self, plan, rule_id):
        return next(row for row in plan if row["id"] == rule_id)

    def live(self, rule_id=RULE):
        return next(r for r in load_rules(self.conn, enabled_only=False) if r["id"] == rule_id)

    def test_export_round_trip_is_unchanged(self):
        doc = self.exported()
        ids = [r["id"] for r in doc["rules"]]
        self.assertEqual(ids, sorted(ids))
        self.assertIn(RULE, ids)
        rule = doc["rules"][ids.index(RULE)]
        self.assertIs(rule["enabled"], True)
        self.assertEqual(rule["techniques"], ["T1110.001"])
        self.assertEqual(rule["params"]["threshold"], 10)
        self.assertEqual(set(rule), portability.RULE_KEYS)
        plan = portability.plan_import(self.conn, doc)
        self.assertEqual({row["outcome"] for row in plan}, {"unchanged"})
        self.assertEqual(portability.summary(plan), {"proposed": 0, "unchanged": len(plan), "refused": 0})
        self.assertEqual(portability.to_propose(plan), 0)
        portability.propose_import(self.conn, plan, "round-trip.json", "analyst")
        self.assertTrue(all(row["outcome"] == "unchanged" for row in plan))
        self.assertFalse(any("change_id" in row for row in plan))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM change_requests").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'change_proposed'").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'rules_imported'").fetchone()[0], 1)
        self.assertEqual(self.live()["params"]["threshold"], 10)
        self.assertEqual(self.live()["enabled"], 1)

    def test_document_level_refusals(self):
        doc = self.exported()
        bad = [
            [],
            {**doc, "format": "sigma"},
            {**doc, "format_version": 2},
            {**doc, "format_version": True},
            {**doc, "format_version": 1.0},
            {**doc, "format_version": "1"},
            {k: v for k, v in doc.items() if k != "format_version"},
            {**doc, "rules": None},
            {**doc, "extra": 1},
            {**doc, "rules": [{"id": RULE}] * (portability.MAX_IMPORT_RULES + 1)},
        ]
        for document in bad:
            with self.subTest(document=type(document).__name__):
                with self.assertRaises(improve.ChangeError):
                    portability.plan_import(self.conn, document)
        self.assertEqual(portability.plan_import(self.conn, {**doc, "rules": []}), [])

    def test_equal_float_does_not_bypass_integer_param_validation(self):
        row = self.rule()
        row["params"]["threshold"] = float(row["params"]["threshold"])
        row["enabled"] = False
        self.assertEqual(self.plan([row])[0]["outcome"], "refused")

    def test_non_dict_params_refuse_one_rule(self):
        good_id = "account_repeated_failures"
        good = self.rule(good_id)
        good["params"] = {**good["params"], "threshold": 21}
        plan = self.plan([
            {**self.rule(), "params": ["nope"]},
            {**self.rule(OTHER), "params": None},
            {**self.rule("web_scanner"), "params": "nope"},
            good,
        ])
        self.assertEqual([row["outcome"] for row in plan], ["refused", "refused", "refused", "would_propose"])
        for row in plan[:3]:
            self.assertIn("params must be an object", row["reason"])
        self.assertEqual(self.item(plan, good_id)["changes"], {"params": {"threshold": 21}})

    def test_id_only_blank_and_duplicate_entries(self):
        plan = self.plan([{"id": RULE}, {"id": ""}, {"id": "   "}, {"id": " brute_force_ip"}])
        self.assertEqual(plan[0]["outcome"], "unchanged")
        self.assertIsNone(plan[1]["id"])
        self.assertIsNone(plan[2]["id"])
        self.assertIn("rule entry 1", plan[1]["reason"])
        self.assertIn("rule entry 2", plan[2]["reason"])
        self.assertIn("non-empty string id", plan[1]["reason"])
        self.assertIn("unknown rule", plan[3]["reason"])
        changed = self.rule()
        changed["params"] = {**changed["params"], "threshold": 25}
        again = self.plan([changed, {**changed}])
        self.assertEqual(again[0]["outcome"], "would_propose")
        self.assertEqual(again[0]["changes"], {"params": {"threshold": 25}})
        self.assertEqual(again[1]["outcome"], "refused")
        self.assertIn("duplicate", again[1]["reason"])

    def test_unknown_rule_key_enabled_and_grouping(self):
        self.conn.execute("UPDATE rules SET grouping = ? WHERE id = ?", ('["src_ip", "user"]', RULE))
        base = self.rule()
        refused = [
            ({**base, "id": "no_such_rule"}, "unknown rule"),
            ({**base, "logic": "def x(): pass"}, "unknown key(s): logic"),
            ({**base, "enabled": "yes"}, "enabled must be true or false"),
            ({**base, "enabled": 1}, "enabled must be true or false"),
            ({**base, "params": {**base["params"], "threshold": True}}, "threshold must be an integer"),
            ({**base, "grouping": "src_ip"}, "grouping must be a list"),
            ({**base, "grouping": ["src_ip", "dest_ip", "user", "host"]}, "up to 3 unique fields"),
            ({**base, "grouping": ["src_ip", "src_ip"]}, "up to 3 unique fields"),
            ({**base, "grouping": ["not_a_field"]}, "up to 3 unique fields"),
        ]
        for entry, text in refused:
            with self.subTest(text=text):
                row = self.plan([entry])[0]
                self.assertEqual(row["outcome"], "refused")
                self.assertIn(text, row["reason"])
        reordered = {**base, "grouping": ["user", "src_ip"]}
        self.assertEqual(self.plan([reordered])[0],
                         {"id": RULE, "outcome": "would_propose", "changes": {"grouping": ["user", "src_ip"]}})
        self.assertEqual(self.plan([{**base, "grouping": ["src_ip", "user"]}])[0]["outcome"], "unchanged")

    def test_list_spelling_is_proposed_and_detached(self):
        entry = self.rule()
        entry["params"] = {**entry["params"], "ignore_users": ["Alice"]}
        entry["grouping"] = ["src_ip"]
        plan = self.plan([entry])
        changes = plan[0]["changes"]
        self.assertEqual(changes["params"], {"ignore_users": ["Alice"]})
        self.assertEqual(changes["grouping"], ["src_ip"])
        changes["params"]["ignore_users"].append("bob")
        changes["grouping"].append("host")
        self.assertEqual(entry["params"]["ignore_users"], ["Alice"])
        self.assertEqual(entry["grouping"], ["src_ip"])

    def test_enabled_sigma_round_trip_skips_the_sample_gate(self):
        _insert(self.conn, SIGMA_ID, SIGMA_PARAMS, enabled=1)
        doc = self.exported()
        plan = portability.plan_import(self.conn, doc)
        self.assertEqual(self.item(plan, SIGMA_ID)["outcome"], "unchanged")
        sigma = self.rule(SIGMA_ID)
        sigma["grouping"] = ["src_ip"]
        grouped = self.plan([sigma])
        self.assertEqual(grouped[0]["outcome"], "would_propose")
        self.assertEqual(grouped[0]["changes"], {"grouping": ["src_ip"]})
        self.assertNotIn("reason", grouped[0])
        sigma["params"] = {**sigma["params"], "title": "Renamed"}
        sigma["grouping"] = []
        renamed = self.plan([sigma])
        self.assertEqual(renamed[0]["outcome"], "refused")
        self.assertIn("no tunable params", renamed[0]["reason"])
        _insert(self.conn, "sigma_disabled", SIGMA_PARAMS, enabled=0)
        disabled = self.rule("sigma_disabled")
        disabled["enabled"] = True
        turned_on = self.plan([disabled])
        self.assertEqual(turned_on[0]["outcome"], "refused")
        self.assertIn("cannot be enabled", turned_on[0]["reason"])
        self.assertIn("no sample", turned_on[0]["reason"])

    def test_corrupt_stored_params_do_not_fail_the_document(self):
        self.conn.execute("UPDATE rules SET params = ? WHERE id = ?", (json.dumps({"threshold": "lots"}), RULE))
        doc = self.exported()
        rule = next(r for r in doc["rules"] if r["id"] == RULE)
        self.assertEqual(rule["params"], {"threshold": "lots"})
        other = next(r for r in doc["rules"] if r["id"] == OTHER)
        self.assertIsInstance(other["params"]["distinct_users"], int)
        rule["enabled"] = False
        plan = portability.plan_import(self.conn, doc)
        self.assertEqual(self.item(plan, RULE), {"id": RULE, "outcome": "would_propose", "changes": {"enabled": False}})
        self.assertEqual(self.item(plan, OTHER)["outcome"], "unchanged")
        repaired = self.rule()
        repaired["params"] = {"threshold": 12, "window_seconds": 300, "ignore_ips": [], "ignore_users": []}
        repair = self.plan([repaired])
        self.assertEqual(repair[0]["outcome"], "would_propose")
        self.assertEqual(repair[0]["changes"]["params"]["threshold"], 12)
        self.conn.execute("UPDATE rules SET params = ?, enabled = 1 WHERE id = ?", ("[]", RULE))
        raw = self.exported()
        listed = next(r for r in raw["rules"] if r["id"] == RULE)
        self.assertEqual(listed["params"], [])
        self.assertEqual(self.item(portability.plan_import(self.conn, raw), RULE)["outcome"], "unchanged")
        listed["params"] = {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []}
        merged = portability.plan_import(self.conn, raw)
        self.assertEqual(self.item(merged, RULE)["outcome"], "refused")
        self.assertIn("cannot be merged", self.item(merged, RULE)["reason"])
        listed["params"] = []
        listed["enabled"] = False
        disabled = portability.plan_import(self.conn, raw)
        self.assertEqual(self.item(disabled, RULE)["changes"], {"enabled": False})

    def test_string_techniques_export(self):
        self.conn.execute(
            "UPDATE rules SET techniques = ? WHERE id = ?",
            (json.dumps(["T1110.001", {"id": "T1110"}, {"id": 3}, "ok"]), RULE),
        )
        self.assertEqual(self.rule()["techniques"], ["T1110.001", "T1110", "ok"])
        self.conn.execute("UPDATE rules SET techniques = ? WHERE id = ?", (json.dumps("T1110.001"), RULE))
        self.assertEqual(self.rule()["techniques"], [])

    def test_propose_import_is_pending_and_audited(self):
        changed = self.rule()
        changed["params"] = {**changed["params"], "threshold": 25}
        changed["enabled"] = False
        plan = self.plan([None, {"enabled": True}, changed, {"id": OTHER}])
        portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        proposed = self.item(plan, RULE)
        self.assertEqual(proposed["outcome"], "proposed")
        self.assertEqual(proposed["changes"], {"params": {"threshold": 25}, "enabled": False})
        self.assertEqual(plan[0]["outcome"], "refused")
        self.assertEqual(plan[1]["outcome"], "refused")
        self.assertEqual(plan[3]["outcome"], "unchanged")
        row = self.conn.execute("SELECT reason, payload, status, proposed_by FROM change_requests WHERE id = ?",
                                (proposed["change_id"],)).fetchone()
        self.assertEqual(row["reason"], "imported from tuning.json")
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["proposed_by"], "analyst")
        self.assertEqual(json.loads(row["payload"]), {"enabled": False, "params": {"threshold": 25}})
        live = self.live()
        self.assertEqual(live["params"]["threshold"], 10)
        self.assertEqual(live["enabled"], 1)
        detail = json.loads(self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'rules_imported'").fetchone()["detail"])
        self.assertEqual(detail["proposed"], [proposed["change_id"]])
        self.assertEqual(detail["unchanged"], 1)
        self.assertEqual(set(detail["refused"]), {"None", "None#2"})
        self.assertIn("rule entry 0", detail["refused"]["None"])
        self.assertIn("rule entry 1", detail["refused"]["None#2"])
        self.assertEqual(portability.summary(plan)["proposed"], 1)
        with self.assertRaises(improve.ChangeError) as caught:
            improve.review_change(self.conn, proposed["change_id"], "approve", "analyst", note="own review")
        self.assertIn("second person", str(caught.exception))
        self.assertEqual(self.conn.execute(
            "SELECT status FROM change_requests WHERE id = ?", (proposed["change_id"],)).fetchone()["status"],
            "pending")

    def test_change_error_keeps_earlier_proposals(self):
        first = self.rule()
        first["params"] = {**first["params"], "threshold": 25}
        second = self.rule(OTHER)
        second["enabled"] = False
        plan = self.plan([first, second])
        real = improve.propose_change

        def gate(conn, kind, target, payload, reason, actor):
            if target == OTHER:
                raise improve.ChangeError("blocked by the gate")
            return real(conn, kind, target, payload, reason, actor)

        with patch.object(portability.improve, "propose_change", gate):
            portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self.assertEqual(plan[0]["outcome"], "proposed")
        self.assertEqual(plan[1]["outcome"], "refused")
        self.assertEqual(plan[1]["reason"], "blocked by the gate")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM change_requests").fetchone()[0], 1)
        detail = json.loads(self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'rules_imported'").fetchone()["detail"])
        self.assertEqual(detail["proposed"], [plan[0]["change_id"]])
        self.assertEqual(detail["refused"], {OTHER: "blocked by the gate"})

    def _two_accepted(self):
        refused = {"id": "no_such_rule"}
        first = self.rule()
        first["enabled"] = False
        second = self.rule(OTHER)
        second["enabled"] = False
        plan = self.plan([refused, first, second])
        self.assertEqual([row["outcome"] for row in plan], ["refused", "would_propose", "would_propose"])
        return plan

    def _assert_rolled_back(self, plan, before):
        self.assertEqual(plan, before)
        self.assertFalse(self.conn.in_transaction)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM change_requests WHERE status = 'pending'").fetchone()[0], 0)
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM audit_log WHERE action = 'rules_imported'").fetchone())
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM audit_log WHERE action = 'change_proposed'").fetchone())
        self.assertEqual(self.live()["enabled"], 1)
        self.assertEqual(self.live(OTHER)["enabled"], 1)

    def _assert_one_sequence(self, plan, refused_reason):
        self.assertEqual(plan[0]["outcome"], "refused")
        self.assertEqual(plan[0]["reason"], refused_reason)
        accepted = [plan[1], plan[2]]
        self.assertEqual([row["outcome"] for row in accepted], ["proposed", "proposed"])
        ids = [row["change_id"] for row in accepted]
        self.assertEqual(len(ids), len(set(ids)))
        rows = self.conn.execute(
            "SELECT id, target, status, proposed_by FROM change_requests ORDER BY id").fetchall()
        self.assertEqual([(row["id"], row["target"], row["status"], row["proposed_by"]) for row in rows],
                         [(ids[0], RULE, "pending", "analyst"), (ids[1], OTHER, "pending", "analyst")])
        proposed_audits = self.conn.execute(
            "SELECT target, detail FROM audit_log WHERE action = 'change_proposed' ORDER BY id").fetchall()
        self.assertEqual([(row["target"], json.loads(row["detail"])["id"]) for row in proposed_audits],
                         [(f"rule_update:{RULE}", ids[0]), (f"rule_update:{OTHER}", ids[1])])
        imported = self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'rules_imported' ORDER BY id").fetchall()
        self.assertEqual(len(imported), 1)
        detail = json.loads(imported[0]["detail"])
        self.assertEqual(detail["proposed"], ids)
        self.assertEqual(detail["unchanged"], 0)
        self.assertEqual(detail["refused"], {"no_such_rule": refused_reason})
        for change_id in ids:
            with self.assertRaises(improve.ChangeError) as caught:
                improve.review_change(self.conn, change_id, "approve", "analyst", note="own review")
            self.assertIn("second person", str(caught.exception))
            self.assertEqual(self.conn.execute(
                "SELECT status FROM change_requests WHERE id = ?", (change_id,)).fetchone()["status"], "pending")
        self.assertEqual(self.live()["enabled"], 1)
        self.assertEqual(self.live(OTHER)["enabled"], 1)
        self.assertFalse(self.conn.in_transaction)

    def test_enclosing_rollback_keeps_the_input_plan_reusable(self):
        plan = self._two_accepted()
        before = copy.deepcopy(plan)
        self.conn.execute("BEGIN IMMEDIATE")
        result = portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self.assertEqual(result[1]["outcome"], "proposed")
        self.assertEqual(plan, before)
        self.conn.rollback()
        self._assert_rolled_back(plan, before)
        portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self._assert_one_sequence(plan, before[0]["reason"])

    def test_refused_ids_do_not_overwrite_another_rows_audit_reason(self):
        plan = self.plan([{"id": "unknown"}, {"id": "unknown"}, {"id": "unknown#2"}])
        portability.propose_import(self.conn, plan, "fixture", "analyst")
        reasons = json.loads(self.conn.execute(
            "SELECT detail FROM audit_log WHERE action='rules_imported'").fetchone()[0])["refused"]
        self.assertCountEqual(reasons.values(), [row["reason"] for row in plan])

    def test_unexpected_error_rolls_back_the_import(self):
        plan = self._two_accepted()
        before = copy.deepcopy(plan)
        real = improve.propose_change
        calls = {"n": 0}

        def boom(conn, kind, target, payload, reason, actor):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("disk failed")
            return real(conn, kind, target, payload, reason, actor)

        with patch.object(portability.improve, "propose_change", boom):
            with self.assertRaises(RuntimeError):
                portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self.assertEqual(calls["n"], 2)
        self._assert_rolled_back(plan, before)
        portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self._assert_one_sequence(plan, before[0]["reason"])

    def test_failed_import_audit_leaves_the_plan_reusable(self):
        plan = self._two_accepted()
        before = copy.deepcopy(plan)
        real_audit = portability.audit

        def boom(conn, actor, action, target=None, detail=None):
            if action == "rules_imported":
                raise RuntimeError("audit failed")
            return real_audit(conn, actor, action, target, detail)

        with patch.object(portability, "audit", boom):
            with self.assertRaises(RuntimeError):
                portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self._assert_rolled_back(plan, before)
        portability.propose_import(self.conn, plan, "tuning.json", "analyst")
        self._assert_one_sequence(plan, before[0]["reason"])

    def test_summary_uses_would_propose_only_while_a_dry_run_has_one(self):
        changed = self.rule()
        changed["params"] = {**changed["params"], "threshold": 30}
        dry = self.plan([changed, {"id": OTHER}])
        self.assertEqual(portability.summary(dry), {"would_propose": 1, "unchanged": 1, "refused": 0})
        self.assertEqual(portability.to_propose(dry), 1)
        quiet = self.plan([{"id": RULE}])
        self.assertEqual(portability.summary(quiet), {"proposed": 0, "unchanged": 1, "refused": 0})
        self.assertNotIn("would_propose", portability.summary(quiet))
