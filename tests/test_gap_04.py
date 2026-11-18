"""apply_rule_change rejects an unknown rule and records a validated merge.

An unknown id raises RuleConfigError and writes nothing. A params payload is
merged onto the stored params and passed through validate_params. The rule
version becomes the previous version plus one. rule_history and an audit row
with action rule_changed both record approved_by.
"""

import json
import unittest
from unittest.mock import patch

from watchpost.db import connect, init_schema
from watchpost.engine import apply_rule_change, seed_rules
from watchpost.rules import RuleConfigError, validate_params

RULE = "brute_force_ip"
CHANGED_BY = "analyst"
APPROVED_BY = "admin"
NOTE = "raise the threshold"
REQUEST_ID = 42


class ApplyRuleChangeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        seed_rules(self.conn)
        row = self.conn.execute(
            "SELECT version, params FROM rules WHERE id = ?", (RULE,)
        ).fetchone()
        self.old_version = row["version"]
        self.stored = json.loads(row["params"])

    def _change(self, rule_id=RULE, params=None, request_id=REQUEST_ID):
        payload = {} if params is None else {"params": params}
        return apply_rule_change(
            self.conn, rule_id, payload, CHANGED_BY, APPROVED_BY, request_id, NOTE
        )

    def _history(self, version):
        return self.conn.execute(
            "SELECT version, params, changed_by, approved_by FROM rule_history"
            " WHERE rule_id = ? AND version = ?",
            (RULE, version),
        ).fetchone()

    def _changed_audits(self):
        return self.conn.execute(
            "SELECT actor, action, target, detail FROM audit_log WHERE action = 'rule_changed'"
        ).fetchall()

    def _saved(self):
        row = self.conn.execute(
            "SELECT version, params FROM rules WHERE id = ?", (RULE,)
        ).fetchone()
        return row["version"], json.loads(row["params"])

    def test_an_unknown_rule_raises_rule_config_error(self):
        before_rules = [
            tuple(row)
            for row in self.conn.execute(
                "SELECT id, version, params FROM rules ORDER BY id"
            )
        ]
        before_history = self.conn.execute(
            "SELECT COUNT(*) FROM rule_history"
        ).fetchone()[0]
        with self.assertRaises(RuleConfigError) as caught:
            self._change("not_a_rule", {"threshold": 25})
        self.assertIn("not_a_rule", str(caught.exception))
        after_rules = [
            tuple(row)
            for row in self.conn.execute(
                "SELECT id, version, params FROM rules ORDER BY id"
            )
        ]
        self.assertEqual(after_rules, before_rules)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM rule_history").fetchone()[0],
            before_history,
        )
        self.assertEqual(self._changed_audits(), [])

    def test_a_params_merge_is_validated_and_the_approver_is_recorded(self):
        patch_params = {"threshold": 25}
        merged = {**self.stored, **patch_params}
        expected = validate_params(RULE, merged)
        with patch(
            "watchpost.engine.rules_mod.validate_params", wraps=validate_params
        ) as spy:
            version = self._change(params=patch_params)
        spy.assert_called_once_with(RULE, merged)
        self.assertEqual(version, self.old_version + 1)
        saved_version, saved_params = self._saved()
        self.assertEqual(saved_version, self.old_version + 1)
        self.assertEqual(saved_params, expected)
        self.assertEqual(saved_params["threshold"], 25)
        self.assertEqual(saved_params["window_seconds"], self.stored["window_seconds"])

        history = self._history(self.old_version + 1)
        self.assertEqual(history["approved_by"], APPROVED_BY)
        self.assertEqual(history["changed_by"], CHANGED_BY)
        self.assertEqual(json.loads(history["params"]), expected)

        audits = self._changed_audits()
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["actor"], APPROVED_BY)
        self.assertEqual(audits[0]["action"], "rule_changed")
        self.assertEqual(audits[0]["target"], RULE)
        self.assertEqual(
            json.loads(audits[0]["detail"]),
            {
                "version": self.old_version + 1,
                "change_request": REQUEST_ID,
            },
        )

        # A later patch is merged onto the stored params, not onto the defaults.
        stored = saved_params
        later = {"window_seconds": 900}
        later_merged = {**stored, **later}
        later_expected = validate_params(RULE, later_merged)
        with patch(
            "watchpost.engine.rules_mod.validate_params", wraps=validate_params
        ) as spy:
            later_version = self._change(params=later, request_id=REQUEST_ID + 1)
        spy.assert_called_once_with(RULE, later_merged)
        self.assertEqual(later_version, self.old_version + 2)
        saved_version, saved_params = self._saved()
        self.assertEqual(saved_version, self.old_version + 2)
        self.assertEqual(saved_params, later_expected)
        self.assertEqual(saved_params["threshold"], 25)
        self.assertEqual(saved_params["window_seconds"], 900)
        later_history = self._history(self.old_version + 2)
        self.assertEqual(later_history["approved_by"], APPROVED_BY)
        self.assertEqual(json.loads(later_history["params"]), later_expected)
        self.assertEqual(len(self._changed_audits()), 2)
        self.assertEqual(
            [row["actor"] for row in self._changed_audits()], [APPROVED_BY, APPROVED_BY]
        )

    def test_an_invalid_merge_is_rejected_without_a_new_version(self):
        for bad in ({"threshold": 1}, {"threshold": True}, {"not_a_param": 3}):
            with self.subTest(bad=bad):
                with self.assertRaises(RuleConfigError):
                    self._change(params=bad)
                version, params = self._saved()
                self.assertEqual(version, self.old_version)
                self.assertEqual(params, self.stored)
                self.assertIsNone(self._history(self.old_version + 1))
                self.assertEqual(self._changed_audits(), [])
