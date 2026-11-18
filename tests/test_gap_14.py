"""_validate_change refuses illegal rule, setting, and suppression payloads.

A rule_update may only carry params, enabled, and grouping, and enabled must
be a bool. A Sigma rule's params cannot change. A setting_update value must
sit inside SECURITY_SETTINGS. A suppression lasts 1 to MAX_SUPPRESSION_DAYS days.
"""

import json
import unittest

from watchpost import engine, improve
from watchpost.db import connect, init_schema

RULE = "brute_force_ip"
SIGMA = "sigma_gap14"
SIGMA_PARAMS = {"title": "gap14", "detection": {"field": "event_type"}}
RULE_KEYS = "rule changes may only contain params, enabled and/or grouping"
SIGMA_PARAMS_MSG = "a Sigma rule has no tunable params: change its YAML and import it again"


class ValidateChangeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, updated_at, updated_by)"
            " VALUES (?, ?, 'synthetic', 'medium', 0, ?, '2026-01-01T00:00:00.000Z', 'test')",
            (SIGMA, SIGMA, json.dumps(SIGMA_PARAMS)),
        )

    def _reject(self, kind, target, payload):
        with self.assertRaises(improve.ChangeError) as caught:
            improve._validate_change(self.conn, kind, target, payload)
        return caught.exception

    def test_rule_update_rejects_keys_other_than_params_enabled_and_grouping(self):
        payloads = (
            {"severity": "high"},
            {"enabled": False, "name": "renamed"},
            {"params": {}, "enabled": False, "grouping": None, "note": "x"},
        )
        for payload in payloads:
            with self.subTest(payload=sorted(payload)):
                err = self._reject("rule_update", RULE, payload)
                self.assertEqual(str(err), RULE_KEYS)
                self.assertEqual(err.status, 400)

    def test_rule_update_rejects_non_bool_enabled(self):
        for enabled in ("true", "false", 1, 0, None):
            with self.subTest(enabled=enabled):
                err = self._reject("rule_update", RULE, {"enabled": enabled})
                self.assertEqual(str(err), "enabled must be true or false")

    def test_bool_enabled_is_accepted(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                self.assertIsNone(improve._validate_change(
                    self.conn, "rule_update", RULE, {"enabled": enabled}))

    def test_sigma_params_mutation_is_rejected(self):
        mutations = (
            {"title": "rewritten"},
            {"detection": {"field": "user"}},
            {"threshold": 1},
        )
        for params in mutations:
            with self.subTest(params=sorted(params)):
                err = self._reject("rule_update", SIGMA, {"params": params})
                self.assertEqual(str(err), SIGMA_PARAMS_MSG)

    def test_sigma_unchanged_params_are_not_a_mutation(self):
        merged = improve._validate_change(
            self.conn, "rule_update", SIGMA, {"params": {"title": SIGMA_PARAMS["title"]}})
        self.assertEqual(merged, SIGMA_PARAMS)

    def test_setting_update_rejects_value_outside_security_settings_bounds(self):
        self.assertEqual(
            {key: bounds[:2] for key, bounds in improve.SECURITY_SETTINGS.items()},
            {
                "login_lockout_threshold": (3, 20),
                "login_lockout_minutes": (1, 1440),
                "viewer_masking": (0, 1),
            },
        )
        for key, (low, high, _default, _desc) in improve.SECURITY_SETTINGS.items():
            for value in (low - 1, high + 1):
                with self.subTest(key=key, value=value):
                    err = self._reject("setting_update", key, {"value": value})
                    self.assertEqual(str(err), f"{key} must be an integer between {low} and {high}")

    def test_setting_update_accepts_inclusive_bounds(self):
        for key, (low, high, _default, _desc) in improve.SECURITY_SETTINGS.items():
            for value in (low, high):
                with self.subTest(key=key, value=value):
                    self.assertIsNone(improve._validate_change(
                        self.conn, "setting_update", key, {"value": value}))

    def test_suppression_days_outside_1_to_90_are_rejected(self):
        self.assertEqual(improve.MAX_SUPPRESSION_DAYS, 90)
        for days in (0, 91, -5, 365):
            with self.subTest(days=days):
                err = self._reject(
                    "suppression_add", RULE, {"group_key": "198.51.100.9", "days": days})
                self.assertEqual(str(err), "days must be an integer between 1 and 90")

    def test_suppression_days_at_1_and_90_are_accepted(self):
        for days in (1, improve.MAX_SUPPRESSION_DAYS):
            with self.subTest(days=days):
                self.assertIsNone(improve._validate_change(
                    self.conn, "suppression_add", RULE,
                    {"group_key": "198.51.100.9", "days": days}))


if __name__ == "__main__":
    unittest.main()
