"""Bugs in suggestion generation and change review that aborted the request.

A rule with no ignore list (log_source_silent) must not crash the catalog.
A Sigma params value that is not an object is a ChangeError, as it is for search rules.
A review note that is not a string is a ChangeError, and a string note is stored stripped.
"""

import unittest

from watchpost.db import connect, init_schema, now_iso
from watchpost.engine import load_rules, seed_rules
from watchpost.improve import (
    ChangeError,
    generate_suggestions,
    get_change,
    propose_change,
    review_change,
    seed_settings,
    suggest_for_rule,
    validate_rule_update,
)

TS = "2026-09-15T12:00:00.000Z"


def add_event(conn, src_ip=None, user=None):
    cur = conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, synthetic)"
        " VALUES (?, ?, 'auth', 'host1', 'login_failed', 'medium', ?, ?, 1)",
        (TS, TS, user, src_ip),
    )
    return cur.lastrowid


def add_alert(conn, rule_id, src_ip=None, user=None, event_count=1, disposition="false_positive"):
    event_id = add_event(conn, src_ip, user)
    cur = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?, 1, ?, 'medium', 'synthetic alert', 'why', 'resolved', ?, ?, ?, ?, 1, ?, ?)",
        (rule_id, f"{rule_id}-{event_id}", disposition, TS, TS, event_count, TS, TS),
    )
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)", (cur.lastrowid, event_id))
    return cur.lastrowid


class SuggestionTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        seed_rules(self.conn)
        self.addCleanup(self.conn.close)

    def test_silence_rule_feedback_does_not_abort_suggestions(self):
        for _ in range(2):
            add_alert(self.conn, "log_source_silent", src_ip="10.1.2.3", user="scanner")
        for _ in range(2):
            add_alert(self.conn, "brute_force_ip", src_ip="10.0.50.5", user="alice")
        created = generate_suggestions(self.conn)
        by_target = {c["target"]: c for c in created}
        self.assertNotIn("log_source_silent", by_target)
        self.assertEqual(by_target["brute_force_ip"]["payload"], {"params": {"ignore_ips": ["10.0.50.5"]}})
        self.assertEqual(by_target["brute_force_ip"]["status"], "pending")

    def test_ignore_list_shape_is_unchanged_for_a_rule_that_has_one(self):
        for _ in range(2):
            add_alert(self.conn, "brute_force_ip", src_ip="10.0.50.5")
        rule = next(r for r in load_rules(self.conn, enabled_only=False) if r["id"] == "brute_force_ip")
        suggestion = suggest_for_rule(self.conn, rule)
        self.assertEqual(suggestion["params"], {"ignore_ips": ["10.0.50.5"]})

    def test_user_suggestion_when_the_rule_has_no_ignore_ips(self):
        for _ in range(2):
            add_alert(self.conn, "users_only", src_ip="10.9.9.9", user="bob")
        suggestion = suggest_for_rule(self.conn, {"id": "users_only", "params": {"ignore_users": []}})
        self.assertEqual(suggestion["params"], {"ignore_users": ["bob"]})

    def test_missing_ignore_lists_still_reaches_the_threshold(self):
        for _ in range(2):
            add_alert(self.conn, "counted", src_ip="10.8.8.8", user="carol", event_count=12)
        add_alert(self.conn, "counted", event_count=20, disposition="true_positive")
        suggestion = suggest_for_rule(self.conn, {"id": "counted", "params": {"threshold": 10}})
        self.assertEqual(suggestion["params"], {"threshold": 13})

    def test_a_rule_with_no_ignore_list_and_no_threshold_suggests_nothing(self):
        for _ in range(2):
            add_alert(self.conn, "log_source_silent", src_ip="10.1.2.3", user="scanner")
        rule = next(r for r in load_rules(self.conn, enabled_only=False) if r["id"] == "log_source_silent")
        self.assertIsNone(suggest_for_rule(self.conn, rule))


class ChangeInputTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        seed_settings(self.conn)
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by)"
            " VALUES ('sigma_test', 'Sigma test', 'compiled', 'low', 0, '{}', 1, ?, 'system')",
            (now_iso(),),
        )
        self.addCleanup(self.conn.close)

    def test_sigma_params_must_be_an_object(self):
        with self.assertRaises(ChangeError) as raised:
            validate_rule_update(self.conn, "sigma_test", {"params": ["nope"]})
        self.assertIn("params must be an object", str(raised.exception))
        self.assertEqual(validate_rule_update(self.conn, "sigma_test", {"params": {}}), {})
        with self.assertRaises(ChangeError) as raised:
            validate_rule_update(self.conn, "sigma_test", {"params": {"title": "renamed"}})
        self.assertIn("no tunable params", str(raised.exception))

    def test_review_note_must_be_a_string(self):
        change = propose_change(
            self.conn, "setting_update", "viewer_masking", {"value": 1},
            "mask names for viewer accounts", "analyst",
        )
        with self.assertRaises(ChangeError) as raised:
            review_change(self.conn, change["id"], "reject", "admin", note=123)
        self.assertIn("note must be a string", str(raised.exception))
        self.assertEqual(get_change(self.conn, change["id"])["status"], "pending")
        reviewed = review_change(self.conn, change["id"], "reject", "admin", note="  not now  ")
        self.assertEqual(reviewed["status"], "rejected")
        self.assertEqual(reviewed["review_note"], "not now")
