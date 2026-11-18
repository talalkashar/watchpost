"""Edge cases for public improve helpers that the other suites do not assert.

Covered here: sampled_family prefix boundaries, suggest_for_rule feedback
thresholds, generate_suggestions skipping sampled rules, setting seed/list
defaults, proposal reason and setting bounds, review-note length, and
evidence_digest stability. Happy paths that already run through the API
(one scanner IP suggestion, lockout threshold 3, digest across ingested
events) are left to those tests.
"""

import unittest

from watchpost import search_rules, sigma
from watchpost.db import connect, init_schema
from watchpost.engine import seed_rules
from watchpost.improve import (
    SECURITY_SETTINGS,
    ChangeError,
    evidence_digest,
    generate_suggestions,
    get_change,
    list_settings,
    propose_change,
    review_change,
    sampled_family,
    seed_settings,
    suggest_for_rule,
)

TS = "2026-09-15T12:00:00.000Z"
RULE = "brute_force_ip"


class DbCase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)


def add_event(conn, src_ip, user):
    cur = conn.execute(
        "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip)"
        " VALUES (?,?,?,?,?,?,?)",
        (TS, TS, "auth", "login_failure", "low", user, src_ip),
    )
    return cur.lastrowid


def add_alert(conn, rule_id, disposition, event_count, evidence=()):
    n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] + 1
    cur = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
        " status, disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?, 1, ?, 'medium', 'synthetic alert', 'why', 'resolved', ?, ?, ?, ?, 1, ?, ?)",
        (rule_id, f"g{n}", disposition, TS, TS, event_count, TS, TS),
    )
    alert_id = cur.lastrowid
    for src_ip, user in evidence:
        event_id = add_event(conn, src_ip, user)
        conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)", (alert_id, event_id))
    return alert_id


def rule(rule_id=RULE, **overrides):
    params = {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []}
    params.update(overrides)
    return {"id": rule_id, "params": params}


class SampledFamilyTests(unittest.TestCase):
    def test_prefix_boundaries(self):
        self.assertIs(sampled_family("sigma_web"), sigma)
        self.assertIs(sampled_family("search_web"), search_rules)
        # sigma is checked first, so a sigma id that continues with "search" stays sigma.
        self.assertIs(sampled_family("sigma_search_web"), sigma)
        self.assertIs(sampled_family("search_sigma_web"), search_rules)
        for rule_id in ("", "sigma", "search", "Sigma_web", "xsigma_web", "brute_force_ip"):
            self.assertIsNone(sampled_family(rule_id), rule_id)


class SuggestForRuleTests(DbCase):
    def suggest(self, **overrides):
        return suggest_for_rule(self.conn, rule(**overrides))

    def test_fewer_than_two_false_positives_returns_none(self):
        self.assertIsNone(self.suggest())
        add_alert(self.conn, RULE, "false_positive", 4, [("203.0.113.5", "ann")])
        add_alert(self.conn, RULE, "benign", 9, [("203.0.113.5", "ann")])
        add_alert(self.conn, RULE, "true_positive", 12, [("203.0.113.5", "ann")])
        add_alert(self.conn, RULE, None, 9, [("203.0.113.5", "ann")])
        self.assertIsNone(self.suggest())

    def test_alerts_for_another_rule_do_not_count(self):
        add_alert(self.conn, "password_spray", "false_positive", 4, [("203.0.113.5", "ann")])
        add_alert(self.conn, "password_spray", "false_positive", 4, [("203.0.113.5", "ann")])
        self.assertIsNone(self.suggest())

    def test_an_ip_needs_two_alerts_and_is_appended_in_sorted_order(self):
        # Two events on one alert are one IP. Each of these IPs is on a single alert.
        add_alert(self.conn, RULE, "false_positive", 3, [("10.9.0.1", None), ("10.9.0.1", "a")])
        add_alert(self.conn, RULE, "false_positive", 4, [("10.1.0.1", "b")])
        self.assertIsNone(self.suggest())
        add_alert(self.conn, RULE, "false_positive", 5, [
            ("10.9.0.1", None), ("10.1.0.1", ""), ("", "bob"), (None, None),
        ])
        got = self.suggest(ignore_ips=["192.0.2.9"])
        self.assertEqual(got["params"], {"ignore_ips": ["192.0.2.9", "10.1.0.1", "10.9.0.1"]})
        self.assertNotIn("bob", got["reason"])
        self.assertIn("appeared in 2", got["reason"])

    def test_an_ip_seen_in_a_true_positive_or_already_ignored_is_left_out(self):
        evidence = [("203.0.113.8", None), ("198.51.100.7", None)]
        add_alert(self.conn, RULE, "false_positive", 4, evidence)
        add_alert(self.conn, RULE, "false_positive", 4, evidence)
        add_alert(self.conn, RULE, "true_positive", 12, [("203.0.113.8", None)])
        got = self.suggest()
        self.assertEqual(got["params"], {"ignore_ips": ["198.51.100.7"]})
        self.assertNotIn("203.0.113.8", got["reason"])
        self.assertIsNone(self.suggest(ignore_ips=["198.51.100.7"]))

    def test_users_are_suggested_only_after_ips_and_stay_sorted(self):
        add_alert(self.conn, RULE, "false_positive", 3, [("10.0.0.1", "zoe"), ("10.0.0.1", "amy")])
        add_alert(self.conn, RULE, "false_positive", 4, [("10.0.0.2", "amy"), ("10.0.0.2", "zoe")])
        got = self.suggest(ignore_users=["kept"])
        self.assertEqual(got["params"], {"ignore_users": ["kept", "amy", "zoe"]})
        self.assertIn("amy, zoe", got["reason"])
        add_alert(self.conn, RULE, "true_positive", 11, [("10.0.0.3", "amy")])
        got = self.suggest(ignore_users=["kept"])
        self.assertEqual(got["params"], {"ignore_users": ["kept", "zoe"]})
        self.assertIsNone(self.suggest(ignore_users=["kept", "zoe"]))

    def test_threshold_rises_only_inside_the_gap_between_labels(self):
        add_alert(self.conn, RULE, "false_positive", 4)
        add_alert(self.conn, RULE, "false_positive", 6)
        self.assertIsNone(self.suggest(threshold=5))  # no true positive to protect
        add_alert(self.conn, RULE, "true_positive", 9)
        add_alert(self.conn, RULE, "true_positive", 12)
        # max false positive is 6, min true positive is 9: 6 <= 6 < 9, so the new threshold is 7.
        self.assertEqual(self.suggest(threshold=6)["params"], {"threshold": 7})
        self.assertIn("from 6 to 7", self.suggest(threshold=6)["reason"])
        self.assertEqual(self.suggest(threshold=5)["params"], {"threshold": 7})
        self.assertIsNone(self.suggest(threshold=7))  # already above every false positive
        add_alert(self.conn, RULE, "true_positive", 6)
        self.assertIsNone(self.suggest(threshold=6))  # 6 is not strictly below the smallest true positive

    def test_a_rule_without_a_threshold_param_is_not_raised(self):
        add_alert(self.conn, RULE, "false_positive", 4)
        add_alert(self.conn, RULE, "false_positive", 6)
        add_alert(self.conn, RULE, "true_positive", 20)
        params = {"distinct_users": 5, "window_seconds": 600, "ignore_ips": [], "ignore_users": []}
        self.assertIsNone(suggest_for_rule(self.conn, {"id": RULE, "params": params}))


class GenerateSuggestionsTests(DbCase):
    def setUp(self):
        super().setUp()
        seed_rules(self.conn)

    def _sampled(self, rule_id):
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version,"
            " updated_at, updated_by) VALUES (?, 'Sampled', 'imported', 'low', 0, '{}', 1, ?, 'analyst')",
            (rule_id, TS),
        )

    def test_thin_feedback_and_sampled_rules_create_nothing(self):
        self.assertEqual(generate_suggestions(self.conn), [])
        add_alert(self.conn, RULE, "false_positive", 4, [("203.0.113.8", "ann")])
        self.assertEqual(generate_suggestions(self.conn), [])
        for rule_id in ("sigma_lab_rule", "search_lab_rule"):
            self._sampled(rule_id)
            add_alert(self.conn, rule_id, "false_positive", 3, [("203.0.113.50", "scanner")])
            add_alert(self.conn, rule_id, "false_positive", 3, [("203.0.113.50", "scanner")])
            direct = suggest_for_rule(self.conn, rule(rule_id))
            self.assertEqual(direct["params"], {"ignore_ips": ["203.0.113.50"]})
        self.assertEqual(generate_suggestions(self.conn), [])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM change_requests").fetchone()[0], 0)


class SettingsTests(DbCase):
    def test_an_empty_table_lists_defaults_and_seed_does_not_overwrite(self):
        listed = list_settings(self.conn)
        self.assertEqual([row["key"] for row in listed], list(SECURITY_SETTINGS))
        for row, (key, (low, high, default, desc)) in zip(listed, SECURITY_SETTINGS.items()):
            self.assertEqual(row["key"], key)
            self.assertEqual(row["value"], str(default))
            self.assertEqual((row["min"], row["max"], row["description"]), (low, high, desc))
            self.assertNotIn("updated_at", row)

        seed_settings(self.conn)
        seeded = {row["key"]: row for row in list_settings(self.conn)}
        self.assertEqual(seeded["login_lockout_threshold"]["updated_by"], "system")
        self.assertEqual(seeded["viewer_masking"]["value"], "0")

        self.conn.execute(
            "UPDATE settings SET value = '9', updated_by = 'admin' WHERE key = 'login_lockout_threshold'")
        self.conn.execute("DELETE FROM settings WHERE key = 'login_lockout_minutes'")
        self.conn.execute(
            "INSERT INTO settings(key, value, updated_at, updated_by) VALUES ('not_a_setting', '1', ?, 'admin')",
            (TS,))
        seed_settings(self.conn)
        again = {row["key"]: row for row in list_settings(self.conn)}
        self.assertEqual(list(again), list(SECURITY_SETTINGS))
        self.assertEqual(again["login_lockout_threshold"]["value"], "9")
        self.assertEqual(again["login_lockout_threshold"]["updated_by"], "admin")
        self.assertEqual(again["login_lockout_minutes"]["value"], "15")
        self.assertEqual(again["login_lockout_minutes"]["updated_by"], "system")
        self.assertIn("updated_at", again["login_lockout_minutes"])
        self.assertEqual(again["viewer_masking"]["value"], "0")
        self.assertNotIn("not_a_setting", again)


class ProposalBoundaryTests(DbCase):
    def propose(self, payload, reason="valid reason", target="login_lockout_minutes"):
        return propose_change(self.conn, "setting_update", target, payload, reason, "analyst")

    def test_reason_bounds_are_stripped_before_they_are_stored(self):
        for reason in ("1234", "    ", "  ab", 5, None, "x" * 2001):
            label = reason if not isinstance(reason, str) else f"len-{len(reason)}"
            with self.subTest(reason=label):
                with self.assertRaises(ChangeError) as caught:
                    self.propose({"value": 30}, reason)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn("5-2000", str(caught.exception))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM change_requests").fetchone()[0], 0)

        self.assertEqual(self.propose({"value": 30}, "12345")["reason"], "12345")
        self.assertEqual(self.propose({"value": 31}, "  12345  ")["reason"], "12345")
        long = self.propose({"value": 32}, "y" * 2000)
        self.assertEqual(len(long["reason"]), 2000)
        self.assertEqual(long["payload"], {"value": 32})
        self.assertIsNone(long["evidence_digest"])
        self.assertIsNone(get_change(self.conn, 999))

    def test_setting_values_reject_bools_floats_and_out_of_range(self):
        self.assertEqual(self.propose({"value": 1})["payload"], {"value": 1})
        self.assertEqual(self.propose({"value": 1440})["payload"], {"value": 1440})
        for payload in (
            {"value": 0}, {"value": 1441}, {"value": True}, {"value": False},
            {"value": 1.5}, {"value": "30"}, {"value": 30, "extra": 1}, {}, None, ["value"],
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ChangeError) as caught:
                    self.propose(payload)
                self.assertEqual(caught.exception.status, 400)
        with self.assertRaises(ChangeError) as caught:
            self.propose({"value": True}, target="viewer_masking")
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("between 0 and 1", str(caught.exception))

    def test_review_note_is_stripped_and_capped_and_a_missing_change_is_404(self):
        change = self.propose({"value": 40}, "inside the window")
        with self.assertRaises(ChangeError) as caught:
            review_change(self.conn, 999, "reject", "admin")
        self.assertEqual(caught.exception.status, 404)
        self.assertIsNone(get_change(self.conn, 999))

        rejected = review_change(
            self.conn, change["id"], "reject", "admin", note="  " + ("n" * 2000) + "tail")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["review_note"], "n" * 2000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0], 0)

        blank = self.propose({"value": 41}, "another value")
        self.assertEqual(review_change(self.conn, blank["id"], "reject", "admin", note="   ")["review_note"], "")
        missing = self.propose({"value": 42}, "third value")
        self.assertEqual(review_change(self.conn, missing["id"], "reject", "admin", note=None)["review_note"], "")

    def test_approving_a_bound_writes_the_value_without_a_digest(self):
        seed_settings(self.conn)
        change = self.propose({"value": 1440}, "at the maximum")
        self.assertIsNone(change["evidence_digest"])
        done = review_change(self.conn, change["id"], "approve", "admin", note="  kept  ")
        self.assertEqual((done["status"], done["review_note"]), ("approved", "kept"))
        row = self.conn.execute(
            "SELECT value, updated_by FROM settings WHERE key = 'login_lockout_minutes'").fetchone()
        self.assertEqual((row["value"], row["updated_by"]), ("1440", "admin"))


class EvidenceDigestTests(unittest.TestCase):
    def test_none_key_order_and_backtest_context(self):
        self.assertIsNone(evidence_digest(None))
        self.assertEqual(evidence_digest({"b": 1, "a": [2, 3]}), evidence_digest({"a": [2, 3], "b": 1}))
        empty = evidence_digest({})
        self.assertEqual(empty, evidence_digest({}))
        self.assertRegex(empty, r"^[0-9a-f]{64}$")

        context = {
            "window": "2026-01-01", "max_event_id": 40, "events_scanned": 100,
            "synthetic_events": 7, "counts": {"lost": 1},
        }
        base = {"rule": RULE, "backtest": context}
        moved = {
            "backtest": {**context, "window": "other", "max_event_id": 1,
                         "events_scanned": 0, "synthetic_events": 99},
            "rule": RULE,
        }
        self.assertEqual(evidence_digest(base), evidence_digest(moved))
        changed = {"rule": RULE, "backtest": {**context, "counts": {"lost": 2}}}
        self.assertNotEqual(evidence_digest(base), evidence_digest(changed))
        self.assertNotEqual(evidence_digest({"backtest": "window"}), evidence_digest({"backtest": "other"}))
        self.assertNotEqual(
            evidence_digest({"backtest": {"kept": []}}),
            evidence_digest({"backtest": {"kept": [1]}}),
        )
