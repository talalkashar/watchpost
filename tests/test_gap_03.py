"""scan_events: lookback pad on both bounds, and history only before the scan.

With both bounds the read is [start - lookback, end + lookback], and history is only
HISTORY_EVENT_TYPES for rules that set history_seconds, strictly before scan_start.
If either bound is missing, every event with id <= max_id comes back, history is
empty, and scan_start is None.
"""

import unittest
from datetime import datetime, timedelta, timezone

from watchpost import engine, rules
from watchpost.db import connect, init_schema, iso, parse_iso

START = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=2)


def ms(n):
    return timedelta(milliseconds=n)


def rule(rule_id, **params):
    return {"id": rule_id, "params": params}


def history_types(rule_list):
    return {t for r in rule_list if r["params"].get("history_seconds")
            for t in rules.HISTORY_EVENT_TYPES[r["id"]]}


class ScanEventsTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def insert(self, when, event_type):
        ts = when if isinstance(when, str) else iso(when)
        self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity) VALUES (?,?,?,?,?)",
            (ts, ts, "lab", event_type, "low"),
        )
        return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def ids(self, rows):
        self.assertTrue(all(isinstance(row, dict) for row in rows))
        return {row["id"] for row in rows}

    def scan(self, rule_list, max_id, start=None, end=None):
        return engine.scan_events(self.conn, rule_list, max_id, start, end)

    def test_both_bounds_include_the_lookback_pad_on_each_side(self):
        # 300s sits under the 3600s floor. 5500 + 1800 sits over it, so each side
        # of the pad is the lookback itself, not a fixed hour.
        cases = (
            ("floor", [rule("brute_force_ip", window_seconds=300)], 3600),
            ("wide", [rule("privilege_escalation_after_login",
                           window_seconds=5500, escalation_seconds=1800)], 7300),
        )
        start, end = iso(START), iso(END)
        for label, rule_list, pad_seconds in cases:
            with self.subTest(label=label):
                self.conn.execute("DELETE FROM events")
                self.assertEqual(rules.lookback_seconds(rule_list), pad_seconds)
                pad = timedelta(seconds=pad_seconds)
                lower = parse_iso(start) - pad
                upper = parse_iso(end) + pad
                at_lower = self.insert(lower, "login_failed")
                before_lower = self.insert(lower - ms(1), "login_failed")
                inside = self.insert(START + timedelta(minutes=30), "auth_success")
                at_upper = self.insert(upper, "fw_allow")
                after_upper = self.insert(upper + ms(1), "fw_allow")
                over_max = self.insert(START, "login_failed")
                events, history, scan_start = self.scan(rule_list, over_max - 1, start, end)
                self.assertEqual(scan_start, iso(lower))
                self.assertEqual(self.ids(events), {at_lower, inside, at_upper})
                self.assertNotIn(before_lower, self.ids(events))
                self.assertNotIn(after_upper, self.ids(events))
                self.assertEqual(history, [])

    def test_history_is_only_declared_types_strictly_before_scan_start(self):
        cloud = rule("cloud_iam_change_by_new_principal",
                     history_seconds=86400, window_seconds=3600)
        exfil = rule("data_exfil_volume", history_seconds=604800,
                     window_seconds=3600, baseline_multiplier=3)
        admin_plain = rule("admin_action_from_new_source",
                           window_seconds=3600, min_prior_actions=3)
        admin_hist = rule("admin_action_from_new_source",
                          history_seconds=604800, min_prior_actions=3, window_seconds=3600)
        brute = rule("brute_force_ip", window_seconds=300)
        cloud_only = [cloud, admin_plain, brute]
        both = [cloud, exfil, admin_hist, brute]

        start, end = iso(START), iso(END)
        pad = timedelta(seconds=3600)
        self.assertEqual(rules.lookback_seconds(cloud_only), 3600)
        self.assertEqual(rules.lookback_seconds(both), 3600)
        self.assertEqual(rules.history_seconds(cloud_only), 86400)
        self.assertEqual(rules.history_seconds(both), 604800)
        scan_start = parse_iso(start) - pad
        day = timedelta(seconds=86400)
        week = timedelta(seconds=604800)

        planted = {
            "at_lower_login": self.insert(scan_start, "login_failed"),
            "before_lower_login": self.insert(scan_start - ms(1), "login_failed"),
            "before_lower_cloud": self.insert(scan_start - ms(1), "cloud_iam_change"),
            "at_scan_cloud": self.insert(scan_start, "cloud_api_call"),
            "hist_iam": self.insert(scan_start - timedelta(hours=12), "cloud_iam_change"),
            "hist_api": self.insert(scan_start - timedelta(hours=12), "cloud_api_call"),
            "hist_data": self.insert(scan_start - timedelta(hours=12), "cloud_data_access"),
            "hist_fw": self.insert(scan_start - timedelta(hours=12), "fw_allow"),
            "hist_net": self.insert(scan_start - timedelta(hours=12), "network_connection"),
            "hist_priv": self.insert(scan_start - timedelta(hours=12), "privilege_use"),
            "hist_esc": self.insert(scan_start - timedelta(hours=12), "privilege_escalation"),
            "hist_login": self.insert(scan_start - timedelta(hours=12), "login_failed"),
            "at_day": self.insert(scan_start - day, "cloud_data_access"),
            "before_day": self.insert(scan_start - day - ms(1), "cloud_iam_change"),
            "deep_fw": self.insert(scan_start - timedelta(days=2), "fw_allow"),
            "deep_cloud": self.insert(scan_start - timedelta(days=2), "cloud_iam_change"),
            "at_week": self.insert(scan_start - week, "privilege_use"),
            "before_week": self.insert(scan_start - week - ms(1), "fw_allow"),
            "in_login": self.insert(START + timedelta(minutes=30), "login_failed"),
            "in_cloud": self.insert(START + timedelta(minutes=30), "cloud_iam_change"),
            "at_upper": self.insert(parse_iso(end) + pad, "privilege_escalation"),
            "after_upper": self.insert(parse_iso(end) + pad + ms(1), "cloud_iam_change"),
        }
        over_max = self.insert(scan_start - timedelta(hours=12), "cloud_iam_change")
        max_id = over_max - 1
        in_window = {
            planted["at_lower_login"], planted["at_scan_cloud"], planted["in_login"],
            planted["in_cloud"], planted["at_upper"],
        }
        # Cloud's types only. Admin has no history_seconds here, so privilege_* stays out,
        # and fw_allow / network_connection are exfil types this rule list does not ask for.
        cloud_history = {
            planted["before_lower_cloud"], planted["hist_iam"], planted["hist_api"],
            planted["hist_data"], planted["at_day"],
        }

        events, history, got_start = self.scan(cloud_only, max_id, start, end)
        self.assertEqual(got_start, iso(scan_start))
        self.assertEqual(history_types(cloud_only), set(rules.CLOUD_TYPES))
        self.assertEqual(self.ids(events), in_window)
        self.assertEqual(self.ids(history), cloud_history)
        self.assertEqual(self.ids(events) & self.ids(history), set())
        self.assertTrue(all(row["ts"] < got_start for row in history))
        self.assertTrue(all(row["event_type"] in rules.CLOUD_TYPES for row in history))

        # Adding exfil and admin history widens the span to a week and the type set to
        # the union. A cloud event older than cloud's own day still comes back, because
        # the fetch uses the longest history_seconds. login_failed never does.
        events, history, got_start = self.scan(both, max_id, start, end)
        wanted = set(rules.CLOUD_TYPES) | set(rules.EXFIL_TYPES) | set(rules.PRIVILEGED_TYPES)
        both_history = cloud_history | {
            planted["hist_fw"], planted["hist_net"], planted["hist_priv"], planted["hist_esc"],
            planted["before_day"], planted["deep_fw"], planted["deep_cloud"], planted["at_week"],
        }
        self.assertEqual(got_start, iso(scan_start))
        self.assertEqual(history_types(both), wanted)
        self.assertEqual(self.ids(events), in_window)
        self.assertEqual(self.ids(history), both_history)
        self.assertEqual(self.ids(events) & self.ids(history), set())
        self.assertTrue(all(row["ts"] < got_start for row in history))
        self.assertTrue(all(row["event_type"] in wanted for row in history))
        self.assertNotIn(planted["hist_login"], self.ids(history))
        self.assertNotIn(planted["before_week"], self.ids(history))
        self.assertNotIn(over_max, self.ids(history) | self.ids(events))

    def test_missing_either_bound_returns_every_event_up_to_max_id(self):
        rule_list = [rule("cloud_iam_change_by_new_principal",
                          history_seconds=86400, window_seconds=3600)]
        ancient = self.insert(datetime(2020, 1, 1, tzinfo=timezone.utc), "login_failed")
        mid = self.insert(START, "cloud_iam_change")
        future = self.insert(datetime(2030, 1, 1, tzinfo=timezone.utc), "fw_allow")
        # Twelve hours before start is history once both bounds exist, and a normal
        # event when a bound is missing.
        early_cloud = self.insert(START - timedelta(hours=12), "cloud_api_call")
        over = self.insert(START, "privilege_use")
        max_id = over - 1
        kept = {ancient, mid, future, early_cloud}
        start, end = iso(START), iso(END)
        for bounds in ((None, None), (start, None), (None, end)):
            with self.subTest(bounds=bounds):
                events, history, scan_start = self.scan(rule_list, max_id, *bounds)
                self.assertEqual(self.ids(events), kept)
                self.assertEqual(history, [])
                self.assertIsNone(scan_start)

        events, history, scan_start = self.scan(rule_list, over, None, None)
        self.assertEqual(self.ids(events), kept | {over})
        self.assertEqual(history, [])
        self.assertIsNone(scan_start)

        events, history, scan_start = self.scan(rule_list, max_id, start, end)
        self.assertEqual(self.ids(events), {mid})
        self.assertEqual(self.ids(history), {early_cloud})
        self.assertEqual(scan_start, iso(parse_iso(start) - timedelta(seconds=3600)))
        self.assertNotIn(over, self.ids(events) | self.ids(history))
