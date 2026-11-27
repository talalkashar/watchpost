"""rule_findings: history-window drops, tuning-exception skips, whole-rule suppression."""

import unittest
from datetime import datetime, timedelta, timezone

from watchpost.db import iso
from watchpost.engine import rule_findings

START = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def at(seconds):
    return iso(START + timedelta(seconds=seconds))


def auth_failure(event_id, src_ip, seconds):
    return {
        "id": event_id,
        "ts": at(seconds),
        "event_type": "auth_failure",
        "src_ip": src_ip,
        "user": "alice",
    }


def brute_rule():
    return {
        "id": "brute_force_ip",
        "params": {"threshold": 2, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    }


def burst(src_ip, first_id, start_second):
    """Two failures inside the brute-force window. last_seen is start_second + 10."""
    return [auth_failure(first_id, src_ip, start_second),
            auth_failure(first_id + 1, src_ip, start_second + 10)]


def transfer(event_id, user, seconds):
    return {
        "id": event_id,
        "ts": at(seconds),
        "event_type": "fw_allow",
        "user": user,
        "src_ip": "198.51.100.8",
        "bytes": 2000,
    }


def exfil_rule():
    # multiplier 0 keeps an excepted principal on flat thresholds, so the rule still emits
    # the finding and this test can see that the engine did not count it as skipped.
    return {
        "id": "data_exfil_volume",
        "params": {
            "bytes_threshold": 1000,
            "access_threshold": 100,
            "window_seconds": 3600,
            "baseline_multiplier": 0,
            "history_seconds": 604800,
            "ignore_ips": [],
            "ignore_users": [],
        },
    }


class RuleFindingsTests(unittest.TestCase):
    def test_last_seen_before_scan_start_is_dropped_and_not_counted(self):
        scan_start = at(100)
        events = (
            burst("203.0.113.1", 1, 0)      # last_seen before scan_start
            + burst("203.0.113.2", 3, 90)   # last_seen == scan_start
            + burst("203.0.113.3", 5, 95)   # first_seen before, last_seen after
        )
        # The early pair is also a tuning exception. Dropping it must not increment skipped.
        suppressed = {("brute_force_ip", "203.0.113.1")}
        findings, skipped = rule_findings(brute_rule(), events, [], scan_start, suppressed)
        self.assertEqual(skipped, 0)
        self.assertEqual({item["group_key"] for item in findings}, {"203.0.113.2", "203.0.113.3"})
        by_key = {item["group_key"]: item for item in findings}
        self.assertEqual(by_key["203.0.113.2"]["last_seen"], scan_start)
        self.assertLess(by_key["203.0.113.3"]["first_seen"], scan_start)
        self.assertGreater(by_key["203.0.113.3"]["last_seen"], scan_start)

    def test_suppressed_pair_is_skipped_unless_exception_enables_baseline(self):
        scan_start = at(0)
        events = burst("203.0.113.10", 1, 0) + burst("203.0.113.11", 3, 0)
        suppressed = {("brute_force_ip", "203.0.113.10"), ("other_rule", "203.0.113.11")}
        findings, skipped = rule_findings(brute_rule(), events, [], scan_start, suppressed)
        self.assertEqual(skipped, 1)
        self.assertEqual([item["group_key"] for item in findings], ["203.0.113.11"])

        exfil_events = [transfer(1, "backup-bot", 10), transfer(2, "other-user", 20)]
        exfil_suppressed = {
            ("data_exfil_volume", "backup-bot"),
            ("data_exfil_volume", "other-user"),
        }
        findings, skipped = rule_findings(exfil_rule(), exfil_events, [], scan_start, exfil_suppressed)
        self.assertEqual(skipped, 0)
        self.assertEqual({item["group_key"] for item in findings}, {"backup-bot", "other-user"})

    def test_suppress_rule_returns_empty_and_counts_remaining(self):
        scan_start = at(100)
        events = (
            burst("203.0.113.1", 1, 0)      # before scan_start: dropped, not counted
            + burst("203.0.113.2", 3, 100)  # pair-suppressed
            + burst("203.0.113.3", 5, 120)  # remaining finding
        )
        suppressed = {("brute_force_ip", "203.0.113.2")}
        findings, skipped = rule_findings(
            brute_rule(), events, [], scan_start, suppressed, suppress_rule=True)
        self.assertEqual(findings, [])
        self.assertEqual(skipped, 2)

        findings, skipped = rule_findings(
            brute_rule(), events, [], scan_start, suppressed, suppress_rule=False)
        self.assertEqual(skipped, 1)
        self.assertEqual([item["group_key"] for item in findings], ["203.0.113.3"])


if __name__ == "__main__":
    unittest.main()
