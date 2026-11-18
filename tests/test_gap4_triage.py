"""Edge cases for triage percentiles, SLA boundaries, pending badges, and windows.

These assertions are the ones tests/test_triage_metrics.py does not already make:
empty samples, a sorted 1..10 median, q=0.9, the high ack minute, and the 7d/30d/all
window counts.
"""

import unittest
from datetime import datetime, timedelta, timezone

from watchpost import triage
from watchpost.db import connect, init_schema, iso

T0 = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)


def row(severity, status="open", created=timedelta(0), acked=None, resolved=None):
    def at(delta):
        return None if delta is None else iso(T0 + delta)

    return {
        "severity": severity,
        "status": status,
        "created_at": at(created),
        "acknowledged_at": at(acked),
        "resolved_at": at(resolved),
    }


class MedianAndPercentileTests(unittest.TestCase):
    def test_median_of_one_value_and_an_unsorted_pair(self):
        self.assertEqual(triage.median([8]), 8)
        self.assertEqual(triage.median([10, 0]), 5)
        original = [3, 1]
        self.assertEqual(triage.median(original), 2)
        self.assertEqual(original, [3, 1])

    def test_percentile_zero_half_and_one_on_unsorted_input(self):
        # Sorted this is 1, 2, 3, 4. q=0.5 needs two samples at or below the rank, so index 1.
        values = [4, 1, 3, 2]
        self.assertEqual(triage.percentile(values, 0), 1)
        self.assertEqual(triage.percentile(values, 0.5), 2)
        self.assertEqual(triage.percentile(values, 1), 4)
        self.assertEqual(values, [4, 1, 3, 2])


class SummarizeTests(unittest.TestCase):
    def test_one_sample_and_nearest_rank_p90_round_to_one_decimal(self):
        one = {"samples": 1, "mean_minutes": 1.7, "median_minutes": 1.7, "p90_minutes": 1.7}
        self.assertEqual(triage.summarize([100 / 60]), one)
        # n=3: mean 7/3 rounds to 2.3, and p90 is the last sample, not the median.
        three = {"samples": 3, "mean_minutes": 2.3, "median_minutes": 2.0, "p90_minutes": 4.0}
        self.assertEqual(triage.summarize([4, 1, 2]), three)
        pair = {"samples": 2, "mean_minutes": 6.5, "median_minutes": 6.5, "p90_minutes": 10.0}
        self.assertEqual(triage.summarize([3, 10]), pair)


class BreachTests(unittest.TestCase):
    def test_info_targets_are_strictly_greater_than_the_limit(self):
        # info shares low: ack 24h, resolve 7d. Equal to the target is still inside.
        open_info = row("info")
        self.assertEqual(triage.breaches(open_info, T0 + timedelta(hours=24)), [])
        self.assertEqual(triage.breaches(open_info, T0 + timedelta(hours=24, minutes=1)), ["ack"])
        self.assertEqual(triage.breaches(open_info, T0 + timedelta(days=7)), ["ack"])
        self.assertEqual(triage.breaches(open_info, T0 + timedelta(days=7, minutes=1)), ["ack", "resolve"])

    def test_high_resolve_boundary_is_strict(self):
        # At 24h the ack (60m) is already late. The resolve target itself is not.
        open_high = row("high")
        self.assertEqual(triage.breaches(open_high, T0 + timedelta(hours=24)), ["ack"])
        self.assertEqual(triage.breaches(open_high, T0 + timedelta(hours=24, minutes=1)), ["ack", "resolve"])

    def test_ack_before_creation_is_not_a_breach(self):
        early = row("high", status="resolved", acked=timedelta(minutes=-5), resolved=timedelta(minutes=10))
        self.assertEqual(triage.breaches(early, T0 + timedelta(days=10)), [])

    def test_resolved_without_resolved_at_does_not_borrow_the_clock(self):
        missing = row("high", status="resolved", acked=timedelta(minutes=90))
        self.assertEqual(triage.breaches(missing, T0 + timedelta(days=10)), ["ack"])


class PendingBreachTests(unittest.TestCase):
    def test_badges_keep_a_live_resolve_and_drop_history(self):
        # Acked inside 60m, still open past the 24h resolve target: only resolve is live.
        open_acked = row("high", acked=timedelta(minutes=30))
        moment = T0 + timedelta(hours=24, minutes=1)
        self.assertEqual(triage.pending_breaches(open_acked, moment), ["resolve"])
        # Left open after a late ack. The ack is history; the resolve breach still badges.
        investigating = row("high", status="investigating", acked=timedelta(minutes=90))
        self.assertEqual(triage.pending_breaches(investigating, moment), ["resolve"])
        done = row("high", status="resolved", acked=timedelta(minutes=90), resolved=timedelta(hours=25))
        self.assertEqual(triage.pending_breaches(done, T0 + timedelta(days=9)), [])


class TriageMetricsEdgeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def add(self, created_at, severity="critical"):
        self.conn.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
            " VALUES ('r', 1, 'k', ?, 't', 'e', 'open', ?, ?, 1, 0, ?, ?)",
            (severity, created_at, created_at, created_at, created_at),
        )

    def test_empty_all_window_orders_severities_and_has_no_since(self):
        result = triage.triage_metrics(self.conn, "all", now=T0)
        self.assertEqual(result["window"], "all")
        self.assertIsNone(result["since"])
        self.assertEqual(result["alerts"], 0)
        self.assertEqual(result["percentile_method"], "nearest-rank")
        self.assertEqual(
            [s["severity"] for s in result["severities"]],
            ["critical", "high", "medium", "low", "info"],
        )
        self.assertEqual([s["count"] for s in result["severities"]], [0, 0, 0, 0, 0])

    def test_windows_include_the_lower_bound_and_later_rows(self):
        now = T0
        day = timedelta(hours=24)
        self.add(iso(now - day))
        self.add(iso(now - day - timedelta(milliseconds=1)))
        self.add(iso(now - timedelta(days=90)))
        self.add(iso(now - timedelta(days=90) - timedelta(milliseconds=1)))
        self.add(iso(now + timedelta(hours=1)))

        day_window = triage.triage_metrics(self.conn, "24h", now=now)
        quarter = triage.triage_metrics(self.conn, "90d", now=now)
        everything = triage.triage_metrics(self.conn, "all", now=now)
        self.assertEqual(day_window["since"], iso(now - day))
        self.assertEqual(day_window["alerts"], 2)
        self.assertEqual(quarter["since"], iso(now - timedelta(days=90)))
        self.assertEqual(quarter["alerts"], 4)
        self.assertIsNone(everything["since"])
        self.assertEqual(everything["alerts"], 5)
        critical = next(s for s in day_window["severities"] if s["severity"] == "critical")
        self.assertEqual(critical["count"], 2)

    def test_unknown_severity_counts_in_the_total_only(self):
        self.add(iso(T0), severity="Critical")
        result = triage.triage_metrics(self.conn, "all", now=T0)
        self.assertEqual(result["alerts"], 1)
        self.assertEqual([s["count"] for s in result["severities"]], [0, 0, 0, 0, 0])


if __name__ == "__main__":
    unittest.main()
