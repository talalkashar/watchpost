"""Edge cases for triage SLA badges, response-time samples, and windows."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from watchpost import triage
from watchpost.db import connect, init_schema, iso
from watchpost.queries import QueryError

T0 = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)


def stamp(delta):
    return iso(T0 + delta)


def clock(delta):
    return T0 + delta


def row(severity="high", status="open", created=timedelta(0), acked=None, resolved=None):
    def one(value):
        if value is None:
            return None
        if isinstance(value, str):
            return value
        return stamp(value)

    return {"severity": severity, "status": status, "created_at": one(created),
            "acknowledged_at": one(acked), "resolved_at": one(resolved)}


def insert(conn, severity="high", status="open", created=None, acked=None, resolved=None, synthetic=0):
    created = stamp(timedelta(0)) if created is None else created
    return conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status, disposition,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at, acknowledged_at, resolved_at)"
        " VALUES ('brute_force_ip', 1, 'k', ?, 't', 'e', ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
        (severity, status, "true_positive" if status == "resolved" else None, created, created, synthetic,
         created, created, acked, resolved),
    ).lastrowid


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = connect(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def severity(self, result, name):
        return next(s for s in result["severities"] if s["severity"] == name)


class PercentileEdgeTests(unittest.TestCase):
    def test_nearest_rank_and_fractions_outside_the_sample(self):
        values = list(range(1, 11))
        self.assertEqual(triage.percentile(values, 0.9), 9)
        self.assertEqual(triage.percentile([5, 1, 3], 0.9), 5)
        self.assertEqual(triage.percentile([4], 0.9), 4)
        self.assertEqual(triage.percentile(values, 1), 10)
        self.assertEqual(triage.percentile(values, 1.5), 10)
        self.assertEqual(triage.percentile(values, 0), 1)
        self.assertEqual(triage.percentile(values, -1), 1)
        self.assertIsNone(triage.percentile([], 0.9))
        self.assertIsNone(triage.percentile([], 1.5))


class BreachEdgeTests(unittest.TestCase):
    def test_reopened_alert_does_not_badge_an_ack_that_already_happened(self):
        # High ack target is 60m. Reopen leaves status open and keeps the 90m ack stamp.
        alert = row(status="open", acked=timedelta(minutes=90))
        early = clock(timedelta(hours=2))
        self.assertEqual(triage.breaches(alert, early), ["ack"])
        self.assertEqual(triage.pending_breaches(alert, early), [])
        late = clock(timedelta(hours=25))
        self.assertEqual(triage.breaches(alert, late), ["ack", "resolve"])
        self.assertEqual(triage.pending_breaches(alert, late), ["resolve"])

    def test_a_recorded_resolve_is_history_even_when_status_is_not_resolved(self):
        alert = row(status="investigating", resolved=timedelta(hours=25))
        now = clock(timedelta(days=2))
        self.assertEqual(triage.breaches(alert, now), ["resolve"])
        self.assertEqual(triage.pending_breaches(alert, now), [])

    def test_exact_target_is_inside_sla_and_one_millisecond_over_is_not(self):
        ms = timedelta(milliseconds=1)
        done = row(severity="critical", status="resolved", acked=timedelta(minutes=15), resolved=timedelta(hours=4))
        self.assertEqual(triage.breaches(done, clock(timedelta(days=1))), [])
        over = row(severity="critical", status="resolved", acked=timedelta(minutes=15) + ms,
                   resolved=timedelta(hours=4) + ms)
        self.assertEqual(triage.breaches(over, clock(timedelta(days=1))), ["ack", "resolve"])
        pending = row(severity="critical")
        self.assertEqual(triage.pending_breaches(pending, clock(timedelta(minutes=15))), [])
        self.assertEqual(triage.pending_breaches(pending, clock(timedelta(minutes=15) + ms)), ["ack"])
        self.assertEqual(triage.pending_breaches(pending, clock(timedelta(hours=4))), ["ack"])
        self.assertEqual(triage.pending_breaches(pending, clock(timedelta(hours=4) + ms)), ["ack", "resolve"])

    def test_legacy_investigating_row_breaches_resolve_only(self):
        alert = row(status="investigating")
        now = clock(timedelta(hours=25))
        self.assertEqual(triage.breaches(alert, now), ["resolve"])
        self.assertEqual(triage.pending_breaches(alert, now), ["resolve"])

    def test_resolved_late_steps_stay_off_the_badge(self):
        alert = row(status="resolved", acked=timedelta(minutes=90), resolved=timedelta(hours=25))
        now = clock(timedelta(days=2))
        self.assertEqual(triage.breaches(alert, now), ["ack", "resolve"])
        self.assertEqual(triage.pending_breaches(alert, now), [])

    def test_open_alert_past_both_targets_badges_both_steps(self):
        alert = row()
        now = clock(timedelta(hours=25))
        self.assertEqual(triage.breaches(alert, now), ["ack", "resolve"])
        self.assertEqual(triage.pending_breaches(alert, now), ["ack", "resolve"])

    def test_blank_ack_is_still_missing(self):
        alert = row(status="open", acked="")
        self.assertEqual(triage.pending_breaches(alert, clock(timedelta(hours=2))), ["ack"])

    def test_low_and_info_targets_are_one_day_and_seven_days(self):
        ms = timedelta(milliseconds=1)
        for severity in ("low", "info"):
            alert = row(severity=severity)
            with self.subTest(severity=severity):
                self.assertEqual(triage.pending_breaches(alert, clock(timedelta(hours=24))), [])
                self.assertEqual(triage.pending_breaches(alert, clock(timedelta(hours=24) + ms)), ["ack"])
                self.assertEqual(triage.pending_breaches(alert, clock(timedelta(days=7))), ["ack"])
                self.assertEqual(triage.pending_breaches(alert, clock(timedelta(days=7) + ms)), ["ack", "resolve"])

    def test_naive_created_at_is_read_as_utc(self):
        naive = row(severity="critical", created="2026-01-05T12:00:00.000")
        zoned = row(severity="critical", created="2026-01-05T12:00:00.000Z")
        now = datetime(2026, 1, 5, 12, 20, tzinfo=timezone.utc)
        self.assertEqual(triage.breaches(naive, now), ["ack"])
        self.assertEqual(triage.breaches(zoned, now), ["ack"])
        self.assertEqual(triage.pending_breaches(naive, now), ["ack"])

    def test_unreadable_stamps_do_not_raise(self):
        alert = row(created="not-a-time", acked="yesterday")
        now = clock(timedelta(days=3))
        self.assertEqual(triage.breaches(alert, now), [])
        self.assertEqual(triage.pending_breaches(alert, now), [])


class MetricsEdgeTests(DbTestCase):
    def test_reopen_keeps_the_late_ack_in_the_metrics(self):
        insert(self.conn, severity="high", status="open", created=stamp(timedelta(0)),
               acked=stamp(timedelta(minutes=90)))
        early = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=2))), "high")
        self.assertEqual((early["open"], early["ack_unknown"]), (1, 0))
        self.assertEqual((early["sla"]["ack_breaches"], early["sla"]["resolve_breaches"]), (1, 0))
        late = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=25))), "high")
        self.assertEqual((late["sla"]["ack_breaches"], late["sla"]["resolve_breaches"]), (1, 1))

    def test_resolve_stamp_on_an_investigating_row_still_counts(self):
        insert(self.conn, severity="high", status="investigating", created=stamp(timedelta(0)),
               resolved=stamp(timedelta(hours=25)))
        high = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(days=2))), "high")
        self.assertEqual(high["ack_unknown"], 1)
        self.assertEqual((high["sla"]["ack_breaches"], high["sla"]["resolve_breaches"]), (0, 1))
        self.assertEqual(high["mttr"]["samples"], 1)

    def test_legacy_row_past_the_resolve_target_counts_resolve_only(self):
        insert(self.conn, severity="high", status="investigating", created=stamp(timedelta(0)))
        high = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=25))), "high")
        self.assertEqual((high["ack_unknown"], high["sla"]["ack_breaches"], high["sla"]["resolve_breaches"]), (1, 0, 1))

    def test_inverted_ack_is_omitted_and_does_not_dilute_a_real_sample(self):
        insert(self.conn, severity="critical", status="investigating", created=stamp(timedelta(0)),
               acked=stamp(timedelta(minutes=-30)))
        alone = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=1))), "critical")
        self.assertEqual((alone["count"], alone["ack_unknown"], alone["mtta"]["samples"]), (1, 0, 0))
        self.assertIsNone(alone["mtta"]["mean_minutes"])
        self.assertEqual(alone["sla"]["ack_breaches"], 0)
        insert(self.conn, severity="critical", status="investigating", created=stamp(timedelta(0)),
               acked=stamp(timedelta(minutes=10)))
        mixed = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=1))), "critical")
        self.assertEqual(mixed["mtta"], {"samples": 1, "mean_minutes": 10.0, "median_minutes": 10.0,
                                         "p90_minutes": 10.0})
        self.assertEqual(mixed["sla"]["ack_breaches"], 0)

    def test_inverted_resolve_is_omitted_from_mttr(self):
        insert(self.conn, severity="critical", status="resolved", created=stamp(timedelta(0)),
               acked=stamp(timedelta(minutes=5)), resolved=stamp(timedelta(minutes=-10)))
        crit = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=1))), "critical")
        self.assertEqual(crit["mttr"]["samples"], 0)
        self.assertEqual(crit["sla"]["resolve_breaches"], 0)
        self.assertEqual(crit["mtta"]["mean_minutes"], 5.0)

    def test_zero_length_ack_is_measured_and_inside_the_target(self):
        insert(self.conn, severity="critical", status="investigating", created=stamp(timedelta(0)),
               acked=stamp(timedelta(0)))
        crit = self.severity(triage.triage_metrics(self.conn, "all", now=clock(timedelta(hours=1))), "critical")
        self.assertEqual(crit["mtta"]["samples"], 1)
        self.assertEqual(crit["mtta"]["mean_minutes"], 0.0)
        self.assertEqual(crit["sla"]["ack_breaches"], 0)

    def test_unreadable_stamps_stay_in_the_count_and_out_of_the_averages(self):
        insert(self.conn, severity="high", status="open", created="not-a-time", acked="yesterday")
        result = triage.triage_metrics(self.conn, "all", now=T0)
        high = self.severity(result, "high")
        self.assertEqual(result["alerts"], 1)
        self.assertEqual((high["count"], high["mtta"]["samples"], high["sla"]["ack_breaches"]), (1, 0, 0))
        self.assertEqual(high["ack_unknown"], 0)

    def test_generated_at_uses_the_injected_clock(self):
        now = clock(timedelta(hours=3))
        self.assertEqual(triage.triage_metrics(self.conn, "all", now=now)["generated_at"], iso(now))

    def test_naive_now_is_utc_for_the_window_and_the_report_stamp(self):
        naive = datetime(2026, 1, 6, 12, 0)
        insert(self.conn, created=iso(T0))
        result = triage.triage_metrics(self.conn, "24h", now=naive)
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(result["since"], iso(T0))
        self.assertEqual(result["generated_at"], iso(naive.replace(tzinfo=timezone.utc)))

    def test_windows_are_counted_from_the_injected_clock(self):
        now = T0
        for age in (timedelta(hours=1), timedelta(days=10), timedelta(days=40), timedelta(days=100)):
            insert(self.conn, created=iso(now - age))
        counts = [triage.triage_metrics(self.conn, window, now=now)["alerts"]
                  for window in ("24h", "7d", "30d", "90d", "all")]
        self.assertEqual(counts, [1, 1, 2, 3, 4])

    def test_window_includes_the_exact_lower_bound(self):
        now = T0
        bound = iso(now - timedelta(hours=24))
        insert(self.conn, created=bound)
        insert(self.conn, created=iso(now - timedelta(hours=24) - timedelta(milliseconds=1)))
        result = triage.triage_metrics(self.conn, "24h", now=now)
        self.assertEqual(result["since"], bound)
        self.assertEqual(result["alerts"], 1)

    def test_an_unknown_window_is_rejected(self):
        with self.assertRaises(QueryError):
            triage.triage_metrics(self.conn, "24h ")

    def test_empty_database_reports_every_severity(self):
        result = triage.triage_metrics(self.conn, now=T0)
        self.assertEqual(result["window"], "30d")
        self.assertEqual(result["alerts"], 0)
        self.assertEqual((result["synthetic"], result["synthetic_alerts"]), ("none", 0))
        self.assertEqual([s["severity"] for s in result["severities"]],
                         ["critical", "high", "medium", "low", "info"])
        for sev in result["severities"]:
            self.assertEqual(sev["count"], 0)
            self.assertEqual(sev["mtta"]["samples"], 0)
            self.assertIsNone(sev["mtta"]["mean_minutes"])
            self.assertEqual(sev["mttr"]["samples"], 0)
            self.assertIsNone(sev["mttr"]["mean_minutes"])


if __name__ == "__main__":
    unittest.main()
