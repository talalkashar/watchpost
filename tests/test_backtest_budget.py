"""Row budget for stored-rule backtest and new-rule preview.

The cap is applied before rows are materialized. A same-time burst larger than the cap, and the
lookback and type-filtered history around it, must not be read and then sliced.
"""

import json
import unittest
from datetime import timedelta

from watchpost import backtest, engine, improve
from watchpost import rules as rules_mod
from watchpost.db import connect, init_schema, iso, parse_iso

RULE = "cloud_iam_change_by_new_principal"
BRUTE = "brute_force_ip"
END = "2026-11-18T12:00:00.000Z"
END_DT = parse_iso(END)


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class CountingConn:
    """Records ids of event rows a statement materializes. COUNT and MAX do not count."""

    def __init__(self, conn):
        self._conn = conn
        self.ids = []

    def execute(self, sql, params=()):
        cursor = self._conn.execute(sql, params)
        folded = " ".join(sql.lower().split())
        if " from events" in folded and not any(token in folded for token in ("count(", "max(", "min(")):
            rows = cursor.fetchall()
            self.ids.extend(row["id"] for row in rows)
            return _Rows(rows)
        return cursor

    def __getattr__(self, name):
        return getattr(self._conn, name)


class BacktestBudgetTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def insert(self, n, ts, event_type, user="alice", src_ip="198.51.100.8"):
        before = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        self.conn.executemany(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,0)",
            [(ts, ts, "test", event_type, "info", user, src_ip, event_type) for _ in range(n)])
        return [row[0] for row in self.conn.execute("SELECT id FROM events WHERE id > ? ORDER BY id", (before,))]

    def params(self, rule_id=RULE):
        raw = json.loads(self.conn.execute("SELECT params FROM rules WHERE id = ?", (rule_id,)).fetchone()["params"])
        return rules_mod.validate_params(rule_id, raw)

    def test_a_same_time_burst_and_its_history_are_bounded_before_materializing(self):
        # Prior cloud rows sit in the minimum lookback's history. Auth rows at the same time must not.
        # The final burst has more rows than the cap and they share one timestamp.
        history = self.insert(500, iso(END_DT - timedelta(hours=2)), "cloud_api_call")
        decoy = self.insert(200, iso(END_DT - timedelta(hours=2)), "auth_failure")
        lookback = self.insert(25, iso(END_DT - timedelta(minutes=30)), "cloud_api_call")
        ancient = self.insert(15, iso(END_DT - timedelta(days=7, hours=2)), "cloud_api_call")
        ancient_auth = self.insert(15, iso(END_DT - timedelta(days=7, hours=2)), "auth_failure")
        burst = self.insert(30, END, "cloud_iam_change")
        budget = len(history) + len(lookback) + len(burst)
        params = self.params()
        counter = CountingConn(self.conn)

        counter.ids.clear()
        small = backtest.backtest(counter, RULE, params, max_events=10)
        small_ids = list(counter.ids)
        self.assertEqual(set(small_ids), set(burst[-10:]))
        self.assertEqual(len(small_ids), 10)
        self.assertTrue(small["capped"])
        self.assertTrue(small["incomplete"])
        self.assertGreater(small["events_omitted"], 0)
        self.assertEqual(small["events_scanned"], len(small_ids))
        self.assertEqual(small["events_scanned"] + small["events_omitted"], budget)
        self.assertEqual(small["events_omitted"], budget - len(small_ids))
        self.assertEqual(small["bound"], {"ts": END, "id": min(burst[-10:])})
        self.assertEqual(small["window"], {"start": END, "end": END})
        self.assertTrue(set(small_ids).isdisjoint(history + decoy + lookback + ancient + ancient_auth))
        # The partial read never saw the prior cloud activity, so the burst looks like a new principal.
        self.assertEqual(small["counts"]["kept"], 1)

        counter.ids.clear()
        again = backtest.backtest(counter, RULE, params, max_events=10)
        self.assertEqual(again, small)
        self.assertEqual(again["counts"], small["counts"])
        self.assertEqual(counter.ids, small_ids)
        self.assertEqual(improve.evidence_digest({"backtest": again}), improve.evidence_digest({"backtest": small}))

        counter.ids.clear()
        preview = backtest.preview_new_rule(
            counter, RULE, params, lambda event: event["event_type"] == "cloud_iam_change", max_events=10)
        self.assertEqual(counter.ids, small_ids)
        self.assertTrue(preview["incomplete"])
        self.assertEqual(preview["events_omitted"], small["events_omitted"])
        self.assertEqual(preview["bound"], small["bound"])
        self.assertEqual(preview["events_scanned"] + preview["events_omitted"], budget)

        counter.ids.clear()
        full = backtest.backtest(counter, RULE, params, max_events=10_000)
        self.assertFalse(full["incomplete"])
        self.assertFalse(full["capped"])
        self.assertEqual(full["events_omitted"], 0)
        self.assertIsNone(full["bound"])
        self.assertEqual(full["window"]["start"], iso(END_DT - timedelta(days=7)))
        self.assertEqual(full["counts"]["kept"], 0)  # the prior cloud rows are visible, so nothing is new
        rules = [{"id": RULE, "params": params, "grouping": []}, {"id": RULE, "params": params, "grouping": []}]
        events, hist, _ = engine.scan_events(
            self.conn, rules, full["max_event_id"], full["window"]["start"], full["window"]["end"])
        scanned = {row["id"] for row in events + hist}
        self.assertEqual(set(counter.ids), scanned)
        self.assertTrue(set(ancient).issubset(scanned))
        self.assertTrue(set(decoy).issubset(scanned))
        self.assertTrue(set(ancient_auth).isdisjoint(scanned))
        self.assertGreater(len(scanned), budget)

    def test_incomplete_long_lookback_stays_inside_requested_day(self):
        self.insert(12, iso(END_DT - timedelta(hours=36)), "auth_failure")
        self.insert(1, END, "auth_failure")
        params = {**self.params(BRUTE), "window_seconds": 2 * 86400}
        replay = backtest.backtest(self.conn, BRUTE, params, window_days=1, max_events=8)
        preview = backtest.preview_new_rule(self.conn, BRUTE, params, lambda e: True, window_days=1, max_events=8)
        for result in (replay, preview):
            self.assertTrue(result["incomplete"])
            self.assertEqual(result["window"]["start"], iso(END_DT - timedelta(days=1)))
        self.assertEqual(preview["matched_events"], 1)
        self.assertEqual(replay["events_scanned"], 8)

    def test_uncapped_evidence_keeps_its_pre_budget_digest(self):
        self.insert(1, END, "auth_failure")
        replay = backtest.backtest(self.conn, BRUTE, self.params(BRUTE))
        earlier = {k: v for k, v in replay.items() if k not in ("incomplete", "events_omitted", "bound")}
        self.assertEqual(improve.evidence_digest({"backtest": replay}), improve.evidence_digest({"backtest": earlier}))

    def test_negative_budget_cannot_disable_sql_limit(self):
        self.insert(1, END, "auth_failure")
        with self.assertRaises(ValueError):
            backtest.backtest(self.conn, BRUTE, self.params(BRUTE), max_events=-1)
        with self.assertRaises(ValueError):
            backtest.preview_new_rule(self.conn, BRUTE, self.params(BRUTE), lambda e: True, max_events=-1)

    def test_stored_grouping_is_replayed_on_both_sides(self):
        self.insert(1, END, "cloud_iam_change", src_ip="203.0.113.9")
        params = self.params()
        plain = backtest.backtest(self.conn, RULE, params)
        self.assertEqual([item["group_key"] for item in plain["kept"]], ["alice"])
        self.assertFalse(plain["incomplete"])
        self.conn.execute("UPDATE rules SET grouping = ? WHERE id = ?", ('["src_ip"]', RULE))
        grouped = backtest.backtest(self.conn, RULE, {**params, "window_seconds": 1800})
        self.assertEqual([item["group_key"] for item in grouped["kept"]], ["203.0.113.9"])
        self.assertEqual(grouped["new"], [])
        self.assertEqual(grouped["lost"], [])

    def test_incomplete_evidence_cannot_be_approved_as_safe(self):
        self.insert(20, END, "auth_failure", user="bob", src_ip="198.51.100.4")
        real = improve.backtest_mod.backtest

        def limited(conn, rule_id, new_params, **kwargs):
            kwargs["max_events"] = 8
            return real(conn, rule_id, new_params, **kwargs)

        improve.backtest_mod.backtest = limited
        self.addCleanup(setattr, improve.backtest_mod, "backtest", real)
        change = improve.propose_change(self.conn, "rule_update", BRUTE, {"params": {"threshold": 9}},
                                        "tighten the threshold a little", "analyst")
        stored = change["evaluation"]["backtest"]
        self.assertTrue(stored["incomplete"])
        self.assertEqual(stored["events_scanned"], 8)
        self.assertEqual(stored["counts"]["lost"], 0)
        self.assertEqual(stored["counts"]["open_alerts_lost"], 0)
        with self.assertRaises(improve.ChangeError) as caught:
            improve.review_change(self.conn, change["id"], "approve", "admin", digest=change["evidence_digest"])
        self.assertIn("cannot be approved as safe", str(caught.exception))
        self.assertNotIn("acknowledge_detection_loss", str(caught.exception))
        self.assertEqual(improve.get_change(self.conn, change["id"])["status"], "pending")
        rejected = improve.review_change(self.conn, change["id"], "reject", "admin", note="not an exact replay")
        self.assertEqual(rejected["status"], "rejected")
