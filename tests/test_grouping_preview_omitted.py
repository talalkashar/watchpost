"""Grouping preview says how many events and keys the caps leave out.

The scan stays the newest 10000 events by id. events_omitted is how many stored
events were past that cap. A table of exactly 10000 is not capped. group_keys
stays the first 20 sorted keys. group_keys_omitted on before and after is 0
when that set fits.
"""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import grouping
from watchpost.db import connect, init_schema
from watchpost.engine import seed_rules

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
ANCHOR = "2026-09-15T12:00:00Z"
LATER = "2026-09-15T12:00:10Z"
EDGE = "203.0.113.50"
KEPT = "198.51.100.8"
INSERT = ("INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip,"
          " message, synthetic) VALUES (?,?,?,?,?,?,?,?,1)")


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    seed_rules(conn)
    return conn


def row(ts, event_type, user, src_ip):
    return (ts, ANCHOR, "demo", event_type, "low", user, src_ip, "synthetic")


class GroupingPreviewOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def preview(self, fields):
        return grouping.preview(self.conn, "brute_force_ip", fields)

    def test_the_caps_stay_10000_events_and_20_keys(self):
        self.assertEqual((grouping.SCAN_LIMIT, grouping.KEY_LIMIT), (10000, 20))

    def test_a_newer_timestamp_on_a_lower_id_is_the_one_past_the_cap(self):
        edge_id = self.conn.execute(INSERT, row(LATER, "auth_failure", "alice", EDGE)).lastrowid
        scanned = [row(ANCHOR, "auth_failure", "alice", EDGE) for _ in range(9)]
        scanned += [row(ANCHOR, "auth_failure", "bob", KEPT) for _ in range(10)]
        fillers = grouping.SCAN_LIMIT - len(scanned)
        scanned += [row(ANCHOR, "heartbeat", None, None) for _ in range(fillers)]
        self.conn.executemany(INSERT, scanned)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                         grouping.SCAN_LIMIT + 1)
        self.assertEqual(edge_id, self.conn.execute("SELECT MIN(id) FROM events").fetchone()[0])
        self.assertGreater(
            self.conn.execute("SELECT ts FROM events WHERE id = ?", (edge_id,)).fetchone()[0],
            self.conn.execute("SELECT ts FROM events WHERE id = (SELECT MAX(id) FROM events)").fetchone()[0])

        preview = self.preview(["user"])
        self.assertEqual(preview["events_scanned"], grouping.SCAN_LIMIT)
        self.assertEqual(preview["events_omitted"], 1)
        self.assertTrue(preview["capped"])
        self.assertEqual(preview["before"]["findings"], 1)
        self.assertEqual(preview["before"]["group_keys"], [KEPT])
        self.assertEqual(preview["before"]["group_keys_omitted"], 0)
        self.assertNotIn(EDGE, preview["before"]["group_keys"])
        self.assertTrue(preview["evidence_ids_preserved"])

    def test_an_exact_cap_is_not_a_drop(self):
        self.conn.execute(INSERT, row(LATER, "auth_failure", "alice", EDGE))
        scanned = [row(ANCHOR, "auth_failure", "alice", EDGE) for _ in range(9)]
        scanned += [row(ANCHOR, "auth_failure", "bob", KEPT) for _ in range(10)]
        fillers = grouping.SCAN_LIMIT - 1 - len(scanned)
        scanned += [row(ANCHOR, "heartbeat", None, None) for _ in range(fillers)]
        self.conn.executemany(INSERT, scanned)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], grouping.SCAN_LIMIT)

        preview = self.preview(["user"])
        self.assertEqual(preview["events_scanned"], grouping.SCAN_LIMIT)
        self.assertEqual(preview["events_omitted"], 0)
        self.assertFalse(preview["capped"])
        self.assertEqual(preview["before"]["findings"], 2)
        self.assertEqual(preview["before"]["group_keys"], sorted([EDGE, KEPT]))

    def test_a_short_list_and_an_empty_table_return_zero(self):
        empty = self.preview([])
        self.assertEqual(empty["events_omitted"], 0)
        self.assertFalse(empty["capped"])
        self.assertEqual(empty["events_scanned"], 0)
        self.assertEqual(empty["before"]["group_keys"], [])
        self.assertEqual(empty["before"]["group_keys_omitted"], 0)
        self.assertEqual(empty["after"]["group_keys_omitted"], 0)

        self.conn.executemany(INSERT, [row(ANCHOR, "auth_failure", "alice", KEPT) for _ in range(10)])
        short = self.preview(["user"])
        self.assertEqual(short["events_omitted"], 0)
        self.assertFalse(short["capped"])
        self.assertEqual(short["events_scanned"], 10)
        self.assertEqual(short["before"]["group_keys"], [KEPT])
        self.assertEqual(short["before"]["group_keys_omitted"], 0)
        self.assertEqual(short["after"]["group_keys"], ["alice"])
        self.assertEqual(short["after"]["group_keys_omitted"], 0)

    def test_the_twenty_first_sorted_key_is_the_one_left_out(self):
        ips = [f"203.0.113.{i}" for i in range(1, grouping.KEY_LIMIT + 2)]
        users = [f"user-{i:02d}" for i in range(grouping.KEY_LIMIT + 1)]
        rows = []
        for ip, user in zip(ips, users):
            rows.extend(row(ANCHOR, "auth_failure", user, ip) for _ in range(10))
        self.conn.executemany(INSERT, rows)

        preview = self.preview(["user"])
        self.assertEqual(preview["events_omitted"], 0)
        self.assertFalse(preview["capped"])
        self.assertEqual(preview["before"]["findings"], grouping.KEY_LIMIT + 1)
        self.assertEqual(preview["before"]["group_keys"], sorted(ips)[:grouping.KEY_LIMIT])
        self.assertNotIn(sorted(ips)[grouping.KEY_LIMIT], preview["before"]["group_keys"])
        self.assertEqual(preview["before"]["group_keys_omitted"], 1)
        self.assertEqual(preview["after"]["group_keys"], sorted(users)[:grouping.KEY_LIMIT])
        self.assertNotIn(sorted(users)[grouping.KEY_LIMIT], preview["after"]["group_keys"])
        self.assertEqual(preview["after"]["group_keys_omitted"], 1)
        self.assertTrue(preview["evidence_ids_preserved"])

    def test_a_side_that_fits_returns_zero_while_the_other_does_not(self):
        ips = [f"203.0.113.{i}" for i in range(1, grouping.KEY_LIMIT + 2)]
        rows = []
        for ip in ips:
            rows.extend(row(ANCHOR, "auth_failure", "alice", ip) for _ in range(10))
        self.conn.executemany(INSERT, rows)
        preview = self.preview(["user"])
        self.assertEqual(preview["before"]["group_keys_omitted"], 1)
        self.assertEqual(len(preview["before"]["group_keys"]), grouping.KEY_LIMIT)
        self.assertEqual(preview["after"]["group_keys"], ["alice"])
        self.assertEqual(preview["after"]["group_keys_omitted"], 0)

    def test_an_exact_key_cap_returns_zero(self):
        ips = [f"198.51.100.{i}" for i in range(1, grouping.KEY_LIMIT + 1)]
        rows = []
        for ip in ips:
            rows.extend(row(ANCHOR, "auth_failure", "bob", ip) for _ in range(10))
        self.conn.executemany(INSERT, rows)
        preview = self.preview([])
        self.assertEqual(preview["before"]["group_keys"], sorted(ips))
        self.assertEqual(preview["before"]["group_keys_omitted"], 0)
        self.assertEqual(preview["after"]["group_keys"], sorted(ips))
        self.assertEqual(preview["after"]["group_keys_omitted"], 0)

    def test_the_docs_name_the_omitted_counts(self):
        api = API.read_text()
        reference = REFERENCE.read_text()
        sentence = ("`events_omitted` is how many stored events were past that cap"
                     " (0 when the table has 10000 or fewer)")
        self.assertIn(sentence, api)
        self.assertIn("`capped` is true only when `events_omitted` is not 0", api)
        self.assertIn("the first 20 sorted `group_keys`", api)
        self.assertIn("`group_keys_omitted` is how many keys were past that cap (0 when the set fits)", api)
        self.assertIn("newest 10000 events by id", reference)
        self.assertIn("`capped` is true only when that count is not 0", reference)
        self.assertIn("`group_keys_omitted` counts the rest (0 when the set fits)", reference)


class GroupingPreviewOmittedApiTests(ServerTestCase):
    def test_a_grouping_proposal_returns_the_omitted_counts(self):
        analyst = self.client("analyst")
        status, change, headers = analyst.post(
            "/api/rules/brute_force_ip/proposals",
            {"grouping": ["user"], "reason": "Deduplicate by account"})
        self.assertEqual(status, 201, change)
        self.assertEqual(headers["Cache-Control"], "no-store")
        preview = change["evaluation"]["grouping_preview"]
        self.assertEqual(preview["events_omitted"], 0)
        self.assertFalse(preview["capped"])
        self.assertEqual(preview["before"]["group_keys_omitted"], 0)
        self.assertEqual(preview["after"]["group_keys_omitted"], 0)
        self.assertEqual(preview["after"]["group_keys"], [])
