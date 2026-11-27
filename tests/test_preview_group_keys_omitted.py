"""A new-rule preview says how many group keys the cap leaves out.

group_keys stays the first 10 sorted keys. group_keys_omitted is 0 when the
set fits. findings stays the full count. sample_findings stays the newest 5.
The scan window stays the last 7 days of stored event time.
"""

import unittest
from datetime import timedelta
from pathlib import Path

from watchpost import backtest, search_rules, sigma
from watchpost.db import connect, init_schema, iso, parse_iso

from .helpers import ServerTestCase

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "docs" / "API.md"
REFERENCE = ROOT / "docs" / "REFERENCE.md"
END = parse_iso("2026-11-18T12:00:00.000Z")
IPS = [f"203.0.113.{n}" for n in range(1, 12)]
OMITTED = sorted(IPS)[10]
EDGE = "198.51.100.50"


def params(**kw):
    body = {"group_by": "src_ip", "threshold": 1, "window_minutes": 5, "severity": "low", **kw}
    return search_rules.compile_rule("Preview rule", "event_type:auth_failure", body)["params"]


def insert(conn, rows):
    for ts, user, src, event_type in rows:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip,"
            " message, synthetic) VALUES (?,?,?,?,?,?,?,?,?,1)",
            (ts, ts, "demo:lab", "web01", event_type, "low", user, src, "[SYNTHETIC] failed login"))


def memory(rows):
    conn = connect(":memory:")
    init_schema(conn)
    insert(conn, rows)
    return conn


def ip_rows(ips, newest=None):
    """One synthetic failure per address. `newest` is the last event; the rest are earlier."""
    earlier = [ip for ip in ips if ip != newest]
    rows = [(iso(END - timedelta(seconds=len(earlier) - n)), "alice", ip, "auth_failure")
            for n, ip in enumerate(earlier)]
    if newest is not None:
        rows.append((iso(END), "alice", newest, "auth_failure"))
    return rows


class PreviewGroupKeysOmittedTests(unittest.TestCase):
    def setUp(self):
        rows = ip_rows(IPS, OMITTED)
        rows.append((iso(END - timedelta(days=8)), "alice", EDGE, "auth_failure"))
        self.conn = memory(rows)
        self.addCleanup(self.conn.close)

    def test_eleven_keys_leave_out_the_eleventh_sorted_address(self):
        insert(self.conn, [(iso(END), "", None, "auth_failure"), (iso(END), "alice", "", "auth_failure")])
        preview = search_rules.preview(self.conn, params())
        self.assertEqual(preview["findings"], 11)
        self.assertEqual(preview["group_keys"], sorted(IPS)[:backtest.PREVIEW_GROUP_KEYS])
        self.assertNotIn(OMITTED, preview["group_keys"])
        self.assertNotIn(EDGE, preview["group_keys"])
        self.assertEqual(preview["group_keys_omitted"], 1)
        self.assertEqual(len(preview["sample_findings"]), backtest.PREVIEW_SAMPLE_FINDINGS)
        self.assertEqual(preview["sample_findings"][0]["group_key"], OMITTED)
        self.assertEqual(preview["sample_findings"][0]["event_count"], 1)
        self.assertEqual(preview["events_scanned"], 13)
        self.assertEqual(preview["synthetic_events"], 13)
        self.assertFalse(preview["capped"])
        self.assertEqual(backtest.DEFAULT_WINDOW_DAYS, 7)
        self.assertEqual(preview["window"]["end"], iso(END))
        self.assertEqual(parse_iso(preview["window"]["end"]) - parse_iso(preview["window"]["start"]),
                         timedelta(days=backtest.DEFAULT_WINDOW_DAYS))

    def test_sigma_preview_uses_the_same_cap(self):
        compiled = sigma.compile_rule(
            "title: Preview rule\nstatus: test\nlevel: low\ndetection:\n"
            "  selection:\n    event_type: auth_failure\n  condition: selection\n")["params"]
        preview = sigma.preview(self.conn, compiled)
        self.assertEqual(preview["findings"], 11)
        self.assertEqual(preview["group_keys"], sorted(IPS)[:10])
        self.assertNotIn(OMITTED, preview["group_keys"])
        self.assertEqual(preview["group_keys_omitted"], 1)
        self.assertEqual(len(preview["sample_findings"]), 5)
        self.assertEqual(preview["sample_findings"][0]["group_key"], OMITTED)
        self.assertEqual(preview["window"]["start"], iso(END - timedelta(days=7)))

    def test_ten_keys_and_a_short_list_and_an_empty_match_return_zero(self):
        exact = memory(ip_rows(sorted(IPS)[:10], sorted(IPS)[9]))
        self.addCleanup(exact.close)
        preview = search_rules.preview(exact, params())
        self.assertEqual(preview["findings"], 10)
        self.assertEqual(preview["group_keys"], sorted(IPS)[:10])
        self.assertEqual(preview["group_keys_omitted"], 0)
        self.assertEqual(len(preview["sample_findings"]), 5)
        self.assertFalse(preview["capped"])

        short = memory(ip_rows(["203.0.113.8"], "203.0.113.8"))
        self.addCleanup(short.close)
        one = search_rules.preview(short, params())
        self.assertEqual(one["findings"], 1)
        self.assertEqual(one["group_keys"], ["203.0.113.8"])
        self.assertEqual(one["group_keys_omitted"], 0)
        self.assertEqual(len(one["sample_findings"]), 1)

        quiet = search_rules.compile_rule(
            "Preview rule", "event_type:auth_success",
            {"group_by": "src_ip", "threshold": 1, "window_minutes": 5, "severity": "low"})["params"]
        missed = search_rules.preview(self.conn, quiet)
        self.assertEqual(missed["events_scanned"], 11)
        self.assertEqual(missed["matched_events"], 0)
        self.assertEqual(missed["findings"], 0)
        self.assertEqual(missed["group_keys"], [])
        self.assertEqual(missed["group_keys_omitted"], 0)
        self.assertEqual(missed["sample_findings"], [])

        bare = memory([])
        self.addCleanup(bare.close)
        empty = search_rules.preview(bare, params())
        self.assertIsNone(empty["window"])
        self.assertEqual(empty["findings"], 0)
        self.assertEqual(empty["group_keys"], [])
        self.assertEqual(empty["group_keys_omitted"], 0)
        self.assertEqual(empty["sample_findings"], [])
        self.assertEqual(empty["events_scanned"], 0)

    def test_user_groups_fold_ascii_and_a_blank_user_is_not_a_key(self):
        names = [f"user-{n}" for n in range(9)] + ["Alice", "alice", "ALICE", "ÉRIN", "érin", ""]
        rows = [(iso(END - timedelta(seconds=len(names) - n)), name, "203.0.113.9", "auth_failure")
                for n, name in enumerate(names)]
        conn = memory(rows)
        self.addCleanup(conn.close)
        preview = search_rules.preview(conn, params(group_by="user"))
        kept = sorted([f"user-{n}" for n in range(9)] + ["alice"])
        self.assertEqual(preview["findings"], 12)
        self.assertEqual(preview["group_keys"], kept)
        self.assertNotIn("Érin", preview["group_keys"])
        self.assertNotIn("érin", preview["group_keys"])
        self.assertEqual(preview["group_keys_omitted"], 2)
        self.assertEqual(len(preview["sample_findings"]), 5)
        self.assertEqual(preview["sample_findings"][0]["group_key"], "érin")

    def test_the_docs_name_the_omitted_count(self):
        api = API.read_text()
        reference = REFERENCE.read_text()
        self.assertIn("A new-rule preview (`backtest` on a Sigma import or a saved-search promotion,"
                      " including `?dry_run=1`) keeps the first 10 sorted `group_keys`.", api)
        self.assertIn("`group_keys_omitted` is how many distinct keys were past that cap"
                      " (0 when the set fits).", api)
        self.assertIn("`findings` stays the full count. `sample_findings` stays the newest 5.", api)
        self.assertIn("The scan window stays the last 7 days of stored event time.", api)
        self.assertEqual(reference.count("`group_keys_omitted` counts keys past the first 10"
                                         " (0 when the set fits)"), 2)


class PreviewGroupKeysOmittedApiTests(ServerTestCase):
    def test_a_dry_run_returns_the_omitted_count(self):
        analyst = self.client("analyst")
        base = END - timedelta(minutes=20)
        events = []
        for n, ip in enumerate(ip for ip in IPS if ip != OMITTED):
            events.append({"ts": iso(base + timedelta(seconds=n)), "type": "auth_failure",
                           "src_ip": ip, "user": "alice", "message": "[SYNTHETIC] failed login"})
        events.append({"ts": iso(base + timedelta(seconds=30)), "type": "auth_failure",
                       "src_ip": OMITTED, "user": "alice", "message": "[SYNTHETIC] failed login"})
        status, data, _ = analyst.post("/api/ingest",
                                       {"source": "lab", "synthetic": True, "events": events})
        self.assertEqual((status, data["accepted"]), (201, 11), data)
        status, saved, _ = analyst.post("/api/hunt/saved",
                                        {"name": "Failure burst", "query": "event_type:auth_failure"})
        self.assertEqual(status, 201, saved)
        status, body, headers = analyst.post(
            f"/api/hunt/saved/{saved['id']}/promote?dry_run=1",
            {"group_by": "src_ip", "threshold": 1, "window_minutes": 5, "severity": "low"})
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        preview = body["backtest"]
        self.assertEqual(preview["findings"], 11)
        self.assertEqual(preview["group_keys"], sorted(IPS)[:10])
        self.assertNotIn(OMITTED, preview["group_keys"])
        self.assertEqual(preview["group_keys_omitted"], 1)
        self.assertEqual(len(preview["sample_findings"]), 5)
        self.assertEqual(preview["sample_findings"][0]["group_key"], OMITTED)
        self.assertEqual(preview["synthetic_events"], preview["events_scanned"])
        self.assertEqual(parse_iso(preview["window"]["end"]) - parse_iso(preview["window"]["start"]),
                         timedelta(days=7))
        self.assertEqual(analyst.get("/api/changes")[1], [])
