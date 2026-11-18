"""The dashboard attacker list says how many source IPs the cap dropped.

The rows stay ordered by alerts, then events. A newer source with fewer events
is the one left out when 40 busier sources fill the list. A list that fits,
including an empty table, returns attackers_omitted 0. An event that is not
alert evidence is not a source IP in that count.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost.db import connect, init_schema
from watchpost.queries import ATTACKER_LIMIT, dashboard

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
QUIET = "198.51.100.9"
LATER = "2026-11-01T00:00:00.000Z"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def source(conn, ip, events=1, alerts=1, ts=ANCHOR, status="open", severity="medium"):
    """Link events on `ip` to alerts. One event can sit on several alerts."""
    ids = [add_event(conn, ts, src_ip=ip, synthetic=1) for _ in range(events)]
    for i in range(alerts):
        chunk = ids if i == 0 else ids[:1]
        add_alert(conn, severity, ts, chunk, status=status)
    return ids


class AttackersOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def board(self):
        body = dashboard(self.conn)
        return body["attackers_omitted"], [row["ip"] for row in body["attackers"]]

    def test_a_newer_quieter_source_is_the_one_past_the_cap(self):
        kept = [f"203.0.113.{i}" for i in range(1, ATTACKER_LIMIT + 1)]
        for ip in kept:
            source(self.conn, ip, events=2)
        source(self.conn, QUIET, events=1, ts=LATER)
        omitted, ips = self.board()
        self.assertEqual(omitted, 1)
        self.assertEqual(len(ips), ATTACKER_LIMIT)
        self.assertNotIn(QUIET, ips)
        self.assertEqual(set(ips), set(kept))

    def test_more_alerts_outrank_more_events(self):
        source(self.conn, "203.0.113.10", events=1, alerts=2, ts=ANCHOR)
        source(self.conn, "203.0.113.20", events=3, alerts=1, ts=LATER)
        source(self.conn, "192.0.2.30", events=1, alerts=1, ts=LATER)
        omitted, ips = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(ips, ["203.0.113.10", "203.0.113.20", "192.0.2.30"])
        row = {a["ip"]: a for a in dashboard(self.conn)["attackers"]}
        self.assertEqual(row["203.0.113.10"]["alerts"], 2)
        self.assertEqual(row["203.0.113.10"]["events"], 1)
        self.assertEqual(row["203.0.113.20"]["events"], 3)
        self.assertEqual(row["203.0.113.10"]["max_severity"], "medium")

    def test_a_resolved_alert_still_counts_and_an_unlinked_event_does_not(self):
        source(self.conn, "203.0.113.7", status="resolved")
        add_event(self.conn, ANCHOR, src_ip="192.0.2.8")
        add_alert(self.conn, "high", ANCHOR, [add_event(self.conn, ANCHOR, src_ip=None)])
        omitted, ips = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(ips, ["203.0.113.7"])
        row = dashboard(self.conn)["attackers"][0]
        self.assertEqual(row["open_alerts"], 0)
        self.assertEqual(row["max_severity"], "medium")

    def test_a_short_list_and_an_exact_cap_return_zero(self):
        self.assertEqual(self.board(), (0, []))
        source(self.conn, "203.0.113.1")
        self.assertEqual(self.board(), (0, ["203.0.113.1"]))
        for i in range(2, ATTACKER_LIMIT + 1):
            source(self.conn, f"203.0.113.{i}")
        omitted, ips = self.board()
        self.assertEqual(omitted, 0)
        self.assertEqual(len(ips), ATTACKER_LIMIT)

    def test_the_docs_name_attackers_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`attackers_omitted` is how many source IPs on alerts were past that cap"
            " (0 when there are 40 or fewer)",
            api)
        self.assertIn("An event that is not alert evidence is not a source IP in that count", api)
        self.assertIn("the top 40 by alerts, then events", api)


class AttackersOmittedApiTests(ServerTestCase):
    def test_the_dashboard_returns_the_omitted_count(self):
        with sqlite3.connect(self.db_path) as db:
            for i in range(1, ATTACKER_LIMIT + 1):
                source(db, f"203.0.113.{i}", events=2)
            source(db, QUIET, events=1, ts=LATER)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body["attackers_omitted"], 1)
        self.assertEqual(len(body["attackers"]), ATTACKER_LIMIT)
        self.assertNotIn(QUIET, [row["ip"] for row in body["attackers"]])
        self.assertNotIn("raw", body["recent_events"][0])

    def test_an_empty_dashboard_and_a_rejected_request(self):
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/dashboard")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["attackers"], [])
        self.assertEqual(body["attackers_omitted"], 0)
        status, denied, _ = self.client().get("/api/dashboard")
        self.assertEqual(status, 401)
        self.assertNotIn("attackers_omitted", denied)
