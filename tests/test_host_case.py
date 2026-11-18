"""Event search and hunt match host names case-insensitively, as the asset inventory does.

Grouping by host stays exact. NOCASE folds ASCII letters only.
"""

import unittest
from datetime import timedelta
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt, queries, search_rules
from watchpost.db import connect, init_schema, iso, utcnow


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = [
        ("web01", "lab", "a"),
        ("WEB01", "lab", "b"),
        ("Db01", "LAB", "c"),
        ("érin-host", "lab", "d"),
        ("Érin-host", "lab", "e"),
    ]
    for n, (host, source, user) in enumerate(rows):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, source, host, "process_start", "low", user, "[SYNTHETIC] host case",))
    return conn


class HostCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def hosts(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["host"] for e in page["events"])

    def test_hunt_and_event_search_fold_ascii_host_names(self):
        self.assertEqual(self.hosts("host:WEB01"), ["WEB01", "web01"])
        self.assertEqual(self.hosts('host:"web01"'), ["WEB01", "web01"])
        self.assertEqual(self.hosts("host:db01"), ["Db01"])
        self.assertEqual(self.hosts("NOT host:web01"), ["Db01", "Érin-host", "érin-host"])
        # A non-ASCII letter is not folded, so these stay two hosts.
        self.assertEqual(self.hosts("host:érin-host"), ["érin-host"])
        self.assertEqual(self.hosts("host:Érin-host"), ["Érin-host"])
        # Source equality stays exact. Three events are source lab; Db01 is source LAB.
        self.assertEqual(self.hosts("source:lab"), ["WEB01", "web01", "Érin-host", "érin-host"])
        self.assertEqual(self.hosts("source:LAB"), ["Db01"])

        found = queries.search_events(self.conn, {"host": "Web01"})
        self.assertEqual(sorted(e["host"] for e in found["events"]), ["WEB01", "web01"])
        self.assertEqual(queries.search_events(self.conn, {"host": "web*"})["total"], 2)

    def test_the_comparison_is_nocase_and_the_rule_matcher_agrees(self):
        where, args = hunt.compile_query("host:WEB01")
        self.assertEqual((where, args), (["host = ? COLLATE NOCASE"], ["WEB01"]))
        match = search_rules.matcher(search_rules.parse_filter("host:WEB01")[1])
        self.assertTrue(match({"host": "web01"}))
        self.assertFalse(match({"host": "web02"}))
        self.assertFalse(match({"host": None}))
        # Grouping still sees each spelling.
        groups = hunt.run(self.conn, {"q": "host:web01 | stats count by host"})
        self.assertEqual(groups["rows"], [["WEB01", 1], ["web01", 1]])


class HostCaseApiTests(ServerTestCase):
    def test_events_and_hunt_accept_either_spelling(self):
        client = self.client("analyst")
        base = utcnow() - timedelta(hours=1)
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": iso(base), "type": "process", "host": "WEB01", "message": "[SYNTHETIC] case"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "process", "host": "db01",
             "message": "[SYNTHETIC] other"},
        ]})
        self.assertEqual(status, 201, body)
        status, data, _ = client.get("/api/events?host=web01")
        self.assertEqual(status, 200, data)
        self.assertEqual([e["host"] for e in data["events"]], ["WEB01"])
        status, hunt_page, _ = client.get("/api/hunt?q=" + quote("host:Web01"))
        self.assertEqual(status, 200, hunt_page)
        self.assertEqual([e["host"] for e in hunt_page["events"]], ["WEB01"])
        self.assertEqual(hunt_page["terms"][0]["text"], "host = Web01")
