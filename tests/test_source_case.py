"""Event search and hunt match source case-insensitively (ASCII).

Grouping by source stays exact. NOCASE folds ASCII letters only. A prefix already folded ASCII
because SQLite LIKE does.
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
        ("demo", "web01"),
        ("Demo", "WEB01"),
        ("DEMO", "db01"),
        ("other", "mail01"),
        ("démo", "a"),
        ("DÉMO", "b"),
    ]
    for n, (source, host) in enumerate(rows):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,1)",
            (ts, ts, source, host, "process_start", "low", "[SYNTHETIC] source case",))
    return conn


class SourceCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def sources(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["source"] for e in page["events"])

    def test_hunt_and_event_search_fold_ascii_source(self):
        folded = ["DEMO", "Demo", "demo"]
        self.assertEqual(self.sources("source:Demo"), folded)
        self.assertEqual(self.sources('source:"demo"'), folded)
        self.assertEqual(self.sources("NOT source:demo"), ["DÉMO", "démo", "other"])
        # A non-ASCII letter is not folded, so these stay two sources.
        self.assertEqual(self.sources("source:démo"), ["démo"])
        self.assertEqual(self.sources("source:DÉMO"), ["DÉMO"])
        # A prefix already folded ASCII. It still does, and it does not fold é.
        self.assertEqual(self.sources("source:de*"), folded)
        self.assertEqual(self.sources("source:dé*"), ["démo"])

        found = queries.search_events(self.conn, {"source": "DEMO"})
        self.assertEqual(sorted(e["source"] for e in found["events"]), folded)
        self.assertEqual(queries.search_events(self.conn, {"source": "de*"})["total"], 3)

    def test_the_comparison_is_nocase_and_grouping_stays_exact(self):
        where, args = hunt.compile_query("source:Demo")
        self.assertEqual((where, args), (["source = ? COLLATE NOCASE"], ["Demo"]))
        match = search_rules.matcher(search_rules.parse_filter("source:Demo")[1])
        self.assertTrue(match({"source": "demo"}))
        self.assertFalse(match({"source": "other"}))
        self.assertFalse(match({"source": None}))
        self.assertFalse(match({"source": "démo"}))
        groups = hunt.run(self.conn, {"q": "source:demo | stats count by source"})
        self.assertEqual(groups["rows"], [["DEMO", 1], ["Demo", 1], ["demo", 1]])


class SourceCaseApiTests(ServerTestCase):
    def test_events_and_hunt_accept_either_spelling(self):
        client = self.client("analyst")
        base = utcnow() - timedelta(hours=1)
        status, body, _ = client.post("/api/ingest", {"source": "Lab", "synthetic": True, "events": [
            {"ts": iso(base), "type": "process", "host": "web01", "message": "[SYNTHETIC] case"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "process", "host": "db01",
             "source": "Other", "message": "[SYNTHETIC] other"},
        ]})
        self.assertEqual(status, 201, body)
        status, data, _ = client.get("/api/events?source=demo:lab")
        self.assertEqual(status, 200, data)
        self.assertEqual([e["source"] for e in data["events"]], ["demo:Lab"])
        status, hunt_page, _ = client.get("/api/hunt?q=" + quote("source:DEMO:lab"))
        self.assertEqual(status, 200, hunt_page)
        self.assertEqual([e["source"] for e in hunt_page["events"]], ["demo:Lab"])
        self.assertEqual(hunt_page["terms"][0]["text"], "source = DEMO:lab")
        status, grouped, _ = client.get("/api/hunt?q=" + quote("source:demo:* | stats count by source"))
        self.assertEqual(status, 200, grouped)
        self.assertEqual(grouped["rows"], [["demo:Lab", 1], ["demo:Other", 1]])
