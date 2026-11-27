"""Event search and hunt match outcome case-insensitively (ASCII).

Grouping by outcome stays exact. NOCASE folds ASCII letters only. A prefix already folded ASCII
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
        ("failure", "web01"),
        ("Failure", "WEB01"),
        ("FAILURE", "db01"),
        ("success", "mail01"),
        ("échec", "a"),
        ("Échec", "b"),
    ]
    for n, (outcome, host) in enumerate(rows):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, outcome, severity, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", host, "process_start", outcome, "low", "[SYNTHETIC] outcome case",))
    return conn


class OutcomeCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def outcomes(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["outcome"] for e in page["events"])

    def test_hunt_and_event_search_fold_ascii_outcome(self):
        folded = ["FAILURE", "Failure", "failure"]
        self.assertEqual(self.outcomes("outcome:Failure"), folded)
        self.assertEqual(self.outcomes('outcome:"failure"'), folded)
        self.assertEqual(self.outcomes("NOT outcome:failure"), ["success", "Échec", "échec"])
        # A non-ASCII letter is not folded, so these stay two outcomes.
        self.assertEqual(self.outcomes("outcome:échec"), ["échec"])
        self.assertEqual(self.outcomes("outcome:Échec"), ["Échec"])
        # A prefix already folded ASCII. It still does, and it does not fold é.
        self.assertEqual(self.outcomes("outcome:fail*"), folded)
        self.assertEqual(self.outcomes("outcome:éch*"), ["échec"])

        found = queries.search_events(self.conn, {"outcome": "FAILURE"})
        self.assertEqual(sorted(e["outcome"] for e in found["events"]), folded)
        self.assertEqual(queries.search_events(self.conn, {"outcome": "fail*"})["total"], 3)

    def test_the_comparison_is_nocase_and_grouping_stays_exact(self):
        where, args = hunt.compile_query("outcome:Failure")
        self.assertEqual((where, args), (["outcome = ? COLLATE NOCASE"], ["Failure"]))
        match = search_rules.matcher([{"field": "outcome", "value": "Failure", "negate": False, "quoted": False}])
        self.assertTrue(match({"outcome": "failure"}))
        self.assertFalse(match({"outcome": "success"}))
        self.assertFalse(match({"outcome": None}))
        self.assertFalse(match({"outcome": "échec"}))
        groups = hunt.run(self.conn, {"q": "outcome:failure | stats count by outcome"})
        self.assertEqual(groups["rows"], [["FAILURE", 1], ["Failure", 1], ["failure", 1]])


class OutcomeCaseApiTests(ServerTestCase):
    def test_events_and_hunt_accept_either_spelling(self):
        client = self.client("analyst")
        base = utcnow() - timedelta(hours=1)
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": iso(base), "type": "process", "host": "web01", "outcome": "Failure",
             "message": "[SYNTHETIC] case"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "process", "host": "db01",
             "outcome": "Success", "message": "[SYNTHETIC] other"},
        ]})
        self.assertEqual(status, 201, body)
        status, data, _ = client.get("/api/events?outcome=failure")
        self.assertEqual(status, 200, data)
        self.assertEqual([e["outcome"] for e in data["events"]], ["Failure"])
        status, hunt_page, _ = client.get("/api/hunt?q=" + quote("outcome:FAILURE"))
        self.assertEqual(status, 200, hunt_page)
        self.assertEqual([e["outcome"] for e in hunt_page["events"]], ["Failure"])
        self.assertEqual(hunt_page["terms"][0]["text"], "outcome = FAILURE")
        status, grouped, _ = client.get("/api/hunt?q=" + quote('"[SYNTHETIC]" | stats count by outcome'))
        self.assertEqual(status, 200, grouped)
        self.assertEqual(grouped["rows"], [["Failure", 1], ["Success", 1]])
