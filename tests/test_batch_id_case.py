"""Event search and hunt match batch_id case-insensitively (ASCII).

A stored lowercase uuid hex matches ABCDEF…. A trailing * stays a prefix.
Grouping by batch_id stays the stored spelling. NOCASE folds ASCII letters only.
"""

import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt, queries, search_rules
from watchpost.db import connect, init_schema, iso, utcnow

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
STORED = "abcdef0123456789abcdef0123456789"
OTHER = "0123456789abcdef0123456789abcdef"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = [
        (STORED, "web01"),
        (STORED.upper(), "WEB01"),
        ("AbCdEf0123456789abcdef0123456789", "db01"),
        (OTHER, "mail01"),
        ("idé", "a"),
        ("idÉ", "b"),
    ]
    for n, (batch_id, host) in enumerate(rows):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message,"
            " synthetic, batch_id) VALUES (?,?,?,?,?,?,?,1,?)",
            (ts, ts, "lab", host, "process_start", "low", "[SYNTHETIC] batch case", batch_id))
    return conn


class BatchIdCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def batches(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["batch_id"] for e in page["events"])

    def test_hunt_and_event_search_fold_ascii_batch_id(self):
        folded = sorted([STORED, STORED.upper(), "AbCdEf0123456789abcdef0123456789"])
        self.assertEqual(self.batches("batch_id:" + STORED.upper()), folded)
        self.assertEqual(self.batches('batch_id:"' + STORED + '"'), folded)
        self.assertEqual(self.batches("NOT batch_id:" + STORED), sorted([OTHER, "idé", "idÉ"]))
        # A non-ASCII letter is not folded, so these stay two ids.
        self.assertEqual(self.batches("batch_id:idé"), ["idé"])
        self.assertEqual(self.batches("batch_id:idÉ"), ["idÉ"])
        # A prefix already folded ASCII. It still does, and it does not fold é.
        self.assertEqual(self.batches("batch_id:ABCDEF*"), folded)
        self.assertEqual(self.batches("batch_id:idÉ*"), ["idÉ"])

        found = queries.search_events(self.conn, {"batch_id": STORED.upper()})
        self.assertEqual(sorted(e["batch_id"] for e in found["events"]), folded)
        self.assertEqual(queries.search_events(self.conn, {"batch_id": "abcdef*"})["total"], 3)

    def test_the_comparison_is_nocase_and_grouping_stays_exact(self):
        where, args = hunt.compile_query("batch_id:" + STORED.upper())
        self.assertEqual((where, args), (["batch_id = ? COLLATE NOCASE"], [STORED.upper()]))
        term = [{"field": "batch_id", "value": STORED.upper(), "negate": False, "quoted": False}]
        match = search_rules.matcher(term)
        self.assertTrue(match({"batch_id": STORED}))
        self.assertFalse(match({"batch_id": OTHER}))
        self.assertFalse(match({"batch_id": None}))
        self.assertFalse(match({"batch_id": "idé"}))
        groups = hunt.run(self.conn, {"q": "batch_id:" + STORED + " | stats count by batch_id"})
        self.assertEqual(groups["rows"], [
            [STORED.upper(), 1],
            ["AbCdEf0123456789abcdef0123456789", 1],
            [STORED, 1],
        ])

    def test_events_field_row_documents_the_fold(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `source`, `host`, `user`, `outcome`, `batch_id`"))
        self.assertIn("and `batch_id` ignore ASCII case", row)
        self.assertIn("grouping by source, outcome, and batch_id stays the stored spelling", row)


class BatchIdCaseApiTests(ServerTestCase):
    def test_events_and_hunt_accept_either_spelling(self):
        client = self.client("analyst")
        base = utcnow() - timedelta(hours=1)
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": iso(base), "type": "process", "host": "web01", "message": "[SYNTHETIC] batch case"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "process", "host": "db01",
             "message": "[SYNTHETIC] other"},
        ]})
        self.assertEqual(status, 201, body)
        batch_id = body["batch_id"]
        self.assertEqual(batch_id, batch_id.lower())
        status, data, _ = client.get("/api/events?batch_id=" + quote(batch_id.upper()))
        self.assertEqual(status, 200, data)
        self.assertEqual(sorted(e["host"] for e in data["events"]), ["db01", "web01"])
        self.assertTrue(all(e["batch_id"] == batch_id for e in data["events"]))
        status, hunt_page, _ = client.get("/api/hunt?q=" + quote("batch_id:" + batch_id.upper()))
        self.assertEqual(status, 200, hunt_page)
        self.assertEqual(sorted(e["host"] for e in hunt_page["events"]), ["db01", "web01"])
        self.assertEqual(hunt_page["terms"][0]["text"], "batch_id = " + batch_id.upper())
        status, prefixed, _ = client.get("/api/events?batch_id=" + quote(batch_id[:8].upper() + "*"))
        self.assertEqual(status, 200, prefixed)
        self.assertEqual(prefixed["total"], 2)
        status, grouped, _ = client.get(
            "/api/hunt?q=" + quote("batch_id:" + batch_id.upper() + " | stats count by batch_id"))
        self.assertEqual(status, 200, grouped)
        self.assertEqual(grouped["rows"], [[batch_id, 2]])
