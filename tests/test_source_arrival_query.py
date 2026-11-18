"""Source inventory reads arrivals once, for every stored spelling.

Folded spellings still share one row. A non-ASCII spelling stays its own row.
Status, events_24h, and sources_omitted stay. The newest 102 arrivals of one
spelling are the page; an older event on that spelling is not an arrival.
The same ingested_at keeps the greater id. A null host stays a row.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchpost import sources
from watchpost.db import connect, init_schema, iso

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NOW = datetime(2026, 9, 15, 18, 0, tzinfo=timezone.utc)
EVENT = ("INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
         " VALUES (?,?,?,?,'other','info','heartbeat',?)")


def _insert(conn, when, source, host, synthetic=1, ts=None):
    stamp = iso(when)
    conn.execute(EVENT, (ts or stamp, stamp, source, host, synthetic))


class SourceArrivalQueryTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        self.calls = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            self.calls.append((sql, args))
            return real_execute(sql, args)

        self.conn.execute = execute

    def inventory(self):
        self.calls.clear()
        return sources.inventory(self.conn, now=iso(NOW))

    def arrival_calls(self):
        return [(sql, args) for sql, args in self.calls if "DENSE_RANK()" in sql]

    def test_folded_spellings_share_one_row_and_one_query(self):
        # Eleven arrivals ending four hours ago, split across ASCII spellings, plus one
        # arrival thirty hours ago. The old event counts, and it is not events_24h.
        start = NOW - timedelta(hours=6)
        for i in range(11):
            _insert(self.conn, start + timedelta(minutes=12 * i),
                    "Demo" if i % 2 else "demo", "WEB01" if i % 2 else "web01")
        _insert(self.conn, NOW - timedelta(hours=30), "DEMO", "web01")
        _insert(self.conn, NOW, "démo", "Érin-host")
        _insert(self.conn, NOW, "DÉMO", "érin-host")
        _insert(self.conn, NOW, "bare", None)
        body = self.inventory()
        folded = next(r for r in body["sources"] if r["source"] == "demo")
        self.assertEqual((folded["host"], folded["status"], folded["events"], folded["events_24h"]),
                         ("web01", "silent", 12, 11))
        accented = sorted((r["source"], r["host"], r["status"]) for r in body["sources"]
                          if r["host"] and "rin-host" in r["host"])
        self.assertEqual(accented, [("dÉmo", "érin-host", "learning"), ("démo", "Érin-host", "learning")])
        bare = next(r for r in body["sources"] if r["source"] == "bare")
        self.assertIsNone(bare["host"])
        self.assertEqual(bare["events_24h"], 1)
        self.assertEqual(body["sources_omitted"], 0)
        self.assertEqual(len(self.arrival_calls()), 1)
        sql, args = self.arrival_calls()[0]
        self.assertIn("PARTITION BY source, host", sql)
        self.assertIn("arrival_rank <= ?", sql)
        self.assertNotIn("source = ?", sql)
        self.assertNotIn("host IS ?", sql)
        self.assertEqual(args, (sources.CADENCE_SAMPLE + 2,))
        self.assertFalse(any("host IS ?" in sql for sql, _ in self.calls))

    def test_an_older_arrival_on_a_full_page_stays_out(self):
        # 103 arrivals, one minute apart. The oldest is the only non-synthetic event.
        for i in range(103):
            when = NOW - timedelta(minutes=102 - i)
            _insert(self.conn, when, "fw", "fw01", synthetic=0 if i == 0 else 1)
        row = self.inventory()["sources"][0]
        self.assertEqual((row["source"], row["host"], row["events"], row["events_24h"]),
                         ("fw", "fw01", 103, 103))
        self.assertEqual(row["synthetic"], 1)
        self.assertEqual(len(self.arrival_calls()), 1)

    def test_the_same_ingested_at_keeps_the_greater_id(self):
        stamp = iso(NOW - timedelta(hours=1))
        self.conn.execute(EVENT, ("2026-09-15T08:00:00.000Z", stamp, "Demo", "WEB01", 1))
        self.conn.execute(EVENT, ("2026-09-15T09:00:00.000Z", stamp, "demo", "web01", 0))
        # Same spelling, same arrival: the later id's event time is the one kept.
        self.conn.execute(EVENT, ("2026-09-15T01:00:00.000Z", stamp, "mail", "mx01", 1))
        self.conn.execute(EVENT, ("2026-09-15T02:00:00.000Z", stamp, "mail", "mx01", 1))
        body = self.inventory()
        folded = next(r for r in body["sources"] if r["source"] == "demo")
        self.assertEqual(folded["last_event_ts"], "2026-09-15T09:00:00.000Z")
        self.assertEqual(folded["events"], 2)
        self.assertEqual(folded["synthetic"], 0)
        mail = next(r for r in body["sources"] if r["source"] == "mail")
        self.assertEqual(mail["last_event_ts"], "2026-09-15T02:00:00.000Z")
        self.assertEqual(mail["events"], 2)

    def test_a_hundred_and_one_pairs_still_omit_one_in_that_one_query(self):
        for i in range(101):
            _insert(self.conn, NOW, f"s{i:03d}", "host")
        body = self.inventory()
        self.assertEqual(body["sources_omitted"], 1)
        self.assertEqual(len(body["sources"]), 100)
        self.assertEqual(body["summary"]["learning"], 101)
        self.assertEqual(len(self.arrival_calls()), 1)

    def test_an_empty_table_still_reads_arrivals_once(self):
        body = self.inventory()
        self.assertEqual(body["sources"], [])
        self.assertEqual(body["sources_omitted"], 0)
        self.assertEqual(body["summary"], {"silent": 0, "late": 0, "healthy": 0, "learning": 0})
        self.assertEqual(len(self.arrival_calls()), 1)

    def test_the_docs_name_the_single_arrival_query(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `GET /api/sources/health`"))
        self.assertIn("one query", row)
        self.assertIn("newest 102", row)
        self.assertIn("non-ASCII", row)
        text = REFERENCE.read_text()
        self.assertIn("newest 102 arrivals in one query", text)
        self.assertIn("A non-ASCII spelling stays its own row.", text)
