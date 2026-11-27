"""Hunt bytes comparisons are bound parameters. Grouping by bytes stays refused."""

import sqlite3
import unittest
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema
from watchpost.normalize import MAX_BYTES

# (user, bytes or None). Synthetic, labelled only by the message written below.
ROWS = [("zero", 0), ("small", 99), ("exact", 100), ("over", 101), ("missing", None),
        ("ceiling", MAX_BYTES)]


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for n, (user, nbytes) in enumerate(ROWS):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, message, bytes, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", "cloud_data_access", "low", user, "[SYNTHETIC] storage read", nbytes))
    return conn


class BytesComparisonTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["user"] for e in page["events"])

    def test_each_operator_is_a_bound_comparison(self):
        cases = {
            "bytes:>=100": ["ceiling", "exact", "over"],
            "bytes:>100": ["ceiling", "over"],
            "bytes:<=100": ["exact", "small", "zero"],
            "bytes:<100": ["small", "zero"],
            "bytes:=100": ["exact"],
            "bytes:>=100 bytes:<101": ["exact"],
            'bytes:">=100"': ["ceiling", "exact", "over"],
            f"bytes:>={MAX_BYTES}": ["ceiling"],
            f"bytes:>{MAX_BYTES}": [],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.users(text), expected)

    def test_a_missing_count_does_not_match_and_not_keeps_it(self):
        self.assertNotIn("missing", self.users("bytes:>=0"))
        self.assertEqual(self.users("NOT bytes:>=100"), ["missing", "small", "zero"])

    def test_the_number_is_bound_and_the_operator_is_whitelisted(self):
        where, args = hunt.compile_query("bytes:>=1000000")
        self.assertEqual(where, ["bytes >= ?"])
        self.assertEqual(args, [1000000])
        self.assertNotIn("1000000", where[0])
        self.assertEqual(hunt.explain("bytes:<=100")[0]["text"], "bytes <= 100")
        self.assertFalse(hunt.bytes_matches(True, ">=", 1))
        self.assertFalse(hunt.bytes_matches(None, "=", 0))

    def test_other_values_list_the_operators(self):
        bad = ["bytes:100", "bytes:huge", "bytes:>=", "bytes:==100", "bytes:>=01", "bytes:>=1.5",
               "bytes:>=-1", "bytes:>=100*", 'bytes:">=1 OR 1=1"', "bytes:>=1;DROP",
               f"bytes:>={MAX_BYTES + 1}"]
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(text)
                self.assertIn(">=, >, <=, < or =", str(caught.exception))

    def test_grouping_by_bytes_stays_refused(self):
        self.assertNotIn("bytes", hunt.GROUPABLE)
        for text in ("| stats count by bytes", "| top bytes", "| stats dc(bytes)",
                     "| timechart span=1h by bytes"):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.run(self.conn, {"q": text})
                message = str(caught.exception)
                self.assertIn("not grouped", message)
                self.assertIn(">=", message)
                tail = message.split("group by one of ", 1)[1]
                self.assertNotIn("bytes", tail.split(", "))
                self.assertIn("dest_port", tail)

    def test_a_stats_stage_counts_only_the_compared_events(self):
        data = hunt.run(self.conn, {"q": "bytes:>=100 | stats count"})
        self.assertEqual(data["rows"], [[3]])


class BytesHuntApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, message, bytes,"
                " synthetic) VALUES (?,?,?,?,?,?,?,?,1)",
                ("2026-10-07T11:00:00.000Z", "2026-10-07T11:00:00.000Z", "lab", "cloud_data_access", "low",
                 "exact", "[SYNTHETIC] storage read", 100))

    def test_the_api_runs_a_comparison_and_rejects_a_bare_number(self):
        client = self.client("viewer")
        status, data, _ = client.get("/api/hunt?q=" + quote("bytes:>=100 synthetic:1"))
        self.assertEqual(status, 200, data)
        self.assertEqual([e["user"] for e in data["events"]], ["exact"])
        self.assertEqual(data["terms"][0]["text"], "bytes >= 100")
        status, data, _ = client.get("/api/hunt?q=" + quote("bytes:100"))
        self.assertEqual(status, 400)
        self.assertIn(">=, >, <=, < or =", data["error"])
        status, data, _ = client.get("/api/hunt?q=" + quote("| top bytes"))
        self.assertEqual(status, 400)
        self.assertIn("not grouped", data["error"])
