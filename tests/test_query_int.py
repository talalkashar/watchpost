"""Query integers accept ASCII digits only.

limit=10 stays 10. limit=1_0, limit=４, and limit=+10 are 400 naming the
parameter. offset, hours, and since_id use the same rule. Ranges stay as they
are. A superscript stays a 400, not a 500. int() on text runs only after isascii.
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import QueryError, _int, metrics, search_events

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
QUERIES = Path(__file__).resolve().parent.parent / "watchpost" / "queries.py"
FULLWIDTH = "\uff14"  # ４
SUPERSCRIPT = "\u00b2"  # ²
UNDERSCORE = "1_0"
PLUS = "+10"
NAMES = ("limit", "offset", "hours", "since_id")


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for n in range(12):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", "web01", "process_start", "low", f"user{n:02d}", "[SYNTHETIC] query int"))
    return conn


class QueryIntTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_ascii_ten_stays_ten_and_ranges_stay(self):
        self.assertEqual(_int("10", "limit", 100, 1, 1000), 10)
        self.assertEqual(_int(10, "limit", 100, 1, 1000), 10)
        self.assertEqual(_int("0", "since_id", None, 0, 2**63 - 1), 0)
        self.assertEqual(_int(None, "limit", 100, 1, 1000), 100)
        self.assertEqual(_int("", "hours", 24, 1, 2160), 24)
        page = search_events(self.conn, {"limit": "10"})
        self.assertEqual(page["total"], 12)
        self.assertEqual(len(page["events"]), 10)
        self.assertEqual(page["events"][0]["user"], "user11")
        self.assertNotIn("user00", [row["user"] for row in page["events"]])
        self.assertEqual(search_events(self.conn, {"since_id": "0"})["total"], 12)
        self.assertEqual(metrics(self.conn, hours="24")["window_hours"], 24)
        self.assertEqual(metrics(self.conn, hours=24)["window_hours"], 24)
        for value, name, low, high in (
            ("0", "limit", 1, 1000),
            ("1001", "limit", 1, 1000),
            ("10001", "offset", 0, 10000),
            ("0", "hours", 1, 2160),
            ("2161", "hours", 1, 2160),
            ("9223372036854775808", "since_id", 0, 2**63 - 1),
        ):
            with self.subTest(name=name, value=value):
                with self.assertRaises(QueryError) as caught:
                    _int(value, name, 1, low, high)
                self.assertEqual(str(caught.exception), f"{name} must be between {low} and {high}")
                self.assertEqual(caught.exception.status, 400)

    def test_lookalikes_name_the_parameter(self):
        for name in NAMES:
            for value in (UNDERSCORE, FULLWIDTH, PLUS, SUPERSCRIPT):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(QueryError) as caught:
                        _int(value, name, 10, 0, 1000)
                    self.assertEqual(str(caught.exception), f"{name} must be an integer")
                    self.assertEqual(caught.exception.status, 400)
                    self.assertNotIn("\u0307", str(caught.exception))
        with self.assertRaisesRegex(QueryError, "limit must be an integer"):
            search_events(self.conn, {"limit": UNDERSCORE})
        with self.assertRaisesRegex(QueryError, "offset must be an integer"):
            search_events(self.conn, {"offset": UNDERSCORE})
        with self.assertRaisesRegex(QueryError, "since_id must be an integer"):
            search_events(self.conn, {"since_id": SUPERSCRIPT})
        with self.assertRaisesRegex(QueryError, "hours must be an integer"):
            metrics(self.conn, hours=PLUS)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 12)

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(_int)
        self.assertLess(source.index("text.isascii()"), source.index("int(text)"))
        self.assertIn("isdigit()", source)
        self.assertEqual(source.count("int(text)"), 1)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)
        body = QUERIES.read_text().split("def _int", 1)[1].split("\ndef _ts", 1)[0]
        self.assertLess(body.index("text.isascii()"), body.index("int(text)"))


class QueryIntApiTests(ServerTestCase):
    def test_events_metrics_and_hunt_refuse_the_lookalikes(self):
        client = self.client("analyst")
        events = [{
            "ts": f"2026-10-07T11:{n:02d}:00Z",
            "type": "process_start",
            "user": f"user{n:02d}",
            "host": "web01",
            "message": "[SYNTHETIC] query int",
        } for n in range(12)]
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": events})
        self.assertEqual(status, 201, body)
        self.assertEqual(body["accepted"], 12)

        status, page, headers = client.get("/api/events?limit=10")
        self.assertEqual(status, 200, page)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(page["total"], 12)
        self.assertEqual(len(page["events"]), 10)
        self.assertEqual(page["events"][0]["user"], "user11")
        self.assertNotIn("user00", [row["user"] for row in page["events"]])

        status, counted, _ = client.get("/api/metrics?hours=24")
        self.assertEqual(status, 200, counted)
        self.assertEqual(counted["window_hours"], 24)

        status, hunted, _ = client.get("/api/hunt?q=&limit=10")
        self.assertEqual(status, 200, hunted)
        self.assertEqual(hunted["total"], 12)
        self.assertEqual(len(hunted["events"]), 10)

        bad = (
            ("/api/events?limit=", "limit"),
            ("/api/events?offset=", "offset"),
            ("/api/events?since_id=", "since_id"),
            ("/api/metrics?hours=", "hours"),
            ("/api/hunt?q=&limit=", "limit"),
            ("/api/hunt?q=&offset=", "offset"),
        )
        for prefix, name in bad:
            for value in (UNDERSCORE, FULLWIDTH, PLUS, SUPERSCRIPT):
                path = prefix + quote(value, safe="")
                with self.subTest(path=path):
                    status, data, headers = client.get(path)
                    self.assertEqual(status, 400, data)
                    self.assertEqual(data["error"], f"{name} must be an integer")
                    self.assertNotIn("\u0307", data["error"])
                    self.assertEqual(headers["Cache-Control"], "no-store")

        for path, message in (
            ("/api/events?limit=0", "limit must be between 1 and 1000"),
            ("/api/events?limit=1001", "limit must be between 1 and 1000"),
            ("/api/events?offset=10001", "offset must be between 0 and 10000"),
            ("/api/metrics?hours=0", "hours must be between 1 and 2160"),
            ("/api/metrics?hours=2161", "hours must be between 1 and 2160"),
            ("/api/hunt?q=&limit=1001", "limit must be between 1 and 1000"),
        ):
            with self.subTest(path=path):
                status, data, _ = client.get(path)
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], message)

        status, untouched, _ = client.get("/api/events?limit=50")
        self.assertEqual(status, 200, untouched)
        self.assertEqual(untouched["total"], 12)

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("`limit=10` stays 10", text)
            self.assertIn(UNDERSCORE, text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn("`limit=+10`", text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn("`limit must be an integer`", text)
            self.assertIn("not a 500", text)
            self.assertIn("`hours=24`", text)
            self.assertIn("`hours must be an integer`", text)
            self.assertIn("`hours must be between 1 and 2160`", text)
            self.assertIn("`since_id`", text)
