"""Hunt and event search fold event_type and severity onto the catalog spelling.

`event_type:Auth_Failure` binds `auth_failure`. `severity=High` binds `high`.
An unknown name is 400 and lists the catalog. The comparison stays exact equality,
so a stored lookalike is not that row. Grouping by those fields keeps each spelling.
ASCII only: a non-ASCII letter is not folded.
"""

import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt, queries, search_rules
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = [
        ("auth_failure", "high", "web01"),
        ("Auth_Failure", "High", "WEB01"),
        ("AUTH_FAILURE", "HIGH", "db01"),
        ("auth_success", "low", "mail01"),
        ("auth_fa\u0131lure", "info", "other"),
    ]
    for n, (event_type, severity, host) in enumerate(rows):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", host, event_type, severity, "[SYNTHETIC] enum case"))
    return conn


class EnumCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def types(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["event_type"] for e in page["events"])

    def test_hunt_binds_the_catalog_spelling(self):
        self.assertEqual(self.types("event_type:Auth_Failure"), ["auth_failure"])
        self.assertEqual(self.types('event_type:"AUTH_FAILURE"'), ["auth_failure"])
        self.assertEqual(self.types("NOT event_type:auth_failure"), [
            "AUTH_FAILURE", "Auth_Failure", "auth_fa\u0131lure", "auth_success"])
        # A prefix stays LIKE, which already folds ASCII. AUTH_FAIL* is the three ASCII spellings.
        # The dotless-i row does not match that prefix.
        self.assertEqual(self.types("event_type:AUTH_FAIL*"), [
            "AUTH_FAILURE", "Auth_Failure", "auth_failure"])
        # Dotless i is not ASCII i, so this is not auth_failure and not a catalog name.
        with self.assertRaises(hunt.HuntError) as caught:
            hunt.compile_query("event_type:auth_fa\u0131lure")
        self.assertIn("event_type must be one of", str(caught.exception))
        self.assertIn("auth_failure", str(caught.exception))

        where, args = hunt.compile_query("event_type:Auth_Failure severity:HIGH")
        self.assertEqual(where, ["event_type = ?", "severity = ?"])
        self.assertEqual(args, ["auth_failure", "high"])
        self.assertNotIn("NOCASE", where[0])
        explained = hunt.explain("severity:High")
        self.assertEqual(explained[0]["value"], "High")
        self.assertEqual(explained[0]["text"], "severity = high")

        found = queries.search_events(self.conn, {"event_type": "Auth_Failure"})
        self.assertEqual([e["event_type"] for e in found["events"]], ["auth_failure"])
        levels = queries.search_events(self.conn, {"severity": "HIGH, low"})
        self.assertEqual(sorted(e["severity"] for e in levels["events"]), ["high", "low"])
        at_least = queries.search_events(
            self.conn, {"severity": " HIGH ", "severity_mode": "min"})
        # min expands the catalog (`high`, `critical`) and still binds those spellings.
        self.assertEqual([e["severity"] for e in at_least["events"]], ["high"])

    def test_an_unknown_name_lists_the_catalog(self):
        for text, message in (
                ("event_type:Auth_Fail", "event_type must be one of"),
                ("severity:Huge", "severity must be one of"),
                ("severity:H\u0131gh", "severity must be one of")):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(text)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn(message, str(caught.exception))
                self.assertIn("auth_failure" if "event_type" in text else "critical",
                              str(caught.exception))
        for params, message, listed in (
                ({"event_type": "Nope"}, "event_type must be one of", "auth_failure"),
                ({"severity": "High,"}, "severity must be from", "info"),
                ({"severity": "urgent"}, "severity must be from", "critical")):
            with self.subTest(params=params):
                with self.assertRaises(queries.QueryError) as caught:
                    queries.search_events(self.conn, params)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn(message, str(caught.exception))
                self.assertIn(listed, str(caught.exception))

    def test_grouping_stays_exact_and_the_matcher_binds_the_catalog(self):
        groups = hunt.run(self.conn, {"q": "| stats count by event_type"})
        self.assertEqual(groups["rows"], [
            ["AUTH_FAILURE", 1], ["Auth_Failure", 1], ["auth_failure", 1],
            ["auth_fa\u0131lure", 1], ["auth_success", 1]])
        by_severity = hunt.run(self.conn, {"q": "| stats count by severity"})
        self.assertEqual(by_severity["rows"], [
            ["HIGH", 1], ["High", 1], ["high", 1], ["info", 1], ["low", 1]])
        match = search_rules.matcher(
            [{"field": "event_type", "value": "Auth_Failure", "negate": False, "quoted": False}])
        self.assertTrue(match({"event_type": "auth_failure"}))
        self.assertFalse(match({"event_type": "Auth_Failure"}))
        self.assertFalse(match({"event_type": "auth_success"}))
        self.assertFalse(match({"event_type": None}))
        level = search_rules.matcher(
            [{"field": "severity", "value": "HIGH", "negate": False, "quoted": False}])
        self.assertTrue(level({"severity": "high"}))
        self.assertFalse(level({"severity": "High"}))

    def test_docs_name_the_catalog_spelling(self):
        api = API.read_text()
        event_type = next(line for line in api.splitlines() if line.startswith("| `event_type` | One"))
        severity = next(line for line in api.splitlines() if "severity_mode=min" in line)
        self.assertIn("Auth_Failure", event_type)
        self.assertIn("auth_failure", event_type)
        self.assertIn("High", severity)
        self.assertIn("high", severity)
        reference = REFERENCE.read_text()
        self.assertIn("`Auth_Failure` binds `auth_failure`", reference)
        self.assertIn("`High` binds `high`", reference)


class EnumCaseApiTests(ServerTestCase):
    def test_events_and_hunt_accept_either_spelling(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": "2026-10-07T12:00:00.000Z", "type": "auth_failure", "severity": "high",
             "host": "web01", "message": "[SYNTHETIC] catalog"},
            {"ts": "2026-10-07T12:01:00.000Z", "type": "process", "severity": "low",
             "host": "db01", "message": "[SYNTHETIC] other"},
        ]})
        self.assertEqual(status, 201, body)
        status, data, headers = client.get("/api/events?event_type=AUTH_FAILURE&severity=High")
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual([e["event_type"] for e in data["events"]], ["auth_failure"])
        self.assertEqual([e["severity"] for e in data["events"]], ["high"])
        status, hunt_page, _ = client.get(
            "/api/hunt?q=" + quote("event_type:Auth_Failure severity:HIGH"))
        self.assertEqual(status, 200, hunt_page)
        self.assertEqual([e["event_type"] for e in hunt_page["events"]], ["auth_failure"])
        self.assertEqual(hunt_page["terms"][0]["text"], "event_type = auth_failure")
        self.assertEqual(hunt_page["terms"][1]["text"], "severity = high")
        status, grouped, _ = client.get(
            "/api/hunt?q=" + quote('"[SYNTHETIC]" | stats count by event_type'))
        self.assertEqual(status, 200, grouped)
        self.assertEqual(grouped["rows"], [["auth_failure", 1], ["process_start", 1]])
        status, bad, headers = client.get("/api/events?event_type=Nope")
        self.assertEqual(status, 400, bad)
        self.assertIn("event_type must be one of", bad["error"])
        self.assertIn("auth_failure", bad["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, bad, headers = client.get("/api/hunt?q=" + quote("severity:Huge"))
        self.assertEqual(status, 400, bad)
        self.assertIn("severity must be one of", bad["error"])
        self.assertIn("critical", bad["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
