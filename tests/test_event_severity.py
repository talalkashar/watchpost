"""Event search strips severity names in a comma list.

`severity=high, critical` is accepted, the same way alerts and incidents accept it.
A blank piece stays invalid.
"""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import queries
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for minute, severity in enumerate(("info", "low", "medium", "high", "critical")):
        ts = f"2026-10-07T11:{minute:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", "web01", "process_start", severity, severity, "[SYNTHETIC] severity list"))
    return conn


class EventSeverityFilterTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def levels(self, **params):
        page = queries.search_events(self.conn, params)
        return sorted(event["severity"] for event in page["events"])

    def test_spaces_around_names_are_ignored(self):
        self.assertEqual(self.levels(severity="high, critical"), ["critical", "high"])
        self.assertEqual(self.levels(severity=" high , critical "), ["critical", "high"])

    def test_one_severity_still_matches(self):
        self.assertEqual(self.levels(severity="high"), ["high"])
        self.assertEqual(self.levels(severity=" high "), ["high"])

    def test_min_mode_uses_the_stripped_name(self):
        self.assertEqual(self.levels(severity=" high ", severity_mode="min"),
                         ["critical", "high"])
        # Two names stay a list. min applies only to one level.
        self.assertEqual(self.levels(severity="high, critical", severity_mode="min"),
                         ["critical", "high"])

    def test_min_mode_folds_ascii_case(self):
        for mode in ("Min", "MIN", "mIn"):
            with self.subTest(mode=mode):
                self.assertEqual(self.levels(severity="high", severity_mode=mode),
                                 ["critical", "high"])
        # minimum is not an alias. The level list stays exact.
        self.assertEqual(self.levels(severity="high", severity_mode="minimum"), ["high"])
        self.assertEqual(self.levels(severity="high", severity_mode="MINIMUM"), ["high"])
        # Dotless i is not ASCII i.
        self.assertEqual(self.levels(severity="high", severity_mode="m\u0131n"), ["high"])
        # A missing mode stays an exact list.
        self.assertEqual(self.levels(severity="high"), ["high"])

    def test_a_blank_or_unknown_piece_is_invalid(self):
        for bad in ("urgent", "high,urgent", "high,", "high, ", ",", " , ", "high, critical,"):
            with self.subTest(bad=bad):
                with self.assertRaises(queries.QueryError) as caught:
                    queries.search_events(self.conn, {"severity": bad})
                self.assertEqual(caught.exception.status, 400)
                self.assertIn("severity must be from", str(caught.exception))
                self.assertEqual(queries.search_events(self.conn, {})["total"], 5)


class EventSeverityApiTests(ServerTestCase):
    def test_events_accept_a_spaced_list_and_refuse_a_blank_piece(self):
        client = self.client("analyst")
        base = "2026-10-07T12:00:00.000Z"
        status, data, _ = client.post("/api/ingest", {"source": "lab", "events": [
            {"ts": base, "type": "process", "severity": "high", "message": "synthetic high"},
            {"ts": base, "type": "process", "severity": "critical", "message": "synthetic critical"},
            {"ts": base, "type": "process", "severity": "medium", "message": "synthetic medium"},
        ]})
        self.assertEqual(status, 201, data)

        status, data, headers = client.get("/api/events?severity=high,%20critical")
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(sorted(event["severity"] for event in data["events"]), ["critical", "high"])

        status, data, headers = client.get("/api/events?severity=high,")
        self.assertEqual(status, 400, data)
        self.assertIn("severity must be from", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, headers = client.get("/api/events?severity=high&severity_mode=Min")
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(sorted(event["severity"] for event in data["events"]), ["critical", "high"])

        status, data, _ = client.get("/api/events?severity=high&severity_mode=minimum")
        self.assertEqual(status, 200, data)
        self.assertEqual([event["severity"] for event in data["events"]], ["high"])

    def test_api_docs_say_spaces_are_ignored(self):
        text = API.read_text()
        row = next(line for line in text.splitlines() if "severity_mode=min" in line)
        self.assertIn("Spaces around each name are ignored", row)
        self.assertIn("A blank or unknown piece is 400", row)
        self.assertIn("`Min` is `min`", row)
        self.assertIn("`minimum` is not an alias", row)
