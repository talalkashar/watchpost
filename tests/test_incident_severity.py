"""Incident list severity accepts one level or a comma list, the same way alerts do."""

import json
import unittest
from pathlib import Path

from watchpost.db import connect, init_schema
from watchpost.incidents import list_incidents
from watchpost.queries import QueryError

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
NOW = "2026-09-15T10:00:00.000Z"
ENTITIES = json.dumps({"src_ip": ["203.0.113.5"], "user": ["erin"], "host": ["db01"]})
STAGES = json.dumps(["Initial Access"])


def add_incident(conn, incident_id, severity, status="open", minute=0):
    seen = f"2026-09-15T10:{minute:02d}:00.000Z"
    conn.execute(
        "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,1,1,?,?)",
        (incident_id, f"Synthetic incident {incident_id}", severity, status, seen, seen,
         ENTITIES, STAGES, NOW, NOW))


class IncidentSeverityFilterTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_incident(self.conn, 1, "critical", "open", 1)
        add_incident(self.conn, 2, "high", "open", 2)
        add_incident(self.conn, 3, "medium", "open", 3)
        add_incident(self.conn, 4, "low", "investigating", 4)
        add_incident(self.conn, 5, "critical", "resolved", 5)
        add_incident(self.conn, 6, "info", "open", 6)

    def ids(self, **params):
        rows, _omitted = list_incidents(self.conn, params)
        return [row["id"] for row in rows]

    def test_a_comma_list_returns_those_severities(self):
        self.assertEqual(self.ids(severity="critical,high"), [1, 2, 5])

    def test_one_severity_still_matches(self):
        self.assertEqual(self.ids(severity="high"), [2])

    def test_spaces_around_names_are_ignored(self):
        self.assertEqual(set(self.ids(severity=" high , critical ")), {1, 2, 5})

    def test_status_and_severity_lists_combine(self):
        self.assertEqual(self.ids(status="open", severity="critical,high"), [1, 2])

    def test_a_blank_or_unknown_level_is_invalid(self):
        for bad in ("urgent", "critical,urgent", "critical,", ",", "critical, "):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryError) as caught:
                    list_incidents(self.conn, {"severity": bad})
                self.assertEqual(str(caught.exception), "invalid severity")
                self.assertEqual(caught.exception.status, 400)

    def test_api_docs_show_the_comma_list(self):
        text = API.read_text()
        row = next(line for line in text.splitlines() if line.startswith("| `GET /api/incidents?"))
        self.assertIn("severity=critical,high", row)
        self.assertIn("`status` and `severity` each take one value or a comma list.", row)
