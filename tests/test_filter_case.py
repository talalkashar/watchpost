"""Alert and incident list filters fold status and severity onto catalog spellings.

`status=Open` binds `open`. `severity=High` binds `high`. A blank piece stays
invalid. The comparison is the catalog spelling, so a stored lookalike is not
that row. A status change still requires the catalog spelling.
ASCII only: a non-ASCII letter is not folded.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.incidents import list_incidents, update_status as update_incident_status
from watchpost.queries import QueryError, list_alerts, update_status as update_alert_status

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
NOW = "2026-10-08T12:00:00.000Z"
ENTITIES = json.dumps({"src_ip": ["203.0.113.5"], "user": ["erin"], "host": ["db01"]})
STAGES = json.dumps(["Initial Access"])


def add_alert(conn, alert_id, severity, status):
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
        (alert_id, "synthetic_rule", f"g{alert_id}", severity, "synthetic alert", "synthetic", status,
         NOW, NOW, NOW, NOW))


def add_incident(conn, incident_id, severity, status):
    conn.execute(
        "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,1,1,?,?)",
        (incident_id, f"Synthetic incident {incident_id}", severity, status, NOW, NOW,
         ENTITIES, STAGES, NOW, NOW))


class FilterCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_alert(self.conn, 1, "critical", "open")
        add_alert(self.conn, 2, "high", "investigating")
        add_alert(self.conn, 3, "low", "resolved")
        add_alert(self.conn, 4, "High", "Open")
        add_incident(self.conn, 1, "critical", "open")
        add_incident(self.conn, 2, "high", "investigating")
        add_incident(self.conn, 3, "info", "resolved")
        add_incident(self.conn, 4, "HIGH", "OPEN")

    def alert_ids(self, **params):
        return [row["id"] for row in list_alerts(self.conn, params)]

    def incident_ids(self, **params):
        return [row["id"] for row in list_incidents(self.conn, params)]

    def test_filters_bind_the_catalog_spelling(self):
        self.assertEqual(self.alert_ids(status="Open"), [1])
        self.assertEqual(sorted(self.alert_ids(status="OPEN, Investigating")), [1, 2])
        self.assertEqual(self.alert_ids(severity="High"), [2])
        self.assertEqual(sorted(self.alert_ids(severity=" HIGH , low ")), [2, 3])
        self.assertEqual(self.alert_ids(status="Open", severity="Critical"), [1])
        self.assertEqual(self.incident_ids(status="Open"), [1])
        self.assertEqual(sorted(self.incident_ids(status="RESOLVED, open")), [1, 3])
        self.assertEqual(self.incident_ids(severity="High"), [2])
        self.assertEqual(self.incident_ids(severity="INFO"), [3])
        self.assertEqual(self.incident_ids(status=" open ", severity=" Critical "), [1])
        # Stored lookalikes are not the catalog row.
        self.assertNotIn(4, self.alert_ids(status="Open"))
        self.assertNotIn(4, self.alert_ids(severity="High"))
        self.assertNotIn(4, self.incident_ids(status="Open"))
        self.assertNotIn(4, self.incident_ids(severity="High"))

    def test_a_blank_or_unknown_piece_stays_invalid(self):
        for bad in ("Open,", "Open, ", ",", "closed", "open,closed"):
            with self.subTest(status=bad):
                for listing in (list_alerts, list_incidents):
                    with self.assertRaises(QueryError) as caught:
                        listing(self.conn, {"status": bad})
                    self.assertEqual(caught.exception.status, 400)
                    self.assertIn("status must be from", str(caught.exception))
        for bad in ("High,", "High, ", "urgent", "critical,urgent", "H\u0131gh", "Investigat\u0131ng"):
            with self.subTest(severity=bad):
                for listing in (list_alerts, list_incidents):
                    with self.assertRaises(QueryError) as caught:
                        listing(self.conn, {"severity": bad})
                    self.assertEqual(caught.exception.status, 400)
                    self.assertEqual(str(caught.exception), "invalid severity")
        for bad in ("\u0130nvestigating", "Investigat\u0131ng"):
            with self.subTest(status=bad):
                for listing in (list_alerts, list_incidents):
                    with self.assertRaises(QueryError) as caught:
                        listing(self.conn, {"status": bad})
                    self.assertIn("status must be from", str(caught.exception))

    def test_a_status_change_still_requires_the_catalog_spelling(self):
        for update, row_id in ((update_alert_status, 1), (update_incident_status, 1)):
            with self.subTest(update=update.__module__):
                with self.assertRaises(QueryError) as caught:
                    update(self.conn, row_id, "analyst", "Open")
                self.assertEqual(caught.exception.status, 400)
                self.assertIn("status must be one of", str(caught.exception))
        self.assertEqual(self.conn.execute("SELECT status FROM alerts WHERE id = 1").fetchone()[0], "open")
        self.assertEqual(self.conn.execute("SELECT status FROM incidents WHERE id = 1").fetchone()[0], "open")

    def test_api_docs_name_the_fold(self):
        text = API.read_text()
        for prefix in ("| `GET /api/alerts?", "| `GET /api/incidents?"):
            row = next(line for line in text.splitlines() if line.startswith(prefix))
            self.assertIn("`status` and `severity` each take one value or a comma list.", row)
            self.assertIn("ASCII case folds onto the catalog spelling (`Open` is `open`, `High` is `high`).", row)


class FilterCaseApiTests(ServerTestCase):
    def test_lists_fold_case_and_refuse_a_blank_piece(self):
        with sqlite3.connect(self.db_path) as db:
            add_alert(db, 1, "critical", "open")
            add_alert(db, 2, "high", "investigating")
            add_incident(db, 1, "critical", "open")
            add_incident(db, 2, "high", "investigating")

        client = self.client("viewer")
        status, data, headers = client.get("/api/alerts?status=Open&severity=Critical")
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual([row["id"] for row in data], [1])

        status, data, headers = client.get("/api/incidents?status=INVESTIGATING&severity=High")
        self.assertEqual(status, 200, data)
        self.assertEqual([row["id"] for row in data], [2])

        status, data, headers = client.get("/api/alerts?status=Open,")
        self.assertEqual(status, 400, data)
        self.assertIn("status must be from", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, headers = client.get("/api/incidents?severity=High,")
        self.assertEqual(status, 400, data)
        self.assertEqual(data["error"], "invalid severity")
        self.assertEqual(headers["Cache-Control"], "no-store")
