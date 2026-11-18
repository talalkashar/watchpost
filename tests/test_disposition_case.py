"""Resolving an alert folds disposition ASCII case onto the catalog spelling.

`False_Positive` stores `false_positive`. A blank, a missing value, and a
non-ASCII lookalike stay the existing error. A status of `Open` stays 400.
Incidents have no disposition.
"""

import inspect
import json
import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.incidents import update_status as update_incident_status
from watchpost.queries import QueryError, update_status

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NOW = "2026-10-08T12:00:00.000Z"
REQUIRED = "resolving requires a disposition: true_positive, false_positive, benign"
ENTITIES = json.dumps({"src_ip": ["203.0.113.5"], "user": ["erin"], "host": ["db01"]})
STAGES = json.dumps(["Initial Access"])


def add_alert(conn, alert_id=1):
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
        (alert_id, "synthetic_rule", f"g{alert_id}", "high", "[SYNTHETIC] disposition alert", "synthetic",
         "open", NOW, NOW, NOW, NOW))


def add_incident(conn, incident_id=1):
    conn.execute(
        "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,1,1,?,?)",
        (incident_id, "Synthetic incident", "high", "open", NOW, NOW, ENTITIES, STAGES, NOW, NOW))


class DispositionCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_alert(self.conn)

    def stored(self):
        return self.conn.execute("SELECT status, disposition FROM alerts WHERE id = 1").fetchone()

    def test_mixed_case_stores_the_catalog_spelling(self):
        for submitted, stored in (
            ("False_Positive", "false_positive"),
            ("BENIGN", "benign"),
            ("True_Positive", "true_positive"),
            ("false_positive", "false_positive"),
        ):
            with self.subTest(submitted=submitted):
                self.conn.execute(
                    "UPDATE alerts SET status = 'open', disposition = NULL, resolved_at = NULL WHERE id = 1")
                row = update_status(self.conn, 1, "analyst", "resolved", submitted)
                self.assertEqual((row["status"], row["disposition"]), ("resolved", stored))
                self.assertEqual(tuple(self.stored()), ("resolved", stored))
                detail = self.conn.execute(
                    "SELECT detail FROM alert_activity WHERE alert_id = 1 ORDER BY id DESC LIMIT 1"
                ).fetchone()[0]
                self.assertEqual(detail, f"open -> resolved ({stored})")
                audit = json.loads(self.conn.execute(
                    "SELECT detail FROM audit_log WHERE action = 'alert_status_changed' ORDER BY id DESC LIMIT 1"
                ).fetchone()[0])
                self.assertEqual(audit["disposition"], stored)

    def test_a_blank_a_missing_value_and_a_lookalike_stay_the_existing_error(self):
        for bad in ("", " ", None, "maybe", "false_pos\u0131tive", "ben\u0131gn", "B\u00e9nign", 1, True):
            with self.subTest(disposition=bad):
                with self.assertRaises(QueryError) as caught:
                    update_status(self.conn, 1, "analyst", "resolved", bad)
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), REQUIRED)
        self.assertEqual(tuple(self.stored()), ("open", None))

    def test_open_stays_invalid_and_a_disposition_on_another_status_stays_refused(self):
        with self.assertRaises(QueryError) as caught:
            update_status(self.conn, 1, "analyst", "Open", "False_Positive")
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("status must be one of", str(caught.exception))
        with self.assertRaises(QueryError) as caught:
            update_status(self.conn, 1, "analyst", "investigating", "Benign")
        self.assertEqual(str(caught.exception), "disposition can only be set when resolving")
        self.assertEqual(tuple(self.stored()), ("open", None))

    def test_an_incident_status_change_has_no_disposition(self):
        self.assertNotIn("disposition", inspect.signature(update_incident_status).parameters)
        add_incident(self.conn)
        row = update_incident_status(self.conn, 1, "analyst", "resolved", note="contained")
        self.assertNotIn("disposition", row)
        self.assertEqual(row["status"], "resolved")
        with self.assertRaises(QueryError) as caught:
            update_incident_status(self.conn, 1, "analyst", "Open")
        self.assertIn("status must be one of", str(caught.exception))

    def test_docs_name_the_fold(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `POST /api/alerts/{id}/status`"))
        self.assertIn("`False_Positive` stores `false_positive`", row)
        self.assertIn("`Benign` stores `benign`", row)
        self.assertIn("`Open` stays 400", row)
        incident = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `POST /api/incidents/{id}/status`"))
        self.assertNotIn("disposition", incident)
        text = REFERENCE.read_text()
        self.assertIn("`False_Positive` stores `false_positive`", text)
        self.assertIn("Incidents have no verdict.", text)


class DispositionCaseApiTests(ServerTestCase):
    def test_resolve_stores_the_catalog_spelling_and_refuses_a_lookalike(self):
        with sqlite3.connect(self.db_path) as db:
            add_alert(db)
            add_incident(db)

        analyst = self.client("analyst")
        status, data, headers = analyst.post(
            "/api/alerts/1/status", {"status": "resolved", "disposition": "False_Positive"})
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(data["disposition"], "false_positive")
        self.assertEqual(data["status"], "resolved")

        status, data, headers = analyst.post(
            "/api/alerts/1/status", {"status": "resolved", "disposition": "ben\u0131gn"})
        self.assertEqual(status, 400, data)
        self.assertEqual(data["error"], REQUIRED)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(analyst.get("/api/alerts/1")[1]["disposition"], "false_positive")

        status, data, headers = analyst.post(
            "/api/alerts/1/status", {"status": "Open", "disposition": "Benign"})
        self.assertEqual(status, 400, data)
        self.assertIn("status must be one of", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(analyst.get("/api/alerts/1")[1]["disposition"], "false_positive")

        status, data, _ = analyst.post(
            "/api/incidents/1/status", {"status": "resolved", "disposition": "False_Positive"})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["status"], "resolved")
        self.assertNotIn("disposition", data)
