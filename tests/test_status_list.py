"""Alert and incident status lists ignore spaces around each name.

`status=open, investigating` is accepted. A blank piece stays invalid, the same way severity does.
"""

import json
import sqlite3
import unittest

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.incidents import list_incidents
from watchpost.queries import QueryError, list_alerts

NOW = "2026-10-08T12:00:00.000Z"
ENTITIES = json.dumps({"src_ip": ["203.0.113.5"], "user": ["erin"], "host": ["db01"]})
STAGES = json.dumps(["Initial Access"])


def add_alert(conn, alert_id, status):
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
        (alert_id, "synthetic_rule", f"g{alert_id}", "high", "synthetic alert", "synthetic", status,
         NOW, NOW, NOW, NOW))


def add_incident(conn, incident_id, status):
    conn.execute(
        "INSERT INTO incidents(id, title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,1,1,?,?)",
        (incident_id, f"Synthetic incident {incident_id}", "high", status, NOW, NOW,
         ENTITIES, STAGES, NOW, NOW))


class StatusListTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_alert(self.conn, 1, "open")
        add_alert(self.conn, 2, "investigating")
        add_alert(self.conn, 3, "resolved")
        add_incident(self.conn, 1, "open")
        add_incident(self.conn, 2, "investigating")
        add_incident(self.conn, 3, "resolved")

    def alert_ids(self, **params):
        return [row["id"] for row in list_alerts(self.conn, params)]

    def incident_ids(self, **params):
        return [row["id"] for row in list_incidents(self.conn, params)]

    def test_spaces_around_names_are_ignored(self):
        self.assertEqual(sorted(self.alert_ids(status="open, investigating")), [1, 2])
        self.assertEqual(sorted(self.alert_ids(status=" open , investigating ")), [1, 2])
        self.assertEqual(sorted(self.incident_ids(status="open, investigating")), [1, 2])
        self.assertEqual(sorted(self.incident_ids(status=" open , investigating ")), [1, 2])

    def test_one_status_still_matches(self):
        self.assertEqual(self.alert_ids(status="investigating"), [2])
        self.assertEqual(self.alert_ids(status=" investigating "), [2])
        self.assertEqual(self.incident_ids(status="resolved"), [3])
        self.assertEqual(self.incident_ids(status=" resolved "), [3])

    def test_a_blank_or_unknown_piece_is_invalid(self):
        for bad in ("closed", "open,closed", "open,", "open, ", ",", " , ", "open, investigating,"):
            with self.subTest(bad=bad):
                for listing in (list_alerts, list_incidents):
                    with self.assertRaises(QueryError) as caught:
                        listing(self.conn, {"status": bad})
                    self.assertEqual(caught.exception.status, 400)
                    self.assertIn("status must be from", str(caught.exception))
        self.assertEqual(self.alert_ids(), [1, 2, 3])
        self.assertEqual(sorted(self.incident_ids()), [1, 2, 3])


class StatusListApiTests(ServerTestCase):
    def test_lists_accept_a_spaced_status_and_refuse_a_blank_piece(self):
        with sqlite3.connect(self.db_path) as db:
            add_alert(db, 1, "open")
            add_alert(db, 2, "investigating")
            add_alert(db, 3, "resolved")
            add_incident(db, 1, "open")
            add_incident(db, 2, "investigating")
            add_incident(db, 3, "resolved")

        client = self.client("viewer")
        status, data, headers = client.get("/api/alerts?status=open,%20investigating")
        self.assertEqual(status, 200, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(sorted(row["id"] for row in data), [1, 2])

        status, data, headers = client.get("/api/incidents?status=open,%20investigating")
        self.assertEqual(status, 200, data)
        self.assertEqual(sorted(row["id"] for row in data), [1, 2])

        status, data, headers = client.get("/api/alerts?status=open,")
        self.assertEqual(status, 400, data)
        self.assertIn("status must be from", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, headers = client.get("/api/incidents?status=open,%20")
        self.assertEqual(status, 400, data)
        self.assertIn("status must be from", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
