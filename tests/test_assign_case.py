"""Alert assign folds ASCII case and stores the saved spelling.

`Admin` stores `admin` when that is the only match. Two enabled analyst or
admin accounts that share the fold are 409 and the assignee stays as it was.
`Érin` does not match `érin`. A disabled account and a viewer do not match.
"""

import json
import sqlite3
import unittest
from pathlib import Path
from tests.helpers import ServerTestCase
from watchpost.auth import create_user
from watchpost.db import connect, init_schema
from watchpost.queries import QueryError, assign

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NOW = "2026-10-08T12:00:00.000Z"
AMBIGUOUS = "assignee matches more than one enabled analyst or admin"
NOT_ELIGIBLE = "assignee must be an enabled analyst or admin account"


def add_alert(conn, alert_id):
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,1,?,?,?,?,?,?,?,1,1,?,?)",
        (alert_id, "synthetic_rule", f"g{alert_id}", "high", "[SYNTHETIC] assign alert", "synthetic",
         "open", NOW, NOW, NOW, NOW))


class AssignCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_alert(self.conn, 1)
        add_alert(self.conn, 2)

    def user(self, username, role="analyst", disabled=0):
        create_user(self.conn, username, "account-password-1", role)
        if disabled:
            self.conn.execute("UPDATE users SET disabled = 1 WHERE username = ?", (username,))

    def stored(self, alert_id=1):
        return self.conn.execute(
            "SELECT assignee, status FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    def test_admin_stores_the_saved_spelling(self):
        self.user("admin", "admin")
        row = assign(self.conn, 1, "analyst", " Admin ")
        self.assertEqual(row["assignee"], "admin")
        self.assertEqual(tuple(self.stored()), ("admin", "open"))
        self.assertIsNone(row["acknowledged_at"])
        detail = self.conn.execute(
            "SELECT detail FROM alert_activity WHERE alert_id = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        self.assertEqual(detail, "nobody -> admin")
        audit = json.loads(self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'alert_assigned' ORDER BY id DESC LIMIT 1"
        ).fetchone()[0])
        self.assertEqual(audit, {"from": None, "to": "admin"})

    def test_two_enabled_accounts_are_409_and_assign_nobody(self):
        self.user("solo")
        assign(self.conn, 1, "analyst", "solo")
        self.user("pat", "analyst")
        self.user("Pat", "admin")
        activity = self.conn.execute("SELECT COUNT(*) FROM alert_activity").fetchone()[0]
        audits = self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'alert_assigned'").fetchone()[0]
        with self.assertRaises(QueryError) as caught:
            assign(self.conn, 1, "analyst", "PAT")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), AMBIGUOUS)
        self.assertEqual(tuple(self.stored()), ("solo", "open"))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM alert_activity").fetchone()[0], activity)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'alert_assigned'").fetchone()[0], audits)

    def test_erin_stays_apart_from_erin(self):
        self.user("Érin")
        self.user("érin")
        row = assign(self.conn, 1, "analyst", "Érin")
        self.assertEqual(row["assignee"], "Érin")
        self.assertEqual(tuple(self.stored()), ("Érin", "open"))
        row = assign(self.conn, 2, "analyst", "érin")
        self.assertEqual(row["assignee"], "érin")
        self.assertEqual(tuple(self.stored(2)), ("érin", "open"))

    def test_a_disabled_account_and_a_viewer_do_not_match(self):
        self.user("dana", disabled=1)
        self.user("Dana", "analyst")
        self.user("Quinn", "viewer")
        self.user("Pat", "viewer")
        self.user("pat", "analyst")
        for bad in ("nobody", "Quinn"):
            with self.subTest(assignee=bad):
                with self.assertRaises(QueryError) as caught:
                    assign(self.conn, 1, "analyst", bad)
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), NOT_ELIGIBLE)
        # The disabled dana is not a second match, so Dana stores Dana.
        row = assign(self.conn, 1, "analyst", "dana")
        self.assertEqual(row["assignee"], "Dana")
        # The viewer Pat is not a second match, so pat stores pat.
        row = assign(self.conn, 2, "analyst", "Pat")
        self.assertEqual(row["assignee"], "pat")
        self.assertEqual(tuple(self.stored(2)), ("pat", "open"))

    def test_docs_name_the_fold(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `POST /api/alerts/{id}/assign`"))
        self.assertIn("`Admin` stores `admin` when that is the only match", row)
        self.assertIn("409 and the assignee stays as it was", row)
        self.assertIn("`Érin` does not match `érin`", row)
        self.assertIn("A disabled account and a viewer do not match", row)
        text = REFERENCE.read_text()
        self.assertIn("`Admin` stores `admin` when that is the only match", text)
        self.assertIn("`Érin` does not match `érin`", text)


class AssignCaseApiTests(ServerTestCase):
    def _user(self, username, role, disabled=0):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO users(username, pw_hash, role, disabled, created_at) VALUES "
                "(?, 'unused-hash', ?, ?, ?)",
                (username, role, disabled, NOW))

    def _alert(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
                " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
                " VALUES ('synthetic_rule', 1, 'g', 'high', '[SYNTHETIC] assign alert', 'synthetic', 'open',"
                " ?, ?, 1, 1, ?, ?)",
                (NOW, NOW, NOW, NOW))
            return db.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1").fetchone()[0]

    def test_the_route_stores_the_saved_spelling_and_refuses_a_clash(self):
        self._user("Casey", "analyst")
        self._user("Érin", "analyst")
        self._user("érin", "analyst")
        self._user("Dana", "analyst", disabled=1)
        alert_id = self._alert()
        analyst = self.client("analyst")
        status, body, headers = analyst.post(
            f"/api/alerts/{alert_id}/assign", {"assignee": "CASEY"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["assignee"], "Casey")
        self.assertEqual(body["status"], "open")
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, body, _ = analyst.post(
            f"/api/alerts/{alert_id}/assign", {"assignee": "Érin"})
        self.assertEqual((status, body["assignee"]), (200, "Érin"), body)
        with sqlite3.connect(self.db_path) as db:
            other = db.execute(
                "SELECT assignee FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]
        self.assertEqual(other, "Érin")
        self._user("Admin", "analyst")
        status, body, headers = analyst.post(
            f"/api/alerts/{alert_id}/assign", {"assignee": "ADMIN"})
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], AMBIGUOUS)
        self.assertEqual(headers["Cache-Control"], "no-store")
        with sqlite3.connect(self.db_path) as db:
            kept = db.execute(
                "SELECT assignee FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]
        self.assertEqual(kept, "Érin")
        status, body, headers = analyst.post(
            f"/api/alerts/{alert_id}/assign", {"assignee": "Dana"})
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"], NOT_ELIGIBLE)
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, body, _ = analyst.post(
            f"/api/alerts/{alert_id}/assign", {"assignee": "viewer"})
        self.assertEqual((status, body["error"]), (400, NOT_ELIGIBLE))
        with sqlite3.connect(self.db_path) as db:
            kept = db.execute(
                "SELECT assignee FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]
        self.assertEqual(kept, "Érin")
