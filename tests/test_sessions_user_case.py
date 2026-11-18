"""GET /api/sessions?user= folds ASCII case. Admin matches admin and Admin.

Érin does not match érin. The cap counts only the matched sessions. An unknown
name is an empty array and omitted 0, not 404. GET /api/auth/sessions stays
the signed-in account only.
"""

import sqlite3
import unittest
from pathlib import Path
from urllib.parse import quote

from watchpost.auth import create_user, list_sessions
from watchpost.db import connect, init_schema

from tests.helpers import ServerTestCase
from tests.test_sessions_omitted import FUTURE, OMITTED, SAME, _insert, _sid

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


class SessionUserCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        create_user(self.conn, "admin", "admin-password-1", "admin")
        create_user(self.conn, "Admin", "admin-password-2", "analyst")
        create_user(self.conn, "bob", "bob-password-1", "analyst")
        create_user(self.conn, "Érin", "erin-password-1", "analyst")
        create_user(self.conn, "érin", "erin-password-2", "analyst")
        self.ids = {
            name: self.conn.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()[0]
            for name in ("admin", "Admin", "bob", "Érin", "érin")}
        self.addCleanup(self.conn.close)

    def test_admin_matches_both_spellings_and_erin_stays_apart(self):
        _insert(self.conn, self.ids["admin"], [(1, SAME, FUTURE)])
        _insert(self.conn, self.ids["Admin"], [(2, SAME, FUTURE)])
        _insert(self.conn, self.ids["Érin"], [(3, SAME, FUTURE)])
        _insert(self.conn, self.ids["érin"], [(4, SAME, FUTURE)])
        rows, omitted = list_sessions(self.conn, "Admin", fold_user=True)
        self.assertEqual(omitted, 0)
        self.assertEqual(sorted(row["username"] for row in rows), ["Admin", "admin"])
        self.assertEqual(sorted(row["id"] for row in rows), [_sid(1), _sid(2)])
        rows, omitted = list_sessions(self.conn, "Érin", fold_user=True)
        self.assertEqual(omitted, 0)
        self.assertEqual([row["username"] for row in rows], ["Érin"])
        self.assertEqual(rows[0]["id"], _sid(3))
        rows, omitted = list_sessions(self.conn, "érin", fold_user=True)
        self.assertEqual([row["username"] for row in rows], ["érin"])
        self.assertEqual(rows[0]["id"], _sid(4))

    def test_the_cap_counts_only_the_matched_sessions(self):
        _insert(self.conn, self.ids["admin"], [(n, SAME, FUTURE) for n in range(101)])
        _insert(self.conn, self.ids["Admin"], [(200, SAME, FUTURE), (201, SAME, FUTURE)])
        _insert(self.conn, self.ids["bob"], [(n, SAME, FUTURE) for n in range(300, 340)])
        rows, omitted = list_sessions(self.conn, "admin", fold_user=True)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 3)
        self.assertTrue(all(row["username"] in ("admin", "Admin") for row in rows))
        self.assertNotIn("bob", [row["username"] for row in rows])
        exact, exact_omitted = list_sessions(self.conn, "Admin")
        self.assertEqual(exact_omitted, 0)
        self.assertEqual([row["username"] for row in exact], ["Admin", "Admin"])

    def test_an_unknown_name_is_empty_and_omitted_zero(self):
        _insert(self.conn, self.ids["admin"], [(1, SAME, FUTURE)])
        rows, omitted = list_sessions(self.conn, "nobody", fold_user=True)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)


class SessionUserCaseApiTests(ServerTestCase):
    def _user(self, username, role):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?, 'unused-hash', ?, ?)",
                (username, role, SAME))
            return db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]

    def test_the_filter_folds_and_the_signed_in_list_does_not(self):
        admin_id = self._user("Admin", "analyst")
        erin_id = self._user("Érin", "analyst")
        erin_lower = self._user("érin", "analyst")
        with sqlite3.connect(self.db_path) as db:
            _insert(db, admin_id, [(1, SAME, FUTURE)])
            _insert(db, erin_id, [(2, SAME, FUTURE)])
            _insert(db, erin_lower, [(3, SAME, FUTURE)])
        admin = self.client("admin")
        status, body, headers = admin.get("/api/sessions?user=Admin")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(sorted(row["username"] for row in body), ["Admin", "admin"])
        self.assertEqual(headers[OMITTED], "0")
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, body, headers = admin.get("/api/sessions?user=" + quote("Érin"))
        self.assertEqual(status, 200, body)
        self.assertEqual([row["username"] for row in body], ["Érin"])
        self.assertEqual(body[0]["id"], _sid(2))
        self.assertEqual(headers[OMITTED], "0")
        status, body, headers = admin.get("/api/sessions?user=" + quote("érin"))
        self.assertEqual([row["username"] for row in body], ["érin"])
        self.assertEqual(headers[OMITTED], "0")
        status, body, headers = admin.get("/api/sessions?user=nobody")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, [])
        self.assertEqual(headers[OMITTED], "0")
        status, own, _ = admin.get("/api/auth/sessions")
        self.assertEqual(status, 200, own)
        self.assertEqual({row["username"] for row in own}, {"admin"})
        self.assertNotIn(_sid(1), [row["id"] for row in own])

    def test_the_docs_name_the_fold(self):
        text = API.read_text()
        line = next(row for row in text.splitlines() if row.startswith("| `GET /api/sessions`"))
        self.assertIn("`Admin` matches `admin` and `Admin`", line)
        self.assertIn("`Érin` does not match `érin`", line)
        self.assertIn("An unknown name is an empty array and omitted 0, not 404", line)
        own = next(row for row in text.splitlines() if row.startswith("| `GET /api/auth/sessions`"))
        self.assertIn("ASCII case does not add another account", own)


if __name__ == "__main__":
    unittest.main()
