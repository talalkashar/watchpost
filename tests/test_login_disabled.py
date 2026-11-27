"""A disabled account checks the stored hash, then returns the same 401 as a wrong password.

failed_logins is not incremented and the account is not locked. The body does not
say the account is disabled. The attempt is an audit row.
"""

import hashlib
import json
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import ADMIN_PW, ANALYST_PW, ServerTestCase
from tests.test_login_username import memory_db
from watchpost import auth
from watchpost.auth import AuthError

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
PASSWORD = "stored-password-1"


class LoginDisabledTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "alice", PASSWORD, "analyst")
        self.conn.execute("UPDATE users SET disabled = 1, failed_logins = 4 WHERE username = 'alice'")

    def _attempt(self, password):
        seen = []
        real = hashlib.pbkdf2_hmac

        def spy(hash_name, secret, salt, iterations, dklen=None):
            seen.append(secret)
            return real(hash_name, secret, salt, iterations, dklen)

        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            with self.assertRaises(AuthError) as caught:
                auth.login(self.conn, "alice", password, 3600)
        return caught.exception, seen

    def test_correct_password_checks_the_hash_and_does_not_sign_in(self):
        err, seen = self._attempt(PASSWORD)
        self.assertEqual(err.status, 401)
        self.assertEqual(str(err), "invalid username or password")
        self.assertNotIn("disabled", str(err))
        self.assertIn(PASSWORD.encode(), seen)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        row = self.conn.execute(
            "SELECT failed_logins, locked_until FROM users WHERE username = 'alice'"
        ).fetchone()
        self.assertEqual(row[0], 4)
        self.assertIsNone(row[1])
        detail = self.conn.execute(
            "SELECT detail FROM audit_log WHERE actor = 'alice' AND action = 'login_failed'"
        ).fetchone()[0]
        self.assertEqual(json.loads(detail), {"reason": "disabled"})

    def test_wrong_passwords_past_the_lockout_threshold_do_not_lock(self):
        for _ in range(6):
            err, seen = self._attempt("not-the-password")
            self.assertEqual(str(err), "invalid username or password")
            self.assertIn(b"not-the-password", seen)
        row = self.conn.execute(
            "SELECT failed_logins, locked_until FROM users WHERE username = 'alice'"
        ).fetchone()
        self.assertEqual(row[0], 4)
        self.assertIsNone(row[1])
        count = self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE actor = 'alice' AND action = 'login_failed'"
        ).fetchone()[0]
        self.assertEqual(count, 6)

    def test_an_enabled_account_still_counts_a_wrong_password(self):
        auth.create_user(self.conn, "bob", PASSWORD, "analyst")
        with self.assertRaises(AuthError) as caught:
            auth.login(self.conn, "bob", "not-the-password", 3600)
        self.assertEqual(str(caught.exception), "invalid username or password")
        row = self.conn.execute("SELECT failed_logins FROM users WHERE username = 'bob'").fetchone()
        self.assertEqual(row[0], 1)


class LoginDisabledApiTests(ServerTestCase):
    def test_disabled_login_matches_an_unknown_account(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE users SET disabled = 1 WHERE username = 'analyst'")
        client = self.client()
        unknown_status, unknown = client.login("nobody-here", "wrong-password-123")
        status, data, headers = client.post(
            "/api/auth/login", {"username": "analyst", "password": ANALYST_PW}
        )
        self.assertEqual(unknown_status, 401)
        self.assertEqual(status, 401)
        self.assertEqual(data, unknown)
        self.assertEqual(data["error"], "invalid username or password")
        self.assertNotIn("disabled", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers["Set-Cookie"])

        status, data, headers = client.post(
            "/api/auth/login", {"username": "analyst", "password": "wrong-password-123"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(data["error"], "invalid username or password")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers["Set-Cookie"])

        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                "SELECT failed_logins, locked_until FROM users WHERE username = 'analyst'"
            ).fetchone()
            audits = db.execute(
                "SELECT detail FROM audit_log WHERE actor = 'analyst' AND action = 'login_failed'"
            ).fetchall()
        self.assertEqual(row, (0, None))
        self.assertEqual([json.loads(item[0]) for item in audits], [{"reason": "disabled"}] * 2)

        status, data = client.login("admin", ADMIN_PW)
        self.assertEqual(status, 200, data)

    def test_api_docs_say_a_disabled_account_checks_the_hash(self):
        text = API.read_text()
        self.assertIn("A disabled account is that same 401", text)
        self.assertIn("checks the stored hash", text)
        self.assertIn("does not increment `failed_logins`", text)
        self.assertIn("does not say the account is disabled", text)
