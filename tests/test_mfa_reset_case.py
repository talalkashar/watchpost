"""Admin MFA reset folds ASCII case and resets the stored account.

`Admin` resets `admin` when that is the only match. Two accounts that share the
fold are 409 and nobody is reset. `Érin` does not match `érin`. A name outside
3–32 stays unmatched. Resetting your own account stays 400.
"""

import sqlite3
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import auth
from watchpost.auth import AuthError
from watchpost.db import connect, init_schema

PASSWORD = "account-password-1"
NOW = "2026-10-08T12:00:00.000Z"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
AMBIGUOUS = "username matches more than one account"
OWN = "use your own disable step (with a current code) for your account"
MISSING = "user not found"
NONE = "that user has no two-factor authentication to reset"


class MfaResetCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "admin", PASSWORD, "admin")
        auth.create_user(self.conn, "analyst", PASSWORD, "analyst")

    def insert_user(self, username, role="analyst"):
        """A second ASCII spelling. create_user itself returns 409 for that name."""
        self.conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
            (username, "unused-hash", role, NOW))

    def arm(self, username, secret):
        self.conn.execute(
            "UPDATE users SET totp_secret = ?, totp_pending = ?, totp_last_step = 4 WHERE username = ?",
            (secret, secret + "-pending", username))
        user_id = self.conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        self.conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (secret, user_id, NOW, NOW))

    def state(self, username):
        row = self.conn.execute(
            "SELECT id, totp_secret, totp_pending, totp_last_step FROM users WHERE username = ?",
            (username,)).fetchone()
        pending = self.conn.execute(
            "SELECT COUNT(*) FROM mfa_pending WHERE user_id = ?", (row["id"],)).fetchone()[0]
        return (row["totp_secret"], row["totp_pending"], row["totp_last_step"], pending)

    def resets(self):
        return self.conn.execute(
            "SELECT actor, target FROM audit_log WHERE action = 'mfa_reset'").fetchall()

    def test_admin_resets_the_stored_spelling(self):
        self.arm("analyst", "analyst-secret")
        result = auth.mfa_admin_reset(self.conn, "Analyst", "admin")
        self.assertEqual(result, {"enabled": False})
        self.assertEqual(self.state("analyst"), (None, None, None, 0))
        self.assertEqual([(row["actor"], row["target"]) for row in self.resets()], [("admin", "analyst")])

    def test_a_pending_enrollment_is_cleared(self):
        self.conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_pending = 'pending-only', totp_last_step = 2"
            " WHERE username = 'analyst'")
        result = auth.mfa_admin_reset(self.conn, "ANALYST", "admin")
        self.assertEqual(result, {"enabled": False})
        self.assertEqual(self.state("analyst"), (None, None, None, 0))

    def test_two_accounts_are_409_and_reset_nobody(self):
        self.insert_user("Analyst")
        self.arm("analyst", "lower-secret")
        self.arm("Analyst", "upper-secret")
        before = len(self.resets())
        with self.assertRaises(AuthError) as caught:
            auth.mfa_admin_reset(self.conn, "ANALYST", "admin")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), AMBIGUOUS)
        self.assertEqual(self.state("analyst"), ("lower-secret", "lower-secret-pending", 4, 1))
        self.assertEqual(self.state("Analyst"), ("upper-secret", "upper-secret-pending", 4, 1))
        self.assertEqual(len(self.resets()), before)

    def test_a_clash_with_your_own_account_resets_nobody(self):
        self.insert_user("Admin", "admin")
        self.arm("admin", "admin-secret")
        self.arm("Admin", "other-secret")
        with self.assertRaises(AuthError) as caught:
            auth.mfa_admin_reset(self.conn, "admin", "admin")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), AMBIGUOUS)
        self.assertEqual(self.state("admin")[0], "admin-secret")
        self.assertEqual(self.state("Admin")[0], "other-secret")
        self.assertEqual(self.resets(), [])

    def test_erin_stays_apart_from_erin(self):
        auth.create_user(self.conn, "Érin", PASSWORD, "analyst")
        auth.create_user(self.conn, "érin", PASSWORD, "analyst")
        self.arm("Érin", "accent-secret")
        self.arm("érin", "other-secret")
        result = auth.mfa_admin_reset(self.conn, "Érin", "admin")
        self.assertEqual(result, {"enabled": False})
        self.assertEqual(self.state("Érin"), (None, None, None, 0))
        self.assertEqual(self.state("érin"), ("other-secret", "other-secret-pending", 4, 1))
        self.assertEqual([(row["actor"], row["target"]) for row in self.resets()], [("admin", "Érin")])
        result = auth.mfa_admin_reset(self.conn, "érin", "admin")
        self.assertEqual(result, {"enabled": False})
        self.assertEqual(self.state("érin"), (None, None, None, 0))

    def test_a_name_outside_3_to_32_stays_unmatched(self):
        self.arm("analyst", "analyst-secret")
        for name in ("ab", "a" * 33, "analyst" + "x" * 26, "analyst" + "x" * 57):
            with self.subTest(name=name):
                with self.assertRaises(AuthError) as caught:
                    auth.mfa_admin_reset(self.conn, name, "admin")
                self.assertEqual(caught.exception.status, 404)
                self.assertEqual(str(caught.exception), MISSING)
        self.assertEqual(self.state("analyst")[0], "analyst-secret")
        self.assertEqual(self.resets(), [])

    def test_resetting_your_own_account_stays_400(self):
        self.arm("admin", "admin-secret")
        for name in ("admin", "Admin", "ADMIN"):
            with self.subTest(name=name):
                with self.assertRaises(AuthError) as caught:
                    auth.mfa_admin_reset(self.conn, name, "admin")
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), OWN)
        self.assertEqual(self.state("admin")[0], "admin-secret")
        self.assertEqual(self.resets(), [])

    def test_an_unknown_name_and_an_account_with_no_mfa_stay_errors(self):
        with self.assertRaises(AuthError) as missing:
            auth.mfa_admin_reset(self.conn, "nobody", "admin")
        self.assertEqual(missing.exception.status, 404)
        self.assertEqual(str(missing.exception), MISSING)
        with self.assertRaises(AuthError) as none:
            auth.mfa_admin_reset(self.conn, "Analyst", "admin")
        self.assertEqual(none.exception.status, 409)
        self.assertEqual(str(none.exception), NONE)
        self.assertEqual(self.resets(), [])

    def test_docs_name_the_fold(self):
        text = REFERENCE.read_text()
        self.assertIn("`Admin` resets `admin` when that is the only match", text)
        self.assertIn("Two accounts that share the fold are 409 and nobody is reset", text)
        self.assertIn("`Érin` does not match `érin`", text)
        self.assertIn("A name outside 3–32 stays unmatched", text)


class MfaResetCaseApiTests(ServerTestCase):
    def _insert(self, username, role="analyst"):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?, 'unused-hash', ?, ?)",
                (username, role, NOW))

    def _arm(self, username, secret):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE users SET totp_secret = ?, totp_pending = ?, totp_last_step = 4 WHERE username = ?",
                (secret, secret + "-pending", username))
            user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
            db.execute(
                "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                (secret, user_id, NOW, NOW))

    def _secret(self, username):
        with sqlite3.connect(self.db_path) as db:
            return db.execute(
                "SELECT totp_secret FROM users WHERE username = ?", (username,)).fetchone()[0]

    def _resets(self):
        with sqlite3.connect(self.db_path) as db:
            return db.execute(
                "SELECT actor, target FROM audit_log WHERE action = 'mfa_reset'").fetchall()

    def test_the_route_resets_the_stored_account_and_refuses_a_clash(self):
        self._arm("analyst", "analyst-secret")
        admin = self.client("admin")
        self._arm("admin", "admin-secret")
        status, body, headers = admin.post("/api/users/Analyst/mfa/reset")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"enabled": False})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(self._secret("analyst"))
        self.assertEqual(self._resets(), [("admin", "analyst")])

        status, body, headers = admin.post("/api/users/Admin/mfa/reset")
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"], OWN)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self._secret("admin"), "admin-secret")

        self._insert("Érin")
        self._insert("érin")
        self._arm("Érin", "accent-secret")
        self._arm("érin", "other-secret")
        status, body, _ = admin.post("/api/users/" + quote("Érin") + "/mfa/reset")
        self.assertEqual(status, 200, body)
        self.assertIsNone(self._secret("Érin"))
        self.assertEqual(self._secret("érin"), "other-secret")
        self.assertIn(("admin", "Érin"), self._resets())

        self._insert("Analyst")
        self._arm("Analyst", "upper-secret")
        self._arm("analyst", "lower-secret")
        status, body, headers = admin.post("/api/users/ANALYST/mfa/reset")
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], AMBIGUOUS)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self._secret("analyst"), "lower-secret")
        self.assertEqual(self._secret("Analyst"), "upper-secret")
        self.assertNotIn(("admin", "Analyst"), self._resets())
        self.assertNotIn(("admin", "ANALYST"), self._resets())

        for path in ("/api/users/ab/mfa/reset", "/api/users/" + ("a" * 33) + "/mfa/reset"):
            with self.subTest(path=path):
                status, body, headers = admin.post(path)
                self.assertEqual(status, 404, body)
                self.assertEqual(body["error"], MISSING)
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self._secret("analyst"), "lower-secret")
