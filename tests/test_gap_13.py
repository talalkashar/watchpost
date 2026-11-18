"""Unit tests for auth.mfa_admin_reset.

An actor equal to the username is 400. A user with neither a TOTP secret nor a
pending enrollment is 409. A reset clears TOTP and writes audit action
mfa_reset. The HTTP audit row is asserted in tests/test_mfa.py.
"""

import os
import unittest

os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")  # fast hashing for tests only

from watchpost import auth  # noqa: E402
from watchpost.auth import AuthError  # noqa: E402
from watchpost.db import connect, init_schema  # noqa: E402

PASSWORD = "account-password-1"
OWN = "use your own disable step (with a current code) for your account"
NONE = "that user has no two-factor authentication to reset"
NOW = "2026-10-08T12:00:00.000Z"


class MfaAdminResetTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "admin", PASSWORD, "admin")
        auth.create_user(self.conn, "analyst", PASSWORD, "analyst")

    def arm(self, username, secret=None, pending=None):
        self.conn.execute(
            "UPDATE users SET totp_secret = ?, totp_pending = ?, totp_last_step = 7 WHERE username = ?",
            (secret, pending, username))
        user_id = self.conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        self.conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (f"pending-{username}", user_id, NOW, NOW))

    def totp(self, username):
        row = self.conn.execute(
            "SELECT id, totp_secret, totp_pending, totp_last_step FROM users WHERE username = ?",
            (username,)).fetchone()
        challenges = self.conn.execute(
            "SELECT COUNT(*) FROM mfa_pending WHERE user_id = ?", (row["id"],)).fetchone()[0]
        return (row["totp_secret"], row["totp_pending"], row["totp_last_step"], challenges)

    def resets(self):
        rows = self.conn.execute(
            "SELECT actor, action, target FROM audit_log WHERE action = 'mfa_reset'")
        return [(row["actor"], row["action"], row["target"]) for row in rows]

    def test_actor_equal_to_the_username_raises_400(self):
        self.arm("analyst", secret="analyst-secret", pending="analyst-pending")
        before = self.totp("analyst")
        with self.assertRaises(AuthError) as caught:
            auth.mfa_admin_reset(self.conn, "analyst", "analyst")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(str(caught.exception), OWN)
        self.assertEqual(self.totp("analyst"), before)
        self.assertEqual(self.resets(), [])

    def test_neither_secret_nor_pending_raises_409(self):
        self.assertEqual(self.totp("analyst"), (None, None, None, 0))
        with self.assertRaises(AuthError) as caught:
            auth.mfa_admin_reset(self.conn, "analyst", "admin")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), NONE)
        self.assertEqual(self.totp("analyst"), (None, None, None, 0))
        self.assertEqual(self.resets(), [])

    def test_reset_clears_totp_and_writes_mfa_reset(self):
        self.arm("analyst", secret="analyst-secret", pending="analyst-pending")
        result = auth.mfa_admin_reset(self.conn, "analyst", "admin")
        self.assertEqual(result, {"enabled": False})
        self.assertEqual(self.totp("analyst"), (None, None, None, 0))
        self.assertEqual(self.resets(), [("admin", "mfa_reset", "analyst")])
