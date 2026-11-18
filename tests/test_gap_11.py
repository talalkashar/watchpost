"""_reserve_code_attempt locks on the call that reaches the threshold.

That call returns True and sets locked_until. The next call raises AuthError 429
before another code is verified. HTTP lockout stays in tests/test_mfa.py.
"""

import unittest
from datetime import timedelta
from unittest import mock

from tests.test_login_username import memory_db
from watchpost import auth
from watchpost.auth import AuthError
from watchpost.db import now_iso, parse_iso, utcnow

PASSWORD = "stored-password-1"
THRESHOLD = 3
LOCK_MINUTES = 20


class ReserveCodeAttemptTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "alice", PASSWORD, "analyst")
        self.user_id = self.conn.execute(
            "SELECT id FROM users WHERE username = 'alice'"
        ).fetchone()["id"]
        self.conn.executemany(
            "INSERT INTO settings(key, value, updated_at, updated_by) VALUES (?,?,?,?)",
            (
                ("login_lockout_threshold", str(THRESHOLD), now_iso(), "test"),
                ("login_lockout_minutes", str(LOCK_MINUTES), now_iso(), "test"),
            ),
        )
        self.verified = []

    def _user(self):
        return self.conn.execute(
            "SELECT failed_logins, locked_until FROM users WHERE id = ?",
            (self.user_id,),
        ).fetchone()

    def _reserve_then_verify(self):
        """Same order as complete_mfa: verify only after the attempt is reserved."""
        locked = auth._reserve_code_attempt(self.conn, self.user_id)
        auth.totp.verify("secret", "000000", None)
        return locked

    def test_threshold_call_locks_and_the_next_refuses_before_verify(self):
        def record(secret, code, last_step):
            self.verified.append((secret, code, last_step))
            return None

        with mock.patch("watchpost.auth.totp.verify", side_effect=record):
            for n in range(THRESHOLD - 1):
                self.assertFalse(self._reserve_then_verify(), n)
                row = self._user()
                self.assertEqual(row["failed_logins"], n + 1)
                self.assertIsNone(row["locked_until"])

            self.assertTrue(self._reserve_then_verify())
            row = self._user()
            self.assertEqual(row["failed_logins"], 0)
            self.assertIsNotNone(row["locked_until"])
            remaining = parse_iso(row["locked_until"]) - utcnow()
            self.assertGreater(remaining, timedelta(minutes=LOCK_MINUTES - 1))
            self.assertLess(remaining, timedelta(minutes=LOCK_MINUTES + 1))

            with self.assertRaises(AuthError) as caught:
                self._reserve_then_verify()

        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(
            str(caught.exception),
            "account temporarily locked after repeated failures; try again later",
        )
        # The refusing call raised inside _reserve_code_attempt, before verify.
        self.assertEqual(self.verified, [("secret", "000000", None)] * THRESHOLD)
        row = self._user()
        self.assertEqual(row["failed_logins"], 0)
        self.assertIsNotNone(row["locked_until"])
        blocked = self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'login_blocked'"
        ).fetchall()
        self.assertEqual([r["detail"] for r in blocked], ['{"reason": "locked"}'])
