"""mfa_disable keeps the secret on a bad code, clears it on a fresh step, and
cancels a pending enrollment with no code.

A wrong code leaves totp_secret set, writes mfa_disable_failed, and spends a
lockout attempt. A code for a step newer than totp_last_step clears the secret,
the pending secret, and mfa_pending. An unconfirmed enrollment (no totp_secret,
a totp_pending) is cancelled with no code and no attempt.
"""

import base64
import os
import unittest
from unittest import mock

os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")

from watchpost import auth, totp  # noqa: E402
from watchpost.db import connect, init_schema  # noqa: E402

PASSWORD = "account-password-1"
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
WHEN = 1_800_000_000
PENDING = "pending-secret"
WRONG = "000000"
INVALID = "invalid authentication code"
LOCKED = "account temporarily locked after repeated failures; try again later"


class MfaDisableTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "analyst", PASSWORD, "analyst")
        patcher = mock.patch.object(totp, "now", lambda: WHEN)
        patcher.start()
        self.addCleanup(patcher.stop)
        window = [totp.code_at(RFC_SECRET, WHEN + offset * 30) for offset in (-1, 0, 1)]
        self.assertNotIn(WRONG, window)

    def user_id(self):
        row = self.conn.execute("SELECT id FROM users WHERE username = 'analyst'").fetchone()
        return row["id"]

    def arm(self, last_step, secret=RFC_SECRET, pending=PENDING):
        self.conn.execute(
            "UPDATE users SET totp_secret = ?, totp_pending = ?, totp_last_step = ?,"
            " failed_logins = 0, locked_until = NULL WHERE username = 'analyst'",
            (secret, pending, last_step),
        )
        user_id = self.user_id()
        self.conn.execute("DELETE FROM mfa_pending WHERE user_id = ?", (user_id,))
        self.conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at)"
            " VALUES (?,?,?,?)",
            ("challenge-hash", user_id, "2026-10-08T12:00:00.000Z", "2026-10-08T12:05:00.000Z"),
        )

    def state(self):
        row = self.conn.execute(
            "SELECT totp_secret, totp_pending, totp_last_step, failed_logins, locked_until"
            " FROM users WHERE username = 'analyst'"
        ).fetchone()
        challenges = self.conn.execute(
            "SELECT COUNT(*) FROM mfa_pending WHERE user_id = ?", (self.user_id(),)
        ).fetchone()[0]
        return row, challenges

    def audits(self, action):
        return self.conn.execute(
            "SELECT actor, action, target, detail FROM audit_log WHERE action = ? ORDER BY id",
            (action,),
        ).fetchall()

    def assert_still_enrolled(self, row, challenges):
        self.assertEqual(row["totp_secret"], RFC_SECRET)
        self.assertEqual(row["totp_pending"], PENDING)
        self.assertEqual(challenges, 1)

    def test_wrong_code_keeps_the_secret_and_counts_toward_lockout(self):
        self.arm(last_step=totp.step_at(WHEN) - 2)
        for n in range(4):
            with self.assertRaises(auth.AuthError) as caught:
                auth.mfa_disable(self.conn, "analyst", WRONG)
            self.assertEqual(caught.exception.status, 400)
            self.assertEqual(str(caught.exception), INVALID)
            row, challenges = self.state()
            self.assert_still_enrolled(row, challenges)
            self.assertEqual(row["failed_logins"], n + 1)
            self.assertIsNone(row["locked_until"])

        with self.assertRaises(auth.AuthError) as caught:
            auth.mfa_disable(self.conn, "analyst", WRONG)
        self.assertEqual(caught.exception.status, 400)
        row, challenges = self.state()
        self.assert_still_enrolled(row, challenges)
        self.assertIsNotNone(row["locked_until"])
        self.assertEqual(row["failed_logins"], 0)

        failed = self.audits("mfa_disable_failed")
        self.assertEqual(len(failed), 5)
        for entry in failed:
            self.assertEqual(entry["actor"], "analyst")
            self.assertEqual(entry["target"], "analyst")
            self.assertIsNone(entry["detail"])
            self.assertNotIn(RFC_SECRET, str(tuple(entry)))

        with self.assertRaises(auth.AuthError) as caught:
            auth.mfa_disable(self.conn, "analyst", WRONG)
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(str(caught.exception), LOCKED)
        row, challenges = self.state()
        self.assert_still_enrolled(row, challenges)
        self.assertEqual(len(self.audits("mfa_disable_failed")), 5)
        blocked = self.audits("login_blocked")
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["detail"], '{"reason": "locked"}')

    def test_a_fresh_step_clears_the_secret_the_pending_secret_and_mfa_pending(self):
        step = totp.step_at(WHEN)
        self.arm(last_step=step - 1)
        stale = totp.code_at(RFC_SECRET, WHEN - 30)
        with self.assertRaises(auth.AuthError) as caught:
            auth.mfa_disable(self.conn, "analyst", stale)
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(str(caught.exception), INVALID)
        row, challenges = self.state()
        self.assert_still_enrolled(row, challenges)
        self.assertEqual(row["totp_last_step"], step - 1)
        self.assertEqual(row["failed_logins"], 1)
        self.assertEqual(len(self.audits("mfa_disable_failed")), 1)

        code = totp.code_at(RFC_SECRET, WHEN)
        result = auth.mfa_disable(self.conn, "analyst", code)
        self.assertEqual(result, {"enabled": False})
        row, challenges = self.state()
        self.assertIsNone(row["totp_secret"])
        self.assertIsNone(row["totp_pending"])
        self.assertIsNone(row["totp_last_step"])
        self.assertEqual(challenges, 0)
        self.assertEqual(row["failed_logins"], 0)
        self.assertIsNone(row["locked_until"])
        disabled = self.audits("mfa_disabled")
        self.assertEqual(len(disabled), 1)
        self.assertEqual(disabled[0]["actor"], "analyst")
        self.assertEqual(disabled[0]["target"], "analyst")
        self.assertIsNone(disabled[0]["detail"])
        self.assertNotIn(RFC_SECRET, str(tuple(disabled[0])))
        self.assertNotIn(code, str(tuple(disabled[0])))

    def test_cancelling_an_unconfirmed_enrollment_needs_no_code(self):
        self.conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_pending = ?, totp_last_step = ?,"
            " failed_logins = 4, locked_until = NULL WHERE username = 'analyst'",
            (PENDING, totp.step_at(WHEN)),
        )
        self.conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at)"
            " VALUES (?,?,?,?)",
            ("challenge-hash", self.user_id(), "2026-10-08T12:00:00.000Z", "2026-10-08T12:05:00.000Z"),
        )

        result = auth.mfa_disable(self.conn, "analyst", None)
        self.assertEqual(result, {"enabled": False})
        row, challenges = self.state()
        self.assertIsNone(row["totp_secret"])
        self.assertIsNone(row["totp_pending"])
        self.assertIsNone(row["totp_last_step"])
        self.assertEqual(challenges, 0)
        self.assertEqual(row["failed_logins"], 4)
        self.assertIsNone(row["locked_until"])
        cancelled = self.audits("mfa_enroll_cancelled")
        self.assertEqual(len(cancelled), 1)
        self.assertEqual(cancelled[0]["actor"], "analyst")
        self.assertEqual(cancelled[0]["target"], "analyst")
        self.assertEqual(self.audits("mfa_disable_failed"), [])
        self.assertEqual(self.audits("mfa_disabled"), [])
