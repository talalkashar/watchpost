"""Lockout, MFA challenge replacement, and password-verify edge cases.

Parallel wrong passwords must not check more hashes than the lockout threshold.
A new password step replaces older MFA challenges. A missing logout token does not raise.
"""

import os

os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")

import base64
import hashlib
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import timedelta
from unittest import mock

from watchpost import auth, totp
from watchpost.auth import AuthError
from watchpost.config import Config
from watchpost.db import connect, init_schema, iso, now_iso, utcnow

PASSWORD = "stored-password-1"
WRONG = "wrong-password-xx"
WHEN = 1_700_000_000


class FileDb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "auth.db")
        conn = connect(self.path)
        init_schema(conn)
        auth.create_user(conn, "alice", PASSWORD, "analyst")
        conn.close()

    def connect(self):
        conn = connect(self.path)
        self.addCleanup(conn.close)
        return conn


class PasswordLockoutTests(FileDb):
    def test_parallel_wrong_passwords_cannot_outrun_the_lockout(self):
        seen = []
        real = hashlib.pbkdf2_hmac

        def spy(hash_name, secret, salt, iterations, dklen=None):
            seen.append(secret)
            return real(hash_name, secret, salt, iterations, dklen)

        def attempt(_):
            conn = connect(self.path)
            try:
                auth.login(conn, "alice", WRONG, 3600)
                return "ok"
            except AuthError as exc:
                return exc.status
            finally:
                conn.close()

        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(attempt, range(20)))
        self.assertLessEqual(len(seen), 5)
        self.assertTrue(seen)
        self.assertTrue(all(secret == WRONG.encode() for secret in seen))
        self.assertNotIn("ok", statuses)
        self.assertIn(401, statuses)
        self.assertIn(429, statuses)
        self.assertTrue(all(status in (401, 429) for status in statuses))
        conn = self.connect()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_account_is_revalidated_after_password_verification(self):
        for change, session, challenge in [
                ("role = 'viewer'", 1, 0), ("pw_hash = 'rotated'", 0, 0),
                ("disabled = 1", 0, 0), ("totp_secret = 'enrolled'", 0, 1)]:
            with self.subTest(change=change):
                conn = self.connect()
                conn.execute("UPDATE users SET pw_hash=?, role='analyst', disabled=0, totp_secret=NULL",
                             (auth.hash_password(PASSWORD),))
                writer = self.connect()
                writer.execute("PRAGMA busy_timeout=500")
                verify = auth.verify_password

                def during_hash(*args):
                    writer.execute("UPDATE users SET " + change)
                    return verify(*args)

                with mock.patch.object(auth, "verify_password", side_effect=during_hash):
                    if session:
                        self.assertEqual(auth.login(conn, "alice", PASSWORD, 3600)[2]["role"], "viewer")
                    elif challenge:
                        self.assertIsInstance(auth.login(conn, "alice", PASSWORD, 3600), auth.MfaChallenge)
                    else:
                        with self.assertRaises(AuthError):
                            auth.login(conn, "alice", PASSWORD, 3600)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], session)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], challenge)
                conn.execute("DELETE FROM sessions")

    def test_overlapping_logins_can_both_use_the_migrated_password(self):
        conn, other = self.connect(), self.connect()
        conn.execute("UPDATE users SET pw_hash=?", (auth.hash_password(PASSWORD, 500),))
        hash_password = auth.hash_password
        sessions = []

        def finish_other_login(password):
            with mock.patch.object(auth, "hash_password", hash_password):
                sessions.append(auth.login(other, "alice", password, 3600)[0])
            return hash_password(password)

        with mock.patch.object(auth, "PBKDF2_ITERATIONS", 1000):
            with mock.patch.object(auth, "hash_password", side_effect=finish_other_login):
                sessions.append(auth.login(conn, "alice", PASSWORD, 3600)[0])
        self.assertNotEqual(*sessions)
        for session in sessions:
            self.assertEqual(auth.session_user(conn, session)["username"], "alice")
        self.assertEqual(auth._stored_iterations(conn.execute("SELECT pw_hash FROM users").fetchone()[0]), 1000)

    def test_password_reset_during_migration_rejects_the_old_password(self):
        conn, writer = self.connect(), self.connect()
        conn.execute("UPDATE users SET pw_hash=?", (auth.hash_password(PASSWORD, 500),))
        replacement = auth.hash_password("replacement-password", 1000)
        hash_password = auth.hash_password

        def reset_password(password):
            writer.execute("UPDATE users SET pw_hash=?", (replacement,))
            return hash_password(password)

        with mock.patch.object(auth, "PBKDF2_ITERATIONS", 1000):
            with mock.patch.object(auth, "hash_password", side_effect=reset_password):
                with self.assertRaises(AuthError) as caught:
                    auth.login(conn, "alice", PASSWORD, 3600)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(conn.execute("SELECT pw_hash FROM users").fetchone()[0], replacement)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_disabled_accounts_share_a_bounded_hash_budget(self):
        conn = self.connect()
        conn.execute("UPDATE users SET disabled=1")
        user_id = conn.execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
        with ExitStack() as stack:
            for _ in range(5):
                stack.enter_context(auth._verification_slot(conn, user_id))
            with mock.patch.object(auth, "verify_password") as verify:
                with self.assertRaises(AuthError) as caught:
                    auth.login(conn, "alice", PASSWORD, 3600)
                self.assertEqual((caught.exception.status, str(caught.exception)), (401, "invalid username or password"))
                verify.assert_not_called()
        self.assertEqual(conn.execute("SELECT failed_logins FROM users").fetchone()[0], 0)

    def test_lowering_the_threshold_does_not_permanently_lock_an_account(self):
        conn = self.connect()
        conn.execute("UPDATE users SET failed_logins = 4 WHERE username = 'alice'")
        conn.execute("INSERT OR REPLACE INTO settings(key,value,updated_at,updated_by)"
                     " VALUES ('login_lockout_threshold','3',?,'fixture')", (now_iso(),))
        self.assertEqual(auth.login(conn, "alice", PASSWORD, 3600)[2]["username"], "alice")
        self.assertEqual(conn.execute("SELECT failed_logins FROM users").fetchone()[0], 0)

    def test_fifth_wrong_password_locks_the_sixth(self):
        conn = self.connect()
        for _ in range(5):
            with self.assertRaises(AuthError) as caught:
                auth.login(conn, "alice", WRONG, 3600)
            self.assertEqual(caught.exception.status, 401)
            self.assertEqual(str(caught.exception), "invalid username or password")
        with self.assertRaises(AuthError) as caught:
            auth.login(conn, "alice", PASSWORD, 3600)
        self.assertEqual(caught.exception.status, 429)
        row = conn.execute(
            "SELECT failed_logins, locked_until FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(row["failed_logins"], 0)
        self.assertIsNotNone(row["locked_until"])

    def test_correct_password_zeros_the_counter(self):
        conn = self.connect()
        with self.assertRaises(AuthError):
            auth.login(conn, "alice", WRONG, 3600)
        token, _csrf, user = auth.login(conn, "alice", PASSWORD, 3600)
        self.assertTrue(token)
        self.assertEqual(user["username"], "alice")
        row = conn.execute(
            "SELECT failed_logins, locked_until FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(row["failed_logins"], 0)
        self.assertIsNone(row["locked_until"])

    def test_correct_password_does_not_reset_failures_when_mfa_is_enrolled(self):
        conn = self.connect()
        conn.execute(
            "UPDATE users SET totp_secret = ?, failed_logins = 4 WHERE username = 'alice'",
            (totp.generate_secret(),))
        result = auth.login(conn, "alice", PASSWORD, 3600)
        self.assertIsInstance(result, auth.MfaChallenge)
        self.assertEqual(
            conn.execute("SELECT failed_logins FROM users WHERE username = 'alice'").fetchone()[0], 4)

    def test_surrogate_password_counts_as_a_wrong_password(self):
        conn = self.connect()
        password = "\ud800" + "x" * 12
        with self.assertRaises(AuthError) as caught:
            auth.login(conn, "alice", password, 3600)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(str(caught.exception), "invalid username or password")
        self.assertEqual(
            conn.execute("SELECT failed_logins FROM users WHERE username = 'alice'").fetchone()[0], 1)

    def test_create_user_rejects_a_password_that_is_not_utf8(self):
        conn = self.connect()
        with self.assertRaises(AuthError) as caught:
            auth.create_user(conn, "bob", "\ud800" + "x" * 12, "analyst")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(str(caught.exception), "password must be valid UTF-8")
        self.assertIsNone(conn.execute("SELECT 1 FROM users WHERE username = 'bob'").fetchone())


class VerifyPasswordTests(unittest.TestCase):
    def test_corrupt_or_unencodable_input_returns_false(self):
        stored = auth.hash_password(PASSWORD)
        self.assertFalse(auth.verify_password("\ud800" + "x" * 12, stored))
        self.assertFalse(auth.verify_password(None, stored))
        salt = base64.b64encode(b"0123456789abcdef").decode()
        digest = base64.b64encode(b"\x00" * 32).decode()
        huge = f"pbkdf2_sha256${10 ** 18}${salt}${digest}"
        self.assertFalse(auth.verify_password(PASSWORD, huge))
        self.assertTrue(auth.verify_password(PASSWORD, stored))


class LogoutTests(FileDb):
    def test_missing_token_does_not_raise_or_end_a_session(self):
        conn = self.connect()
        token, _csrf, _user = auth.login(conn, "alice", PASSWORD, 3600)
        auth.logout(conn, None)
        auth.logout(conn, "")
        self.assertIsNone(auth.session_user(conn, None))
        self.assertEqual(auth.session_user(conn, token)["username"], "alice")
        auth.logout(conn, token)
        self.assertIsNone(auth.session_user(conn, token))


class MfaChallengeTests(FileDb):
    def _enroll(self, conn):
        secret = totp.generate_secret()
        conn.execute("UPDATE users SET totp_secret = ? WHERE username = 'alice'", (secret,))
        return secret

    def test_in_flight_challenge_cannot_clear_a_post_rotation_failure(self):
        conn = self.connect()
        writer = self.connect()
        secret = self._enroll(conn)
        challenge = auth.login(conn, "alice", PASSWORD, 3600)
        rotated = auth.hash_password("rotated-password-2")
        verify_code = totp.verify

        def rotate_and_fail(*args):
            writer.execute("UPDATE users SET pw_hash = ?, failed_logins = 0 WHERE username = 'alice'",
                           (rotated,))
            with self.assertRaises(AuthError):
                auth.login(writer, "alice", WRONG, 3600)
            return verify_code(*args, timestamp=WHEN)

        with mock.patch.object(totp, "verify", side_effect=rotate_and_fail):
            with self.assertRaisesRegex(AuthError, "sign-in step expired"):
                auth.complete_mfa(conn, challenge.mfa_token, totp.code_at(secret, WHEN), 3600)
        self.assertEqual(tuple(conn.execute("SELECT failed_logins, locked_until FROM users").fetchone()),
                         (1, None))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='login_failed'").fetchone()[0], 1)

    def test_concurrent_redemption_commits_one_session(self):
        conn = self.connect()
        secret = self._enroll(conn)
        challenge = auth.login(conn, "alice", PASSWORD, 3600)
        start = threading.Barrier(2)

        def redeem():
            other = connect(self.path)
            try:
                start.wait(timeout=5)
                auth.complete_mfa(other, challenge.mfa_token, totp.code_at(secret, WHEN), 3600)
                return True
            except AuthError:
                return False
            finally:
                other.close()

        with mock.patch.object(totp, "now", return_value=WHEN), ThreadPoolExecutor(2) as pool:
            results = [pool.submit(redeem) for _ in range(2)]
            self.assertCountEqual([f.result(timeout=10) for f in results], [True, False])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT failed_logins FROM users").fetchone()[0], 0)

    def test_new_password_step_replaces_the_previous_challenge(self):
        conn = self.connect()
        secret = self._enroll(conn)
        first = auth.login(conn, "alice", PASSWORD, 3600)
        second = auth.login(conn, "alice", PASSWORD, 3600)
        code = totp.code_at(secret, WHEN)
        with mock.patch("watchpost.totp.now", return_value=WHEN):
            with self.assertRaises(AuthError) as caught:
                auth.complete_mfa(conn, first.mfa_token, code, 3600)
            self.assertEqual(str(caught.exception), "sign-in step expired; sign in again")
            token, _csrf, user = auth.complete_mfa(conn, second.mfa_token, code, 3600)
        self.assertTrue(token)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 0)

    def test_success_drops_a_sibling_challenge(self):
        conn = self.connect()
        secret = self._enroll(conn)
        challenge = auth.login(conn, "alice", PASSWORD, 3600)
        user_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
        conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            ("sibling", user_id, now_iso(), iso(utcnow() + timedelta(minutes=5))))
        code = totp.code_at(secret, WHEN)
        with mock.patch("watchpost.totp.now", return_value=WHEN):
            auth.complete_mfa(conn, challenge.mfa_token, code, 3600)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 0)

    def test_locking_disable_attempt_drops_pending_tokens(self):
        conn = self.connect()
        self._enroll(conn)
        conn.execute("UPDATE users SET failed_logins = 4 WHERE username = 'alice'")
        user_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
        conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            ("pending", user_id, now_iso(), iso(utcnow() + timedelta(minutes=5))))
        with self.assertRaises(AuthError) as caught:
            auth.mfa_disable(conn, "alice", "000000")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 0)

    def test_non_locking_disable_attempt_keeps_pending_tokens(self):
        conn = self.connect()
        self._enroll(conn)
        user_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
        conn.execute(
            "INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            ("pending", user_id, now_iso(), iso(utcnow() + timedelta(minutes=5))))
        with self.assertRaises(AuthError) as caught:
            auth.mfa_disable(conn, "alice", "000000")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 1)


class CredentialsFileTests(unittest.TestCase):
    def test_bootstrap_tightens_an_existing_credentials_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "initial_credentials.txt")
            with open(path, "w") as handle:
                handle.write("old\n")
            os.chmod(path, 0o644)
            db_path = os.path.join(tmp, "empty.db")
            conn = connect(db_path)
            try:
                init_schema(conn)
                config = Config.from_env(
                    db_path=db_path, admin_password=None, analyst_password=None, viewer_password=None)
                written = auth.bootstrap_users(conn, config, tmp)
            finally:
                conn.close()
            self.assertEqual(written, path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
