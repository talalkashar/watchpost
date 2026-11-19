"""Lockout, MFA challenge replacement, and password-verify edge cases.

Parallel wrong passwords must not check more hashes than the lockout threshold.
A new password step replaces older MFA challenges. A missing logout token does not raise.
"""

import os

os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")

import base64
import hashlib
import json
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
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
        # User ids restart at 1 in each file. A leaked in-flight count would block the next account.
        auth._verify_slots.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "auth.db")
        conn = connect(self.path)
        init_schema(conn)
        auth.create_user(conn, "alice", PASSWORD, "analyst")
        conn.close()

    def tearDown(self):
        auth._verify_slots.clear()

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


NEW_PASSWORD = "rotated-password-1"


class SignInRevalidationTests(FileDb):
    def test_unrelated_write_completes_during_verification(self):
        real = hashlib.pbkdf2_hmac
        wrote = {}

        def spy(hash_name, secret, salt, iterations, dklen=None):
            if "during" not in wrote:
                other = connect(self.path)
                try:
                    # Fail fast if sign-in still holds the write lock across PBKDF2.
                    other.execute("PRAGMA busy_timeout = 1000")
                    other.execute("INSERT INTO health_probe(written_at) VALUES (?)", (now_iso(),))
                    wrote["during"] = other.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0]
                finally:
                    other.close()
            return real(hash_name, secret, salt, iterations, dklen)

        conn = self.connect()
        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            token, _csrf, user = auth.login(conn, "alice", PASSWORD, 3600)
        self.assertEqual(wrote["during"], 1)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(auth.session_user(conn, token)["username"], "alice")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM health_probe").fetchone()[0], 1)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login'").fetchone()[0], 1)

    def test_rotated_password_is_not_a_session(self):
        real = hashlib.pbkdf2_hmac
        started = threading.Event()

        def spy(hash_name, secret, salt, iterations, dklen=None):
            if not started.is_set():
                started.set()
                other = connect(self.path)
                try:
                    other.execute(
                        "UPDATE users SET pw_hash = ? WHERE username = 'alice'",
                        (auth.hash_password(NEW_PASSWORD),))
                finally:
                    other.close()
            return real(hash_name, secret, salt, iterations, dklen)

        conn = self.connect()
        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            with self.assertRaises(AuthError) as caught:
                auth.login(conn, "alice", PASSWORD, 3600)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(str(caught.exception), "invalid username or password")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT failed_logins FROM users WHERE username = 'alice'").fetchone()[0], 1)
        detail = conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'login_failed'").fetchone()[0]
        self.assertEqual(json.loads(detail)["reason"], "credential_changed")
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login'").fetchone()[0], 0)
        token, _csrf, user = auth.login(conn, "alice", NEW_PASSWORD, 3600)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(auth.session_user(conn, token)["username"], "alice")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)

    def test_mfa_required_during_verification_issues_a_challenge(self):
        real = hashlib.pbkdf2_hmac
        secret = totp.generate_secret()
        started = threading.Event()

        def spy(hash_name, secret_bytes, salt, iterations, dklen=None):
            if not started.is_set():
                started.set()
                other = connect(self.path)
                try:
                    other.execute(
                        "UPDATE users SET totp_secret = ? WHERE username = 'alice'", (secret,))
                finally:
                    other.close()
            return real(hash_name, secret_bytes, salt, iterations, dklen)

        conn = self.connect()
        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            result = auth.login(conn, "alice", PASSWORD, 3600)
        self.assertIsInstance(result, auth.MfaChallenge)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 1)
        self.assertEqual(
            conn.execute("SELECT failed_logins FROM users WHERE username = 'alice'").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login_mfa_challenge'").fetchone()[0], 1)
        with mock.patch("watchpost.totp.now", return_value=WHEN):
            token, _csrf, user = auth.complete_mfa(conn, result.mfa_token, totp.code_at(secret, WHEN), 3600)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(auth.session_user(conn, token)["username"], "alice")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 0)
        detail = conn.execute("SELECT detail FROM audit_log WHERE action = 'login'").fetchone()[0]
        self.assertEqual(json.loads(detail), {"mfa": True})

    def test_disabled_during_verification_gets_no_session(self):
        real = hashlib.pbkdf2_hmac
        started = threading.Event()

        def spy(hash_name, secret, salt, iterations, dklen=None):
            if not started.is_set():
                started.set()
                other = connect(self.path)
                try:
                    other.execute("UPDATE users SET disabled = 1 WHERE username = 'alice'")
                finally:
                    other.close()
            return real(hash_name, secret, salt, iterations, dklen)

        conn = self.connect()
        conn.execute("UPDATE users SET failed_logins = 2 WHERE username = 'alice'")
        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            with self.assertRaises(AuthError) as caught:
                auth.login(conn, "alice", PASSWORD, 3600)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(str(caught.exception), "invalid username or password")
        self.assertNotIn("disabled", str(caught.exception))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        row = conn.execute(
            "SELECT failed_logins, locked_until, disabled FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(row["failed_logins"], 2)
        self.assertIsNone(row["locked_until"])
        self.assertEqual(row["disabled"], 1)
        detail = conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'login_failed'").fetchone()[0]
        self.assertEqual(json.loads(detail), {"reason": "disabled"})
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login'").fetchone()[0], 0)

    def test_concurrent_failures_cannot_exceed_the_lockout(self):
        real = hashlib.pbkdf2_hmac
        seen = []
        barrier = threading.Barrier(5)
        state = {"current": 0, "peak": 0}
        guard = threading.Lock()

        def spy(hash_name, secret, salt, iterations, dklen=None):
            seen.append(secret)
            with guard:
                state["current"] += 1
                state["peak"] = max(state["peak"], state["current"])
            try:
                barrier.wait(timeout=10)
                return real(hash_name, secret, salt, iterations, dklen)
            finally:
                with guard:
                    state["current"] -= 1

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
        self.assertEqual(state["peak"], 5)
        self.assertEqual(len(seen), 5)
        self.assertTrue(all(secret == WRONG.encode() for secret in seen))
        self.assertNotIn("ok", statuses)
        self.assertIn(401, statuses)
        self.assertIn(429, statuses)
        self.assertTrue(all(status in (401, 429) for status in statuses))
        conn = self.connect()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login'").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login_failed'").fetchone()[0], 5)
        row = conn.execute(
            "SELECT failed_logins, locked_until FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(row["failed_logins"], 0)
        self.assertIsNotNone(row["locked_until"])

    def test_one_challenge_redemption(self):
        conn = self.connect()
        secret = totp.generate_secret()
        conn.execute("UPDATE users SET totp_secret = ? WHERE username = 'alice'", (secret,))
        challenge = auth.login(conn, "alice", PASSWORD, 3600)
        code = totp.code_at(secret, WHEN)
        real_verify = totp.verify
        barrier = threading.Barrier(2)

        def blocked(secret_value, code_value, last_step=None, timestamp=None):
            barrier.wait(timeout=10)
            return real_verify(secret_value, code_value, last_step, timestamp)

        def redeem(_):
            own = connect(self.path)
            try:
                return auth.complete_mfa(own, challenge.mfa_token, code, 3600)
            except AuthError as exc:
                return exc
            finally:
                own.close()

        with mock.patch("watchpost.totp.now", return_value=WHEN):
            with mock.patch("watchpost.auth.totp.verify", blocked):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(redeem, range(2)))
        ok = [item for item in results if not isinstance(item, AuthError)]
        bad = [item for item in results if isinstance(item, AuthError)]
        self.assertEqual(len(ok), 1)
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0].status, 401)
        self.assertEqual(str(bad[0]), "sign-in step expired; sign in again")
        token, _csrf, user = ok[0]
        self.assertEqual(user["username"], "alice")
        self.assertEqual(auth.session_user(conn, token)["username"], "alice")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT failed_logins, locked_until FROM users WHERE username = 'alice'").fetchone()[:],
            (0, None))
        details = [row[0] for row in conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'login'").fetchall()]
        self.assertEqual(details, ['{"mfa": true}'])

    def test_rotated_hash_voids_a_challenge(self):
        conn = self.connect()
        secret = totp.generate_secret()
        conn.execute("UPDATE users SET totp_secret = ? WHERE username = 'alice'", (secret,))
        challenge = auth.login(conn, "alice", PASSWORD, 3600)
        real_verify = totp.verify

        def rotate(secret_value, code_value, last_step=None, timestamp=None):
            other = connect(self.path)
            try:
                other.execute(
                    "UPDATE users SET pw_hash = ? WHERE username = 'alice'",
                    (auth.hash_password(NEW_PASSWORD),))
            finally:
                other.close()
            return real_verify(secret_value, code_value, last_step, timestamp)

        with mock.patch("watchpost.totp.now", return_value=WHEN):
            with mock.patch("watchpost.auth.totp.verify", rotate):
                with self.assertRaises(AuthError) as caught:
                    auth.complete_mfa(conn, challenge.mfa_token, totp.code_at(secret, WHEN), 3600)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(str(caught.exception), "sign-in step expired; sign in again")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT failed_logins, locked_until FROM users WHERE username = 'alice'").fetchone()[:],
            (0, None))
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'login'").fetchone()[0], 0)
