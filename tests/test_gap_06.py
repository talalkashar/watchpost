"""verify_password returns False for a bad stored hash and True for a match.

A wrong algorithm and a truncated stored string return False and do not raise.
A bytes stored value does the same. None and other non-strings raise
AttributeError, because only ValueError and TypeError are caught; that case is
an expected failure. A matching pbkdf2_sha256 password returns True. login calls
verify_password. No test inserts a corrupt pw_hash.
"""

import unittest
from unittest import mock

from watchpost import auth
from watchpost.auth import AuthError
from watchpost.db import connect, init_schema

PASSWORD = "stored-password-1"
# The iteration count is stored in the hash string. 1 keeps these checks fast.
ITERATIONS = 1


def _stored(password=PASSWORD):
    return auth.hash_password(password, iterations=ITERATIONS)


class VerifyPasswordTests(unittest.TestCase):
    def test_wrong_algorithm_returns_false(self):
        # Same salt and digest as a real hash. Skipping the algorithm check would return True.
        _algo, iterations, salt, digest = _stored().split("$")
        for algo in ("bcrypt", "scrypt", "PBKDF2_SHA256"):
            stored = f"{algo}${iterations}${salt}${digest}"
            with self.subTest(algo=algo):
                self.assertIs(auth.verify_password(PASSWORD, stored), False)

    def test_truncated_stored_string_returns_false(self):
        stored = _stored()
        _algo, iterations, salt, digest = stored.split("$")
        truncated = (
            "",
            "pbkdf2_sha256",
            f"pbkdf2_sha256${iterations}",
            f"pbkdf2_sha256${iterations}${salt}",
            f"pbkdf2_sha256${iterations}${salt}$",
            f"pbkdf2_sha256${iterations}${salt}${digest[:8]}",
            stored[: len(stored) // 2],
            stored[:-1],
        )
        for value in truncated:
            with self.subTest(value=value):
                self.assertIs(auth.verify_password(PASSWORD, value), False)

    def test_bytes_stored_value_returns_false(self):
        stored = _stored()
        for value in (stored.encode(), bytearray(stored.encode())):
            with self.subTest(kind=type(value).__name__):
                self.assertIs(auth.verify_password(PASSWORD, value), False)

    @unittest.expectedFailure
    def test_non_string_stored_value_returns_false(self):
        """None, numbers, and collections must return False and not raise.

        verify_password calls stored.split and only catches ValueError and TypeError.
        These values raise AttributeError instead.
        """
        for stored in (None, 123, ["pbkdf2_sha256"], {"pw": "x"}):
            with self.subTest(stored=stored):
                self.assertIs(auth.verify_password(PASSWORD, stored), False)

    def test_matching_pbkdf2_sha256_password_returns_true(self):
        stored = _stored()
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertIs(auth.verify_password(PASSWORD, stored), True)
        self.assertIs(auth.verify_password("not-the-password", stored), False)


class LoginCallsVerifyPasswordTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "alice", PASSWORD, "analyst")

    def test_login_calls_verify_password(self):
        stored = self.conn.execute(
            "SELECT pw_hash FROM users WHERE username = 'alice'").fetchone()["pw_hash"]
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        with mock.patch("watchpost.auth.verify_password", wraps=auth.verify_password) as spy:
            token, _csrf, user = auth.login(self.conn, "alice", PASSWORD, 3600)
        self.assertTrue(token)
        self.assertEqual(user["username"], "alice")
        spy.assert_called_once_with(PASSWORD, stored)
        self.assertIs(auth.verify_password(PASSWORD, stored), True)
        with self.assertRaises(AuthError):
            auth.login(self.conn, "alice", "not-the-password", 3600)
