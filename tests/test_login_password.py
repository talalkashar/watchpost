"""Login rejects a password that is not a string or is longer than 256 characters.

The value is not hashed and the account is not looked up. The response stays the
same as an unknown account. The timing check uses the short fixed dummy string.
"""

import hashlib
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import ADMIN_PW, ServerTestCase
from tests.test_login_username import LookupSpy, memory_db
from watchpost import auth
from watchpost.auth import AuthError

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
LONG = "p" * 257


class LoginPasswordTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "alice", "stored-password-1", "analyst")

    def _hashed(self, password):
        seen = []
        real = hashlib.pbkdf2_hmac

        def spy(hash_name, secret, salt, iterations, dklen=None):
            seen.append(secret)
            return real(hash_name, secret, salt, iterations, dklen)

        spy_conn = LookupSpy(self.conn)
        with mock.patch("watchpost.auth.hashlib.pbkdf2_hmac", spy):
            with self.assertRaises(AuthError) as caught:
                auth.login(spy_conn, "alice", password, 3600)
        return caught.exception, seen, spy_conn.lookups

    def test_overlong_password_is_not_hashed_or_looked_up(self):
        err, seen, lookups = self._hashed(LONG)
        self.assertEqual(err.status, 401)
        self.assertEqual(str(err), "invalid username or password")
        self.assertEqual(lookups, [])
        self.assertTrue(seen)
        self.assertTrue(all(secret == b"dummy-password-for-timing" for secret in seen))
        self.assertNotIn(LONG.encode(), seen)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        row = self.conn.execute("SELECT failed_logins FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(row[0], 0)

    def test_non_string_password_is_not_coerced_or_looked_up(self):
        for password in (None, 123, ["stored-password-1"], {"password": "stored-password-1"}):
            with self.subTest(password=password):
                err, seen, lookups = self._hashed(password)
                self.assertEqual(err.status, 401)
                self.assertEqual(str(err), "invalid username or password")
                self.assertEqual(lookups, [])
                self.assertNotIn(str(password).encode(), seen)
                self.assertTrue(all(secret == b"dummy-password-for-timing" for secret in seen))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_max_length_password_still_signs_in(self):
        password = "P" * auth.PASSWORD_MAX_LEN
        auth.create_user(self.conn, "maxpw", password, "analyst")
        token, _csrf, user = auth.login(self.conn, "maxpw", password, 3600)
        self.assertTrue(token)
        self.assertEqual(user["username"], "maxpw")

    def test_short_wrong_password_still_looks_up_the_account(self):
        spy = LookupSpy(self.conn)
        with self.assertRaises(AuthError) as caught:
            auth.login(spy, "alice", "not-the-password", 3600)
        self.assertEqual(str(caught.exception), "invalid username or password")
        self.assertEqual(spy.lookups, ["alice"])
        row = self.conn.execute("SELECT failed_logins FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(row[0], 1)


class LoginPasswordApiTests(ServerTestCase):
    def test_overlong_password_matches_an_unknown_account(self):
        client = self.client()
        unknown_status, unknown = client.login("nobody-here", "wrong-password-123")
        status, data, headers = client.post(
            "/api/auth/login", {"username": "admin", "password": LONG}
        )
        self.assertEqual(unknown_status, 401)
        self.assertEqual(status, 401)
        self.assertEqual(data, unknown)
        self.assertEqual(data["error"], "invalid username or password")
        self.assertNotIn("too long", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers["Set-Cookie"])

        status, data, headers = client.post(
            "/api/auth/login", {"username": "admin", "password": None}
        )
        self.assertEqual(status, 401)
        self.assertEqual(data["error"], "invalid username or password")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers["Set-Cookie"])

        status, data = client.login("admin", ADMIN_PW)
        self.assertEqual(status, 200, data)

    def test_api_docs_say_login_does_not_hash_an_overlong_password(self):
        text = API.read_text()
        self.assertIn("longer than 256 characters", text)
        self.assertIn("does not hash that value", text)
        self.assertIn("does not look up the account", text)
