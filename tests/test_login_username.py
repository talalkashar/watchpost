"""Login rejects a username outside 3–32 characters before the lookup.

A slice of the first 64 characters could sign in a stored prefix. The response
stays the same as an unknown account.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ADMIN_PW, ServerTestCase
from watchpost import auth
from watchpost.auth import AuthError
from watchpost.db import connect, init_schema, now_iso

PASSWORD = "stored-password-1"
API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def insert_user(conn, username):
    conn.execute(
        "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
        (username, auth.hash_password(PASSWORD), "analyst", now_iso()),
    )


class LookupSpy:
    """Records username lookups. Other connection calls pass through."""

    def __init__(self, conn):
        self.conn = conn
        self.lookups = []

    def execute(self, sql, params=()):
        if "FROM users WHERE username" in sql:
            self.lookups.append(params[0] if params else None)
        return self.conn.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self.conn, name)


class LoginUsernameTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        self.long_name = "a" * 64
        insert_user(self.conn, self.long_name)
        insert_user(self.conn, "ab")
        insert_user(self.conn, "None")
        insert_user(self.conn, "123")
        auth.create_user(self.conn, "abc", PASSWORD, "analyst")
        auth.create_user(self.conn, "u" * 32, PASSWORD, "analyst")

    def _login(self, username, password=PASSWORD):
        spy = LookupSpy(self.conn)
        with self.assertRaises(AuthError) as caught:
            auth.login(spy, username, password, 3600)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(str(caught.exception), "invalid username or password")
        self.assertEqual(spy.lookups, [])
        return caught.exception

    def test_overlong_username_is_not_sliced_or_looked_up(self):
        self._login(self.long_name + "Z")
        self._login(self.long_name)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        row = self.conn.execute(
            "SELECT failed_logins FROM users WHERE username = ?", (self.long_name,)
        ).fetchone()
        self.assertEqual(row[0], 0)

    def test_short_and_non_string_match_the_unknown_user_response(self):
        for username in ("ab", "", "a", None, 123, ["admin"]):
            with self.subTest(username=username):
                self._login(username)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_bounds_still_sign_in(self):
        for username in ("abc", "u" * 32):
            token, _csrf, user = auth.login(self.conn, username, PASSWORD, 3600)
            self.assertTrue(token)
            self.assertEqual(user["username"], username)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 2)


class LoginUsernameApiTests(ServerTestCase):
    def test_overlong_username_is_the_same_401_as_an_unknown_account(self):
        client = self.client()
        unknown_status, unknown = client.login("nobody", "wrong-password-123")
        status, data, headers = client.post(
            "/api/auth/login", {"username": "admin" + ("x" * 30), "password": ADMIN_PW}
        )
        self.assertEqual(unknown_status, 401)
        self.assertEqual(status, 401)
        self.assertEqual(data, unknown)
        self.assertEqual(data["error"], "invalid username or password")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers["Set-Cookie"])

        status, data = client.login("admin", ADMIN_PW)
        self.assertEqual(status, 200, data)

    def test_a_stored_name_outside_3_to_32_cannot_sign_in(self):
        stored = "b" * 40
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
                (stored, auth.hash_password(PASSWORD), "analyst", now_iso()),
            )
        client = self.client()
        status, data, headers = client.post("/api/auth/login", {"username": stored, "password": PASSWORD})
        self.assertEqual(status, 401)
        self.assertEqual(data["error"], "invalid username or password")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIsNone(headers["Set-Cookie"])

    def test_api_docs_say_login_does_not_truncate(self):
        text = API.read_text()
        self.assertIn("not 3–32 characters", text)
        self.assertIn("invalid username or password", text)
        self.assertIn("Login does not truncate it", text)
