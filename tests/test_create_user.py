"""create_user refuses a second account that differs only by ASCII case.

The unique index is case-sensitive and login is exact, so Admin and admin would
both sign in. The second name is 409 naming the stored spelling, before the new
password is hashed. An exact duplicate is that same 409. Érin and érin stay two
accounts.
"""

import unittest
from pathlib import Path
from unittest import mock

from watchpost import auth
from watchpost.auth import AuthError
from watchpost.db import connect, init_schema

PASSWORD = "account-password-1"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
TAKEN = "a user named 'admin' already exists"


class CreateUserCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        auth.create_user(self.conn, "admin", PASSWORD, "admin")

    def _names(self):
        return [row[0] for row in self.conn.execute("SELECT username FROM users ORDER BY id")]

    def _created(self):
        return self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'user_created'").fetchone()[0]

    def test_ascii_case_names_the_stored_row_and_does_not_hash(self):
        with mock.patch("watchpost.auth.hash_password", side_effect=AssertionError("hashed")):
            for variant in ("Admin", "ADMIN", "admin"):
                with self.subTest(variant=variant):
                    with self.assertRaises(AuthError) as caught:
                        auth.create_user(self.conn, variant, "another-password-1", "analyst")
                    self.assertEqual(caught.exception.status, 409)
                    self.assertEqual(str(caught.exception), TAKEN)
        self.assertEqual(self._names(), ["admin"])
        self.assertEqual(self._created(), 1)
        stored = self.conn.execute("SELECT role FROM users WHERE username = 'admin'").fetchone()[0]
        self.assertEqual(stored, "admin")

    def test_erin_and_erin_stay_two_accounts(self):
        auth.create_user(self.conn, "Érin", PASSWORD, "analyst")
        auth.create_user(self.conn, "érin", PASSWORD, "viewer")
        self.assertEqual(self._names(), ["admin", "Érin", "érin"])
        roles = {
            row[0]: row[1]
            for row in self.conn.execute("SELECT username, role FROM users WHERE username != 'admin'")}
        self.assertEqual(roles, {"Érin": "analyst", "érin": "viewer"})
        self.assertEqual(self._created(), 3)

    def test_exact_duplicate_conflict_names_the_stored_row(self):
        real = self.conn.execute
        skipped = {"done": False}
        lookup = "SELECT username FROM users WHERE username = ? COLLATE NOCASE"

        def execute(sql, params=()):
            # The lookup misses once, so the insert hits the case-sensitive UNIQUE index.
            if not skipped["done"] and sql == lookup:
                skipped["done"] = True
                return real("SELECT username FROM users WHERE 0")
            return real(sql, params)

        self.conn.execute = execute
        with self.assertRaises(AuthError) as caught:
            auth.create_user(self.conn, "admin", "another-password-1", "analyst")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), TAKEN)
        self.assertTrue(skipped["done"])
        self.conn.execute = real
        self.assertEqual(self._names(), ["admin"])
        self.assertEqual(self._created(), 1)

    def test_reference_names_the_refusal(self):
        text = REFERENCE.read_text()
        self.assertIn("`Admin` when `admin` is stored", text)
        self.assertIn("`Érin` and `érin` stay two accounts", text)
        self.assertIn("An exact duplicate is that same refusal", text)
