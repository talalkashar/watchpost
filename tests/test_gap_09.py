"""create_api_token refuses a viewer ingest grant, duplicate capabilities, and a lifetime outside 1..365.

A created row stores sha256 of the secret. The returned plaintext starts with wp_ and is not the stored value.
"""

import unittest

from watchpost.auth import AuthError, create_api_token, sha256
from watchpost.db import connect, init_schema

VIEWER_INGEST = "viewer tokens can only have the read capability"
DUPLICATE = "capabilities must be unique and chosen from read, ingest, triage"
EXPIRES = "expires_in_days must be an integer from 1 to 365"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


class CreateApiTokenTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def _count(self):
        return self.conn.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0]

    def test_viewer_with_ingest_raises(self):
        for capabilities in (["ingest"], ["read", "ingest"]):
            with self.subTest(capabilities=capabilities):
                with self.assertRaises(AuthError) as caught:
                    create_api_token(self.conn, "shipper", "admin", role="viewer", capabilities=capabilities)
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), VIEWER_INGEST)
        self.assertEqual(self._count(), 0)

    def test_duplicate_capabilities_raise(self):
        for capabilities in (["ingest", "ingest"], ["read", "read"], ["read", "ingest", "read"]):
            with self.subTest(capabilities=capabilities):
                with self.assertRaises(AuthError) as caught:
                    create_api_token(self.conn, "shipper", "admin", capabilities=capabilities)
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), DUPLICATE)
        self.assertEqual(self._count(), 0)

    def test_expires_in_days_outside_1_to_365_raises(self):
        for days in (0, -1, 366, 1000):
            with self.subTest(days=days):
                with self.assertRaises(AuthError) as caught:
                    create_api_token(
                        self.conn, "shipper", "admin", capabilities=["read"], expires_in_days=days)
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), EXPIRES)
        self.assertEqual(self._count(), 0)

    def test_row_stores_sha256_and_plaintext_starts_with_wp(self):
        for days in (1, 30, 365):
            with self.subTest(days=days):
                token = create_api_token(
                    self.conn, f"shipper-{days}", "admin", capabilities=["read"], expires_in_days=days)
                self.assertTrue(token.startswith("wp_"))
                self.assertGreater(len(token), len("wp_"))
                row = self.conn.execute(
                    "SELECT * FROM api_tokens WHERE name = ?", (f"shipper-{days}",)).fetchone()
                self.assertEqual(row["token_hash"], sha256(token))
                self.assertNotEqual(row["token_hash"], token)
                for key in row.keys():
                    value = row[key]
                    if value is None:
                        continue
                    self.assertNotEqual(value, token)
                    self.assertNotIn(token, str(value))
                self.assertEqual(row["prefix"], token[:7])
                self.assertNotEqual(row["prefix"], token)
