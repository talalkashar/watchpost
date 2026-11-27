"""token_user accepts only an active wp_ bearer with usable capabilities.

A missing wp_ prefix, a revoked or expired token, capabilities that are not
valid JSON, and a viewer token whose caps are not exactly ["read"] return
None and leave last_used_at unset. A valid token returns its role and
capabilities and stamps last_used_at. HTTP expiry and a bad role are covered
in tests/test_api.py.
"""

import unittest

from watchpost.auth import create_api_token, sha256, token_user
from watchpost.db import connect, init_schema, parse_iso


class TokenUserTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def _last_used(self, name):
        return self.conn.execute(
            "SELECT last_used_at FROM api_tokens WHERE name = ?", (name,),
        ).fetchone()[0]

    def _insert(self, token, name, role, capabilities):
        self.conn.execute(
            "INSERT INTO api_tokens(name, token_hash, prefix, created_by, created_at,"
            " role, capabilities) VALUES (?,?,?,?,?,?,?)",
            (name, sha256(token), token[:7], "admin", "2026-01-01T00:00:00.000Z",
             role, capabilities),
        )

    def test_missing_wp_prefix_returns_none(self):
        for token in (None, "", "secret-without-prefix", "WP_not-lower", "wp"):
            with self.subTest(token=token):
                self.assertIsNone(token_user(self.conn, token))

    def test_revoked_or_expired_token_returns_none(self):
        revoked = create_api_token(self.conn, "revoked", "admin")
        expired = create_api_token(
            self.conn, "expired", "admin", expires_in_days=1)
        self.conn.execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE name = 'revoked'",
            ("2020-01-01T00:00:00.000Z",))
        self.conn.execute(
            "UPDATE api_tokens SET expires_at = ? WHERE name = 'expired'",
            ("2000-01-01T00:00:00.000Z",))
        self.assertIsNone(token_user(self.conn, revoked))
        self.assertIsNone(token_user(self.conn, expired))
        self.assertIsNone(self._last_used("revoked"))
        self.assertIsNone(self._last_used("expired"))

    def test_capabilities_that_are_not_json_return_none(self):
        token = "wp_badjson0123456789abcdefghijklmnop"
        self._insert(token, "broken", "analyst", "{not-json")
        self.assertIsNone(token_user(self.conn, token))
        self.assertIsNone(self._last_used("broken"))

    def test_viewer_caps_other_than_read_return_none(self):
        cases = (
            ("viewer-ingest", "wp_vieweringest0123456789abcdef", '["ingest"]'),
            ("viewer-both", "wp_viewerboth0123456789abcdefghij", '["read", "ingest"]'),
        )
        for name, token, capabilities in cases:
            self._insert(token, name, "viewer", capabilities)
            with self.subTest(name=name):
                self.assertIsNone(token_user(self.conn, token))
                self.assertIsNone(self._last_used(name))

    def test_valid_token_returns_role_capabilities_and_stamps_last_used(self):
        analyst = create_api_token(
            self.conn, "collector", "admin", role="analyst",
            capabilities=["read", "ingest"], expires_in_days=7)
        viewer = create_api_token(
            self.conn, "readonly", "admin", role="viewer", capabilities=["read"])
        self.assertIsNone(self._last_used("collector"))
        self.assertIsNone(self._last_used("readonly"))

        got = token_user(self.conn, analyst)
        self.assertEqual(got, {
            "username": "token:collector",
            "role": "analyst",
            "capabilities": ["read", "ingest"],
            "via": "token",
        })
        stamped = self._last_used("collector")
        parse_iso(stamped)
        self.assertTrue(stamped.endswith("Z"))

        got_viewer = token_user(self.conn, viewer)
        self.assertEqual(got_viewer["role"], "viewer")
        self.assertEqual(got_viewer["capabilities"], ["read"])
        self.assertEqual(got_viewer["username"], "token:readonly")
        self.assertIsNotNone(self._last_used("readonly"))
        self.assertEqual(self._last_used("collector"), stamped)
