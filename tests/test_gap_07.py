"""session_user rejects an empty token, a disabled user, and an expired session.

A live session returns username, role, and csrf. last_seen_at is written at most
once per SESSION_SEEN_INTERVAL_SECONDS (60).
"""

import os

os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")  # fast hashing for tests only

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from watchpost.auth import (
    SESSION_SEEN_INTERVAL_SECONDS,
    create_user,
    session_user,
    sha256,
)
from watchpost.db import connect, init_schema, iso

PASSWORD = "stored-password-1"
TOKEN = "session-token-1"
CSRF = "csrf-token-1"
SID = "aabbccddeeff0011"
FROZEN = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


class SessionUserTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        create_user(self.conn, "alice", PASSWORD, "analyst")
        self.user_id = self.conn.execute(
            "SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
        patcher = mock.patch("watchpost.auth.utcnow", return_value=FROZEN)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _insert(self, *, expires_at, last_seen_at, token=TOKEN, sid=SID):
        stored_seen = None if last_seen_at is None else iso(last_seen_at)
        self.conn.execute(
            "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at,"
            " sid, last_seen_at) VALUES (?,?,?,?,?,?,?)",
            (sha256(token), self.user_id, CSRF, iso(FROZEN - timedelta(hours=1)),
             iso(expires_at), sid, stored_seen),
        )
        return stored_seen

    def _last_seen(self, token=TOKEN):
        row = self.conn.execute(
            "SELECT last_seen_at FROM sessions WHERE token_hash = ?",
            (sha256(token),),
        ).fetchone()
        return None if row is None else row[0]

    def test_an_empty_token_returns_none(self):
        seen = self._insert(expires_at=FROZEN + timedelta(hours=1), last_seen_at=FROZEN)
        for token in ("", None):
            with self.subTest(token=token):
                self.assertIsNone(session_user(self.conn, token))
        self.assertEqual(self._last_seen(), seen)

    def test_a_disabled_user_returns_none(self):
        seen = self._insert(expires_at=FROZEN + timedelta(hours=1), last_seen_at=FROZEN)
        self.conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (self.user_id,))
        self.assertIsNone(session_user(self.conn, TOKEN))
        self.assertEqual(self._last_seen(), seen)

    def test_an_expired_session_returns_none(self):
        seen = self._insert(
            expires_at=FROZEN - timedelta(seconds=1),
            last_seen_at=FROZEN - timedelta(minutes=5),
        )
        self.assertIsNone(session_user(self.conn, TOKEN))
        self.assertEqual(self._last_seen(), seen)

    def test_a_live_session_returns_username_role_and_csrf(self):
        seen = self._insert(expires_at=FROZEN + timedelta(hours=1), last_seen_at=FROZEN)
        user = session_user(self.conn, TOKEN)
        self.assertEqual(user, {
            "username": "alice",
            "role": "analyst",
            "csrf": CSRF,
            "via": "session",
            "sid": SID,
        })
        self.assertEqual(self._last_seen(), seen)

    def test_last_seen_at_is_written_at_most_once_per_interval(self):
        self.assertEqual(SESSION_SEEN_INTERVAL_SECONDS, 60)
        self._insert(
            expires_at=FROZEN + timedelta(hours=1),
            last_seen_at=FROZEN - timedelta(seconds=SESSION_SEEN_INTERVAL_SECONDS),
        )
        user = session_user(self.conn, TOKEN)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["role"], "analyst")
        self.assertEqual(user["csrf"], CSRF)
        written = iso(FROZEN)
        self.assertEqual(self._last_seen(), written)
        again = session_user(self.conn, TOKEN)
        self.assertEqual(again["username"], "alice")
        self.assertEqual(again["role"], "analyst")
        self.assertEqual(again["csrf"], CSRF)
        self.assertEqual(self._last_seen(), written)

    def test_last_seen_inside_the_interval_is_not_rewritten(self):
        recent = FROZEN - timedelta(seconds=SESSION_SEEN_INTERVAL_SECONDS - 1)
        seen = self._insert(expires_at=FROZEN + timedelta(hours=1), last_seen_at=recent)
        user = session_user(self.conn, TOKEN)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["role"], "analyst")
        self.assertEqual(user["csrf"], CSRF)
        self.assertEqual(self._last_seen(), seen)

    def test_a_missing_last_seen_is_written_once(self):
        self._insert(expires_at=FROZEN + timedelta(hours=1), last_seen_at=None)
        self.assertIsNone(self._last_seen())
        user = session_user(self.conn, TOKEN)
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["role"], "analyst")
        self.assertEqual(user["csrf"], CSRF)
        written = iso(FROZEN)
        self.assertEqual(self._last_seen(), written)
        session_user(self.conn, TOKEN)
        self.assertEqual(self._last_seen(), written)
