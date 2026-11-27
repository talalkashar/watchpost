"""for_user builds a masker only for a viewer with masking on, and refuses an unbounded name set.

A missing user, any other role, or viewer_masking other than 1 returns None before the event
table is counted. More than CANDIDATE_LIMIT distinct event usernames (SQLite lower(), so ASCII
case is one name, and blank users are not names) raises Unavailable instead of masking a partial set.
"""

import unittest
from unittest import mock

from watchpost import masking
from watchpost.db import connect, init_schema

TS = "2026-01-01T00:00:00Z"
VIEWER = {"role": "viewer", "username": "viewer"}


class ForUserTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def set_masking(self, value):
        self.conn.execute(
            "INSERT INTO settings(key, value, updated_at, updated_by)"
            " VALUES ('viewer_masking', ?, ?, 'test')"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (value, TS))
        self.conn.commit()

    def add_event_users(self, names):
        self.conn.executemany(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, synthetic)"
            " VALUES (?, ?, 'test', 'auth_success', 'low', ?, 1)",
            [(TS, TS, name) for name in names])
        self.conn.commit()

    def test_missing_user_returns_none(self):
        self.set_masking("1")
        self.add_event_users(["alice"])
        self.assertIsNone(masking.for_user(self.conn, None))
        self.assertIsNone(masking.for_user(self.conn, {}))

    def test_non_viewer_returns_none(self):
        self.set_masking("1")
        self.add_event_users(["alice"])
        for role in ("analyst", "admin"):
            with self.subTest(role=role):
                self.assertIsNone(masking.for_user(self.conn, {"role": role, "username": role}))

    def test_masking_off_returns_none(self):
        self.add_event_users(["alice"])
        self.assertIsNone(masking.for_user(self.conn, VIEWER))  # setting row absent
        self.set_masking("0")
        self.assertIsNone(masking.for_user(self.conn, VIEWER))

    def test_more_than_candidate_limit_distinct_event_usernames_raises(self):
        """The cap is distinct event usernames. Repeats, ASCII case, and blanks do not add to it."""
        limit = 2
        self.set_masking("1")
        with mock.patch.object(masking, "CANDIDATE_LIMIT", limit):
            self.add_event_users(["Alice", "alice", "ALICE", "", None, "bob"])
            masker = masking.for_user(self.conn, VIEWER)
            self.assertIsInstance(masker, masking.Masker)
            self.assertEqual(set(masker.names), {"alice", "bob"})

            self.add_event_users(["carol"])
            # The gate still wins: these callers never see the cap.
            self.assertIsNone(masking.for_user(self.conn, None))
            self.assertIsNone(masking.for_user(self.conn, {"role": "analyst", "username": "analyst"}))
            self.set_masking("0")
            self.assertIsNone(masking.for_user(self.conn, VIEWER))
            self.set_masking("1")
            with self.assertRaises(masking.Unavailable) as caught:
                masking.for_user(self.conn, VIEWER)
            self.assertIn(f"{limit:,}", str(caught.exception))
