"""Session lists stay bare arrays and name the active rows past 100.

Newest by created_at, then sid. A later created_at on a lower sid stays, and
the same timestamp keeps the greater sid. An expired session is not a row and
is not omitted. X-Watchpost-Omitted is that count, including 0 when the list
fits or is empty. A 401 sends no header. The body never includes the token or
its hash. Revoking a session past the cap by sid still works.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from watchpost.auth import create_user, list_sessions, revoke_session
from watchpost.db import connect, init_schema

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
FUTURE = "2099-01-01T00:00:00.000Z"
EXPIRED = "2020-01-01T00:00:00.000Z"
OLDER = "2026-01-01T00:00:00.000Z"
SAME = "2026-06-01T00:00:00.000Z"
NEWER = "2026-09-01T00:00:00.000Z"
FIELDS = {"id", "username", "created_at", "last_seen_at", "expires_at", "current"}
INSERT = ("INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at, sid, last_seen_at)"
          " VALUES (?, ?, 'csrf-not-returned', ?, ?, ?, ?)")


def _sid(number):
    return f"{number:016x}"


def _insert(db, user_id, specs):
    """specs: (number, created_at, expires_at). token_hash is hash-<sid>."""
    db.executemany(INSERT, [
        (f"hash-{_sid(number)}", user_id, created, expires, _sid(number), created)
        for number, created, expires in specs])


class SessionsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        create_user(self.conn, "alice", "alice-password-1", "analyst")
        self.user_id = self.conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
        self.addCleanup(self.conn.close)

    def test_the_lowest_sid_is_the_one_left_out_when_times_match(self):
        _insert(self.conn, self.user_id, [(n, SAME, FUTURE) for n in range(101)])
        rows, omitted = list_sessions(self.conn, current_sid=_sid(100))
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        self.assertEqual([row["id"] for row in rows], [_sid(n) for n in range(100, 0, -1)])
        self.assertNotIn(_sid(0), [row["id"] for row in rows])
        self.assertTrue(rows[0]["current"])
        self.assertTrue(all(not row["current"] for row in rows[1:]))
        self.assertTrue(all(set(row) == FIELDS for row in rows))

    def test_an_older_session_is_left_out_even_with_a_higher_sid(self):
        _insert(self.conn, self.user_id, [(n, SAME, FUTURE) for n in range(1, 101)])
        _insert(self.conn, self.user_id, [(0, OLDER, FUTURE)])
        rows, omitted = list_sessions(self.conn, current_sid=_sid(0))
        self.assertEqual(omitted, 1)
        self.assertEqual([row["id"] for row in rows], [_sid(n) for n in range(100, 0, -1)])
        self.assertNotIn(_sid(0), [row["id"] for row in rows])
        self.assertTrue(all(not row["current"] for row in rows))

    def test_an_expired_session_is_not_a_row_and_is_not_omitted(self):
        _insert(self.conn, self.user_id, [(n, SAME, FUTURE) for n in range(100)])
        _insert(self.conn, self.user_id, [(200, NEWER, EXPIRED), (201, OLDER, FUTURE)])
        rows, omitted = list_sessions(self.conn)
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 1)
        ids = [row["id"] for row in rows]
        self.assertEqual(ids, [_sid(n) for n in range(99, -1, -1)])
        self.assertNotIn(_sid(200), ids)
        self.assertNotIn(_sid(201), ids)
        text = json.dumps(rows)
        self.assertNotIn("hash-", text)
        self.assertNotIn("csrf-not-returned", text)

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        _insert(self.conn, self.user_id, [(n, SAME, FUTURE) for n in range(100)])
        rows, omitted = list_sessions(self.conn, "alice")
        self.assertEqual(len(rows), 100)
        self.assertEqual(omitted, 0)
        self.assertIn(_sid(0), [row["id"] for row in rows])
        self.conn.execute("DELETE FROM sessions")
        rows, omitted = list_sessions(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)
        _insert(self.conn, self.user_id, [(1, NEWER, EXPIRED)])
        rows, omitted = list_sessions(self.conn)
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)

    def test_revoking_a_session_past_the_cap_still_works(self):
        _insert(self.conn, self.user_id, [(n, SAME, FUTURE) for n in range(101)])
        self.assertEqual(revoke_session(self.conn, _sid(0), "admin"), {"ok": True})
        rows, omitted = list_sessions(self.conn)
        self.assertEqual(omitted, 0)
        self.assertEqual(len(rows), 100)
        self.assertNotIn(_sid(0), [row["id"] for row in rows])
        self.assertIsNone(self.conn.execute(
            "SELECT token_hash FROM sessions WHERE sid = ?", (_sid(0),)).fetchone())


class SessionsOmittedApiTests(ServerTestCase):
    def _load(self, username, specs):
        with sqlite3.connect(self.db_path) as db:
            user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
            _insert(db, user_id, specs)

    def test_both_lists_stay_arrays_and_name_the_leftover(self):
        admin = self.client("admin")
        self._load("admin", [(n, SAME, FUTURE) for n in range(100)])
        self._load("admin", [(200, NEWER, EXPIRED)])
        status, body, headers = admin.get("/api/sessions")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        ids = [row["id"] for row in body]
        self.assertNotIn(_sid(0), ids)
        self.assertNotIn(_sid(200), ids)
        self.assertIn(_sid(1), ids)
        self.assertEqual(sum(row["current"] for row in body), 1)
        self.assertTrue(all(set(row) == FIELDS for row in body))
        text = json.dumps(body)
        self.assertNotIn("hash-", text)
        self.assertNotIn("csrf-not-returned", text)
        status, own, headers = admin.get("/api/auth/sessions")
        self.assertEqual(status, 200, own)
        self.assertIsInstance(own, list)
        self.assertEqual([row["id"] for row in own], ids)
        self.assertEqual(headers[OMITTED], "1")
        status, fitted, headers = self.client("analyst").get("/api/auth/sessions")
        self.assertEqual(status, 200)
        self.assertEqual(len(fitted), 1)
        self.assertEqual(headers[OMITTED], "0")

    def test_revoking_past_the_cap_still_removes_that_session(self):
        admin = self.client("admin")
        self._load("admin", [(n, SAME, FUTURE) for n in range(100)])
        status, body, _ = admin.post(f"/api/sessions/{_sid(0)}/revoke")
        self.assertEqual(status, 200, body)
        status, body, headers = admin.get("/api/sessions")
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body), 100)
        self.assertEqual(headers[OMITTED], "0")
        self.assertNotIn(_sid(0), [row["id"] for row in body])
        with sqlite3.connect(self.db_path) as db:
            left = db.execute("SELECT sid FROM sessions WHERE sid = ?", (_sid(0),)).fetchone()
        self.assertIsNone(left)

    def test_a_rejected_request_does_not_send_the_header(self):
        anonymous = self.client()
        for path in ("/api/sessions", "/api/auth/sessions"):
            status, _body, headers = anonymous.get(path)
            self.assertEqual(status, 401)
            self.assertIsNone(headers.get(OMITTED))
            self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        text = API.read_text()
        for start in ("| `GET /api/auth/sessions`", "| `GET /api/sessions`"):
            line = next(row for row in text.splitlines() if row.startswith(start))
            self.assertIn("The body stays a bare array", line)
            self.assertIn(
                "`X-Watchpost-Omitted` is how many active sessions were past that cap "
                "(0 when the list fits or is empty)",
                line)
            self.assertIn("never includes the token or its hash", line)


if __name__ == "__main__":
    unittest.main()
