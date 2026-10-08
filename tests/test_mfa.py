"""Milestone 13: TOTP second factor, the two-step login, and session listing and revocation."""

import base64
import os
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

from tests.helpers import ADMIN_PW, ANALYST_PW, VIEWER_PW, Client, ServerTestCase
from watchpost import auth, totp
from watchpost.config import Config
from watchpost.db import SCHEMA_VERSION, connect, init_schema, iso, utcnow

RFC_KEY = b"12345678901234567890"  # RFC 6238 Appendix B, SHA-1 seed
RFC_SECRET = base64.b32encode(RFC_KEY).decode().rstrip("=")
RFC_VECTORS = [  # (time, 8-digit TOTP)
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
]


class TotpTests(unittest.TestCase):
    def test_rfc6238_sha1_vectors(self):
        for t, expected in RFC_VECTORS:
            with self.subTest(t=t):
                self.assertEqual(totp.code_at(RFC_SECRET, t, digits=8), expected)
                self.assertEqual(totp.code_at(RFC_SECRET, t), expected[-6:])  # 6 digits = last 6 of the 8

    def test_drift_of_one_step_is_accepted_two_is_not(self):
        t = 1111111111
        step = totp.step_at(t)
        for offset in (-1, 0, 1):
            code = totp.code_at(RFC_SECRET, t + offset * 30)
            self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=t), step + offset, offset)
        for offset in (-2, 2):
            code = totp.code_at(RFC_SECRET, t + offset * 30)
            self.assertIsNone(totp.verify(RFC_SECRET, code, timestamp=t), offset)

    def test_replay_of_the_same_or_an_older_step_is_refused(self):
        t = 1111111111
        code = totp.code_at(RFC_SECRET, t)
        step = totp.verify(RFC_SECRET, code, timestamp=t)
        self.assertIsNone(totp.verify(RFC_SECRET, code, last_step=step, timestamp=t))
        older = totp.code_at(RFC_SECRET, t - 30)
        self.assertIsNone(totp.verify(RFC_SECRET, older, last_step=step, timestamp=t))
        newer = totp.code_at(RFC_SECRET, t + 30)
        self.assertEqual(totp.verify(RFC_SECRET, newer, last_step=step, timestamp=t), step + 1)

    def test_malformed_codes_are_refused(self):
        for bad in (None, 123456, "", "12345", "1234567", "abcdef"):
            self.assertIsNone(totp.verify(RFC_SECRET, bad, timestamp=59), bad)

    def test_secret_and_uri(self):
        secret = totp.generate_secret()
        self.assertEqual(len(totp.decode_secret(secret)), 20)
        self.assertEqual(totp.otpauth_uri("alice", secret),
                         f"otpauth://totp/Watchpost:alice?secret={secret}&issuer=Watchpost")


class Clock:
    """Drives watchpost.totp.now so each code lands on a fresh step without waiting 30 s."""

    def __init__(self, start=1_800_000_000):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, steps=1):
        self.t += 30 * steps


class MfaApiTests(ServerTestCase):
    def config_overrides(self):
        return {"rate_limit_enabled": False}  # these tests sign in many times from one address

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        patcher = mock.patch.object(totp, "now", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def code(self, secret, steps_ahead=0):
        return totp.code_at(secret, self.clock() + 30 * steps_ahead)

    def enroll(self, client):
        status, data, _ = client.post("/api/auth/mfa/enroll")
        self.assertEqual(status, 200, data)
        self.clock.advance()
        status, body, _ = client.post("/api/auth/mfa/confirm", {"code": self.code(data["secret"])})
        self.assertEqual(status, 200, body)
        self.clock.advance()
        return data["secret"]

    def audit(self, action):
        return [a for a in self.client("admin").get("/api/audit")[1] if a["action"] == action]

    def password_step(self, username, password):
        client = Client(self.base)
        status, data, _ = client.post("/api/auth/login", {"username": username, "password": password})
        return client, status, data

    def test_enroll_then_confirm_then_login_needs_a_code(self):
        analyst = self.client("analyst")
        status, data, _ = analyst.post("/api/auth/mfa/enroll")
        self.assertEqual(status, 200, data)
        self.assertEqual(data["otpauth_uri"],
                         f"otpauth://totp/Watchpost:analyst?secret={data['secret']}&issuer=Watchpost")
        # Pending until confirmed: login is still one step, and a wrong code does not activate it.
        self.assertEqual(analyst.get("/api/auth/mfa/status")[1], {"enabled": False, "pending": True, "available": True})
        self.assertEqual(self.password_step("analyst", ANALYST_PW)[1], 200)
        self.assertEqual(analyst.post("/api/auth/mfa/confirm", {"code": "000000"})[0], 400)
        self.assertEqual(analyst.post("/api/auth/mfa/confirm", {"code": self.code(data["secret"])})[0], 200)
        self.assertTrue(analyst.get("/api/auth/mfa/status")[1]["enabled"])

        self.clock.advance()
        client, status, body = self.password_step("analyst", ANALYST_PW)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["mfa_required"])
        self.assertNotIn("csrf_token", body)
        self.assertEqual(client.get("/api/alerts")[0], 401)  # the password step is not a session
        status, body, headers = client.post("/api/auth/mfa", {"mfa_token": body["mfa_token"],
                                                              "code": self.code(data["secret"])})
        self.assertEqual(status, 200, body)
        self.assertIn("wp_session=", headers["Set-Cookie"])
        self.assertEqual(client.get("/api/alerts")[0], 200)
        self.assertEqual([a["detail"] for a in self.audit("login") if a["actor"] == "analyst"][0], '{"mfa": true}')
        # Neither the secret nor any code reaches the audit log.
        for entry in self.client("admin").get("/api/audit")[1]:
            self.assertNotIn(data["secret"], str(entry))
            self.assertNotIn(self.code(data["secret"]), str(entry["detail"] or ""))

    def test_same_step_cannot_be_used_twice(self):
        secret = self.enroll(self.client("analyst"))
        code = self.code(secret)
        first = self.password_step("analyst", ANALYST_PW)
        self.assertEqual(first[0].post("/api/auth/mfa", {"mfa_token": first[2]["mfa_token"], "code": code})[0], 200)
        second = self.password_step("analyst", ANALYST_PW)
        status, data, _ = second[0].post("/api/auth/mfa", {"mfa_token": second[2]["mfa_token"], "code": code})
        self.assertEqual(status, 401, data)
        self.assertEqual(self.audit("login_failed")[0]["detail"], '{"reason": "mfa", "locked": false}')

    def test_mfa_token_is_single_use_and_expires(self):
        secret = self.enroll(self.client("analyst"))
        client, _, body = self.password_step("analyst", ANALYST_PW)
        token = body["mfa_token"]
        self.assertEqual(client.post("/api/auth/mfa", {"mfa_token": token, "code": self.code(secret)})[0], 200)
        self.clock.advance()
        status, data, _ = Client(self.base).post("/api/auth/mfa", {"mfa_token": token, "code": self.code(secret)})
        self.assertEqual((status, data["error"]), (401, "sign-in step expired; sign in again"))

        self.clock.advance()
        _, _, body = self.password_step("analyst", ANALYST_PW)
        conn = connect(self.db_path)
        conn.execute("UPDATE mfa_pending SET expires_at = ?", (iso(utcnow() - timedelta(seconds=1)),))
        conn.close()
        status, _, _ = Client(self.base).post("/api/auth/mfa", {"mfa_token": body["mfa_token"], "code": self.code(secret)})
        self.assertEqual(status, 401)
        self.assertEqual(Client(self.base).post("/api/auth/mfa", {"mfa_token": "nope", "code": "123456"})[0], 401)

    def test_wrong_codes_lock_the_account(self):
        secret = self.enroll(self.client("analyst"))
        client, _, body = self.password_step("analyst", ANALYST_PW)
        for n in range(5):  # default threshold 5
            status, data, _ = client.post("/api/auth/mfa", {"mfa_token": body["mfa_token"], "code": "000000"})
            self.assertEqual(status, 401, (n, data))
        details = [a["detail"] for a in self.audit("login_failed")]
        self.assertEqual(details[0], '{"reason": "mfa", "locked": true}')
        self.assertEqual(len(details), 5)
        # Locking drops the pending token, and the password step is now refused too.
        status, _, _ = client.post("/api/auth/mfa", {"mfa_token": body["mfa_token"], "code": self.code(secret)})
        self.assertEqual(status, 401)
        self.assertEqual(self.password_step("analyst", ANALYST_PW)[1], 429)

    def test_correct_password_does_not_reset_code_failures(self):
        self.enroll(self.client("analyst"))
        for _ in range(4):
            client, _, body = self.password_step("analyst", ANALYST_PW)
            client.post("/api/auth/mfa", {"mfa_token": body["mfa_token"], "code": "000000"})
        client, _, body = self.password_step("analyst", ANALYST_PW)
        client.post("/api/auth/mfa", {"mfa_token": body["mfa_token"], "code": "000000"})
        self.assertEqual(self.password_step("analyst", ANALYST_PW)[1], 429)

    def test_viewer_cannot_enroll_and_still_logs_in_one_step(self):
        viewer = Client(self.base)
        status, data = viewer.login("viewer", VIEWER_PW)
        self.assertEqual(status, 200)
        self.assertEqual(set(data), {"user", "csrf_token"})
        self.assertEqual(viewer.post("/api/auth/mfa/enroll")[0], 403)
        self.assertEqual(viewer.post("/api/auth/mfa/confirm", {"code": "123456"})[0], 403)
        self.assertEqual(viewer.get("/api/auth/mfa/status")[1]["available"], False)
        # Even written straight into the database, the auth layer refuses a viewer enrollment.
        conn = connect(self.db_path)
        with self.assertRaises(auth.AuthError) as ctx:
            auth.mfa_enroll(conn, "viewer")
        conn.close()
        self.assertEqual(ctx.exception.status, 403)

    def test_disable_needs_a_current_code(self):
        analyst = self.client("analyst")
        secret = self.enroll(analyst)
        self.assertEqual(analyst.post("/api/auth/mfa/disable", {"code": "000000"})[0], 400)
        self.assertEqual(analyst.post("/api/auth/mfa/disable", {"code": self.code(secret)})[0], 200)
        self.assertFalse(analyst.get("/api/auth/mfa/status")[1]["enabled"])
        self.assertEqual(self.password_step("analyst", ANALYST_PW)[1], 200)
        self.assertEqual(len(self.audit("mfa_disabled")), 1)

    def test_wrong_disable_codes_count_toward_the_lockout(self):
        analyst = self.client("analyst")
        secret = self.enroll(analyst)
        codes = [analyst.post("/api/auth/mfa/disable", {"code": "000000"})[0] for _ in range(6)]
        self.assertEqual(codes, [400] * 5 + [429])
        self.assertEqual(analyst.post("/api/auth/mfa/disable", {"code": self.code(secret)})[0], 429)
        self.assertTrue(analyst.get("/api/auth/mfa/status")[1]["enabled"])

    def test_parallel_code_guesses_cannot_outrun_the_lockout(self):
        from concurrent.futures import ThreadPoolExecutor
        self.enroll(self.client("analyst"))
        client, _, body = self.password_step("analyst", ANALYST_PW)
        guess = lambda _: Client(self.base).post("/api/auth/mfa", {"mfa_token": body["mfa_token"], "code": "000000"})[0]
        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(guess, range(24)))
        # Every attempt is counted before its code is checked: at most the threshold (5) codes are ever checked.
        self.assertLessEqual(len(self.audit("login_failed")), 5)
        self.assertEqual(statuses.count(401) + statuses.count(429), 24)

    def test_admin_reset_is_audited(self):
        self.enroll(self.client("analyst"))
        admin = self.client("admin")
        status, data, _ = admin.post("/api/users/analyst/mfa/reset")
        self.assertEqual(status, 200, data)
        entry = self.audit("mfa_reset")[0]
        self.assertEqual((entry["actor"], entry["target"]), ("admin", "analyst"))
        self.assertEqual(self.password_step("analyst", ANALYST_PW)[1], 200)  # one step again
        self.assertEqual(admin.post("/api/users/analyst/mfa/reset")[0], 409)
        self.assertEqual(admin.post("/api/users/admin/mfa/reset")[0], 400)
        analyst = self.client("analyst")
        self.assertEqual(analyst.post("/api/users/admin/mfa/reset")[0], 403)

    def test_session_list_hides_tokens(self):
        self.client("analyst")
        second = self.client("analyst")
        self.client("admin")
        status, rows, _ = second.get("/api/auth/sessions")
        self.assertEqual(status, 200)
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(r["current"] for r in rows), 1)
        self.assertEqual({r["username"] for r in rows}, {"analyst"})
        self.assertEqual(set(rows[0]), {"id", "username", "created_at", "last_seen_at", "expires_at", "current"})
        conn = connect(self.db_path)
        hashes = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
        conn.close()
        text = str(rows)
        for h in hashes:
            self.assertNotIn(h, text)
        for r in rows:
            self.assertRegex(r["id"], r"^[0-9a-f]{16}$")

    def test_revoke_own_and_others_sessions(self):
        a1, a2 = self.client("analyst"), self.client("analyst")
        other = [r for r in a1.get("/api/auth/sessions")[1] if not r["current"]][0]
        self.assertEqual(a1.post(f"/api/auth/sessions/{other['id']}/revoke")[0], 200)
        self.assertEqual(a2.get("/api/alerts")[0], 401)
        self.assertEqual(a1.get("/api/alerts")[0], 200)

        admin = self.client("admin")
        admin_sid = next(r["id"] for r in admin.get("/api/auth/sessions")[1] if r["current"])
        # A non-admin cannot revoke someone else's session, by either route.
        self.assertEqual(a1.post(f"/api/auth/sessions/{admin_sid}/revoke")[0], 404)
        self.assertEqual(a1.post(f"/api/sessions/{admin_sid}/revoke")[0], 403)
        self.assertEqual(a1.get("/api/sessions")[0], 403)
        self.assertEqual(admin.get("/api/alerts")[0], 200)

        everyone = admin.get("/api/sessions")[1]
        self.assertEqual({r["username"] for r in everyone}, {"analyst", "admin"})
        mine = admin.get("/api/sessions?user=analyst")[1]
        self.assertEqual(len(mine), 1)
        self.assertEqual(admin.post(f"/api/sessions/{mine[0]['id']}/revoke")[0], 200)
        self.assertEqual(a1.get("/api/alerts")[0], 401)
        entries = self.audit("session_revoked")
        self.assertEqual([(e["actor"], e["target"]) for e in entries], [("admin", "analyst"), ("analyst", "analyst")])

    def test_viewer_can_list_but_not_revoke(self):
        viewer = self.client("viewer")
        rows = viewer.get("/api/auth/sessions")[1]
        self.assertEqual(len(rows), 1)
        self.assertEqual(viewer.post(f"/api/auth/sessions/{rows[0]['id']}/revoke")[0], 403)


class MigrationTests(unittest.TestCase):
    def test_v7_database_gains_mfa_and_session_ids(self):
        self.assertEqual(SCHEMA_VERSION, 13)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v7.db")
            conn = connect(path)
            init_schema(conn)
            # What a 7.x database looked like.
            conn.execute("DROP INDEX idx_sessions_sid")
            for column in ("totp_secret", "totp_pending", "totp_last_step"):
                conn.execute(f"ALTER TABLE users DROP COLUMN {column}")
            for column in ("sid", "last_seen_at"):
                conn.execute(f"ALTER TABLE sessions DROP COLUMN {column}")
            conn.execute("DROP TABLE mfa_pending")
            conn.execute("UPDATE meta SET value = '7' WHERE key = 'schema_version'")
            auth.create_user(conn, "alice", "alice-password-123", "analyst")
            for n in range(2):
                conn.execute("INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at)"
                             " VALUES (?, 1, 'c', ?, ?)", (f"h{n}", iso(utcnow()), iso(utcnow() + timedelta(hours=1))))
            conn.close()

            conn = connect(path)
            self.addCleanup(conn.close)
            init_schema(conn)
            self.assertEqual(conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "13")
            sids = [r[0] for r in conn.execute("SELECT sid FROM sessions")]
            self.assertEqual(len(set(sids)), 2)
            self.assertTrue(all(s and len(s) == 16 for s in sids))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM mfa_pending").fetchone()[0], 0)
            user = conn.execute("SELECT totp_secret, totp_pending FROM users WHERE username = 'alice'").fetchone()
            self.assertEqual(tuple(user), (None, None))
            result = auth.login(conn, "alice", "alice-password-123", 3600)
            self.assertIsInstance(result, tuple)  # not enrolled: one step, as before
            listed = auth.list_sessions(conn, "alice")
            self.assertEqual(len(listed), 3)
            init_schema(conn)  # idempotent
            self.assertEqual(sorted(r[0] for r in conn.execute("SELECT sid FROM sessions")),
                             sorted(r["id"] for r in listed))


if __name__ == "__main__":
    unittest.main()
