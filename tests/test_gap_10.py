"""Handler._authorize: public stays anonymous, bearer capabilities, session CSRF.

role="public" returns with user left unset, even when a bearer token and a
session cookie are present. A bearer token that omits the route capability is
403: GET needs read, ingest_json and ingest_upload need ingest, alert_note,
alert_status, alert_assign, and incident_status need triage, and any other
mutation is 403. A session POST whose X-CSRF-Token does not match is 403.
"""

import unittest
from datetime import timedelta

from watchpost import auth
from watchpost.db import connect, init_schema, iso, now_iso, utcnow
from watchpost.server import (
    SESSION_COOKIE,
    ApiError,
    Handler,
    alert_assign,
    alert_note,
    alert_status,
    detection_run,
    incident_status,
    ingest_json,
    ingest_upload,
)

CAPABILITY_ERROR = "API token does not have the required capability"

# command, token key, route function, route role. GET ignores the function name.
DENIED = [
    ("GET", "ingest", None, "viewer"),
    ("GET", "triage", None, "viewer"),
    ("GET", "ingest-triage", ingest_json, "viewer"),
    ("POST", "read", ingest_json, "ingest"),
    ("POST", "triage", ingest_json, "ingest"),
    ("POST", "read-triage", ingest_json, "ingest"),
    ("POST", "read", ingest_upload, "ingest"),
    ("POST", "triage", ingest_upload, "ingest"),
    ("POST", "read", alert_note, "analyst"),
    ("POST", "ingest", alert_note, "analyst"),
    ("POST", "read-ingest", alert_note, "analyst"),
    ("POST", "read", alert_status, "analyst"),
    ("POST", "ingest", alert_assign, "analyst"),
    ("POST", "read-ingest", incident_status, "analyst"),
    ("POST", "all", detection_run, "analyst"),
    ("POST", "all", None, "analyst"),
]

# The same token is accepted when the route capability is present.
ALLOWED = [
    ("GET", "read", None, "viewer"),
    ("GET", "all", ingest_json, "viewer"),
    ("POST", "ingest", ingest_json, "ingest"),
    ("POST", "all", ingest_upload, "ingest"),
    ("POST", "triage", alert_note, "analyst"),
    ("POST", "triage", alert_status, "analyst"),
    ("POST", "triage", alert_assign, "analyst"),
    ("POST", "all", incident_status, "analyst"),
]


def other_mutation(req):
    """A POST name that is not in the bearer capability map."""
    return req


class AuthorizeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        cur = self.conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
            ("analyst", "not-a-hash", "analyst", now_iso()),
        )
        self.user_id = cur.lastrowid
        self.tokens = {
            "read": self._token("read-only", ["read"]),
            "ingest": self._token("ingest-only", ["ingest"]),
            "triage": self._token("triage-only", ["triage"]),
            "read-ingest": self._token("read-ingest", ["read", "ingest"]),
            "read-triage": self._token("read-triage", ["read", "triage"]),
            "ingest-triage": self._token("ingest-triage", ["ingest", "triage"]),
            "all": self._token("all-caps", ["read", "ingest", "triage"]),
        }
        self.session_token = "session-token-value"
        self.csrf = "csrf-token-value-aaa"
        self.conn.execute(
            "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at,"
            " sid, last_seen_at) VALUES (?,?,?,?,?,?,?)",
            (auth.sha256(self.session_token), self.user_id, self.csrf, now_iso(),
             iso(utcnow() + timedelta(hours=1)), "0123456789abcdef", now_iso()),
        )

    def _token(self, name, capabilities):
        return auth.create_api_token(self.conn, name, "admin", role="analyst", capabilities=capabilities)

    def _handler(self, command, headers):
        handler = Handler.__new__(Handler)
        handler.command = command
        handler.headers = headers
        handler.conn = self.conn
        handler.user = {"username": "preset"}
        return handler

    def test_public_role_returns_without_setting_user(self):
        headers = {
            "Authorization": f"Bearer {self.tokens['all']}",
            "Cookie": f"{SESSION_COOKIE}={self.session_token}",
            "X-CSRF-Token": self.csrf,
        }
        for command, csrf in (("GET", False), ("POST", True)):
            with self.subTest(command=command, csrf=csrf):
                handler = self._handler(command, headers)
                self.assertIsNone(handler._authorize("public", csrf, detection_run))
                self.assertIsNone(handler.user)

    def test_bearer_missing_route_capability_is_403(self):
        denied = DENIED + [("POST", "all", other_mutation, "analyst")]
        for command, key, fn, role in denied:
            name = fn.__name__ if fn else "none"
            with self.subTest(command=command, token=key, fn=name):
                handler = self._handler(command, {"Authorization": f"Bearer {self.tokens[key]}"})
                with self.assertRaises(ApiError) as caught:
                    handler._authorize(role, True, fn)
                self.assertEqual(caught.exception.status, 403)
                self.assertEqual(str(caught.exception), CAPABILITY_ERROR)

    def test_bearer_with_route_capability_sets_token_user(self):
        for command, key, fn, role in ALLOWED:
            name = fn.__name__ if fn else "none"
            with self.subTest(command=command, token=key, fn=name):
                handler = self._handler(command, {"Authorization": f"Bearer {self.tokens[key]}"})
                handler._authorize(role, True, fn)
                self.assertEqual(handler.user["via"], "token")
                self.assertEqual(handler.user["role"], "analyst")

    def test_session_post_csrf_mismatch_is_403(self):
        for sent in ("csrf-token-value-bbb", "", "forged"):
            with self.subTest(sent=sent or "<missing>"):
                handler = self._handler("POST", {
                    "Cookie": f"{SESSION_COOKIE}={self.session_token}",
                    "X-CSRF-Token": sent,
                })
                with self.assertRaises(ApiError) as caught:
                    handler._authorize("analyst", True, detection_run)
                self.assertEqual(caught.exception.status, 403)
                self.assertIn("CSRF", str(caught.exception))

        matched = self._handler("POST", {
            "Cookie": f"{SESSION_COOKIE}={self.session_token}",
            "X-CSRF-Token": self.csrf,
        })
        matched._authorize("analyst", True, detection_run)
        self.assertEqual(matched.user["via"], "session")
        self.assertEqual(matched.user["username"], "analyst")
