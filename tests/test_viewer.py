"""The read-only `viewer` role (Watchpost 2.0 / F): allowed reads, denied writes, and account seeding."""

import os
import re
import sqlite3
import tempfile
import unittest
import urllib.error
import urllib.request

from tests.helpers import VIEWER_PW, ServerTestCase
from watchpost import auth, server
from watchpost.config import Config
from watchpost.db import connect, init_schema

# Sample values for the capture groups in route patterns, tried in order until one matches.
GROUP_SAMPLES = ["1", "brute_force_ip", "login_lockout_threshold", "md"]
# Non-GET routes a viewer may call.
VIEWER_POSTS = {"/api/auth/login", "/api/auth/logout"}


def sample_path(pattern):
    """Turn a route regex like ^/api/alerts/(\\d+)/report\\.(md|pdf)$ into a concrete path."""
    source = pattern.pattern.strip("^$")
    groups = re.findall(r"\([^()]*\)", source)
    path = source
    for group in groups:
        value = next(v for v in GROUP_SAMPLES if re.fullmatch(group, v))
        path = path.replace(group, value, 1)
    path = path.replace("\\.", ".")
    assert pattern.match(path), (pattern.pattern, path)
    return path


class ViewerAccessTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.client("admin").post("/api/demo/load")[0], 200)
        self.viewer = self.client("viewer")

    def get_raw(self, client, path):
        req = urllib.request.Request(self.base + path)
        try:
            with client.opener.open(req, timeout=30) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), (b"" if path == "/api/stream" else resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers.get("Content-Type", ""), exc.read()

    def test_viewer_account_is_seeded_from_env(self):
        status, me, _ = self.viewer.get("/api/auth/me")
        self.assertEqual((status, me["user"]), (200, {"username": "viewer", "role": "viewer"}))

    def test_viewer_is_allowed_on_every_read_route(self):
        for method, pattern, _fn, role, _csrf in server.ROUTES:
            if method != "GET":
                continue
            path = sample_path(pattern)
            with self.subTest(path=path, role=role):
                status, ctype, _ = self.get_raw(self.viewer, path)
                if role in ("public", "viewer"):
                    self.assertEqual(status, 200, path)
                else:
                    self.assertEqual(status, 403, path)

    def test_named_read_routes(self):
        incident = self.viewer.get("/api/incidents")[1][0]["id"]
        alert = self.viewer.get("/api/alerts")[1][0]["id"]
        for path in ["/api/dashboard", "/api/events", "/api/alerts", f"/api/alerts/{alert}", "/api/incidents",
                     f"/api/incidents/{incident}", "/api/attack/coverage", "/api/health", "/api/health/details",
                     "/api/metrics", "/api/rules", "/api/geo?ips=203.0.113.45"]:
            with self.subTest(path=path):
                self.assertEqual(self.viewer.get(path)[0], 200)
        for path in [f"/api/incidents/{incident}/report.pdf", f"/api/incidents/{incident}/report.md",
                     f"/api/alerts/{alert}/report.pdf", f"/api/alerts/{alert}/report.md"]:
            with self.subTest(path=path):
                self.assertEqual(self.get_raw(self.viewer, path)[0], 200)
        status, ctype, _ = self.get_raw(self.viewer, "/api/stream")
        self.assertEqual((status, ctype.split(";")[0]), (200, "text/event-stream"))
        for path in ["/api/tokens", "/api/audit"]:
            with self.subTest(path=path):
                self.assertEqual(self.viewer.get(path)[0], 403)

    def test_viewer_is_denied_on_every_mutating_route(self):
        with sqlite3.connect(self.db_path) as db:
            before = [db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                      for t in ("events", "alert_notes", "change_requests", "api_tokens", "evaluation_runs", "rule_history")]
            states = db.execute("SELECT status FROM alerts ORDER BY id").fetchall() + \
                db.execute("SELECT status FROM incidents ORDER BY id").fetchall()
        posts = [(sample_path(p), fn) for m, p, fn, _r, _c in server.ROUTES if m == "POST"]
        self.assertGreaterEqual(len(posts), 15)
        body = {"status": "resolved", "disposition": "true_positive", "body": "x", "name": "x", "value": 6,
                "reason": "x", "decision": "approve", "scenario": "brute_force", "force": True, "events": []}
        for path, _fn in posts:
            if path in VIEWER_POSTS:
                continue
            with self.subTest(path=path):
                status, data, _ = self.viewer.post(path, body)
                self.assertEqual(status, 403, (path, data))
        # Upload takes a raw body; it is refused before the body is parsed.
        status, _, _ = self.viewer.post("/api/ingest/upload?format=authlog", raw=b"x",
                                        headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 403)
        with sqlite3.connect(self.db_path) as db:
            after = [db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                     for t in ("events", "alert_notes", "change_requests", "api_tokens", "evaluation_runs", "rule_history")]
            self.assertEqual(after, before)
            self.assertEqual(db.execute("SELECT status FROM alerts ORDER BY id").fetchall() +
                             db.execute("SELECT status FROM incidents ORDER BY id").fetchall(), states)
        # Logout still works for a viewer.
        self.assertEqual(self.viewer.post("/api/auth/logout")[0], 200)
        self.assertEqual(self.viewer.get("/api/auth/me")[0], 401)

    def test_read_only_backstop_covers_routes_without_an_explicit_role(self):
        @server.route("POST", "/api/test-only-write")  # default role is "viewer"
        def test_only_write(req):
            return {"wrote": True}
        try:
            status, data, _ = self.viewer.post("/api/test-only-write")
            self.assertEqual((status, data["error"]), (403, "viewer accounts are read-only"))
            self.assertEqual(self.client("analyst").post("/api/test-only-write")[1], {"wrote": True})
        finally:
            server.ROUTES[:] = [r for r in server.ROUTES if r[2] is not test_only_write]


class ViewerSeedingTests(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = connect(os.path.join(self.tmp.name, "t.db"))
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def config(self, **kw):
        return Config.from_env(db_path=":memory:", admin_password="admin-password-123",
                               analyst_password="analyst-password-123", **kw)

    def users(self):
        return dict(self.conn.execute("SELECT username, role FROM users").fetchall())

    def test_no_viewer_without_env(self):
        auth.bootstrap_users(self.conn, self.config(viewer_password=None), self.tmp.name)
        self.assertEqual(self.users(), {"admin": "admin", "analyst": "analyst"})

    def test_viewer_created_on_first_start_and_on_existing_database(self):
        auth.bootstrap_users(self.conn, self.config(viewer_password=None), self.tmp.name)
        auth.bootstrap_users(self.conn, self.config(viewer_password=VIEWER_PW), self.tmp.name)
        self.assertEqual(self.users()["viewer"], "viewer")
        auth.login(self.conn, "viewer", VIEWER_PW, 60)

    def test_existing_viewer_password_is_not_reset(self):
        auth.bootstrap_users(self.conn, self.config(viewer_password=VIEWER_PW), self.tmp.name)
        auth.bootstrap_users(self.conn, self.config(viewer_password="a-different-password"), self.tmp.name)
        auth.login(self.conn, "viewer", VIEWER_PW, 60)
        with self.assertRaises(auth.AuthError):
            auth.login(self.conn, "viewer", "a-different-password", 60)

    def test_weak_viewer_password_is_refused(self):
        with self.assertRaises(auth.AuthError):
            auth.bootstrap_users(self.conn, self.config(viewer_password="short"), self.tmp.name)


if __name__ == "__main__":
    unittest.main()
