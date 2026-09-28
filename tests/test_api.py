import json
import sqlite3
import unittest
from datetime import timedelta

from tests.helpers import ADMIN_PW, ServerTestCase
from watchpost.db import iso, utcnow


def recent(minutes_ago=30):
    return iso(utcnow() - timedelta(minutes=minutes_ago))


class AuthTests(ServerTestCase):
    def test_protected_endpoints_require_login(self):
        anon = self.client()
        for path in ["/api/events", "/api/alerts", "/api/metrics", "/api/rules", "/api/health/details"]:
            with self.subTest(path=path):
                self.assertEqual(anon.get(path)[0], 401)
        self.assertEqual(anon.post("/api/ingest", [])[0], 401)

    def test_public_health_hides_details(self):
        status, data, headers = self.client().get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(set(data["checks"]), {"storage", "ingestion", "detection", "dependencies"})
        self.assertNotIn("details", json.dumps(data))
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_login_cookie_flags_and_logout(self):
        c = self.client()
        status, data, headers = c.post("/api/auth/login", {"username": "admin", "password": ADMIN_PW})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        c.csrf = data["csrf_token"]
        self.assertEqual(c.get("/api/auth/me")[1]["user"]["role"], "admin")
        self.assertEqual(c.post("/api/auth/logout")[0], 200)
        self.assertEqual(c.get("/api/auth/me")[0], 401)

    def test_wrong_password_and_unknown_user_look_the_same(self):
        c = self.client()
        s1, d1 = c.login("admin", "wrong-password-123")
        s2, d2 = c.login("nobody", "wrong-password-123")
        self.assertEqual((s1, d1), (s2, d2))
        self.assertEqual(s1, 401)

    def test_lockout_after_repeated_failures(self):
        c = self.client()
        for _ in range(5):
            c.login("admin", "wrong-password-123")
        status, data = c.login("admin", ADMIN_PW)
        self.assertEqual(status, 429)
        self.assertIn("locked", data["error"])

    def test_csrf_required_for_session_posts(self):
        c = self.client("analyst")
        c.csrf = "forged"
        status, data, _ = c.post("/api/detection/run")
        self.assertEqual(status, 403)
        self.assertIn("CSRF", data["error"])

    def test_role_enforcement(self):
        analyst = self.client("analyst")
        for path, body in [("/api/tokens", {"name": "x"}), ("/api/demo/load", {}),
                           ("/api/changes/1/review", {"decision": "approve"}),
                           ("/api/settings/login_lockout_threshold/proposals", {"value": 6, "reason": "tighten"})]:
            with self.subTest(path=path):
                self.assertEqual(analyst.post(path, body)[0], 403)
        self.assertEqual(analyst.get("/api/audit")[0], 403)

        with sqlite3.connect(self.db_path) as db:
            from watchpost.auth import hash_password
            db.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES "
                       "('viewer1', ?, 'viewer', '2026-01-01')", (hash_password("viewer-password-1"),))
        viewer = self.client()
        self.assertEqual(viewer.login("viewer1", "viewer-password-1")[0], 200)
        self.assertEqual(viewer.get("/api/alerts")[0], 200)
        self.assertEqual(viewer.post("/api/ingest", [{"ts": recent()}])[0], 403)
        self.assertEqual(viewer.post("/api/alerts/1/notes", {"body": "x"})[0], 403)

    def test_api_token_lifecycle(self):
        admin = self.client("admin")
        status, data, _ = admin.post("/api/tokens", {"name": "collector"})
        self.assertEqual(status, 201)
        token = data["token"]
        bot = self.client()
        auth = {"Authorization": f"Bearer {token}"}
        status, result, _ = bot.post("/api/ingest", [{"ts": recent(), "type": "login"}], headers=auth)
        self.assertEqual(status, 201)
        self.assertEqual(result["accepted"], 1)
        # Tokens are ingest-only.
        self.assertEqual(bot.get("/api/events", headers=auth)[0], 403)
        # Only a hash is stored.
        with sqlite3.connect(self.db_path) as db:
            stored = db.execute("SELECT token_hash, prefix, last_used_at FROM api_tokens").fetchone()
        self.assertNotEqual(stored[0], token)
        self.assertIsNotNone(stored[2])
        token_id = admin.get("/api/tokens")[1][0]["id"]
        self.assertEqual(admin.post(f"/api/tokens/{token_id}/revoke")[0], 200)
        self.assertEqual(bot.post("/api/ingest", [{"ts": recent()}], headers=auth)[0], 401)
        self.assertEqual(bot.post("/api/ingest", [{"ts": recent()}], headers={"Authorization": "Bearer wp_x"})[0], 401)

    def test_static_files_and_traversal(self):
        import urllib.request
        with urllib.request.urlopen(self.base + "/") as resp:
            self.assertIn(b"Watchpost", resp.read())
        c = self.client()
        for path in ["/../watchpost/config.py", "/%2e%2e/watchpost/config.py", "/nope.js"]:
            with self.subTest(path=path):
                req = urllib.request.Request(self.base + path)
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 404)
        self.assertEqual(c.get("/api/nope")[0], 404)


class IngestTests(ServerTestCase):
    def test_partial_batch_reports_rejections(self):
        c = self.client("analyst")
        status, data, _ = c.post("/api/ingest", {"source": "fw01", "events": [
            {"ts": recent(), "type": "login_failed", "user": "a", "src_ip": "10.0.0.1"},
            {"ts": "garbage"},
            {"ts": recent(), "src_ip": "300.1.1.1"},
        ]})
        self.assertEqual(status, 207)
        self.assertEqual((data["accepted"], data["rejected"]), (1, 2))
        self.assertEqual(data["detection"]["status"], "ok")
        batches = c.get("/api/ingest/batches")[1]
        self.assertEqual(batches[0]["source"], "fw01")
        self.assertEqual(len(batches[0]["errors"]), 2)

    def test_all_rejected_is_422_and_bad_requests_are_400(self):
        c = self.client("analyst")
        self.assertEqual(c.post("/api/ingest", [{"ts": "bad"}])[0], 422)
        self.assertEqual(c.post("/api/ingest", raw=b"{not json", headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(c.post("/api/ingest", raw=b"[]", headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(c.post("/api/ingest", {"source": "bad source", "events": []})[0], 400)
        self.assertEqual(c.post("/api/ingest/upload", raw=b"", headers={"Content-Type": "text/plain"})[0], 400)
        self.assertEqual(c.post("/api/ingest/upload?format=authlog", raw=b"\xff\xfe",
                                headers={"Content-Type": "text/plain"})[0], 400)

    def test_body_size_limit(self):
        self.app.config.max_upload_bytes = 1000
        c = self.client("analyst")
        status, data, _ = c.post("/api/ingest/upload", raw=b"x" * 2000, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 413)

    def test_authlog_upload_detects_brute_force(self):
        c = self.client("analyst")
        now = utcnow() - timedelta(hours=1)
        lines = [f"{iso(now + timedelta(seconds=i))} web01 sshd[1]: Failed password for root from 203.0.113.99 "
                 f"port 22 ssh2" for i in range(12)]
        status, data, _ = c.post("/api/ingest/upload?format=authlog&source=web01-auth",
                                 raw="\n".join(lines).encode(), headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 201, data)
        self.assertEqual(data["accepted"], 12)
        self.assertGreaterEqual(data["detection"]["alerts_created"], 1)
        alerts = c.get("/api/alerts?rule_id=brute_force_ip")[1]
        self.assertEqual(alerts[0]["group_key"], "203.0.113.99")
        self.assertEqual(alerts[0]["synthetic"], 0)

    def test_repeat_ingest_extends_open_alert_instead_of_duplicating(self):
        c = self.client("analyst")
        start = utcnow() - timedelta(hours=1)
        batch = lambda offset: [{"ts": iso(start + timedelta(seconds=offset + i)), "type": "login_failed",
                                 "user": "x", "src_ip": "192.0.2.50"} for i in range(10)]
        c.post("/api/ingest", batch(0))
        second = c.post("/api/ingest", batch(20))[1]
        self.assertEqual(second["detection"]["alerts_created"], 0)
        self.assertGreaterEqual(second["detection"]["alerts_updated"], 1)
        alerts = c.get("/api/alerts?rule_id=brute_force_ip")[1]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 20)
        # A full rescan does not create duplicates either.
        rescan = c.post("/api/detection/run")[1]
        self.assertEqual((rescan["status"], rescan["alerts_created"], rescan["alerts_updated"]), ("ok", 0, 0))


class SearchTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.c = self.client("analyst")
        base = utcnow() - timedelta(hours=2)
        self.c.post("/api/ingest", {"source": "vpn", "events": [
            {"ts": iso(base), "type": "login_failed", "user": "Alice", "src_ip": "10.0.0.1", "message": "bad pw 50%"},
            {"ts": iso(base + timedelta(minutes=10)), "type": "login", "user": "bob", "src_ip": "10.0.0.2",
             "severity": "high"},
            {"ts": iso(base + timedelta(minutes=20)), "type": "process", "host": "db01", "dest_ip": "10.0.0.1"},
        ]})
        self.base_ts = base

    def total(self, query):
        status, data, _ = self.c.get("/api/events?" + query)
        self.assertEqual(status, 200, data)
        return data["total"]

    def test_filters(self):
        self.assertEqual(self.total(""), 3)
        self.assertEqual(self.total("user=alice"), 1)  # case-insensitive
        self.assertEqual(self.total("ip=10.0.0.1"), 2)  # matches src or dest
        self.assertEqual(self.total("event_type=auth_failure"), 1)
        self.assertEqual(self.total("severity=high"), 1)
        self.assertEqual(self.total("severity=low&severity_mode=min"), 2)
        self.assertEqual(self.total("source=vp*"), 3)
        self.assertEqual(self.total("host=db01"), 1)
        self.assertEqual(self.total("q=50%25"), 1)
        self.assertEqual(self.total("q=%25"), 1)  # literal percent, not a wildcard
        start = iso(self.base_ts + timedelta(minutes=5))
        self.assertEqual(self.total(f"start={start}"), 2)
        self.assertEqual(self.total(f"end={start}"), 1)
        self.assertEqual(self.total("synthetic=1"), 0)

    def test_pagination_and_validation(self):
        data = self.c.get("/api/events?limit=2&offset=2")[1]
        self.assertEqual((data["total"], len(data["events"])), (3, 1))
        for query in ["limit=0", "limit=abc", "severity=urgent", "event_type=x", "start=notadate"]:
            with self.subTest(query=query):
                self.assertEqual(self.c.get("/api/events?" + query)[0], 400)

    def test_sql_injection_attempts_are_inert(self):
        from urllib.parse import quote
        self.assertEqual(self.total("user=" + quote("' OR '1'='1")), 0)
        self.assertEqual(self.total("q=" + quote("'; DROP TABLE events;--")), 0)
        self.assertEqual(self.total(""), 3)

    def test_event_detail(self):
        event_id = self.c.get("/api/events?limit=1")[1]["events"][0]["id"]
        status, data, _ = self.c.get(f"/api/events/{event_id}")
        self.assertEqual(status, 200)
        self.assertIn("raw", data)
        self.assertEqual(self.c.get("/api/events/999999")[0], 404)


if __name__ == "__main__":
    unittest.main()
