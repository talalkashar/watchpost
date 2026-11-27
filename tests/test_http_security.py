"""HTTP response policy, streaming credentials, and bounded diagnostic work."""

import contextlib
import io
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from tests.helpers import ServerTestCase, VIEWER_PW
from watchpost import health, simulate, stream
from watchpost.server import SECURITY_HEADERS


class HttpSecurityTests(ServerTestCase):
    def test_headers_on_secure_deployments_include_framework_errors(self):
        viewer = self.client("viewer")
        self.app.config.secure_cookies = True
        for path, method, status in (("/", "GET", 200), ("/app.js", "GET", 200),
                                     ("/api/auth/me", "GET", 401), ("/missing", "GET", 404),
                                     ("/", "HEAD", 501)):
            with self.subTest(path=path, method=method):
                req = urllib.request.Request(self.base + path, method=method)
                try:
                    response = urllib.request.urlopen(req)
                except urllib.error.HTTPError as exc:
                    response = exc
                with response:
                    self.assertEqual(response.status, status)
                    self.assertEqual(response.headers.get_all("Strict-Transport-Security"), ["max-age=31536000"])
                    for key, value in SECURITY_HEADERS.items():
                        self.assertEqual(response.headers.get_all(key), [value])
                    if status >= 400:
                        self.assertEqual(response.headers["Cache-Control"], "no-store")
        status, _, headers = self.client().post("/api/auth/login", {"username": "viewer", "password": VIEWER_PW})
        self.assertEqual(status, 200)
        flags = set(headers["Set-Cookie"].split("; ")[1:])
        self.assertTrue({"Path=/", "Secure", "HttpOnly", "SameSite=Strict"} <= flags)
        self.assertFalse(any(flag.startswith("Domain=") for flag in flags))
        with viewer.opener.open(self.base + "/api/rules/export") as response:
            self.assertIn("attachment", response.headers["Content-Disposition"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(response.headers["Strict-Transport-Security"], "max-age=31536000")
        self.app.config.secure_cookies = False
        with urllib.request.urlopen(self.base) as response:
            self.assertIsNone(response.headers["Strict-Transport-Security"])

    def test_stream_closes_after_logout_and_bearer_revocation(self):
        admin = self.client("admin")
        status, token, _ = admin.post("/api/tokens", {"name": "stream-reader", "role": "viewer",
                                                     "capabilities": ["read"]})
        self.assertEqual(status, 201)
        token_id = admin.get("/api/tokens")[1][0]["id"]
        for kind in ("session", "bearer"):
            with self.subTest(kind=kind):
                client = self.client("analyst") if kind == "session" else self.client()
                headers = {} if kind == "session" else {"Authorization": "Bearer " + token["token"]}
                request = urllib.request.Request(self.base + "/api/stream", headers=headers)
                with client.opener.open(request, timeout=5) as response:
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    for key, value in SECURITY_HEADERS.items():
                        self.assertEqual(response.headers.get_all(key), [value])
                    for _ in range(2):  # hello and initial health
                        while (line := response.readline()) and line != b"\n":
                            pass
                        self.assertTrue(line)
                    if kind == "session":
                        self.assertEqual(client.post("/api/auth/logout")[0], 200)
                    else:
                        self.assertEqual(admin.post(f"/api/tokens/{token_id}/revoke")[0], 200)
                    stream.BROKER.publish("health", {"partial": True})
                    self.assertEqual(response.readline(), b"")

    def test_public_probes_are_coalesced_and_refresh_after_expiry(self):
        snapshot = self.app.health_snapshot
        with patch.object(health, "_builtin_checks", wraps=health._builtin_checks) as checks:
            with ThreadPoolExecutor(max_workers=2) as pool:
                reports = list(pool.map(lambda _: snapshot.report(), range(2)))
            self.assertEqual(reports[0]["status"], reports[1]["status"])
            self.assertEqual(checks.call_count, 1)
            snapshot.expires = 0
            snapshot.report()
            self.assertEqual(checks.call_count, 2)

    def test_simulator_keeps_batches_at_configured_https_destination(self):
        handler = simulate.NoIngestRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://example.invalid/"))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit), \
                patch("urllib.request.build_opener", side_effect=AssertionError("transport opened")):
            simulate.main(["--url", "http://example.invalid", "--allow-remote", "--token", "test"])
