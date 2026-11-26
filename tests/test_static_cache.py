"""Static 404 and 405 send Cache-Control no-store. A file that exists stays no-cache."""

import gzip
import json
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from tests.helpers import ServerTestCase
from watchpost.health import STATIC_DIR

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


class StaticCacheTests(ServerTestCase):
    def _open(self, path, method="GET", headers=None):
        data = b"" if method == "POST" else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read(), exc.headers

    def test_missing_file_and_wrong_method_are_not_stored(self):
        status, body, headers = self._open("/nope.js")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"not found")
        self.assertEqual(headers["Content-Type"], "text/plain")
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, body, headers = self._open("/../watchpost/config.py")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"not found")
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, body, headers = self._open("/style.css", method="POST")
        self.assertEqual(status, 405)
        self.assertEqual(json.loads(body), {"error": "method not allowed"})
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_a_real_file_stays_no_cache(self):
        status, body, headers = self._open("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Watchpost", body)
        self.assertEqual(headers["Cache-Control"], "no-cache")

        status, body, headers = self._open("/robots.txt")
        self.assertEqual(status, 200)
        self.assertTrue(body)
        self.assertEqual(headers["Cache-Control"], "no-cache")

    def test_console_styles_preserve_cascade_as_one_encoded_response(self):
        sheets = ("style.css", "views.css", "glass.css", "orbit.css", "declutter.css", "graph.css")
        expected = b"\n".join((STATIC_DIR / name).read_bytes() for name in sheets)
        status, body, headers = self._open("/console.css", headers={"Accept-Encoding": "br, gzip"})
        self.assertEqual(status, 200)
        self.assertEqual(gzip.decompress(body), expected)
        self.assertLess(len(body), len(expected))
        self.assertEqual(headers["Vary"], "Accept-Encoding")
        self.assertEqual(headers["Content-Encoding"], "gzip")
        self.assertTrue(headers["Content-Type"].startswith("text/css"))

    def test_conditional_requests_match_the_selected_representation(self):
        _, body, headers = self._open("/app.js", headers={"Accept-Encoding": "gzip"})
        etag = headers["ETag"]
        for validator in (etag, f'"old", W/{etag}', "*"):
            status, empty, cached = self._open("/app.js", headers={
                "Accept-Encoding": "gzip", "If-None-Match": validator})
            self.assertEqual((status, empty), (304, b""))
            self.assertEqual(cached["ETag"], etag)
            self.assertEqual(cached["Vary"], "Accept-Encoding")
        status, raw, headers = self._open("/app.js", headers={
            "Accept-Encoding": "*;q=1, gzip;q=0", "If-None-Match": etag})
        self.assertEqual(status, 200)
        self.assertIsNone(headers["Content-Encoding"])
        self.assertNotEqual(headers["ETag"], etag)
        self.assertEqual(raw, gzip.decompress(body))

    def test_bundle_revalidates_when_a_source_changes(self):
        root = Path(self.tmp.name)
        source = root / "style.css"
        source.write_bytes(b"body { color: black }")
        with patch("watchpost.server.STATIC_DIR", root), patch(
                "watchpost.static_assets.CONSOLE_STYLES", ("style.css",)):
            _, _, first = self._open("/console.css")
            source.write_bytes(b"body { color: white }")
            status, body, second = self._open("/console.css", headers={"If-None-Match": first["ETag"]})
        self.assertEqual((status, body), (200, b"body { color: white }"))
        self.assertNotEqual(first["ETag"], second["ETag"])

    def test_texture_revalidation_skips_the_body(self):
        path = "/textures/earth-night-1024.webp"
        _, _, headers = self._open(path, headers={"Accept-Encoding": "gzip"})
        self.assertIsNone(headers["Content-Encoding"])
        status, body, _ = self._open(path, headers={"If-None-Match": headers["ETag"]})
        self.assertEqual((status, body), (304, b""))

    def test_api_docs_name_the_static_cache_headers(self):
        text = API.read_text()
        self.assertIn("missing static file is 404 `not found` (`text/plain`)", text)
        self.assertIn('non-GET on a static path is 405 `{"error": "method not allowed"}`', text)
        self.assertIn("Both send `Cache-Control: no-store`", text)
        self.assertIn("stays `Cache-Control: no-cache`", text)
