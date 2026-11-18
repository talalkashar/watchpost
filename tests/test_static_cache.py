"""Static 404 and 405 send Cache-Control no-store. A file that exists stays no-cache."""

import json
import urllib.error
import urllib.request
from pathlib import Path

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


class StaticCacheTests(ServerTestCase):
    def _open(self, path, method="GET"):
        data = b"" if method == "POST" else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
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

    def test_api_docs_name_the_static_cache_headers(self):
        text = API.read_text()
        self.assertIn("missing static file is 404 `not found` (`text/plain`)", text)
        self.assertIn('non-GET on a static path is 405 `{"error": "method not allowed"}`', text)
        self.assertIn("Both send `Cache-Control: no-store`", text)
        self.assertIn("stays `Cache-Control: no-cache`", text)
