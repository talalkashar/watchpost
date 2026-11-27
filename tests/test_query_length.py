"""A query string longer than 8192 bytes is 414 before parse_qs.

The hunt query cap (500 characters) runs only after the parameters are parsed.
A longer request line must not be parsed in full to reach that check.
"""

import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs as real_parse_qs

from tests.helpers import ServerTestCase
from watchpost.server import MAX_QUERY_BYTES, ApiError, query_params

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
AT_LIMIT = "q=" + ("a" * (MAX_QUERY_BYTES - 2))
OVER_LIMIT = "q=" + ("a" * (MAX_QUERY_BYTES - 1))


class QueryLengthTests(unittest.TestCase):
    def test_over_the_limit_is_414_before_parse_qs(self):
        self.assertEqual(len(OVER_LIMIT), MAX_QUERY_BYTES + 1)
        with patch("watchpost.server.parse_qs") as parse:
            with self.assertRaises(ApiError) as caught:
                query_params(OVER_LIMIT)
        self.assertEqual(caught.exception.status, 414)
        self.assertEqual(str(caught.exception), f"query string exceeds {MAX_QUERY_BYTES} bytes")
        parse.assert_not_called()

    def test_exactly_8192_bytes_is_parsed(self):
        self.assertEqual(len(AT_LIMIT), MAX_QUERY_BYTES)
        with patch("watchpost.server.parse_qs", wraps=real_parse_qs) as parse:
            params = query_params(AT_LIMIT)
        parse.assert_called_once_with(AT_LIMIT)
        self.assertEqual(params, {"q": "a" * (MAX_QUERY_BYTES - 2)})

    def test_api_docs_name_the_maximum(self):
        text = API.read_text()
        self.assertIn("longer than 8192 bytes is 414 `query string exceeds 8192 bytes`", text)
        self.assertIn("before the parameters are parsed", text)


class QueryLengthApiTests(ServerTestCase):
    def test_hunt_over_the_limit_is_414_not_the_hunt_cap(self):
        client = self.client("viewer")
        status, data, headers = client.get("/api/hunt?" + OVER_LIMIT)
        self.assertEqual(status, 414)
        self.assertEqual(data["error"], f"query string exceeds {MAX_QUERY_BYTES} bytes")
        self.assertNotIn("500", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, _ = client.get("/api/hunt?" + AT_LIMIT)
        self.assertEqual(status, 400, data)
        self.assertIn("500", data["error"])

    def test_a_public_query_at_the_limit_still_runs(self):
        pad = "x=" + ("y" * (MAX_QUERY_BYTES - 2))
        self.assertEqual(len(pad), MAX_QUERY_BYTES)
        status, data, _ = self.client().get("/api/health?" + pad)
        self.assertEqual(status, 200, data)
        self.assertIn(data["status"], ("ok", "degraded", "failing"))

        status, data, headers = self.client().get("/api/health?" + pad + "y")
        self.assertEqual(status, 414)
        self.assertEqual(data["error"], f"query string exceeds {MAX_QUERY_BYTES} bytes")
        self.assertEqual(headers["Cache-Control"], "no-store")
