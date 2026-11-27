"""A repeated query key is 400 naming that key. parse_qs would keep only the first value."""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.server import ApiError, query_params

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
SENTENCE = ("A repeated key (`severity=low&severity=critical`) is 400 "
            "`repeated query key 'severity'`.")


class RepeatedQueryKeyTests(unittest.TestCase):
    def test_a_repeated_key_names_that_key(self):
        with self.assertRaises(ApiError) as caught:
            query_params("severity=low&severity=critical")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(str(caught.exception), "repeated query key 'severity'")

    def test_the_same_value_twice_is_still_repeated(self):
        with self.assertRaises(ApiError) as caught:
            query_params("status=open&status=open")
        self.assertEqual(str(caught.exception), "repeated query key 'status'")

    def test_two_repeated_keys_name_the_earlier_one(self):
        with self.assertRaises(ApiError) as caught:
            query_params("limit=1&severity=low&limit=2&severity=critical")
        self.assertEqual(str(caught.exception), "repeated query key 'limit'")

    def test_a_percent_encoded_repeat_uses_the_decoded_name(self):
        with self.assertRaises(ApiError) as caught:
            query_params("seve%72ity=low&severity=critical")
        self.assertEqual(str(caught.exception), "repeated query key 'severity'")

    def test_one_value_and_a_comma_list_pass_through(self):
        self.assertEqual(query_params("severity=critical,high&status=open"),
                         {"severity": "critical,high", "status": "open"})
        self.assertEqual(query_params(""), {})
        self.assertEqual(query_params("severity=low"), {"severity": "low"})

    def test_api_docs_name_the_repeated_key_error(self):
        self.assertIn(SENTENCE, API.read_text())


class RepeatedQueryApiTests(ServerTestCase):
    def test_the_api_refuses_a_repeated_key_and_keeps_one_value(self):
        status, data, headers = self.client().get("/api/health?severity=low&severity=critical")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "repeated query key 'severity'")
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, _ = self.client().get("/api/health?severity=critical")
        self.assertEqual(status, 200)
        self.assertIn(data["status"], ("ok", "degraded", "failing"))
