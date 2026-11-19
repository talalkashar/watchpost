"""TOTP verify accepts six ASCII digits only.

An ASCII code still verifies. １２３４５６ returns None because it is not six
ASCII digits, before HMAC. The fullwidth spelling of a real code does not
match. No new acceptance.
"""

import inspect
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import ANALYST_PW, Client, ServerTestCase
from tests.test_mfa import RFC_SECRET, Clock
from watchpost import totp

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
FULLWIDTH = "\uff11\uff12\uff13\uff14\uff15\uff16"  # １２３４５６
WHEN = 59


def _fullwidth(text):
    return "".join(chr(ord(ch) + 0xFEE0) for ch in text)


class TotpCodeDigitTests(unittest.TestCase):
    def test_ascii_code_verifies_and_fullwidth_returns_before_hmac(self):
        code = totp.code_at(RFC_SECRET, WHEN)
        self.assertTrue(code.isascii() and code.isdigit() and len(code) == 6)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=WHEN), totp.step_at(WHEN))
        self.assertEqual(totp.verify(RFC_SECRET, f" {code[:3]} {code[3:]} ", timestamp=WHEN), totp.step_at(WHEN))

        def boom(*_args, **_kwargs):
            raise AssertionError("hmac")

        with mock.patch("watchpost.totp.hmac.new", side_effect=boom):
            with mock.patch("watchpost.totp.hmac.compare_digest", side_effect=boom):
                self.assertIsNone(totp.verify(RFC_SECRET, FULLWIDTH, timestamp=WHEN))
                self.assertIsNone(totp.verify(RFC_SECRET, _fullwidth(code), timestamp=WHEN))

    def test_check_is_ascii_digits_before_hmac(self):
        source = inspect.getsource(totp.verify)
        self.assertLess(source.index("isascii()"), source.index("compare_digest"))
        self.assertLess(source.index("isascii()"), source.index("decode_secret"))
        self.assertIn("isdigit()", source)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("six ASCII digits", text)
            self.assertIn("An ASCII code still verifies", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn("not compared with HMAC", text)


class TotpCodeDigitApiTests(ServerTestCase):
    def config_overrides(self):
        return {"rate_limit_enabled": False}

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.patcher = mock.patch.object(totp, "now", self.clock)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        super().tearDown()

    def _enroll(self):
        analyst = self.client("analyst")
        status, data, _ = analyst.post("/api/auth/mfa/enroll")
        self.assertEqual(status, 200, data)
        self.clock.advance()
        code = totp.code_at(data["secret"], self.clock())
        status, body, _ = analyst.post("/api/auth/mfa/confirm", {"code": code})
        self.assertEqual(status, 200, body)
        self.clock.advance()
        return data["secret"]

    def test_fullwidth_code_is_401_and_ascii_code_signs_in(self):
        secret = self._enroll()
        client = Client(self.base)
        status, body, _ = client.post("/api/auth/login", {"username": "analyst", "password": ANALYST_PW})
        self.assertEqual(status, 200, body)
        token = body["mfa_token"]
        code = totp.code_at(secret, self.clock())

        def boom(*_args, **_kwargs):
            raise AssertionError("hmac")

        with mock.patch("watchpost.totp.hmac.new", side_effect=boom):
            status, refused, headers = client.post("/api/auth/mfa", {"mfa_token": token, "code": FULLWIDTH})
        self.assertEqual(status, 401, refused)
        self.assertEqual(refused["error"], "invalid authentication code")
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(client.get("/api/alerts")[0], 401)

        status, signed, headers = client.post("/api/auth/mfa", {"mfa_token": token, "code": code})
        self.assertEqual(status, 200, signed)
        self.assertIn("wp_session=", headers["Set-Cookie"])
        self.assertEqual(client.get("/api/alerts")[0], 200)
