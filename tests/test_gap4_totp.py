"""Edge cases for watchpost.totp that TotpTests does not assert.

Covers secret normalization, step boundaries, the RFC 4226 counter-0 code,
code whitespace, the default clock, and username quoting in the otpauth URI.
"""

import base64
import binascii
import unittest
from unittest import mock

from watchpost import totp

RFC_KEY = b"12345678901234567890"  # RFC 4226 / RFC 6238 SHA-1 seed
RFC_SECRET = base64.b32encode(RFC_KEY).decode().rstrip("=")


class TotpGapTests(unittest.TestCase):
    def test_decode_secret_normalizes_case_spaces_and_padding(self):
        raw = b"a"
        padded = base64.b32encode(raw).decode()
        self.assertIn("=", padded)
        unpadded = padded.rstrip("=")
        grouped = " ".join(unpadded[i:i + 4] for i in range(0, len(unpadded), 4))
        for text in (unpadded, padded, unpadded.lower(), grouped, f"  {grouped.lower()}  "):
            with self.subTest(text=text):
                self.assertEqual(totp.decode_secret(text), raw)
        self.assertEqual(totp.decode_secret(""), b"")
        self.assertEqual(totp.decode_secret("   "), b"")
        # code_at goes through the same decoder, so a pasted secret still matches.
        messy = " ".join(RFC_SECRET[i:i + 4] for i in range(0, len(RFC_SECRET), 4)).lower()
        when = 1_111_111_111
        self.assertEqual(totp.code_at(messy, when), totp.code_at(RFC_SECRET, when))

    def test_decode_secret_rejects_non_base32(self):
        for bad in ("1", "!!!!", "===="):
            with self.subTest(bad=bad):
                with self.assertRaises(binascii.Error):
                    totp.decode_secret(bad)

    def test_step_at_uses_floor_division_at_the_boundaries(self):
        self.assertEqual(totp.step_at(0), 0)
        self.assertEqual(totp.step_at(29.999), 0)
        self.assertEqual(totp.step_at(30), 1)
        self.assertEqual(totp.step_at(59.9), 1)
        self.assertEqual(totp.step_at(60), 2)
        # Floor, not truncation toward zero: -31 // 30 is -2.
        self.assertEqual(totp.step_at(-1), -1)
        self.assertEqual(totp.step_at(-30), -1)
        self.assertEqual(totp.step_at(-31), -2)
        self.assertEqual(totp.code_at(RFC_SECRET, 30), totp.code_at(RFC_SECRET, 59.9))
        self.assertNotEqual(totp.code_at(RFC_SECRET, 59.9), totp.code_at(RFC_SECRET, 60))

    def test_hotp_counter_zero_matches_rfc4226(self):
        # Appendix D, 6 digits. The TOTP vectors start at time 59, which is counter 1.
        self.assertEqual(totp.hotp(RFC_KEY, 0), "755224")
        # Wider output is the 31-bit truncation modulo 10**digits (1284755224 % 10**8),
        # not the 6-digit code with leading zeros.
        self.assertEqual(totp.hotp(RFC_KEY, 0, digits=8), "84755224")
        # The first timestamp whose drift window includes counter 0 without going negative.
        self.assertEqual(totp.verify(RFC_SECRET, "755224", timestamp=30), 0)

    def test_verify_strips_spaces_and_reads_now_when_timestamp_is_omitted(self):
        when = 59
        code = totp.code_at(RFC_SECRET, when)
        self.assertEqual(totp.verify(RFC_SECRET, f"  {code[:3]} {code[3:]} \n", timestamp=when), 1)
        messy = " ".join(RFC_SECRET.lower()[i:i + 4] for i in range(0, len(RFC_SECRET), 4))
        self.assertEqual(totp.verify(messy, code, timestamp=when), 1)
        # Spaces are removed before the length check, so a short code stays short.
        self.assertIsNone(totp.verify(RFC_SECRET, "12 345", timestamp=when))
        self.assertIsNone(totp.verify(RFC_SECRET, "   ", timestamp=when))
        with mock.patch.object(totp, "now", return_value=float(when)):
            self.assertEqual(totp.verify(RFC_SECRET, code), totp.step_at(when))

    @unittest.expectedFailure
    def test_verify_at_step_zero_does_not_walk_a_negative_counter(self):
        # timestamp in [0, 30) is step 0. Drift also tries step -1, and struct.pack(">Q", -1) raises.
        code = totp.code_at(RFC_SECRET, 0)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=0), 0)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=29), 0)

    def test_otpauth_uri_quotes_reserved_characters_in_the_username(self):
        secret = "SECRET"
        self.assertEqual(
            totp.otpauth_uri("Ada Lovelace", secret),
            "otpauth://totp/Watchpost:Ada%20Lovelace?secret=SECRET&issuer=Watchpost",
        )
        self.assertEqual(
            totp.otpauth_uri("a@b", secret),
            "otpauth://totp/Watchpost:a%40b?secret=SECRET&issuer=Watchpost",
        )
        self.assertEqual(
            totp.otpauth_uri("a&b", secret),
            "otpauth://totp/Watchpost:a%26b?secret=SECRET&issuer=Watchpost",
        )
        self.assertEqual(
            totp.otpauth_uri("", secret),
            "otpauth://totp/Watchpost:?secret=SECRET&issuer=Watchpost",
        )

    @unittest.expectedFailure
    def test_otpauth_uri_percent_encodes_a_slash_in_the_username(self):
        # quote() keeps "/" safe, so the label becomes an extra path segment.
        self.assertEqual(
            totp.otpauth_uri("a/b", "SECRET"),
            "otpauth://totp/Watchpost:a%2Fb?secret=SECRET&issuer=Watchpost",
        )
