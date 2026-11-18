"""Fail-closed edges for watchpost.totp.verify: bad input returns None, and the drift window stays on the unsigned counter range."""

import base64
import unittest

from watchpost import totp

RFC_KEY = b"12345678901234567890"  # RFC 6238 Appendix B, SHA-1 seed
RFC_SECRET = base64.b32encode(RFC_KEY).decode().rstrip("=")
RFC_VECTORS = [  # (time, 8-digit TOTP)
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
]
MAX_COUNTER = 2**64 - 1


class TotpBlitzTests(unittest.TestCase):
    def test_rfc6238_sha1_vectors(self):
        for t, expected in RFC_VECTORS:
            with self.subTest(t=t):
                self.assertEqual(totp.code_at(RFC_SECRET, t, digits=8), expected)
                self.assertEqual(totp.code_at(RFC_SECRET, t), expected[-6:])
                self.assertEqual(totp.verify(RFC_SECRET, expected[-6:], timestamp=t), totp.step_at(t))
                self.assertIsNone(totp.verify(RFC_SECRET, expected, timestamp=t))

    def test_drift_of_one_step_is_accepted_two_is_not(self):
        t = 1111111111
        step = totp.step_at(t)
        for offset in (-1, 0, 1):
            code = totp.code_at(RFC_SECRET, t + offset * 30)
            self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=t), step + offset, offset)
        for offset in (-2, 2):
            code = totp.code_at(RFC_SECRET, t + offset * 30)
            self.assertIsNone(totp.verify(RFC_SECRET, code, timestamp=t), offset)

    def test_replay_of_the_same_or_an_older_step_is_refused(self):
        t = 1111111111
        step = totp.step_at(t)
        code = totp.code_at(RFC_SECRET, t)
        self.assertIsNone(totp.verify(RFC_SECRET, code, last_step=step, timestamp=t))
        older = totp.code_at(RFC_SECRET, t - 30)
        self.assertIsNone(totp.verify(RFC_SECRET, older, last_step=step, timestamp=t))
        newer = totp.code_at(RFC_SECRET, t + 30)
        self.assertEqual(totp.verify(RFC_SECRET, newer, last_step=step, timestamp=t), step + 1)

    def test_whitespace_inside_a_code_is_ignored(self):
        code = totp.code_at(RFC_SECRET, 59)
        step = totp.step_at(59)
        for shaped in (f" {code} ", f"{code[:3]} {code[3:]}", f"{code[:3]}\t{code[3:]}",
                       f"{code[:3]}\n{code[3:]}", f"{code[:3]}\u00a0{code[3:]}"):
            self.assertEqual(totp.verify(RFC_SECRET, shaped, timestamp=59), step, shaped)

    def test_non_ascii_digits_are_refused_without_raising(self):
        for bad in ("١٢٣٤٥٦", "１２３４５６", "12345⁶", "①②③④⑤⑥"):
            self.assertIsNone(totp.verify(RFC_SECRET, bad, timestamp=59), bad)

    def test_malformed_codes_are_refused(self):
        for bad in (None, 123456, b"123456", "", "12345", "1234567", "abcdef", "12345a"):
            self.assertIsNone(totp.verify(RFC_SECRET, bad, timestamp=59), bad)

    def test_bad_or_empty_secret_is_refused_without_raising(self):
        code = totp.code_at(RFC_SECRET, 59)
        for secret in (None, "", "   ", "!!!!", "========", b"AAAA", 123, "not-base32"):
            self.assertIsNone(totp.verify(secret, code, timestamp=59), secret)
        blank = totp.code_at("", 59)
        self.assertIsNone(totp.verify("", blank, timestamp=59))
        self.assertIsNone(totp.verify(" \n ", blank, timestamp=59))

    def test_grouped_and_lowercase_secret_still_verifies(self):
        secret = totp.generate_secret()
        self.assertEqual(len(totp.decode_secret(secret)), 20)
        self.assertNotIn("=", secret)
        messy = secret[:8].lower() + "\n" + secret[8:16] + " " + secret[16:]
        code = totp.code_at(secret, 59)
        self.assertEqual(totp.decode_secret(messy), totp.decode_secret(secret))
        self.assertEqual(totp.verify(messy, code, timestamp=59), totp.step_at(59))
        padded = base64.b32encode(RFC_KEY).decode()  # same key, padding restored if any
        self.assertEqual(totp.decode_secret(padded.lower()), RFC_KEY)

    def test_epoch_window_does_not_pack_a_negative_counter(self):
        code = totp.code_at(RFC_SECRET, 0)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=0), 0)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=29), 0)
        # One step before the epoch the drift window still reaches counter 0.
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=-1), 0)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=-30), 0)
        self.assertIsNone(totp.verify(RFC_SECRET, code, timestamp=-31))
        self.assertIsNone(totp.verify(RFC_SECRET, code, last_step=0, timestamp=-1))
        nxt = totp.code_at(RFC_SECRET, 30)
        self.assertEqual(totp.verify(RFC_SECRET, nxt, last_step=0, timestamp=0), 1)

    def test_counter_past_uint64_is_refused_and_the_last_counter_still_works(self):
        ts = MAX_COUNTER * totp.STEP_SECONDS
        code = totp.code_at(RFC_SECRET, ts)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=ts), MAX_COUNTER)
        prev = totp.code_at(RFC_SECRET, ts - totp.STEP_SECONDS)
        self.assertEqual(totp.verify(RFC_SECRET, prev, timestamp=ts), MAX_COUNTER - 1)
        # One step past the last counter, drift still reaches it. Two steps past, it does not.
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=ts + totp.STEP_SECONDS), MAX_COUNTER)
        self.assertIsNone(totp.verify(RFC_SECRET, code, timestamp=ts + 2 * totp.STEP_SECONDS))
        self.assertIsNone(totp.verify(RFC_SECRET, "000000", timestamp=10**30))

    def test_bad_timestamp_or_last_step_is_refused_without_raising(self):
        code = totp.code_at(RFC_SECRET, 59)
        step = totp.step_at(59)
        for ts in (float("nan"), float("inf"), float("-inf"), "59", object()):
            self.assertIsNone(totp.verify(RFC_SECRET, code, timestamp=ts), ts)
        self.assertEqual(totp.verify(RFC_SECRET, code, timestamp=59.9), step)
        for last in ("1", b"1", object()):
            self.assertIsNone(totp.verify(RFC_SECRET, code, last_step=last, timestamp=59), last)

    def test_secret_and_uri(self):
        secret = totp.generate_secret()
        self.assertEqual(totp.otpauth_uri("alice", secret),
                         f"otpauth://totp/Watchpost:alice?secret={secret}&issuer=Watchpost")
        self.assertEqual(totp.otpauth_uri("Érin", secret),
                         f"otpauth://totp/Watchpost:%C3%89rin?secret={secret}&issuer=Watchpost")


if __name__ == "__main__":
    unittest.main()
