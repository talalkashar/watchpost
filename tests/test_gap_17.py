"""Masker.unmask: a viewer pseudonym resolves to the real username or internal IP.

An unknown token is left unchanged. path=True percent-encodes only the replacement.
HTTP pivot resolution is covered in tests/test_masking.py.
"""

import ipaddress
import unittest
from urllib.parse import quote

from watchpost import masking
from watchpost.db import connect, init_schema


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


class UnmaskTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, src_ip, dest_ip)"
            " VALUES ('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'test', 'auth_success', 'low', ?, ?)",
            ("10.1.2.3", "FD00::5"))
        self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, src_ip)"
            " VALUES ('2026-01-01T00:01:00Z', '2026-01-01T00:01:00Z', 'test', 'auth_success', 'low', ?)",
            ("203.0.113.9",))
        self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, src_ip)"
            " VALUES ('2026-01-01T00:02:00Z', '2026-01-01T00:02:00Z', 'test', 'auth_success', 'low', ?)",
            ("not-an-ip",))
        self.m = masking.Masker(b"k" * 32, ["Alice", "érin"], self_name="viewer")

    def ip_token(self, text):
        return self.m.ip(ipaddress.ip_address(text))

    def test_pseudonym_resolves_to_username_or_internal_ip(self):
        # Candidates are ASCII-folded, so Alice and alice are one pivot value.
        user = self.m.user("Alice")
        self.assertEqual(user, self.m.user("alice"))
        src = self.ip_token("10.1.2.3")
        dest = self.ip_token("FD00::5")
        self.assertEqual(self.m.unmask(self.conn, user), "alice")
        self.assertEqual(self.m.unmask(self.conn, f"user:{user} from {src}"), "user:alice from 10.1.2.3")
        # The stored spelling comes back, including a dest address and a non-canonical IPv6 form.
        self.assertEqual(self.m.unmask(self.conn, dest), "FD00::5")

    def test_unknown_token_is_left_unchanged(self):
        unknown_user = "user-00000000"
        unknown_ip = "internal-deadbeef"
        public = self.ip_token("203.0.113.9")
        self.assertEqual(self.m.unmask(self.conn, unknown_user), unknown_user)
        self.assertEqual(self.m.unmask(self.conn, unknown_ip), unknown_ip)
        self.assertEqual(self.m.unmask(self.conn, public), public)
        self.assertEqual(self.m.unmask(self.conn, f"note {unknown_user} {public}"), f"note {unknown_user} {public}")
        self.assertEqual(self.m.unmask(self.conn, "plain alice 10.1.2.3"), "plain alice 10.1.2.3")

    def test_path_percent_encodes_the_replacement(self):
        user = self.m.user("érin")
        dest = self.ip_token("FD00::5")
        encoded_user = quote("érin", safe="")
        encoded_ip = quote("FD00::5", safe="")
        self.assertNotEqual(encoded_user, "érin")
        self.assertIn("%3A", encoded_ip)
        self.assertEqual(
            self.m.unmask(self.conn, f"/api/entities/user/{user}", path=True),
            "/api/entities/user/" + encoded_user)
        self.assertEqual(self.m.unmask(self.conn, dest, path=True), encoded_ip)
        self.assertEqual(self.m.unmask(self.conn, user), "érin")
        self.assertEqual(self.m.unmask(self.conn, dest), "FD00::5")
        self.assertEqual(self.m.unmask(self.conn, "user-00000000", path=True), "user-00000000")
        # No pseudonym: the string is returned as given, not quoted as a whole.
        self.assertEqual(self.m.unmask(self.conn, "érin", path=True), "érin")


if __name__ == "__main__":
    unittest.main()
