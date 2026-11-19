"""Focused tests for viewer masking: the contract in tests/test_masking.py, plus the edges that leaked.

Leading-zero quads, an internal v4 embedded in a non-internal v6 token, a rejected token that starts with an
internal address, 6to4 and Teredo, role-account pivots, and public addresses filling the unmask cap.
"""

import ipaddress
import json
import sqlite3
import unittest
from unittest import mock
from urllib.parse import quote, unquote

from tests.helpers import ServerTestCase
from watchpost import entities, hunt, masking
from watchpost.db import connect, init_schema

PSEUDO_IP = r"internal-[0-9a-f]{8}"
VIEWER = {"role": "viewer", "username": "viewer"}


def _teredo(client, server="192.0.2.1", flags=0x8000):
    """A Teredo address whose client is `client`. The client sits bit-flipped in the last 32 bits."""
    obscured = (~int(ipaddress.IPv4Address(client))) & 0xFFFFFFFF
    server_n = int(ipaddress.IPv4Address(server))
    raw = (0x20010000 << 96) | (server_n << 64) | (flags << 48) | obscured
    return ipaddress.IPv6Address(raw)


def _json_download(masker, payload):
    """application/json downloads are masked as data, as Handler._download_body does."""
    if masker is None:
        return json.dumps(payload, sort_keys=True, indent=2)
    return json.dumps(masker.mask(payload), sort_keys=True, indent=2)


def _text_download(masker, text):
    """text/* downloads are masked with Masker.text."""
    if masker is None:
        return text
    return masker.text(text)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.m = masking.Masker(b"k" * 32, ["alice", "ops-admin", "admin", "dave"], self_name="viewer")

    def test_known_names_longest_match_and_own_name(self):
        text = self.m.text("Failed password for alice. ALICE again; ops-admin and admin, not alicex or hr_admin")
        self.assertNotRegex(text.lower(), r"(?<![\w.@-])(alice|ops-admin|admin)(?![\w@-])")
        self.assertIn("alicex", text)
        self.assertIn("hr_admin", text)
        self.assertEqual(self.m.text("alice"), self.m.text("Alice"))
        self.assertEqual(self.m.text("ops-admin").count("user-"), 1)
        self.assertEqual(self.m.mask({"username": "viewer"})["username"], "viewer")
        other = masking.Masker(b"j" * 32, ["alice"])
        self.assertEqual(self.m.user("alice"), self.m.user("alice"))
        self.assertNotEqual(self.m.user("alice"), other.user("alice"))

    def test_role_word_stays_in_prose_and_identity_fields_are_masked(self):
        out = self.m.mask({"assignee": "analyst", "reviewed_by": "ANALYST", "note": "Analyst notes from analyst"})
        self.assertEqual(out["assignee"], self.m.user("analyst"))
        self.assertEqual(out["reviewed_by"], self.m.user("analyst"))
        self.assertEqual(out["note"], "Analyst notes from analyst")

    def test_accented_names_stay_apart(self):
        masker = masking.Masker(b"k" * 32, ["ÉRIN", "érin", "Alice"], self_name="érin")
        self.assertNotEqual(masker.user("ÉRIN"), masker.user("érin"))
        self.assertEqual(masker.user("Alice"), masker.user("alice"))
        self.assertEqual(masker.text("érin"), "érin")
        self.assertEqual(masker.mask({"user": "ÉRIN"})["user"], masker.user("ÉRIN"))
        self.assertNotIn("ÉRIN", masker.text("ÉRIN called"))

    def test_canonical_internal_addresses_are_masked_and_public_text_is_not(self):
        for ip in ("10.0.1.20", "172.16.4.5", "192.168.1.1", "127.0.0.1", "169.254.10.10", "::1", "fe80::1",
                   "fd00::5", "::ffff:10.0.0.1"):
            with self.subTest(ip=ip):
                self.assertRegex(self.m.text(f"from {ip}."), rf"^from {PSEUDO_IP}\.$")
        mapped = ipaddress.ip_address("::ffff:10.0.0.1")
        self.assertEqual(self.m.text("::ffff:10.0.0.1"), self.m.ip(mapped))
        self.assertNotEqual(self.m.ip(mapped), self.m.ip(mapped.ipv4_mapped))
        for text in ("203.0.113.45", "198.51.100.23", "8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8",
                     "14:05:00", "aa:bb:cc:dd:ee:ff", "2026-10-07T14:05:00.000Z", "v10.0.1",
                     "0.0.0.0", "255.255.255.255", "100.64.0.1", "fec0::1", "192.0.2.77"):
            with self.subTest(text=text):
                self.assertEqual(self.m.text(text), text)
        self.assertEqual(self.m.text("src_ip:10.0.0.5 dave|10.0.1.23|192.0.2.77").count("internal-"), 2)
        self.assertRegex(self.m.text("fe80::1%eth0"), rf"^{PSEUDO_IP}%eth0$")
        self.assertEqual(self.m.text("10.0.0.1:443"), self.m.ip(ipaddress.ip_address("10.0.0.1")) + ":443")
        self.assertEqual(self.m.text("[::1]"), "[" + self.m.ip(ipaddress.ip_address("::1")) + "]")
        walked = self.m.mask({"10.0.0.5": {"user": "dave"}})
        self.assertEqual(walked[self.m.text("10.0.0.5")]["user"], self.m.user("dave"))


class AddressEdgeTests(unittest.TestCase):
    def setUp(self):
        self.m = masking.Masker(b"k" * 32, ["alice"], self_name="viewer")

    def _v4(self, text):
        return self.m.ip(ipaddress.ip_address(text))

    def test_is_internal_follows_the_embedded_v4_only(self):
        for text in ("::ffff:10.0.0.1", "2002:a00:1::", "2002:ac10:1::", "2002:c0a8:1::",
                     "2002:7f00:1::", "2002:a9fe:1::"):
            self.assertTrue(masking.is_internal(ipaddress.ip_address(text)), text)
        for text in ("::ffff:8.8.8.8", "2002:808:808::", "2002:c000:201::", "2001:db8::1",
                     "100.64.0.1", "fec0::1", "0.0.0.0", "192.0.2.45"):
            self.assertFalse(masking.is_internal(ipaddress.ip_address(text)), text)
        hidden = _teredo("10.9.8.7")
        self.assertEqual(str(hidden.teredo[1]), "10.9.8.7")
        self.assertTrue(masking.is_internal(hidden))
        shown = ipaddress.ip_address("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
        self.assertEqual(str(shown.teredo[1]), "192.0.2.45")
        self.assertFalse(masking.is_internal(shown))

    def test_leading_zero_quads_prefer_an_internal_decimal_reading(self):
        ten = self._v4("10.0.0.1")
        for raw in ("10.0.0.01", "010.0.0.1", "010.000.000.001", "012.0.0.1"):
            self.assertEqual(self.m.text(raw), ten, raw)
        self.assertEqual(self.m.text("192.168.001.010"), self._v4("192.168.1.10"))
        self.assertEqual(self.m.text("172.016.001.001"), self._v4("172.16.1.1"))
        self.assertEqual(self.m.text("10.010.0.1"), self._v4("10.10.0.1"))
        self.assertNotEqual(self.m.text("10.010.0.1"), self._v4("10.8.0.1"))
        self.assertEqual(self.m.text("0177.0.0.1"), self._v4("127.0.0.1"))
        for kept in ("008.008.008.008", "192.0.2.001", "000.000.000.000", "177.0.0.1", "017.0.0.1",
                     "256.1.2.3", "08.8.8.8"):
            self.assertEqual(self.m.text(kept), kept, kept)
        self.assertEqual(
            self.m.text("gw 10.0.0.01 talked to 8.8.8.8 and 008.008.008.008"),
            f"gw {ten} talked to 8.8.8.8 and 008.008.008.008",
        )

    def test_embedded_internal_quad_is_masked_when_the_v6_token_is_not(self):
        ten = self._v4("10.0.0.1")
        nat = self._v4("10.1.2.3")
        self.assertEqual(self.m.text("::10.0.0.1"), "::" + ten)
        self.assertEqual(self.m.text("::ffff:0:10.0.0.1"), "::ffff:0:" + ten)
        self.assertEqual(self.m.text("1:2:3:4:5:6:10.0.0.1"), "1:2:3:4:5:6:" + ten)
        self.assertEqual(self.m.text("64:ff9b::10.1.2.3"), "64:ff9b::" + nat)
        self.assertEqual(self.m.text("64:ff9b::8.8.8.8"), "64:ff9b::8.8.8.8")
        self.assertEqual(self.m.text("64:ff9b::010.0.0.1"), "64:ff9b::" + ten)
        self.assertEqual(self.m.text("fe80::10.0.0.01"), "fe80::" + ten)
        self.assertEqual(self.m.text("::ffff:10.0.0.01"), "::ffff:" + ten)
        self.assertEqual(self.m.text("::10.0.0.01"), "::" + ten)
        self.assertNotIn("10.0.0.1", self.m.text("saw ::10.0.0.1 and 64:ff9b::10.1.2.3"))

    def test_rejected_token_still_masks_an_internal_prefix(self):
        self.assertEqual(self.m.text("fd00::1::2"), self.m.ip(ipaddress.ip_address("fd00::1")) + "::2")
        self.assertEqual(self.m.text("::1::2"), self.m.ip(ipaddress.ip_address("::1")) + "::2")
        self.assertEqual(self.m.text("fe80::1::"), self.m.ip(ipaddress.ip_address("fe80::1")) + "::")
        for kept in ("2001:db8::1::extra", "2001:db8::1::2", "14:05:00", "aa:bb:cc:dd:ee:ff"):
            self.assertEqual(self.m.text(kept), kept, kept)
        ten = self._v4("10.0.0.1")
        self.assertEqual(
            self.m.text("a 10.0.0.01 b fd00::1::2 c"),
            "a " + ten + " b " + self.m.ip(ipaddress.ip_address("fd00::1")) + "::2 c",
        )

    def test_sixtofour_and_teredo_mask_the_whole_address_when_the_client_is_internal(self):
        hidden_six = ipaddress.ip_address("2002:0a00:0001::")
        self.assertEqual(self.m.text("2002:0a00:0001::"), self.m.ip(hidden_six))
        self.assertEqual(self.m.text("2002:0808:0808::"), "2002:0808:0808::")
        # 2002::10.0.0.1 is 6to4 of 0.0.0.0; the dotted quad is the internal address that has to go.
        self.assertEqual(self.m.text("2002::10.0.0.1"), "2002::" + self._v4("10.0.0.1"))
        hidden = _teredo("10.9.8.7")
        self.assertEqual(self.m.text(str(hidden)), self.m.ip(hidden))
        shown = "2001:0000:4136:e378:8000:63bf:3fff:fdd2"
        self.assertEqual(self.m.text(shown), shown)


class PivotTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def enable(self):
        self.conn.execute("INSERT INTO settings(key, value, updated_at, updated_by)"
                          " VALUES ('viewer_masking', '1', '2026-01-01T00:00:00Z', 'test')")

    def event(self, **fields):
        row = {
            "ts": "2026-01-01T00:00:00Z",
            "ingested_at": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "auth_success",
            "severity": "low",
            "synthetic": 1,
        }
        row.update(fields)
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        self.conn.execute(f"INSERT INTO events({cols}) VALUES ({marks})", tuple(row.values()))

    def account(self, username, role="analyst"):
        self.conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?, 'x', ?, '2026-01-01T00:00:00Z')",
            (username, role),
        )

    def viewer(self):
        return masking.for_user(self.conn, VIEWER)

    def test_masking_is_off_unless_the_viewer_setting_is_on(self):
        self.assertIsNone(self.viewer())
        self.enable()
        self.assertIsNone(masking.for_user(self.conn, {"role": "analyst", "username": "ann"}))
        self.assertIsNotNone(self.viewer())

    def test_role_account_pivots_without_masking_the_word(self):
        self.enable()
        self.account("analyst")
        masker = self.viewer()
        self.assertNotIn("analyst", masker.names)
        note = "Analyst notes from analyst"
        masked = masker.mask({"assignee": "analyst", "note": note})
        self.assertEqual(masked["note"], note)
        self.assertEqual(masked["assignee"], masker.user("analyst"))
        self.assertEqual(masker.unmask(self.conn, masked["assignee"]), "analyst")

    def test_an_event_username_that_is_a_role_word_is_still_masked(self):
        self.enable()
        self.account("analyst")
        self.event(user="analyst", message="ticket analyst")
        masker = self.viewer()
        self.assertIn("analyst", masker.names)
        self.assertNotIn("analyst", masker.text("ticket analyst"))
        self.assertEqual(masker.unmask(self.conn, masker.user("analyst")), "analyst")

    def test_accented_names_count_separately_and_the_viewers_own_name_is_kept(self):
        self.enable()
        self.account("viewer", role="viewer")
        for name in ("ÉRIN", "érin", "Alice", "viewer"):
            self.event(user=name)
        with mock.patch.object(masking, "CANDIDATE_LIMIT", 1):
            with self.assertRaises(masking.Unavailable) as caught:
                self.viewer()
        self.assertEqual(caught.exception.status, 503)
        masker = self.viewer()
        self.assertEqual(set(masker.names), {"Érin", "érin", "alice"})
        self.assertNotEqual(masker.user("ÉRIN"), masker.user("érin"))
        self.assertEqual(masker.user("Alice"), masker.user("alice"))
        self.assertEqual(masker.mask({"username": "Viewer"})["username"], "Viewer")

    def test_public_addresses_do_not_crowd_out_an_internal_pivot(self):
        self.enable()
        for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.9", "192.0.2.20"):
            self.event(src_ip=ip)
        self.event(dest_ip="10.9.9.9")
        masker = self.viewer()
        pseudo = masker.ip(ipaddress.ip_address("10.9.9.9"))
        with mock.patch.object(masking, "CANDIDATE_LIMIT", 1):
            self.assertEqual(masker.unmask(self.conn, pseudo), "10.9.9.9")
            self.assertEqual(masker.unmask(self.conn, pseudo, path=True), quote("10.9.9.9", safe=""))
            public = masker.ip(ipaddress.ip_address("8.8.8.8"))
            self.assertEqual(masker.unmask(self.conn, public), public)

    def test_padded_text_pivots_to_the_stored_canonical_address(self):
        self.enable()
        self.event(src_ip="8.8.8.8")
        self.event(dest_ip="10.0.0.1")
        self.event(dest_ip="127.0.0.1")
        masker = self.viewer()
        with mock.patch.object(masking, "CANDIDATE_LIMIT", 2):
            self.assertEqual(masker.unmask(self.conn, masker.text("from 10.0.0.01")), "from 10.0.0.1")
            self.assertEqual(masker.unmask(self.conn, masker.text("0177.0.0.1")), "127.0.0.1")

    def test_mapped_and_sixtofour_internal_addresses_pivot(self):
        self.enable()
        self.event(src_ip="8.8.8.8")
        self.event(src_ip="2002:808:808::")
        self.event(dest_ip="::ffff:10.2.3.4")
        self.event(dest_ip="2002:a00:1::")
        masker = self.viewer()
        mapped = ipaddress.ip_address("::ffff:10.2.3.4")
        six = ipaddress.ip_address("2002:a00:1::")
        public_six = ipaddress.ip_address("2002:808:808::")
        with mock.patch.object(masking, "CANDIDATE_LIMIT", 2):
            self.assertEqual(masker.unmask(self.conn, masker.ip(mapped)), "::ffff:10.2.3.4")
            self.assertEqual(masker.unmask(self.conn, masker.ip(six)), "2002:a00:1::")
            self.assertEqual(masker.unmask(self.conn, masker.ip(public_six)), masker.ip(public_six))

    def _open(self):
        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        conn.execute("INSERT INTO settings(key, value, updated_at, updated_by)"
                     " VALUES ('viewer_masking', '1', '2026-01-01T00:00:00Z', 'test')")
        return conn

    def _insert(self, conn, **fields):
        row = {
            "ts": "2026-01-01T00:00:00Z",
            "ingested_at": "2026-01-01T00:00:00Z",
            "source": "test",
            "event_type": "auth_success",
            "severity": "low",
            "synthetic": 1,
        }
        row.update(fields)
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        conn.execute(f"INSERT INTO events({cols}) VALUES ({marks})", tuple(row.values()))

    def test_each_stored_spelling_follows_a_masked_pivot(self):
        hidden = _teredo("10.9.8.7")
        flags0 = _teredo("10.9.8.7", flags=0)
        bare = _teredo("10.0.0.1", server="0.0.0.0", flags=0)
        cases = (
            ("src_ip", "::ffff:10.2.3.4"),
            ("src_ip", "::ffff:a00:1"),
            ("src_ip", "::ffff:0a00:0001"),
            ("src_ip", "::FFFF:A00:1"),
            ("src_ip", "::ffff:ac10:1"),
            ("src_ip", "::ffff:c0a8:1"),
            ("src_ip", "::ffff:7f00:1"),
            ("src_ip", "::ffff:a9fe:1"),
            ("dest_ip", "2002:a00:1::"),
            ("src_ip", "2002:0a00:0001::"),
            ("src_ip", str(hidden)),
            ("src_ip", hidden.exploded),
            ("dest_ip", str(flags0)),
            ("src_ip", flags0.exploded),
            ("src_ip", str(bare)),
            ("src_ip", bare.exploded),
        )
        for field, stored in cases:
            with self.subTest(field=field, stored=stored):
                conn = self._open()
                message = f"saw {stored}"
                self._insert(conn, message=message, **{field: stored})
                masker = masking.for_user(conn, VIEWER)
                parsed = ipaddress.ip_address(stored)
                pseudo = masker.ip(parsed)
                self.assertTrue(masking.is_internal(parsed))
                self.assertEqual(masker.text(message), f"saw {pseudo}")
                self.assertNotIn(stored, masker.text(message))
                self.assertEqual(masker.unmask(conn, pseudo), stored)
                self.assertEqual(masker.unmask(conn, pseudo, path=True), quote(stored, safe=""))
                self.assertEqual(unquote(masker.unmask(conn, pseudo, path=True)), stored)
                found = masker.unmask(conn, f'"{pseudo}"')
                self.assertEqual(found, f'"{stored}"')
                self.assertGreaterEqual(hunt.run(conn, {"q": found})["total"], 1)
                field_query = masker.unmask(conn, f"{field}:{pseudo}")
                self.assertEqual(hunt.run(conn, {"q": field_query}, resolved_ips=masker.resolved_ips)["total"], 1)
                if field == "src_ip":
                    entity = entities.get_entity(conn, field, stored, resolved_ips=masker.resolved_ips)
                    self.assertEqual(entity["event_count"], 1)
                if stored == str(parsed):
                    page = hunt.run(conn, {"q": f"{field}:{stored}"})
                    self.assertGreaterEqual(page["total"], 1)
                    if field == "src_ip":
                        self.assertGreaterEqual(
                            entities.get_entity(conn, "src_ip", stored)["event_count"], 1)

    def test_two_spellings_of_one_address_prefer_the_canonical_row(self):
        self.enable()
        self.event(src_ip="::ffff:10.0.0.1", message="dotted ::ffff:10.0.0.1")
        self.event(src_ip="::ffff:a00:1", message="hex ::ffff:a00:1")
        self.event(src_ip="2002:a00:1::", message="six 2002:a00:1::")
        self.event(dest_ip="2002:0a00:0001::", message="pad 2002:0a00:0001::")
        masker = self.viewer()
        mapped = ipaddress.ip_address("::ffff:a00:1")
        six = ipaddress.ip_address("2002:0a00:0001::")
        self.assertEqual(masker.unmask(self.conn, masker.ip(mapped)), str(mapped))
        self.assertEqual(masker.unmask(self.conn, masker.ip(six)), "2002:a00:1::")
        self.assertEqual(entities.get_entity(self.conn, "src_ip", "::ffff:10.0.0.1")["event_count"], 1)
        self.assertEqual(hunt.run(self.conn, {"q": "src_ip:::ffff:10.0.0.1"})["total"], 1)
        self.assertEqual(hunt.run(self.conn, {"q": "src_ip:2002:a00:1::"})["total"], 1)
        # The padded dest row is the same address; the pseudonym follows the canonical src row.
        self.assertEqual(hunt.run(self.conn, {"q": '"2002:a00:1::"'})["total"], 1)

    def test_public_embedded_addresses_do_not_crowd_an_internal_spelling(self):
        publics = ("8.8.8.8", "::ffff:8.8.8.8", "2002:808:808::", str(_teredo("8.8.8.8")))
        internals = (
            "::ffff:a00:1",
            "2002:0a00:0001::",
            str(_teredo("10.9.8.7")),
            str(_teredo("10.0.0.1", server="0.0.0.0", flags=0)),
        )
        for internal in internals:
            with self.subTest(internal=internal):
                conn = self._open()
                for ip in publics:
                    self._insert(conn, src_ip=ip)
                self._insert(conn, dest_ip=internal, message=f"hidden {internal}")
                masker = masking.for_user(conn, VIEWER)
                parsed = ipaddress.ip_address(internal)
                with mock.patch.object(masking, "CANDIDATE_LIMIT", 1):
                    self.assertEqual(masker.unmask(conn, masker.ip(parsed)), internal)
                    for ip in publics:
                        public_pseudo = masker.ip(ipaddress.ip_address(ip))
                        out = masker.unmask(conn, public_pseudo)
                        self.assertEqual(out, public_pseudo)
                        self.assertNotIn(internal, out)

    def test_public_address_scan_is_bounded_and_username_pivot_does_not_scan_ips(self):
        self.enable()
        self.account("analyst")
        for address in ("1.1.1.1", "1.1.1.2", "10.1.2.3"):
            self.event(src_ip=address)
        masker = self.viewer()
        pseudo = masker.ip(ipaddress.ip_address("10.1.2.3"))
        queries = []
        self.conn.set_trace_callback(queries.append)
        with mock.patch.object(masking, "IP_SCAN_LIMIT", 2):
            self.assertEqual(masker.unmask(self.conn, masker.user("analyst")), "analyst")
            self.assertFalse(any("src_ip" in query for query in queries))
            self.assertEqual(masker.unmask(self.conn, pseudo), pseudo)

    def test_ip_ceiling_leaves_unresolved_pivots_without_a_raw_address(self):
        self.enable()
        addrs = [f"10.0.0.{i}" for i in range(1, 6)]
        for ip in addrs:
            self.event(src_ip=ip, message=f"from {ip}")
        masker = self.viewer()
        with mock.patch.object(masking, "CANDIDATE_LIMIT", 2):
            resolved, failed = [], []
            for ip in addrs:
                pseudo = masker.ip(ipaddress.ip_address(ip))
                out = masker.unmask(self.conn, pseudo)
                path = masker.unmask(self.conn, f"pivot {pseudo} now", path=False)
                if out == ip:
                    resolved.append(out)
                else:
                    failed.append(out)
                    self.assertEqual(out, pseudo)
                    self.assertEqual(path, f"pivot {pseudo} now")
                    for raw in addrs:
                        self.assertNotIn(raw, out)
                        self.assertNotIn(raw, path)
            self.assertEqual(len(resolved), 2)
            self.assertEqual(len(failed), 3)

    def test_masked_download_hides_addresses_and_other_names(self):
        self.enable()
        self.account("analyst")
        self.account("dave")
        self.account("viewer", role="viewer")
        self.event(user="dave", src_ip="10.1.2.3", message="dave saw 10.1.2.3")
        masker = self.viewer()
        note = "Analyst notes from analyst. viewer checked dave at 10.1.2.3"
        payload = {
            "assignee": "analyst",
            "user": "dave",
            "username": "viewer",
            "note": note,
            "src_ip": "10.1.2.3",
        }
        body = _json_download(masker, payload)
        text = _text_download(masker, note)
        masked = masker.mask(payload)
        self.assertEqual(masked["note"], text)
        self.assertEqual(masked["username"], "viewer")
        self.assertEqual(masked["assignee"], masker.user("analyst"))
        self.assertEqual(masked["user"], masker.user("dave"))
        self.assertEqual(masked["src_ip"], masker.ip(ipaddress.ip_address("10.1.2.3")))
        self.assertEqual(masker.unmask(self.conn, masked["assignee"]), "analyst")
        for rendered in (body, text):
            self.assertNotIn("10.1.2.3", rendered)
            self.assertNotRegex(rendered, r"(?<![\w.@-])dave(?![\w@-])")
            self.assertIn("Analyst notes from analyst", rendered)
            self.assertIn("viewer", rendered)
        self.assertIn(masker.user("dave"), body)
        self.assertIn(masker.ip(ipaddress.ip_address("10.1.2.3")), body)

    def test_analyst_and_setting_off_leave_the_download_raw(self):
        payload = {"user": "dave", "note": "Analyst notes from analyst", "src_ip": "10.1.2.3"}
        text = "Analyst notes from analyst. dave at 10.1.2.3"
        self.assertIsNone(self.viewer())
        self.assertIsNone(masking.for_user(self.conn, {"role": "analyst", "username": "ann"}))
        self.assertIn("dave", _json_download(None, payload))
        self.assertIn("10.1.2.3", _json_download(None, payload))
        self.assertEqual(_text_download(None, text), text)
        self.enable()
        self.assertIsNone(masking.for_user(self.conn, {"role": "analyst", "username": "ann"}))
        self.assertIsNone(masking.for_user(self.conn, {"role": "admin", "username": "ada"}))
        self.assertIn("10.1.2.3", _text_download(None, text))


class MaskedPivotHttpTests(ServerTestCase):
    def test_stored_ip_spelling_survives_viewer_entity_and_field_hunt(self):
        raw = "::FFFF:0A02:0304"
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT OR REPLACE INTO settings(key,value,updated_at,updated_by)"
                       " VALUES ('viewer_masking','1','2026-11-18','fixture')")
            event = db.execute("INSERT INTO events(ts,ingested_at,source,event_type,severity,src_ip)"
                               " VALUES ('2026-11-18','2026-11-18','fixture','other','low',?)", (raw,)).lastrowid
        viewer = self.client("viewer")
        status, detail, _ = viewer.get(f"/api/events/{event}")
        self.assertEqual(status, 200)
        pseudo = detail["src_ip"]
        self.assertRegex(pseudo, PSEUDO_IP)
        for route, key in ((f"/api/entities/src_ip/{pseudo}", "recent_events"),
                           (f"/api/hunt?q=src_ip:{pseudo}", "events")):
            status, page, _ = viewer.get(route)
            self.assertEqual(status, 200, page)
            self.assertEqual([row["id"] for row in page[key]], [event])
            self.assertNotIn(raw.lower(), json.dumps(page).lower())


if __name__ == "__main__":
    unittest.main()
