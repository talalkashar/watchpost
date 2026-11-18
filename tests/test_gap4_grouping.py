"""Edges for grouping.validate, grouping.apply, and grouping.preview.

Folding, evidence preservation, the long-key hash, and preview caps are already
covered. These tests hit empty input, malformed input, and the 256-character boundary.
"""

import hashlib
import unittest

from watchpost import grouping
from watchpost.db import connect, init_schema
from watchpost.engine import seed_rules

LIST_MSG = "grouping must be a list of field names"
FIELDS_MSG = (
    "grouping may contain up to 3 unique fields from "
    "src_ip, dest_ip, user, host, event_type, source"
)
ANCHOR = "2026-09-15T12:00:00Z"
INSERT = (
    "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip,"
    " message, synthetic) VALUES (?,?,?,?,?,?,?,?,1)"
)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    seed_rules(conn)
    return conn


def row(user, src_ip):
    return (ANCHOR, ANCHOR, "demo", "auth_failure", "low", user, src_ip, "synthetic")


class ValidateEdges(unittest.TestCase):
    def test_empty_and_three_fields_keep_the_given_order(self):
        empty = []
        self.assertEqual(grouping.validate(empty), [])
        three = ["src_ip", "event_type", "host"]
        self.assertEqual(grouping.validate(three), ["src_ip", "event_type", "host"])
        self.assertEqual(three, ["src_ip", "event_type", "host"])

    def test_malformed_values_must_be_a_list_of_strings(self):
        samples = (None, "user", ("user",), {"user": "host"}, 3, [None], [1], ["user", b"host"])
        for fields in samples:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError) as raised:
                    grouping.validate(fields)
                self.assertEqual(str(raised.exception), LIST_MSG)

    def test_blank_wrong_case_and_unknown_names_are_rejected(self):
        for fields in ([""], ["User"], [" user"], ["src_ip", "host", "nope"]):
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError) as raised:
                    grouping.validate(fields)
                self.assertEqual(str(raised.exception), FIELDS_MSG)


class ApplyEdges(unittest.TestCase):
    def test_empty_fields_return_the_same_findings(self):
        findings = [{"group_key": "keep", "event_ids": [1]}]
        events = [{"id": 1, "user": "alice"}]
        self.assertIs(grouping.apply(findings, events, []), findings)
        self.assertIs(grouping.apply(findings, events, None), findings)
        self.assertEqual(findings[0]["group_key"], "keep")

    def test_blank_non_string_and_missing_events_shape_the_key(self):
        events = [
            {"id": 1, "user": None, "host": "", "src_ip": 0},
            {"id": 2, "user": "", "host": " ", "src_ip": None},
        ]
        finding = {"group_key": "old", "event_ids": [1, 2, 99], "title": "kept"}
        changed = grouping.apply([finding], events, ["user", "host", "src_ip"])[0]
        # The host part is one space. Blank users are dropped. src_ip 0 is kept.
        self.assertEqual(changed["group_key"], "(none)| |0")
        self.assertEqual(changed["event_ids"], [1, 2, 99])
        self.assertEqual(changed["title"], "kept")
        self.assertEqual(finding["group_key"], "old")
        self.assertEqual(events[0]["src_ip"], 0)

    def test_no_evidence_and_no_findings(self):
        finding = {"group_key": "old", "event_ids": []}
        changed = grouping.apply([finding], [{"id": 1, "user": "amy"}], ["user", "host"])[0]
        self.assertEqual(changed["group_key"], "(none)|(none)")
        self.assertEqual(changed["event_ids"], [])
        self.assertEqual(grouping.apply([], [{"id": 1, "user": "amy"}], ["user"]), [])

    def test_a_repeated_event_id_keeps_the_later_row(self):
        events = [{"id": 1, "src_ip": "1.1.1.1"}, {"id": 1, "src_ip": "9.9.9.9"}]
        changed = grouping.apply([{"group_key": "old", "event_ids": [1]}], events, ["src_ip"])[0]
        self.assertEqual(changed["group_key"], "9.9.9.9")

    def test_duplicate_values_collapse_and_field_order_is_the_request(self):
        events = [
            {"id": 1, "user": "zoe", "src_ip": "9.9.9.9"},
            {"id": 2, "user": "amy", "src_ip": "1.1.1.1"},
            {"id": 3, "user": "amy", "src_ip": "1.1.1.1"},
        ]
        finding = {"group_key": "old", "event_ids": [1, 2, 3]}
        forward = grouping.apply([finding], events, ["user", "src_ip"])[0]["group_key"]
        reverse = grouping.apply([finding], events, ["src_ip", "user"])[0]["group_key"]
        self.assertEqual(forward, "amy,zoe|1.1.1.1,9.9.9.9")
        self.assertEqual(reverse, "1.1.1.1,9.9.9.9|amy,zoe")

    def test_a_key_of_256_stays_literal_and_257_is_hashed(self):
        finding = {"group_key": "old", "event_ids": [1]}
        literal = "a" * 256
        longer = "b" * 257
        kept = grouping.apply([finding], [{"id": 1, "user": literal}], ["user"])[0]
        hashed = grouping.apply([finding], [{"id": 1, "user": longer}], ["user"])[0]
        self.assertEqual(kept["group_key"], literal)
        self.assertEqual(len(kept["group_key"]), 256)
        digest = hashlib.sha256(longer.encode()).hexdigest()
        self.assertEqual(hashed["group_key"], "sha256:" + digest)


class PreviewEdges(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_an_unknown_rule_is_rejected(self):
        for rule_id in ("", "Brute_Force_Ip", None):
            with self.subTest(rule_id=rule_id):
                with self.assertRaises(ValueError) as raised:
                    grouping.preview(self.conn, rule_id, [])
                self.assertEqual(str(raised.exception), "unknown rule")

    def test_shared_after_keys_collapse_and_the_request_is_echoed(self):
        ips = ("192.0.2.1", "192.0.2.2")
        rows = [row("alice", ip) for ip in ips for _ in range(10)]
        self.conn.executemany(INSERT, rows)
        fields = ["host", "user"]
        preview = grouping.preview(self.conn, "brute_force_ip", fields)
        self.assertIs(preview["fields"], fields)
        self.assertEqual(preview["rule"], "brute_force_ip")
        self.assertEqual(preview["before"]["findings"], 2)
        self.assertEqual(preview["before"]["group_keys"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(preview["after"]["findings"], 2)
        self.assertEqual(preview["after"]["group_keys"], ["(none)|alice"])
        self.assertEqual(preview["after"]["group_keys_omitted"], 0)


if __name__ == "__main__":
    unittest.main()
