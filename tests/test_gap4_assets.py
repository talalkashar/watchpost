"""Edge cases for asset validation, matching, weighting, and change planning.

These assert boundaries, empty input, malformed input, and ordering that the
other asset tests do not already check.
"""

import unittest

from watchpost import assets
from watchpost.db import connect, init_schema

_NAME_ERROR = "name must be 1-128 chars of letters, digits, _ . : -"
_ADDRESS_LIST_ERROR = "addresses must be a list of at most 32 IP addresses"
_TAG_ERROR = "data_tags must be a list of tags"


def _asset(name, criticality="medium", tags=(), addresses=(), **extra):
    row = {"name": name, "kind": "server", "criticality": criticality,
           "data_tags": list(tags), "addresses": list(addresses)}
    row.update(extra)
    return row


class ValidateEdgeTests(unittest.TestCase):
    def test_name_length_alphabet_and_non_string(self):
        self.assertEqual(assets.validate({"name": "a" * 128})["name"], "a" * 128)
        self.assertEqual(assets.validate({"name": "a.b:c_d-1"})["name"], "a.b:c_d-1")
        self.assertEqual(assets.validate({"name": 123})["name"], "123")
        for bad in ("a" * 129, "Érin-host", "a!"):
            with self.subTest(bad=bad):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.validate({"name": bad})
                self.assertEqual(str(caught.exception), _NAME_ERROR)
                self.assertEqual(caught.exception.status, 400)

    def test_address_bounds_order_and_malformed_values(self):
        clean = assets.validate({"name": "edge", "addresses": ["10.0.0.1"] * 32})
        self.assertEqual(clean["addresses"], ["10.0.0.1"])
        clean = assets.validate({"name": "edge", "addresses": ["10.0.0.2", " 10.0.0.1 "]})
        self.assertEqual(clean["addresses"], ["10.0.0.1", "10.0.0.2"])
        text = ",".join(["10.0.0.1"] * 33)
        for bad in (["10.0.0.1"] * 33, text, 5, {"10.0.0.1": True}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.validate({"name": "edge", "addresses": bad})
                self.assertEqual(str(caught.exception), _ADDRESS_LIST_ERROR)
        for bad in ("", "010.0.0.1", None):
            with self.subTest(bad=bad):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.validate({"name": "edge", "addresses": [bad]})
                self.assertEqual(str(caught.exception), f"invalid IP address {bad!r}")
        for empty in (None, "", []):
            with self.subTest(empty=empty):
                self.assertEqual(assets.validate({"name": "edge", "addresses": empty})["addresses"], [])

    def test_empty_tags_collapse_and_a_bad_tag_list_is_rejected(self):
        for tags in (None, "", [], " , "):
            with self.subTest(tags=tags):
                self.assertEqual(assets.validate({"name": "edge", "data_tags": tags})["data_tags"], [])
        clean = assets.validate({"name": "edge", "data_tags": [" PII ", "pii", " ", "PCI"]})
        self.assertEqual(clean["data_tags"], ["pci", "pii"])
        for bad in (1, {"pii": True}, ["pii", 1]):
            with self.subTest(bad=bad):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.validate({"name": "edge", "data_tags": bad})
                self.assertEqual(str(caught.exception), _TAG_ERROR)

    def test_owner_and_description_trim_and_synthetic_is_zero_or_one(self):
        clean = assets.validate({
            "name": "edge", "owner": " " + ("o" * 129), "description": " " + ("d" * 500)})
        self.assertEqual(clean["owner"], "o" * 128)
        self.assertEqual(clean["description"], "d" * 500)
        self.assertEqual(assets.validate({"name": "edge", "description": "d" * 501})["description"], "d" * 500)
        clean = assets.validate({"name": "edge", "owner": "   ", "description": "\n"})
        self.assertEqual((clean["owner"], clean["description"], clean["synthetic"]), (None, None, 0))
        self.assertEqual(assets.validate({"name": "edge", "synthetic": True})["synthetic"], 1)
        self.assertEqual(assets.validate({"name": "edge", "synthetic": 0})["synthetic"], 0)


class MatchEdgeTests(unittest.TestCase):
    def test_empty_inputs_and_blank_fields_match_nothing(self):
        indexed = assets.index([_asset("web01", addresses=["10.0.0.5"])])
        self.assertEqual(assets.match(indexed, []), [])
        self.assertEqual(assets.match(assets.index([]), [{"host": "web01", "dest_ip": "10.0.0.5"}]), [])
        self.assertEqual(assets.match(indexed, [{"host": "", "src_ip": "", "dest_ip": None}]), [])

    def test_host_and_address_hits_are_sorted_by_stored_name(self):
        indexed = assets.index([
            _asset("zz", addresses=["10.0.0.2"]),
            _asset("aa", addresses=["10.0.0.1"]),
            _asset("WEB02"),
        ])
        found = assets.match(indexed, [{"host": "zz", "dest_ip": "10.0.0.1"}, {"host": "WEB02"}])
        self.assertEqual([row["name"] for row in found], ["WEB02", "aa", "zz"])

    def test_a_later_asset_wins_the_same_host_key(self):
        indexed = assets.index([_asset("WEB01", "low"), _asset("web01", "critical")])
        found = assets.match(indexed, [{"host": "Web01"}])
        self.assertEqual([(row["name"], row["criticality"]) for row in found], [("web01", "critical")])

    def test_an_asset_without_an_address_list_still_matches_by_name(self):
        indexed = assets.index([{"name": "mail01", "criticality": "low", "data_tags": []}])
        self.assertEqual([row["name"] for row in assets.match(indexed, [{"host": "mail01"}])], ["mail01"])
        self.assertEqual(assets.match(indexed, [{"dest_ip": "10.0.0.1"}]), [])


class BoostEdgeTests(unittest.TestCase):
    def test_the_note_names_the_top_asset_and_only_three_sensitive_ones(self):
        levels, note = assets.boost([
            _asset("low-host", "low", ["pii"]),
            _asset("mid-host", "medium", ["pci"]),
            _asset("zzz", "critical"),
            _asset("aaa", "high", ["phi"]),
            _asset("bbb", "low", ["financial"]),
        ])
        self.assertEqual(levels, 2)
        self.assertEqual(note, "raised 2 level(s): zzz is a critical-criticality asset; "
                         "sensitive data on low-host (pii), mid-host (pci), aaa (phi)")

    def test_a_criticality_tie_keeps_the_first_asset(self):
        levels, note = assets.boost([_asset("m-first", "critical"), _asset("a-second", "critical")])
        self.assertEqual((levels, note), (2, "raised 2 level(s): m-first is a critical-criticality asset"))

    def test_a_no_change_note_stops_after_three_names(self):
        levels, note = assets.boost([_asset(name, "low") for name in ("a", "b", "c", "d")])
        self.assertEqual((levels, note), (0, "touches known asset(s) a, b, c; no severity change"))


class WeighEdgeTests(unittest.TestCase):
    def test_an_unknown_base_severity_starts_at_info(self):
        self.assertEqual(assets.weigh("urgent", []), {
            "severity": "info", "base_severity": "urgent", "assets": [], "severity_note": None})
        self.assertEqual(assets.weigh("", [])["severity"], "info")
        weighed = assets.weigh(None, [_asset("db01", "critical")])
        self.assertEqual(weighed["severity"], "medium")
        self.assertIsNone(weighed["base_severity"])
        self.assertEqual(weighed["severity_note"], "raised 2 level(s): db01 is a critical-criticality asset")

    def test_info_raised_by_a_critical_asset_is_medium(self):
        weighed = assets.weigh("info", [_asset("db01", "critical")])
        self.assertEqual((weighed["severity"], weighed["base_severity"]), ("medium", "info"))

    def test_public_assets_keep_caller_order_and_drop_private_fields(self):
        first = {"id": 3, "name": "zz", "kind": "server", "criticality": "low", "data_tags": [],
                 "addresses": ["10.0.0.1"], "owner": "ops", "description": "secret", "synthetic": 0}
        second = {"name": "aa", "kind": "database", "criticality": "high", "data_tags": ["pci"],
                  "addresses": ["10.0.0.2"], "owner": "dba"}
        weighed = assets.weigh("low", [first, second])
        self.assertEqual([row["name"] for row in weighed["assets"]], ["zz", "aa"])
        self.assertEqual(set(weighed["assets"][0]),
                         {"id", "name", "kind", "criticality", "data_tags", "synthetic"})
        self.assertEqual(set(weighed["assets"][1]), {"name", "kind", "criticality", "data_tags"})
        # high criticality (+1) plus the pci tag (+1) lifts low two levels.
        self.assertEqual(weighed["severity"], "high")


class PlanChangeEdgeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.asset = assets.save_asset(self.conn, {
            "name": "db01", "criticality": "high", "data_tags": ["pii"],
            "addresses": ["10.0.0.10"], "owner": "dba"}, "admin")

    def test_an_add_must_target_the_cleaned_name_and_writes_nothing(self):
        for target, payload in (("db02", {"name": " web02 "}), ("web02", {"name": "WEB02"})):
            with self.subTest(target=target):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.plan_change(self.conn, "asset_add", target, payload)
                self.assertEqual(str(caught.exception), "an asset_add targets the name of the asset it adds")
                self.assertEqual(caught.exception.status, 400)
        before, after = assets.plan_change(
            self.conn, "asset_add", "web02", {"name": " web02 ", "criticality": "LOW"})
        self.assertIsNone(before)
        self.assertEqual((after["name"], after["criticality"], after["kind"]), ("web02", "low", "server"))
        self.assertEqual([row["name"] for row in assets.list_assets(self.conn)], ["db01"])

    def test_delete_rejects_a_payload_and_returns_the_current_snapshot(self):
        with self.assertRaises(assets.AssetError) as caught:
            assets.plan_change(self.conn, "asset_delete", self.asset["id"], {"owner": "x"})
        self.assertEqual(str(caught.exception), "an asset_delete takes an empty payload")
        self.assertEqual(caught.exception.status, 400)
        before, after = assets.plan_change(self.conn, "asset_delete", str(self.asset["id"]), {})
        self.assertIsNone(after)
        self.assertEqual((before["id"], before["name"]), (self.asset["id"], "db01"))
        self.assertEqual(assets.get_asset(self.conn, self.asset["id"])["name"], "db01")

    def test_unknown_fields_are_named_in_sorted_order(self):
        with self.assertRaises(assets.AssetError) as caught:
            assets.plan_change(self.conn, "asset_update", self.asset["id"], {"zzz": 1, "aaa": 2, "owner": "x"})
        self.assertEqual(str(caught.exception), "unknown asset field(s) aaa, zzz")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(assets.get_asset(self.conn, self.asset["id"])["owner"], "dba")

    def test_a_case_only_criticality_is_already_applied(self):
        with self.assertRaises(assets.AssetError) as caught:
            assets.plan_change(self.conn, "asset_update", self.asset["id"], {"criticality": "HIGH"})
        self.assertEqual(str(caught.exception), "the asset already matches this change; nothing to apply")
        self.assertEqual(caught.exception.status, 409)

    def test_a_partial_payload_merges_and_does_not_write(self):
        before, after = assets.plan_change(
            self.conn, "asset_update", self.asset["id"], {"criticality": "low", "data_tags": []})
        self.assertEqual(before["criticality"], "high")
        self.assertEqual((after["criticality"], after["data_tags"], after["owner"], after["addresses"]),
                         ("low", [], "dba", ["10.0.0.10"]))
        stored = assets.get_asset(self.conn, self.asset["id"])
        self.assertEqual((stored["criticality"], stored["data_tags"]), ("high", ["pii"]))

    def test_a_non_numeric_target_is_a_missing_asset(self):
        for target in ("db01", ""):
            with self.subTest(target=target):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.plan_change(self.conn, "asset_update", target, {"owner": "net-ops"})
                self.assertEqual(caught.exception.status, 409)
                self.assertEqual(str(caught.exception), f"asset #{target} no longer exists; nothing was applied")
