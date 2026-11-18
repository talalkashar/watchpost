"""plan_change checks an inventory proposal against the assets stored now.

An asset_add whose payload name differs from target raises. A missing asset id
raises 409. An asset_delete with a non-empty payload raises. An update that
changes nothing raises 409. Unknown fields are rejected.
"""

import unittest

from watchpost.assets import AssetError, get_asset, plan_change, save_asset
from watchpost.db import connect, init_schema


class PlanChangeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.asset = save_asset(self.conn, {
            "name": "web01",
            "kind": "server",
            "criticality": "high",
            "owner": "web-team",
            "description": "Public web server",
        }, "tester")

    def test_asset_add_whose_name_differs_from_target_raises(self):
        with self.assertRaises(AssetError) as caught:
            plan_change(self.conn, "asset_add", "web01", {"name": "web02"})
        self.assertEqual(str(caught.exception), "an asset_add targets the name of the asset it adds")
        self.assertEqual(caught.exception.status, 400)

    def test_a_missing_asset_id_raises_409(self):
        missing = str(self.asset["id"] + 1)
        with self.assertRaises(AssetError) as caught:
            plan_change(self.conn, "asset_update", missing, {"criticality": "low"})
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), f"asset #{missing} no longer exists; nothing was applied")

    def test_asset_delete_with_a_non_empty_payload_raises(self):
        with self.assertRaises(AssetError) as caught:
            plan_change(self.conn, "asset_delete", str(self.asset["id"]), {"name": "web01"})
        self.assertEqual(str(caught.exception), "an asset_delete takes an empty payload")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(get_asset(self.conn, self.asset["id"])["name"], "web01")

    def test_an_update_that_changes_nothing_raises_409(self):
        with self.assertRaises(AssetError) as caught:
            plan_change(self.conn, "asset_update", str(self.asset["id"]), {
                "criticality": self.asset["criticality"],
            })
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), "the asset already matches this change; nothing to apply")

    def test_unknown_fields_are_rejected(self):
        with self.assertRaises(AssetError) as caught:
            plan_change(self.conn, "asset_update", str(self.asset["id"]), {
                "criticality": "critical",
                "nope": True,
                "zone": 1,
            })
        self.assertEqual(str(caught.exception), "unknown asset field(s) nope, zone")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(get_asset(self.conn, self.asset["id"])["criticality"], "high")


if __name__ == "__main__":
    unittest.main()
