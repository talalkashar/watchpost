"""Asset create and edit fold kind and criticality onto the catalog spelling.

`Server` stores `server` and `High` stores `high`. A value that is only spaces,
and `Hıgh`, stay the existing error. An address stays the form already stored.
"""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import assets

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
KIND_ERROR = f"kind must be one of {', '.join(assets.KINDS)}"
CRITICALITY_ERROR = f"criticality must be one of {', '.join(assets.CRITICALITIES)}"


class AssetCatalogCaseTests(unittest.TestCase):
    def test_kind_and_criticality_store_the_catalog_spelling(self):
        for kind, criticality, stored_kind, stored_criticality in (
            ("Server", "High", "server", "high"),
            ("DATABASE", "CRITICAL", "database", "critical"),
            ("WorkStation", "Medium", "workstation", "medium"),
            ("CLOUD", "LOW", "cloud", "low"),
            ("Network", "high", "network", "high"),
            ("Other", "low", "other", "low"),
        ):
            with self.subTest(kind=kind, criticality=criticality):
                clean = assets.validate({"name": "web01", "kind": kind, "criticality": criticality})
                self.assertEqual((clean["kind"], clean["criticality"]), (stored_kind, stored_criticality))

    def test_a_missing_value_stays_the_default(self):
        clean = assets.validate({"name": "web01"})
        self.assertEqual((clean["kind"], clean["criticality"]), ("server", "medium"))
        clean = assets.validate({"name": "web01", "kind": "", "criticality": ""})
        self.assertEqual((clean["kind"], clean["criticality"]), ("server", "medium"))

    def test_spaces_and_a_lookalike_stay_the_existing_error(self):
        for bad in (" ", "  ", "server ", " Server", "toaster", "servér", 1, True):
            with self.subTest(kind=bad):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.validate({"name": "web01", "kind": bad})
                self.assertEqual(str(caught.exception), KIND_ERROR)
                self.assertEqual(caught.exception.status, 400)
        for bad in (" ", "Hıgh", "hıgh", "urgent", "critical ", "HİGH"):
            with self.subTest(criticality=bad):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.validate({"name": "web01", "criticality": bad})
                self.assertEqual(str(caught.exception), CRITICALITY_ERROR)

    def test_an_address_stays_the_stored_form(self):
        clean = assets.validate({
            "name": "files01", "kind": "Server", "criticality": "High",
            "addresses": ["2001:DB8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"],
        })
        self.assertEqual(clean["addresses"], ["2001:db8::1"])
        self.assertEqual((clean["kind"], clean["criticality"]), ("server", "high"))

    def test_docs_name_the_fold(self):
        row = next(line for line in API.read_text().splitlines() if line.startswith("| `POST /api/assets`"))
        self.assertIn("`Server` stores `server`", row)
        self.assertIn("`High` stores `high`", row)
        self.assertIn("`Hıgh`", row)
        text = REFERENCE.read_text()
        self.assertIn("`Server` stores `server`", text)
        self.assertIn("`High` stores `high`", text)


class AssetCatalogCaseApiTests(ServerTestCase):
    def test_create_and_edit_store_the_catalog_spelling(self):
        admin = self.client("admin")
        status, data, _ = admin.post("/api/assets", {
            "name": "files01", "kind": "Server", "criticality": "High",
            "addresses": "2001:DB8::1",
        })
        self.assertEqual(status, 201, data)
        asset = data["asset"]
        self.assertEqual((asset["kind"], asset["criticality"], asset["addresses"]),
                         ("server", "high", ["2001:db8::1"]))
        status, data, _ = admin.post(f"/api/assets/{asset['id']}", {
            "name": "files01", "kind": "Database", "criticality": "CRITICAL",
            "addresses": ["2001:DB8::1"],
        })
        self.assertEqual(status, 200, data)
        self.assertEqual((data["asset"]["kind"], data["asset"]["criticality"]), ("database", "critical"))
        status, body, _ = admin.post("/api/assets", {"name": "web01", "criticality": "Hıgh"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], CRITICALITY_ERROR)
        status, body, _ = admin.post("/api/assets", {"name": "web01", "kind": " "})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], KIND_ERROR)
