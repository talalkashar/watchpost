"""Inventory plan_change loads an ASCII digit target only.

Target 4 still loads asset 4. A target of ４ or ² is 409 asset #… no longer
exists, and ² is not a 500. The change is not applied to asset 4. int() runs
only after isascii.
"""

import inspect
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import assets
from watchpost.auth import create_user
from watchpost.db import connect, now_iso

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
ASSETS = Path(__file__).resolve().parent.parent / "watchpost" / "assets.py"
FULLWIDTH = "\uff14"  # ４
SUPERSCRIPT = "\u00b2"  # ²
KEEP = "keep-four"


def _message(target):
    return f"asset #{target} no longer exists; nothing was applied"


class PlanChangeDigitTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        self.asset_id = None
        for name in ("syn-host-1", "syn-host-2", "syn-host-3", KEEP):
            status, body, _ = self.admin.post("/api/assets", {
                "name": name, "kind": "server", "criticality": "low",
                "owner": "lab", "description": "synthetic inventory host",
                "addresses": [f"192.0.2.{10 + (self.asset_id or 0)}"],
                "synthetic": True,
            })
            self.assertEqual(status, 201, body)
            self.assertEqual(body["asset"]["synthetic"], 1)
            self.asset_id = body["asset"]["id"]
        self.assertEqual(self.asset_id, 4)
        self.assertEqual(self._row()["name"], KEEP)

    def _conn(self):
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def _row(self):
        listing = self.admin.get("/api/assets")[1]["assets"]
        return next(row for row in listing if row["id"] == 4)

    def _refuse(self, target):
        with self.assertRaises(assets.AssetError) as caught:
            assets.plan_change(self._conn(), "asset_delete", target, {})
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(str(caught.exception), _message(target))
        self.assertNotIn("\u0307", str(caught.exception))
        self.assertEqual(self._row()["name"], KEEP)
        self.assertNotIn("asset_deleted", [a["action"] for a in self.admin.get("/api/audit")[1]])

    def test_ascii_digits_load_asset_four(self):
        conn = self._conn()
        for target in ("4", 4):
            with self.subTest(target=target):
                before, after = assets.plan_change(conn, "asset_delete", target, {})
                self.assertIsNone(after)
                self.assertEqual(before["id"], 4)
                self.assertEqual(before["name"], KEEP)
        self.assertEqual(self._row()["name"], KEEP)

    def test_fullwidth_and_superscript_do_not_load_asset_four(self):
        self._refuse(FULLWIDTH)
        self._refuse(SUPERSCRIPT)
        conn = self._conn()
        for target in (FULLWIDTH, SUPERSCRIPT):
            with self.subTest(target=target):
                with self.assertRaises(assets.AssetError) as caught:
                    assets.apply_change(conn, "asset_update", target, {"owner": "other"}, "admin2", {})
                self.assertEqual(caught.exception.status, 409)
                self.assertEqual(str(caught.exception), _message(target))
        self.assertEqual(self._row()["owner"], "lab")
        self.assertEqual(self._row()["name"], KEEP)

    def test_approval_of_a_stored_lookalike_is_409_and_keeps_the_asset(self):
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        if not conn.execute("SELECT 1 FROM users WHERE username = 'admin2'").fetchone():
            create_user(conn, "admin2", "second-admin-password", "admin")
        for target in (FULLWIDTH, SUPERSCRIPT):
            cur = conn.execute(
                "INSERT INTO change_requests(kind, target, payload, reason, proposed_by, status,"
                " created_at) VALUES ('asset_delete', ?, '{}', 'synthetic lookalike target', 'admin',"
                " 'pending', ?)",
                (target, now_iso()),
            )
            change_id = cur.lastrowid
            reviewer = self.client()
            self.assertEqual(reviewer.login("admin2", "second-admin-password")[0], 200)
            status, body, headers = reviewer.post(
                f"/api/changes/{change_id}/review",
                {"decision": "approve", "note": "checked", "evidence_digest": "not-the-evidence"},
            )
            self.assertEqual(status, 409, body)
            self.assertNotEqual(status, 500)
            self.assertEqual(body["error"], _message(target))
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertNotIn("internal error", body["error"])
            stored = conn.execute(
                "SELECT status FROM change_requests WHERE id = ?", (change_id,)).fetchone()
            self.assertEqual(stored["status"], "pending")
        self.assertEqual(self._row()["name"], KEEP)
        errors = conn.execute("SELECT COUNT(*) FROM error_log").fetchone()[0]
        self.assertEqual(errors, 0)

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(assets.plan_change)
        self.assertLess(source.index("isascii()"), source.index("int("))
        self.assertIn("isdigit()", source)
        self.assertEqual(source.count("int("), 1)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)
        body = ASSETS.read_text().split("def plan_change", 1)[1].split("\ndef change_evidence", 1)[0]
        self.assertLess(body.index("isascii()"), body.index("int("))
        self.assertEqual(body.count("int("), 1)

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("ASCII digits", text)
            self.assertIn("Target `4` still loads asset 4", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn("`asset #… no longer exists`", text)
            self.assertIn("not a 500", text)
            self.assertIn("not applied to asset 4", text)


if __name__ == "__main__":
    unittest.main()
