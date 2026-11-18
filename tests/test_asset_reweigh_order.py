"""Asset reweigh orders the inventory the same way list_assets does.

Criticality rank first, then the stored name compared as the name column is (A-Z only).
baclup stays ahead of bacKup. Zed stays ahead of İtem. erin stays ahead of Érin.
A proposed asset lands where list_assets would put that stored name. Insert order does not matter.
The stored spelling is not rewritten.
"""

import unittest

from watchpost import assets
from watchpost.db import connect, init_schema

TS = "2026-09-15T12:00:00.000Z"
KELVIN = "bac\u212aup"
DOTTED = "\u0130tem"
ROWS = (
    ("alpha", "medium"), ("Érin", "medium"), ("mmm", "low"), ("Zed", "medium"),
    ("erin", "medium"), ("zzz", "critical"), ("baclup", "medium"), (KELVIN, "medium"),
    ("item", "medium"), (DOTTED, "medium"), ("backup", "medium"),
)


def add_asset(conn, name, criticality):
    conn.execute(
        "INSERT INTO assets(name, kind, criticality, data_tags, addresses, owner, description,"
        " synthetic, created_at, updated_at, updated_by)"
        " VALUES (?, 'server', ?, '[]', '[]', NULL, 'synthetic labelled', 1, ?, ?, 'test')",
        (name, criticality, TS, TS))


def fill(conn, rows):
    for name, criticality in rows:
        add_asset(conn, name, criticality)


def names_indexed(conn, before, after):
    seen = []
    real = assets.index

    def wrapped(inventory):
        seen.append([(a["name"], a["criticality"]) for a in inventory])
        return real(inventory)

    assets.index = wrapped
    try:
        assets.change_evidence(conn, before, after)
    finally:
        assets.index = real
    return seen[0]


class AssetReweighOrderTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_reweigh_matches_list_assets_and_keeps_lookalikes_in_place(self):
        fill(self.conn, ROWS)
        stored = [(a["name"], a["criticality"]) for a in assets.list_assets(self.conn)]
        zed = next(a for a in assets.list_assets(self.conn) if a["name"] == "Zed")
        ordered = names_indexed(self.conn, zed, {**zed, "description": "synthetic labelled review"})
        self.assertEqual(ordered, stored)
        names = [name for name, _ in ordered]
        self.assertEqual(names, [
            "zzz", "alpha", "backup", "baclup", KELVIN, "erin", "item", "Zed", "Érin", DOTTED, "mmm"])
        self.assertLess(names.index("baclup"), names.index(KELVIN))
        self.assertLess(names.index("Zed"), names.index(DOTTED))
        self.assertLess(names.index("erin"), names.index("Érin"))
        self.assertEqual(names[names.index(KELVIN)], KELVIN)
        self.assertEqual(names[names.index(DOTTED)], DOTTED)

    def test_a_proposed_name_lands_where_list_assets_would_store_it(self):
        fill(self.conn, ROWS)
        other = connect(":memory:")
        init_schema(other)
        self.addCleanup(other.close)
        fill(other, ROWS + (("Beta", "medium"),))
        proposed = {"id": None, "name": "Beta", "criticality": "medium", "addresses": [], "data_tags": []}
        self.assertEqual(
            [name for name, _ in names_indexed(self.conn, None, proposed)],
            [a["name"] for a in assets.list_assets(other)])

    def test_insert_order_does_not_change_the_list(self):
        lists = []
        for order in (ROWS, tuple(reversed(ROWS))):
            conn = connect(":memory:")
            init_schema(conn)
            self.addCleanup(conn.close)
            fill(conn, order)
            row = next(a for a in assets.list_assets(conn) if a["name"] == "Zed")
            lists.append(names_indexed(conn, row, {**row, "owner": "lab"}))
            self.assertEqual(
                [name for name, _ in lists[-1]],
                [a["name"] for a in assets.list_assets(conn)])
        self.assertEqual(lists[0], lists[1])
