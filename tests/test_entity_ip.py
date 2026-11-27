"""A source-IP entity page uses the address form ingest stores.

`2001:DB8::1` matches events stored as `2001:db8::1`, and `value` is that form.
A row stored under another spelling stays a different entity. Anything that is
not one address is 400. User and host folding stay as they are.
"""

import sqlite3
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema
from watchpost.queries import QueryError

STORED = "2001:db8::1"
EXPANDED = "2001:0db8:0000:0000:0000:0000:0000:0001"


class EntityIpTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_either_spelling_is_the_stored_address(self):
        stored = add_event(self.conn, ANCHOR, src_ip=STORED)
        other = add_event(self.conn, ANCHOR, src_ip="203.0.113.9")
        raw = add_event(self.conn, ANCHOR, src_ip="2001:DB8::1")
        kept = add_alert(self.conn, "high", ANCHOR, [stored])
        add_alert(self.conn, "low", ANCHOR, [other])
        raw_alert = add_alert(self.conn, "medium", ANCHOR, [raw])

        for spelling in ("2001:DB8::1", EXPANDED, STORED):
            detail = entities.get_entity(self.conn, "src_ip", spelling)
            self.assertEqual(detail["value"], STORED)
            self.assertEqual(detail["event_count"], 1)
            self.assertEqual(detail["score"], 20.0)
            self.assertEqual({c["alert_id"] for c in detail["contributions"]}, {kept})
            self.assertEqual(detail["alerts_by_day"]["days"], [{"day": "2026-09-15", "count": 1}])

        # Inserted past ingest. Equality matches only the stored form.
        leftover = entities.get_entity(self.conn, "src_ip", "2001:db8::2")
        self.assertEqual(leftover["value"], "2001:db8::2")
        self.assertEqual(leftover["event_count"], 0)
        listed = [r["value"] for r in entities.list_entities(self.conn, {"kind": "src_ip"})["entities"]]
        self.assertIn(STORED, listed)
        self.assertIn("2001:DB8::1", listed)
        self.assertEqual(entities.get_entity(self.conn, "src_ip", "2001:DB8::1")["score"], 20.0)
        self.assertEqual({c["alert_id"] for c in entities.get_entity(
            self.conn, "src_ip", "2001:DB8::1")["contributions"]}, {kept})
        self.assertNotIn(raw_alert, {c["alert_id"] for c in entities.get_entity(
            self.conn, "src_ip", "2001:DB8::1")["contributions"]})

    def test_a_bad_address_is_400_and_other_kinds_stay(self):
        add_event(self.conn, ANCHOR, user="Alice", host="WEB01", src_ip=STORED)
        for spelling in ("not-an-ip", "999.1.1.1", "2001:DB8*", "2001:db8::1/64"):
            with self.subTest(spelling=spelling):
                with self.assertRaises(QueryError) as caught:
                    entities.get_entity(self.conn, "src_ip", spelling)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn("src_ip must be a valid IP address", str(caught.exception))
        self.assertEqual(entities.get_entity(self.conn, "user", "Alice")["value"], "alice")
        self.assertEqual(entities.get_entity(self.conn, "host", "WEB01")["value"], "web01")

    def test_the_comparison_binds_the_stored_form(self):
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append((sql, args))
            return real_execute(sql, args)

        self.conn.execute = execute
        entities.get_entity(self.conn, "src_ip", "2001:DB8::1")
        ip_sql = [(sql, args) for sql, args in captured if "e.src_ip = ?" in sql]
        self.assertTrue(ip_sql)
        self.assertTrue(all("e.src_ip = ?" in sql and "COLLATE" not in sql for sql, _ in ip_sql))
        self.assertTrue(all(args == (STORED,) for _, args in ip_sql))

    def test_the_docs_name_the_stored_form(self):
        root = Path(__file__).resolve().parent.parent
        for path in (root / "docs" / "API.md", root / "docs" / "REFERENCE.md"):
            text = path.read_text()
            self.assertIn("`2001:DB8::1` matches `2001:db8::1`", text)
            self.assertIn("400", text)


class EntityIpApiTests(ServerTestCase):
    def test_either_spelling_returns_the_stored_address(self):
        with sqlite3.connect(self.db_path) as db:
            stored = add_event(db, ANCHOR, src_ip=STORED)
            add_alert(db, "high", ANCHOR, [stored])
        viewer = self.client("viewer")
        status, detail, _ = viewer.get("/api/entities/src_ip/" + quote("2001:DB8::1", safe=""))
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail["value"], STORED)
        self.assertEqual(detail["event_count"], 1)
        self.assertEqual(detail["score"], 20.0)
        expanded = viewer.get("/api/entities/src_ip/" + quote(EXPANDED, safe=""))
        self.assertEqual(expanded[0], 200, expanded[1])
        self.assertEqual(expanded[1]["value"], STORED)
        self.assertEqual(expanded[1]["score"], 20.0)

        status, body, headers = viewer.get("/api/entities/src_ip/" + quote("999.1.1.1", safe=""))
        self.assertEqual(status, 400)
        self.assertIn("src_ip must be a valid IP address", body["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, body, headers = viewer.get("/api/entities/src_ip/" + quote("not-an-ip", safe=""))
        self.assertEqual(status, 400, body)
        self.assertIn("src_ip must be a valid IP address", body["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
