"""GET /api/entities folds kind onto the catalog spelling.

`kind=User` is `user`. `HOST` is `host`. `SRC_IP` is `src_ip`.
An unknown kind stays 400 and names the three kinds. A non-ASCII lookalike
does not fold. The path stays the three lowercase kinds.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema
from watchpost.queries import QueryError

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"


class EntityKindCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        event = add_event(self.conn, ANCHOR, user="alice", src_ip="203.0.113.9", host="web01")
        add_alert(self.conn, "high", ANCHOR, [event])

    def values(self, kind):
        return [(row["kind"], row["value"]) for row in entities.list_entities(self.conn, {"kind": kind})["entities"]]

    def test_kind_folds_onto_the_catalog_spelling(self):
        self.assertEqual(self.values("User"), [("user", "alice")])
        self.assertEqual(self.values("HOST"), [("host", "web01")])
        self.assertEqual(self.values("SRC_IP"), [("src_ip", "203.0.113.9")])
        self.assertEqual(self.values("Src_Ip"), [("src_ip", "203.0.113.9")])
        self.assertEqual(
            {(row["kind"], row["value"]) for row in entities.list_entities(self.conn, {})["entities"]},
            {("user", "alice"), ("src_ip", "203.0.113.9"), ("host", "web01")})

    def test_an_unknown_kind_stays_invalid(self):
        for bad in ("planet", "users", "src-ip", "Usér", "host ", "Hıst"):
            with self.subTest(kind=bad):
                with self.assertRaises(QueryError) as ctx:
                    entities.list_entities(self.conn, {"kind": bad})
                self.assertEqual(str(ctx.exception), "kind must be one of user, src_ip, host")
                self.assertEqual(ctx.exception.status, 400)

    def test_the_detail_path_stays_the_lowercase_kind(self):
        with self.assertRaises(QueryError) as ctx:
            entities.get_entity(self.conn, "User", "alice")
        self.assertEqual((ctx.exception.status, str(ctx.exception)), (404, "entity kind not found"))
        self.assertEqual(entities.get_entity(self.conn, "user", "alice")["value"], "alice")

    def test_the_docs_name_the_kind_fold(self):
        api = API.read_text()
        reference = REFERENCE.read_text()
        self.assertIn("`User`, `HOST`, and `SRC_IP` are those three", api)
        self.assertIn("`User` is not a path", api)
        self.assertIn("`User` is `user`", reference)
        self.assertIn("The entity path stays those three lowercase kinds", reference)


class EntityKindApiTests(ServerTestCase):
    def test_the_query_folds_and_the_path_does_not(self):
        with sqlite3.connect(self.db_path) as db:
            event = add_event(db, ANCHOR, user="alice", src_ip="203.0.113.9", host="web01")
            add_alert(db, "high", ANCHOR, [event])
        viewer = self.client("viewer")
        status, body, _ = viewer.get("/api/entities?kind=User")
        self.assertEqual(status, 200, body)
        self.assertEqual([(row["kind"], row["value"]) for row in body["entities"]], [("user", "alice")])
        hosts = viewer.get("/api/entities?kind=HOST")[1]["entities"]
        self.assertEqual([(row["kind"], row["value"]) for row in hosts], [("host", "web01")])
        addresses = viewer.get("/api/entities?kind=SRC_IP")[1]["entities"]
        self.assertEqual([(row["kind"], row["value"]) for row in addresses], [("src_ip", "203.0.113.9")])

        status, body, headers = viewer.get("/api/entities?kind=planet")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "kind must be one of user, src_ip, host")
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, body, headers = viewer.get("/api/entities/User/alice")
        self.assertEqual((status, body["error"]), (404, "not found"))
        self.assertEqual(headers["Cache-Control"], "no-store")
        detail = viewer.get("/api/entities/user/alice")
        self.assertEqual(detail[0], 200)
        self.assertEqual(detail[1]["value"], "alice")
