"""Host entity risk folds ASCII case. WEB01 and web01 are one score; the value is lowercase.

COLLATE NOCASE folds ASCII letters only, the same way event search matches a host.
A non-ASCII letter stays, so Érin-host and érin-host remain two hosts.
"""

import sqlite3
import unittest
from urllib.parse import quote

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema


class HostEntityCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_ascii_spellings_are_one_host_and_the_value_is_lowercase(self):
        web = add_event(self.conn, ANCHOR, host="WEB01")
        folded = add_event(self.conn, ANCHOR, host="web01")
        mixed = add_event(self.conn, ANCHOR, host="Db01")
        upper = add_alert(self.conn, "high", ANCHOR, [web])
        lower = add_alert(self.conn, "medium", ANCHOR, [folded])
        other = add_alert(self.conn, "low", ANCHOR, [mixed])

        for spelling in ("WEB01", "web01", "Web01"):
            detail = entities.get_entity(self.conn, "host", spelling)
            self.assertEqual(detail["value"], "web01")
            self.assertEqual(detail["score"], 30.0)
            self.assertEqual(detail["event_count"], 2)
            self.assertEqual({c["alert_id"] for c in detail["contributions"]}, {upper, lower})

        db = entities.get_entity(self.conn, "host", "DB01")
        self.assertEqual(db["value"], "db01")
        self.assertEqual({c["alert_id"] for c in db["contributions"]}, {other})

        hosts = [r for r in entities.list_entities(self.conn, {"kind": "host"})["entities"]]
        self.assertEqual(sorted(r["value"] for r in hosts), ["db01", "web01"])
        self.assertEqual({r["value"]: r["score"] for r in hosts}, {"web01": 30.0, "db01": 5.0})

    def test_a_non_ascii_letter_stays_two_hosts(self):
        first = add_event(self.conn, ANCHOR, host="Érin-host")
        second = add_event(self.conn, ANCHOR, host="érin-host")
        add_alert(self.conn, "high", ANCHOR, [first])
        add_alert(self.conn, "low", ANCHOR, [second])

        upper = entities.get_entity(self.conn, "host", "Érin-host")
        lower = entities.get_entity(self.conn, "host", "érin-host")
        self.assertEqual(upper["value"], "Érin-host")
        self.assertEqual(lower["value"], "érin-host")
        self.assertEqual(upper["event_count"], 1)
        self.assertEqual(lower["event_count"], 1)
        self.assertEqual(upper["score"], 20.0)
        self.assertEqual(lower["score"], 5.0)
        # ASCII letters in the same name still fold. É itself does not.
        mixed = entities.get_entity(self.conn, "host", "WEB-Érin")
        self.assertEqual(mixed["value"], "web-Érin")
        self.assertEqual(mixed["event_count"], 0)

    def test_day_bars_include_both_ascii_spellings(self):
        early = add_event(self.conn, "2026-09-14T12:00:00.000Z", host="WEB01")
        later = add_event(self.conn, ANCHOR, host="web01")
        add_alert(self.conn, "high", "2026-09-14T12:00:00.000Z", [early])
        add_alert(self.conn, "low", ANCHOR, [later])
        series = entities.get_entity(self.conn, "host", "Web01")["alerts_by_day"]
        self.assertEqual(series["days"], [
            {"day": "2026-09-14", "count": 1},
            {"day": "2026-09-15", "count": 1},
        ])

    def test_the_host_comparison_is_nocase_and_an_ip_is_not(self):
        add_event(self.conn, ANCHOR, host="WEB01", src_ip="203.0.113.9")
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append(sql)
            return real_execute(sql, args)

        self.conn.execute = execute
        entities.get_entity(self.conn, "host", "WEB01")
        host_sql = [sql for sql in captured if "e.host = ?" in sql]
        self.assertTrue(host_sql)
        self.assertTrue(all("e.host = ? COLLATE NOCASE" in sql for sql in host_sql))
        self.assertFalse(any("src_ip COLLATE" in sql for sql in captured))

        ip = entities.get_entity(self.conn, "src_ip", "203.0.113.9")
        self.assertEqual(ip["value"], "203.0.113.9")


class HostEntityApiTests(ServerTestCase):
    def test_either_spelling_returns_the_lowercase_host(self):
        with sqlite3.connect(self.db_path) as db:
            upper = add_event(db, ANCHOR, host="WEB01")
            lower = add_event(db, ANCHOR, host="web01")
            add_alert(db, "high", ANCHOR, [upper])
            add_alert(db, "medium", ANCHOR, [lower])
        viewer = self.client("viewer")
        status, detail, _ = viewer.get("/api/entities/host/" + quote("WEB01"))
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail["value"], "web01")
        self.assertEqual(detail["event_count"], 2)
        self.assertEqual(detail["score"], 30.0)
        listed = viewer.get("/api/entities?kind=host")[1]["entities"]
        self.assertEqual([row["value"] for row in listed], ["web01"])
        self.assertEqual(viewer.get("/api/entities/host/" + quote("web01"))[1]["score"], 30.0)
