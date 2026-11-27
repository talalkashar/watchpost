"""User entity risk folds ASCII case. Erin, ERIN, and erin are one score; the value is erin.

COLLATE NOCASE folds ASCII letters only. str.lower also folds É, so ÉRIN and érin
used to share the list key érin while the detail lookup missed the ÉRIN rows.
Those two stay two accounts. The returned value is the folded key.
"""

import sqlite3
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from tests.test_entities import ANCHOR, add_alert, add_event
from watchpost import entities
from watchpost.db import connect, init_schema


class UserEntityCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_ascii_spellings_are_one_account_and_the_value_is_lowercase(self):
        upper = add_event(self.conn, ANCHOR, user="ERIN")
        lower = add_event(self.conn, ANCHOR, user="erin")
        mixed = add_event(self.conn, ANCHOR, user="Erin")
        other = add_event(self.conn, ANCHOR, user="Bob")
        high = add_alert(self.conn, "high", ANCHOR, [upper])
        medium = add_alert(self.conn, "medium", ANCHOR, [lower])
        low = add_alert(self.conn, "low", ANCHOR, [mixed])
        bob = add_alert(self.conn, "low", ANCHOR, [other])

        for spelling in ("ERIN", "erin", "Erin"):
            detail = entities.get_entity(self.conn, "user", spelling)
            self.assertEqual(detail["value"], "erin")
            self.assertEqual(detail["score"], 35.0)
            self.assertEqual(detail["event_count"], 3)
            self.assertEqual({c["alert_id"] for c in detail["contributions"]}, {high, medium, low})

        listed = [r for r in entities.list_entities(self.conn, {"kind": "user"})["entities"]]
        self.assertEqual(sorted(r["value"] for r in listed), ["bob", "erin"])
        self.assertEqual({r["value"]: r["score"] for r in listed}, {"erin": 35.0, "bob": 5.0})
        self.assertEqual({c["alert_id"] for c in next(r for r in listed if r["value"] == "erin")["contributions"]},
                         {high, medium, low})
        self.assertEqual({c["alert_id"] for c in entities.get_entity(self.conn, "user", "BOB")["contributions"]},
                         {bob})

    def test_a_non_ascii_letter_stays_two_accounts(self):
        first = add_event(self.conn, ANCHOR, user="ÉRIN")
        second = add_event(self.conn, ANCHOR, user="érin")
        upper = add_alert(self.conn, "high", ANCHOR, [first])
        lower = add_alert(self.conn, "low", ANCHOR, [second])

        accented = entities.get_entity(self.conn, "user", "ÉRIN")
        plain = entities.get_entity(self.conn, "user", "érin")
        self.assertEqual(accented["value"], "Érin")
        self.assertEqual(plain["value"], "érin")
        self.assertEqual(accented["event_count"], 1)
        self.assertEqual(plain["event_count"], 1)
        self.assertEqual({c["alert_id"] for c in accented["contributions"]}, {upper})
        self.assertEqual({c["alert_id"] for c in plain["contributions"]}, {lower})
        self.assertEqual(accented["score"], 20.0)
        self.assertEqual(plain["score"], 5.0)
        # ASCII letters in the same name still fold. É itself does not.
        self.assertEqual(entities.get_entity(self.conn, "user", "Érin")["value"], "Érin")
        self.assertEqual(entities.get_entity(self.conn, "user", "Érin")["event_count"], 1)

        accounts = [r for r in entities.list_entities(self.conn, {"kind": "user"})["entities"]]
        self.assertEqual(sorted(r["value"] for r in accounts), ["Érin", "érin"])
        self.assertEqual({r["value"]: r["score"] for r in accounts}, {"Érin": 20.0, "érin": 5.0})

    def test_day_bars_include_both_ascii_spellings(self):
        early = add_event(self.conn, "2026-09-14T12:00:00.000Z", user="ERIN")
        later = add_event(self.conn, ANCHOR, user="erin")
        add_alert(self.conn, "high", "2026-09-14T12:00:00.000Z", [early])
        add_alert(self.conn, "low", ANCHOR, [later])
        series = entities.get_entity(self.conn, "user", "Erin")["alerts_by_day"]
        self.assertEqual(series["days"], [
            {"day": "2026-09-14", "count": 1},
            {"day": "2026-09-15", "count": 1},
        ])

    def test_the_lookup_binds_the_folded_key(self):
        add_event(self.conn, ANCHOR, user="ERIN")
        captured = []
        real_execute = self.conn.execute

        def execute(sql, args=()):
            captured.append((sql, args))
            return real_execute(sql, args)

        self.conn.execute = execute
        entities.get_entity(self.conn, "user", "ERIN")
        user_sql = [(sql, args) for sql, args in captured if "e.user = ?" in sql]
        self.assertTrue(user_sql)
        self.assertTrue(all("e.user = ? COLLATE NOCASE" in sql for sql, _ in user_sql))
        self.assertTrue(all(args == ("erin",) for _, args in user_sql))

    def test_the_docs_name_the_ascii_fold(self):
        root = Path(__file__).resolve().parent.parent
        for path in (root / "docs" / "API.md", root / "docs" / "REFERENCE.md"):
            text = path.read_text()
            self.assertIn("`Érin` and `érin` stay two", text)
            self.assertIn("`erin`", text)


class UserEntityApiTests(ServerTestCase):
    def test_either_spelling_returns_the_folded_account(self):
        with sqlite3.connect(self.db_path) as db:
            upper = add_event(db, ANCHOR, user="ERIN")
            lower = add_event(db, ANCHOR, user="erin")
            accented = add_event(db, ANCHOR, user="ÉRIN")
            other = add_event(db, ANCHOR, user="érin")
            add_alert(db, "high", ANCHOR, [upper])
            add_alert(db, "medium", ANCHOR, [lower])
            add_alert(db, "low", ANCHOR, [accented])
            add_alert(db, "info", ANCHOR, [other])
        viewer = self.client("viewer")
        status, detail, _ = viewer.get("/api/entities/user/" + quote("ERIN"))
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail["value"], "erin")
        self.assertEqual(detail["event_count"], 2)
        self.assertEqual(detail["score"], 30.0)
        accented_page = viewer.get("/api/entities/user/" + quote("ÉRIN"))[1]
        self.assertEqual(accented_page["value"], "Érin")
        self.assertEqual(accented_page["event_count"], 1)
        self.assertEqual(accented_page["score"], 5.0)
        other_page = viewer.get("/api/entities/user/" + quote("érin"))[1]
        self.assertEqual(other_page["value"], "érin")
        self.assertEqual(other_page["event_count"], 1)
        listed = viewer.get("/api/entities?kind=user")[1]["entities"]
        self.assertEqual(sorted(row["value"] for row in listed), ["erin", "Érin", "érin"])
