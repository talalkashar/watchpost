"""Hunt synthetic: folds ASCII case only, the same four words as event search.

TRUE, False, 0, and 1 still filter. truİe, trüe, and yes stay 400 naming
those four. A promoted saved search uses that same fold. Grouping by
synthetic stays the stored 0 or 1.
"""

import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt, search_rules
from watchpost.db import connect, init_schema
from watchpost.engine import store_batch
from watchpost.queries import QueryError

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
FLAG_ERROR = "synthetic must be 0, 1, true or false"
TS = "2026-10-07T11:00:00.000Z"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    store_batch(conn, [{
        "ts": TS, "source": "lab", "severity": "info", "host": "web01",
        "event_type": "auth_success", "user": "labelled",
        "message": "[SYNTHETIC] labelled login",
    }], [], "lab", "json", "test", synthetic=True)
    store_batch(conn, [{
        "ts": "2026-10-07T11:00:01.000Z", "source": "lab", "severity": "info", "host": "web01",
        "event_type": "auth_success", "user": "plain", "message": "plain login",
    }], [], "lab", "json", "test", synthetic=False)
    return conn


class HuntSyntheticTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, query):
        page = hunt.run(self.conn, {"q": query})
        return sorted(event["user"] for event in page["events"])

    def test_flag_words_filter(self):
        for word in ("1", "true", "True", "TRUE", "tRuE", "0", "false", "False", "FALSE"):
            with self.subTest(word=word):
                where, _args = hunt.compile_query(f"synthetic:{word}")
                self.assertEqual(where, ["synthetic = ?"])
                self.assertNotIn("lower(", where[0])
        for word in ("1", "true", "TRUE", "tRuE"):
            with self.subTest(word=word):
                self.assertEqual(hunt.compile_query(f"synthetic:{word}")[1], [1])
                self.assertEqual(self.users(f"synthetic:{word}"), ["labelled"])
        for word in ("0", "false", "False", "FALSE"):
            with self.subTest(word=word):
                self.assertEqual(hunt.compile_query(f"synthetic:{word}")[1], [0])
                self.assertEqual(self.users(f"synthetic:{word}"), ["plain"])
        self.assertEqual(self.users("NOT synthetic:TRUE"), ["plain"])
        self.assertEqual(self.users("NOT synthetic:0"), ["labelled"])

    def test_other_values_name_the_four_words(self):
        for word in ("yes", "tr\u00fce", "tru\u0130e", "2"):
            with self.subTest(word=word):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(f"synthetic:{word}")
                self.assertEqual(str(caught.exception), FLAG_ERROR)
                self.assertEqual(caught.exception.status, 400)
                for name in ("0", "1", "true", "false"):
                    self.assertIn(name, str(caught.exception))
        self.assertEqual(self.users(""), ["labelled", "plain"])

    def test_grouping_keeps_the_stored_bit(self):
        self.assertEqual(hunt._group_expr("synthetic", "synthetic"), "synthetic")
        page = hunt.run(self.conn, {"q": "| stats count by synthetic"})
        self.assertEqual(page["columns"], ["synthetic", "count"])
        self.assertEqual(page["rows"], [[0, 1], [1, 1]])
        self.assertTrue(all(isinstance(row[0], int) for row in page["rows"]))
        self.assertEqual(page["groups_omitted"], 0)


class SearchRuleSyntheticTests(unittest.TestCase):
    def test_the_promoted_rule_uses_the_same_fold(self):
        rule = search_rules.compile_rule("Labelled logins", "synthetic:TRUE", {
            "group_by": "user", "threshold": 1, "window_minutes": 5, "severity": "low",
        })
        findings = search_rules.run([
            {"id": 1, "ts": TS, "user": "labelled", "synthetic": 1},
            {"id": 2, "ts": TS, "user": "plain", "synthetic": 0},
        ], rule["params"])
        self.assertEqual([f["group_key"] for f in findings], ["labelled"])
        quiet = search_rules.compile_rule("Plain logins", "synthetic:False", {
            "group_by": "user", "threshold": 1, "window_minutes": 5, "severity": "low",
        })
        findings = search_rules.run([
            {"id": 1, "ts": TS, "user": "labelled", "synthetic": 1},
            {"id": 2, "ts": TS, "user": "plain", "synthetic": 0},
        ], quiet["params"])
        self.assertEqual([f["group_key"] for f in findings], ["plain"])

    def test_a_bad_flag_is_the_named_error_not_a_key_error(self):
        for word in ("yes", "tr\u00fce", "tru\u0130e"):
            with self.subTest(word=word):
                with self.assertRaises(search_rules.SearchRuleError) as caught:
                    search_rules.parse_filter(f"synthetic:{word}")
                self.assertEqual(str(caught.exception), FLAG_ERROR)
                term = {"field": "synthetic", "value": word, "negate": False, "quoted": False}
                with self.assertRaises(QueryError) as direct:
                    search_rules._predicate(term)
                self.assertEqual(str(direct.exception), FLAG_ERROR)


class HuntSyntheticApiTests(ServerTestCase):
    def test_hunt_accepts_the_flag_words_and_refuses_the_lookalikes(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": TS, "type": "login", "user": "labelled", "message": "[SYNTHETIC] labelled login"},
        ]})
        self.assertEqual(status, 201, body)
        status, body, _ = client.post("/api/ingest", {"source": "lab", "events": [
            {"ts": TS, "type": "login", "user": "plain", "message": "plain login"},
        ]})
        self.assertEqual(status, 201, body)

        def users(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return sorted(event["user"] for event in data["events"])

        self.assertEqual(users("synthetic:TRUE"), ["labelled"])
        self.assertEqual(users("synthetic:1"), ["labelled"])
        self.assertEqual(users("synthetic:False"), ["plain"])
        self.assertEqual(users("synthetic:0"), ["plain"])

        for word in ("yes", "tr\u00fce", "tru\u0130e"):
            with self.subTest(word=word):
                status, data, headers = client.get("/api/hunt?q=" + quote(f"synthetic:{word}"))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], FLAG_ERROR)
                self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, _ = client.get("/api/hunt?q=" + quote("| stats count by synthetic"))
        self.assertEqual(status, 200, data)
        self.assertEqual(data["rows"], [[0, 1], [1, 1]])

    def test_docs_name_the_ascii_fold(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        self.assertIn("ASCII case folds", hunt_row)
        self.assertIn(FLAG_ERROR, hunt_row)
        self.assertIn("stored 0 or 1", hunt_row)
        fields = next(line for line in REFERENCE.read_text().splitlines() if line.startswith("Fields:"))
        self.assertIn("`TRUE` is `true`", fields)
        self.assertIn(FLAG_ERROR, fields)
        self.assertIn("stored 0 or 1", fields)
