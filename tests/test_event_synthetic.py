"""GET /api/events?synthetic= accepts the hunt flag set.

`0`, `1`, `true`, and `false`, folded on ASCII letters only. Any other
present value is 400 naming those four. An absent parameter stays unfiltered.
"""

import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import queries
from watchpost.db import connect, init_schema
from watchpost.server import ApiError, query_params

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
FLAG_ERROR = "synthetic must be 0, 1, true or false"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = (
        (1, "labelled", "[SYNTHETIC] labelled login"),
        (0, "plain", "plain login"),
    )
    for bit, user, message in rows:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            ("2026-10-07T11:00:00.000Z", "2026-10-07T11:00:00.000Z", "lab", "web01",
             "auth_success", "info", user, message, bit))
    return conn


class EventSyntheticFilterTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, **params):
        page = queries.search_events(self.conn, params)
        return sorted(event["user"] for event in page["events"]), page["total"]

    def test_flag_words_filter_and_an_absent_key_does_not(self):
        for word in ("1", "true", "True", "TRUE", "tRuE"):
            with self.subTest(word=word):
                self.assertEqual(self.users(synthetic=word), (["labelled"], 1))
        for word in ("0", "false", "False", "FALSE"):
            with self.subTest(word=word):
                self.assertEqual(self.users(synthetic=word), (["plain"], 1))
        self.assertEqual(self.users(), (["labelled", "plain"], 2))

    def test_any_other_present_value_is_rejected_and_filters_nothing(self):
        for word in ("yes", "2", "1.0", "", " true", "tr\u00fce", "tru\u0130e", "minimum"):
            with self.subTest(word=word):
                with self.assertRaises(queries.QueryError) as caught:
                    queries.search_events(self.conn, {"synthetic": word})
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), FLAG_ERROR)
                for name in ("0", "1", "true", "false"):
                    self.assertIn(name, str(caught.exception))
        self.assertEqual(queries.search_events(self.conn, {})["total"], 2)

    def test_a_blank_synthetic_reaches_event_search_and_two_blanks_are_repeated(self):
        self.assertEqual(query_params("synthetic="), {"synthetic": ""})
        self.assertEqual(query_params("syn%74hetic="), {"synthetic": ""})
        self.assertEqual(query_params("limit=1"), {"limit": "1"})
        self.assertEqual(query_params("severity="), {})
        with self.assertRaises(ApiError) as caught:
            query_params("synthetic=&synthetic=")
        self.assertEqual(str(caught.exception), "repeated query key 'synthetic'")
        # A real value still wins over a blank copy. The blank is not a second key.
        self.assertEqual(query_params("synthetic=true&synthetic="), {"synthetic": "true"})


class EventSyntheticApiTests(ServerTestCase):
    def test_events_accept_the_flag_words_and_refuse_anything_else(self):
        client = self.client("analyst")
        base = "2026-10-07T12:00:00.000Z"
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": base, "type": "login", "user": "labelled", "message": "[SYNTHETIC] labelled login"},
        ]})
        self.assertEqual(status, 201, body)
        status, body, _ = client.post("/api/ingest", {"source": "lab", "events": [
            {"ts": base, "type": "login", "user": "plain", "message": "plain login"},
        ]})
        self.assertEqual(status, 201, body)

        def users(query):
            status, data, headers = client.get("/api/events?" + query)
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return sorted(event["user"] for event in data["events"])

        self.assertEqual(users("synthetic=true"), ["labelled"])
        self.assertEqual(users("synthetic=" + quote("True")), ["labelled"])
        self.assertEqual(users("synthetic=1"), ["labelled"])
        self.assertEqual(users("synthetic=FALSE"), ["plain"])
        self.assertEqual(users("synthetic=0"), ["plain"])
        self.assertEqual(users("limit=20"), ["labelled", "plain"])

        for word in ("yes", "2", "", "tr\u00fce"):
            with self.subTest(word=word):
                status, data, headers = client.get("/api/events?synthetic=" + quote(word))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], FLAG_ERROR)
                self.assertEqual(headers["Cache-Control"], "no-store")
        status, data, _ = client.get("/api/events?synthetic=&synthetic=")
        self.assertEqual(status, 400, data)
        self.assertEqual(data["error"], "repeated query key 'synthetic'")
        self.assertEqual(users("limit=20"), ["labelled", "plain"])

    def test_api_docs_name_the_four_flag_words(self):
        text = API.read_text()
        row = next(line for line in text.splitlines() if line.startswith("| `synthetic` |"))
        self.assertIn("`0`, `1`, `true`, or `false`", row)
        self.assertIn(FLAG_ERROR, row)
        self.assertIn("An absent parameter stays unfiltered", row)
        self.assertIn("blank `synthetic=`", row)


if __name__ == "__main__":
    unittest.main()
