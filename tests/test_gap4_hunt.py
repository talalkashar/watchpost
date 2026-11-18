"""Edges of parse, parse_stage, bytes_bound, bytes_matches, and save_search.

Ordinary hunt queries are covered elsewhere. These tests cover empty input,
non-text input, the length boundary, case folding, a dropped pipeline stage,
aggregate caps, and saved-search text limits.
"""

import unittest

from watchpost import hunt
from watchpost.db import connect, init_schema
from watchpost.normalize import MAX_BYTES


class ParseEdgeTests(unittest.TestCase):
    def test_non_text_and_empty_input(self):
        for value in (None, 0, b"user:a", ["user:a"]):
            with self.subTest(value=value):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.parse(value)
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(str(caught.exception), "query must be text")
        self.assertEqual(hunt.parse(""), [])
        self.assertEqual(hunt.parse(" \t\n"), [])

    def test_length_boundary_case_and_a_dropped_stage(self):
        self.assertEqual(hunt.parse("x" * hunt.MAX_QUERY_LENGTH), [{
            "field": "message", "value": "x" * hunt.MAX_QUERY_LENGTH, "negate": False, "quoted": False,
        }])
        self.assertEqual(
            [(t["field"], t["value"], t["quoted"]) for t in hunt.parse("USER:Alice\nHOST:web01")],
            [("user", "Alice", False), ("host", "web01", False)])
        self.assertEqual(
            [(t["field"], t["value"]) for t in hunt.parse("  user:alice | stats count by host")],
            [("user", "alice")])
        self.assertEqual(hunt.parse("| stats count"), [])
        # AND is not a term, so twenty words joined by AND stay inside the cap.
        self.assertEqual(
            [t["value"] for t in hunt.parse(" AND ".join(["x"] * hunt.MAX_TERMS))],
            ["x"] * hunt.MAX_TERMS)
        self.assertEqual(
            [(t["field"], t["value"]) for t in hunt.parse("AND AND user:a AND")],
            [("user", "a")])

    def test_malformed_quotes_and_words_that_only_look_like_syntax(self):
        for text, message in (('""', "message: needs a value"), ('user:""', "user: needs a value"),
                              ('"abc\\', "unterminated quote")):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.parse(text)
                self.assertIn(message, str(caught.exception))
        # A quoted OR is a message word. The bare keyword is what parse refuses.
        self.assertEqual(
            [(t["field"], t["value"]) for t in hunt.parse('user:a "OR" user:b')],
            [("user", "a"), ("message", "OR"), ("user", "b")])
        self.assertEqual(
            [(t["field"], t["value"]) for t in hunt.parse("or user:a")],
            [("message", "or"), ("user", "a")])
        # Value checks belong to compile. parse keeps the text.
        self.assertEqual(
            [t["value"] for t in hunt.parse("event_type:nope dest_port:70000 last:400d")],
            ["nope", "70000", "400d"])


class ParseStageEdgeTests(unittest.TestCase):
    def test_empty_stage(self):
        for text in ("", "   ", "\n\t"):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.parse_stage(text)
                self.assertEqual(str(caught.exception),
                                 "| must be followed by a command: stats, top or timechart")

    def test_commands_fields_and_span_fold_ascii_case(self):
        stage = hunt.parse_stage("STATS COUNT, DC(User), COUNT(DISTINCT Host) BY SRC_IP, user")
        self.assertEqual(stage, {
            "command": "stats",
            "aggregates": [("count", None, None), ("dc(user)", "user", "user"), ("dc(host)", "host", "host")],
            "by": [("src_ip", "src_ip"), ("user", "user")],
        })
        self.assertEqual(hunt.parse_stage("stats count by USER")["by"], [("user", "user")])
        self.assertEqual(hunt.parse_stage("Top 1 src_ip"),
                         {"command": "top", "limit": 1, "by": [("src_ip", "src_ip")]})
        self.assertEqual(hunt.parse_stage("TOP 100 host"),
                         {"command": "top", "limit": 100, "by": [("host", "host")]})
        self.assertEqual(hunt.parse_stage("TIMECHART SPAN=1H COUNT BY USER"),
                         {"command": "timechart", "span": "1h", "by": [("user", "user")]})

    def test_duplicate_aggregates_and_a_repeated_span(self):
        for text in ("stats count, count", "stats dc(user), count(distinct user)", "stats DC(USER), dc(user)",
                     "stats count, dc(user), dc(host), dc(src_ip)"):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.parse_stage(text)
                self.assertEqual(str(caught.exception), "stats takes at most 3 different aggregates")
        for text in ("timechart span=1h span=1h", "timechart span=1h span=15m"):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.parse_stage(text)
                self.assertIn("given once", str(caught.exception))
                self.assertIn("1h", str(caught.exception))


class BytesBoundTests(unittest.TestCase):
    def test_operator_boundaries_and_non_text(self):
        self.assertEqual(
            [hunt.bytes_bound(op + "0") for op in (">=", ">", "<=", "<", "=")],
            [(">=", 0), (">", 0), ("<=", 0), ("<", 0), ("=", 0)])
        # The longer operator has to win. >=10 is not > with a value of =10.
        self.assertEqual(hunt.bytes_bound(">=10"), (">=", 10))
        self.assertEqual(hunt.bytes_bound(">10"), (">", 10))
        self.assertEqual(hunt.bytes_bound(f"={MAX_BYTES}"), ("=", MAX_BYTES))
        self.assertEqual(hunt.bytes_bound(f"<={MAX_BYTES}"), ("<=", MAX_BYTES))
        self.assertEqual(hunt.bytes_bound(f">{MAX_BYTES}"), (">", MAX_BYTES))
        for value in (None, 0, "", b">=1"):
            with self.subTest(value=value):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.bytes_bound(value)
                self.assertIn("followed by an integer from 0 to", str(caught.exception))
                self.assertIn(str(MAX_BYTES), str(caught.exception))


class BytesMatchTests(unittest.TestCase):
    def test_zero_and_non_integers(self):
        # A count of 0 meets =, >=, and <=, and misses a strict comparison with 0.
        self.assertTrue(hunt.bytes_matches(0, "=", 0))
        self.assertTrue(hunt.bytes_matches(0, ">=", 0))
        self.assertTrue(hunt.bytes_matches(0, "<=", 0))
        self.assertFalse(hunt.bytes_matches(0, ">", 0))
        self.assertFalse(hunt.bytes_matches(0, "<", 0))
        # bool is an int subclass. False == 0 must still not match.
        self.assertFalse(hunt.bytes_matches(False, "=", 0))
        self.assertFalse(hunt.bytes_matches(False, ">=", 0))
        self.assertFalse(hunt.bytes_matches(100.0, "=", 100))
        self.assertFalse(hunt.bytes_matches("100", ">=", 100))
        self.assertFalse(hunt.bytes_matches(-1, ">=", 0))
        self.assertTrue(hunt.bytes_matches(-1, "<", 0))

    def test_a_bad_operator_is_refused_before_the_count_is_read(self):
        for count in (None, 0, False):
            with self.subTest(count=count):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.bytes_matches(count, "!=", 0)
                self.assertEqual(str(caught.exception), "bytes must be one of >=, >, <=, < or =")


class SaveSearchEdgeTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)

    def test_non_text_missing_fields_and_a_bad_stage_insert_nothing(self):
        cases = (
            ({"name": 1, "query": "user:a"}, "name must be text"),
            ({"name": "x", "query": "user:a", "description": 5}, "description must be text"),
            ({}, "name is required"),
            ({"name": "x"}, "query is required"),
            ({"name": "x", "query": "| top"}, "top takes one field"),
        )
        for data, message in cases:
            with self.subTest(data=data):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.save_search(self.conn, data, "analyst")
                self.assertEqual(caught.exception.status, 400)
                self.assertIn(message, str(caught.exception))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM saved_searches").fetchone()[0], 0)

    def test_text_is_stripped_and_the_exact_limits_are_kept(self):
        saved = hunt.save_search(self.conn, {
            "name": "  " + "n" * hunt.NAME_MAX,
            "query": "  host:web* last:24h  ",
            "description": "\n" + "d" * hunt.DESCRIPTION_MAX + " ",
        }, "Analyst")
        self.assertEqual(saved["name"], "n" * hunt.NAME_MAX)
        self.assertEqual(saved["query"], "host:web* last:24h")
        self.assertEqual(saved["description"], "d" * hunt.DESCRIPTION_MAX)
        self.assertEqual(saved["owner"], "Analyst")
        blank = hunt.save_search(self.conn, {"name": "plain", "query": " user:a ", "description": " \t "}, "Analyst")
        self.assertEqual(blank["query"], "user:a")
        self.assertIsNone(blank["description"])
        omitted = hunt.save_search(self.conn, {"name": "omit", "query": "user:b"}, "Analyst")
        self.assertIsNone(omitted["description"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM saved_searches").fetchone()[0], 3)
