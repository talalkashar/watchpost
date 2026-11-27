"""An empty hunt timechart names the query and the bucket instead of a blank chart."""

import json
import re
import shutil
import subprocess
import unittest
from datetime import datetime, timezone
from pathlib import Path

from watchpost import hunt

from tests.test_hunt_stats import memory_db

STATIC = Path(__file__).resolve().parent.parent / "static"
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class TimechartSpanTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text}, now=NOW)

    def test_a_miss_with_no_window_names_the_span_and_returns_no_rows(self):
        query = "user:nobody | timechart span=1h"
        data = self.run_q(query)
        self.assertEqual(data["rows"], [])
        self.assertEqual(data["span"], "1h")
        self.assertEqual(data["query"], query)
        self.assertEqual(data["note"], f"No events match {query} in 1h buckets.")

    def test_a_window_with_no_events_is_all_zero_buckets(self):
        query = "user:nobody last:6h | timechart span=15m"
        data = self.run_q(query)
        self.assertEqual(data["span"], "15m")
        self.assertGreater(len(data["rows"]), 0)
        self.assertTrue(all(count == 0 for row in data["rows"] for count in row[1:]))
        self.assertEqual(data["note"], f"No events match {query} in 15m buckets.")

    def test_a_by_chart_with_no_events_still_names_the_query(self):
        query = "user:nobody last:1h | timechart span=15m by host"
        data = self.run_q(query)
        self.assertGreater(len(data["rows"]), 0)
        self.assertTrue(all(not row[1:] or all(count == 0 for count in row[1:]) for row in data["rows"]))
        self.assertEqual(data["note"], f"No events match {query} in 15m buckets.")

    def test_a_hit_keeps_its_span_and_omits_the_note(self):
        data = self.run_q("event_type:auth_failure | timechart span=1d count")
        self.assertEqual(data["span"], "1d")
        self.assertTrue(any(count > 0 for row in data["rows"] for count in row[1:]))
        self.assertNotIn("note", data)

    def test_a_zero_bucket_beside_a_hit_omits_the_note(self):
        data = self.run_q("event_type:auth_failure | timechart span=1h count")
        self.assertIn(0, [row[1] for row in data["rows"]])
        self.assertTrue(any(row[1] > 0 for row in data["rows"]))
        self.assertNotIn("note", data)
        series = self.run_q("event_type:auth_failure | timechart span=1h by user")
        self.assertTrue(any(count > 0 for row in series["rows"] for count in row[1:]))
        self.assertNotIn("note", series)

    def test_stats_and_top_do_not_add_a_note(self):
        for query in ("user:nobody | stats count", "user:nobody | top user"):
            with self.subTest(query=query):
                self.assertNotIn("note", self.run_q(query))

    def test_the_docs_name_the_empty_timechart_note(self):
        root = Path(__file__).resolve().parent.parent
        reference = (root / "docs" / "REFERENCE.md").read_text()
        api = (root / "docs" / "API.md").read_text()
        for text in (reference, api):
            self.assertIn("No events match <query> in <span> buckets.", text)
            self.assertIn("every bucket count", text)


class TimechartEmptyNoteTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def note(self, data):
        const_line = re.search(r"^const HUNT_TIMECHART_SPANS = \[.*\];$", self.app, re.M)
        self.assertIsNotNone(const_line)
        script = const_line.group(0) + "\n" + function_body(self.app, "huntTimechartEmpty") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(huntTimechartEmpty(input)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps(data),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_an_empty_result_names_the_query_and_the_bucket(self):
        query = "user:nobody | timechart span=1h"
        self.assertEqual(
            self.note({"query": query, "span": "1h", "rows": []}),
            "No events match user:nobody | timechart span=1h in 1h buckets.")
        zeros = {"query": "user:nobody last:6h | timechart span=15m", "span": "15m",
                 "rows": [["2026-10-07T06:00:00.000Z", 0], ["2026-10-07T06:15:00.000Z", 0]]}
        self.assertEqual(
            self.note(zeros),
            "No events match user:nobody last:6h | timechart span=15m in 15m buckets.")
        for span in ("5m", "6h", "1d"):
            with self.subTest(span=span):
                self.assertIn(f"in {span} buckets.", self.note({"query": f"| timechart span={span}", "span": span, "rows": []}))

    def test_a_hit_and_a_partial_zero_add_no_sentence(self):
        hit = {"query": "event_type:auth_failure | timechart span=1h", "span": "1h",
               "rows": [["2026-10-07T08:00:00.000Z", 2], ["2026-10-07T09:00:00.000Z", 0]]}
        self.assertEqual(self.note(hit), "")
        series = {"query": "| timechart span=1h by user", "span": "1h",
                  "rows": [["2026-10-07T10:00:00.000Z", 0, 3]]}
        self.assertEqual(self.note(series), "")
        self.assertEqual(self.note({"query": "user:a | timechart span=1h", "span": "1h", "rows": [["t", "4"]]}), "")

    def test_a_missing_query_or_span_stays_generic(self):
        for data in (
            {"span": "1h", "rows": []},
            {"query": "   ", "span": "1h", "rows": []},
            {"query": "user:nobody | timechart span=1h", "span": "2h", "rows": []},
            {"query": "user:nobody | timechart span=1h", "rows": []},
            None,
        ):
            with self.subTest(data=data):
                self.assertEqual(self.note(data), "No matching events.")

    def test_the_chart_shows_the_sentence_and_skips_the_svg(self):
        body = function_body(self.app, "huntTimechart")
        self.assertIn("huntTimechartEmpty(data)", body)
        self.assertLess(body.index("huntTimechartEmpty(data)"), body.index('svgEl("svg"'))
        self.assertIn('id: "hunt-timechart-empty"', body)
        self.assertIn('role: "status"', body)
        self.assertNotIn("No matching events.", body)


if __name__ == "__main__":
    unittest.main()
