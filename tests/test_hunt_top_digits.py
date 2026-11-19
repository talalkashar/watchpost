"""Hunt | top accepts ASCII digits only.

| top 10 src_ip stays a limit of 10. | top １０ src_ip is the existing one-field
error, not limit 10. | top ² src_ip and | top ① src_ip are that 400, not a 500.
| top 101 src_ip stays the range error. int() runs only after the token is ASCII digits.
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
HUNT = Path(__file__).resolve().parent.parent / "watchpost" / "hunt.py"
FIELD_ERROR = "top takes one field, optionally after a count: | top src_ip or | top 10 src_ip"
RANGE_ERROR = "top N must be between 1 and 100"
FULLWIDTH = "\uff11\uff10"  # １０
SUPERSCRIPT = "\u00b2"  # ²
CIRCLED = "\u2460"  # ①
IPS = [f"203.0.113.{n}" for n in range(1, 13)]


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for ip in IPS:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, src_ip,"
            " message, synthetic) VALUES (?,?,?,?,?,?,?,?,?)",
            ("2026-10-07T12:00:00.000Z", "2026-10-07T12:00:00.000Z", "lab", "fw01", "fw_deny",
             "info", ip, "[SYNTHETIC] deny", 1))
    return conn


class HuntTopDigitTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def top(self, query):
        return hunt.run(self.conn, {"q": query})

    def test_ascii_ten_stays_a_limit_of_ten(self):
        stage = hunt.parse_stage("top 10 src_ip")
        self.assertEqual(stage["limit"], 10)
        self.assertEqual(stage["by"][0][0], "src_ip")
        data = self.top("| top 10 src_ip")
        kept = [row[0] for row in data["rows"]]
        self.assertEqual(kept, sorted(IPS)[:10])
        self.assertEqual(len(kept), 10)
        self.assertEqual((data["truncated"], data["groups_omitted"]), (True, 2))
        self.assertNotIn(sorted(IPS)[10], kept)
        self.assertNotIn(sorted(IPS)[11], kept)
        narrower = self.top("| top 2 src_ip")
        self.assertEqual(len(narrower["rows"]), 2)
        self.assertEqual(narrower["groups_omitted"], 10)

    def test_non_ascii_digits_stay_the_one_field_error(self):
        for token in (FULLWIDTH, SUPERSCRIPT, CIRCLED):
            query = f"| top {token} src_ip"
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    self.top(query)
                self.assertEqual(str(caught.exception), FIELD_ERROR)
                self.assertEqual(caught.exception.status, 400)
        # The successful limit is unchanged after the rejected queries.
        again = self.top("| top 10 src_ip")
        self.assertEqual(len(again["rows"]), 10)
        self.assertEqual(again["groups_omitted"], 2)

    def test_one_hundred_one_stays_the_range_error(self):
        with self.assertRaises(hunt.HuntError) as caught:
            self.top("| top 101 src_ip")
        self.assertEqual(str(caught.exception), RANGE_ERROR)
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(len(self.top("| top 10 src_ip")["rows"]), 10)

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(hunt.parse_stage)
        top = source.split('if command == "top":', 1)[1].split("span, by, pos", 1)[0]
        self.assertIn("isascii()", top)
        self.assertIn("isdigit()", top)
        self.assertLess(top.index("isascii()"), top.index("int("))
        body = HUNT.read_text()
        branch = body.split('if command == "top":', 1)[1].split("span, by, pos", 1)[0]
        self.assertIn("words[0].isascii()", branch)
        self.assertLess(branch.index("words[0].isascii()"), branch.index("int(words[0])"))


class HuntTopDigitApiTests(ServerTestCase):
    def test_hunt_rejects_non_ascii_top_counts(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [{
            "ts": "2026-10-07T12:00:00Z", "type": "fw_deny", "src_ip": ip,
            "message": "[SYNTHETIC] deny",
        } for ip in IPS]})
        self.assertEqual(status, 201, body)

        def rows(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return data

        page = rows("| top 10 src_ip")
        self.assertEqual([row[0] for row in page["rows"]], sorted(IPS)[:10])
        self.assertEqual(page["groups_omitted"], 2)

        for token in (FULLWIDTH, SUPERSCRIPT, CIRCLED):
            query = f"| top {token} src_ip"
            with self.subTest(query=query):
                status, data, headers = client.get("/api/hunt?q=" + quote(query))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], FIELD_ERROR)
                self.assertNotIn("rows", data)
                self.assertEqual(headers["Cache-Control"], "no-store")

        status, data, headers = client.get("/api/hunt?q=" + quote("| top 101 src_ip"))
        self.assertEqual(status, 400, data)
        self.assertEqual(data["error"], RANGE_ERROR)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(len(rows("| top 10 src_ip")["rows"]), 10)

    def test_docs_name_the_ascii_digits(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        top_row = next(line for line in REFERENCE.read_text().splitlines()
                       if line.startswith("| `top [N] <field>`"))
        for text in (hunt_row, top_row):
            self.assertIn("ASCII digits only", text)
            self.assertIn("top 10 src_ip", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn(CIRCLED, text)
            self.assertIn("top takes one field", text)
            self.assertIn("not limit 10", text)
            self.assertIn("not a 500", text)
            self.assertIn(RANGE_ERROR, text)
        self.assertIn(FIELD_ERROR, hunt_row)
