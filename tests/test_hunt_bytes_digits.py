"""Hunt bytes comparisons accept ASCII digits only.

bytes:>=1000 stays 1000. bytes:>=1４ is the existing bytes error, not 14.
bytes:>=４ stays that error. int() runs only after the number is ASCII digits.
Neither refusal is a 500.
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema
from watchpost.normalize import MAX_BYTES

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
BYTES_ERROR = (
    "bytes must be one of >=, >, <=, < or = followed by an integer from 0 to "
    f"{MAX_BYTES}, such as bytes:>=1000000")
ONE_FULLWIDTH = "1\uff14"  # 1４
FULLWIDTH_FOUR = "\uff14"  # ４


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for user, nbytes in (("thousand", 1000), ("fourteen", 14), ("four", 4)):
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, message, bytes,"
            " synthetic) VALUES (?,?,?,?,?,?,?,?,1)",
            ("2026-10-07T11:00:00.000Z", "2026-10-07T11:00:00.000Z", "lab", "cloud_data_access",
             "low", user, "[SYNTHETIC] storage read", nbytes))
    return conn


class HuntBytesDigitTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(event["user"] for event in page["events"])

    def test_ascii_one_thousand_stays_one_thousand(self):
        where, args = hunt.compile_query("bytes:>=1000")
        self.assertEqual((where, args), (["bytes >= ?"], [1000]))
        self.assertNotIn("1000", where[0])
        self.assertEqual(hunt.explain("bytes:>=1000")[0]["text"], "bytes >= 1000")
        self.assertEqual(hunt.bytes_bound(">=1000"), (">=", 1000))
        self.assertEqual(self.users("bytes:>=1000"), ["thousand"])
        self.assertNotIn("fourteen", self.users("bytes:>=1000"))
        self.assertNotIn("four", self.users("bytes:>=1000"))

    def test_non_ascii_digits_stay_the_existing_error(self):
        for value in (ONE_FULLWIDTH, FULLWIDTH_FOUR):
            query = f"bytes:>={value}"
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(query)
                self.assertEqual(str(caught.exception), BYTES_ERROR)
                self.assertEqual(caught.exception.status, 400)
                with self.assertRaises(hunt.HuntError) as bound:
                    hunt.bytes_bound(">=" + value)
                self.assertEqual(str(bound.exception), BYTES_ERROR)
        self.assertEqual(self.users("bytes:>=1000"), ["thousand"])
        self.assertEqual(self.users("bytes:>=14"), ["fourteen", "thousand"])

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(hunt.bytes_bound)
        self.assertIn("isascii()", source)
        self.assertIn("isdigit()", source)
        self.assertLess(source.index("isascii()"), source.index("int("))
        self.assertNotIn(r"\d", hunt._BYTES_CMP.pattern)
        self.assertIn("[0-9]", hunt._BYTES_CMP.pattern)
        calls = []
        real = int

        def spy(value, *args):
            calls.append(value)
            return real(value, *args)

        hunt.int = spy
        try:
            for value in (ONE_FULLWIDTH, FULLWIDTH_FOUR):
                with self.assertRaises(hunt.HuntError):
                    hunt.bytes_bound(">=" + value)
            self.assertEqual(calls, [])
            self.assertEqual(hunt.bytes_bound(">=1000"), (">=", 1000))
            self.assertEqual(calls, ["1000"])
        finally:
            del hunt.int


class HuntBytesDigitApiTests(ServerTestCase):
    def test_hunt_rejects_non_ascii_byte_counts(self):
        client = self.client("analyst")
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": "2026-10-07T11:00:00Z", "type": "cloud_data_access", "user": "thousand",
             "bytes": 1000, "message": "[SYNTHETIC] storage read"},
            {"ts": "2026-10-07T11:01:00Z", "type": "cloud_data_access", "user": "fourteen",
             "bytes": 14, "message": "[SYNTHETIC] storage read"},
        ]})
        self.assertEqual(status, 201, body)

        def users(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return sorted(event["user"] for event in data["events"])

        self.assertEqual(users("bytes:>=1000"), ["thousand"])

        for value in (ONE_FULLWIDTH, FULLWIDTH_FOUR):
            query = f"bytes:>={value}"
            with self.subTest(query=query):
                status, data, headers = client.get("/api/hunt?q=" + quote(query))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], BYTES_ERROR)
                self.assertNotIn("events", data)
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(users("bytes:>=1000"), ["thousand"])
        self.assertEqual(users("bytes:>=14"), ["fourteen", "thousand"])

    def test_docs_name_the_ascii_digits(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        bytes_row = next(line for line in REFERENCE.read_text().splitlines()
                         if line.startswith("| `bytes:opN`"))
        for text in (hunt_row, bytes_row):
            self.assertIn("ASCII digits only", text)
            self.assertIn("`bytes:>=1000`", text)
            self.assertIn("1\uff14", text)
            self.assertIn("\uff14", text)
            self.assertIn(BYTES_ERROR, text)
            self.assertIn("not 14", text)
            self.assertIn("not a 500", text)
