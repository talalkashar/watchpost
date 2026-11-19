"""Ingest parse_int accepts ASCII digits or a real int.

A dest_port of "443" or "0", or a JSON number 443, stores 443 or 0.
"４４３", "4_43", "+443", and "²" are dest_port must be an integer and store nothing.
A bool stays rejected. bytes "1000" and "0" stay. "1_000", "１", "+1", and "²"
are bytes must be an integer. int() runs only after the text is ASCII digits.
"""

import inspect
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect
from watchpost.normalize import EventError, normalize_record, parse_int

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NORMALIZE = Path(__file__).resolve().parent.parent / "watchpost" / "normalize.py"
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
TS = "2026-10-07T12:00:00Z"
FULLWIDTH = "\uff14\uff14\uff13"  # ４４３
PLUS = "+443"
UNDERSCORE = "4_43"
SUPERSCRIPT = "\u00b2"  # ²
BYTES_FULL = "\uff11"  # １
BYTES_UNDER = "1_000"
BYTES_PLUS = "+1"


def _event(**fields):
    record = {"ts": TS, "event_type": "fw_deny", "message": "[SYNTHETIC] deny"}
    record.update(fields)
    return normalize_record(record, "lab", NOW)


class ParseIntTests(unittest.TestCase):
    def test_ascii_digits_and_a_json_number_stay(self):
        self.assertEqual(parse_int("443", "dest_port", 65535), 443)
        self.assertEqual(parse_int("0", "dest_port", 65535), 0)
        self.assertEqual(parse_int(443, "dest_port", 65535), 443)
        self.assertEqual(parse_int(0, "dest_port", 65535), 0)
        self.assertEqual(_event(dest_port="443")["dest_port"], 443)
        self.assertEqual(_event(dest_port="0")["dest_port"], 0)
        self.assertEqual(_event(dest_port=443)["dest_port"], 443)
        self.assertEqual(parse_int("1000", "bytes", 10 ** 15), 1000)
        self.assertEqual(parse_int("0", "bytes", 10 ** 15), 0)
        self.assertEqual(_event(bytes="1000")["bytes"], 1000)
        self.assertEqual(_event(bytes="0")["bytes"], 0)
        self.assertIsNone(_event()["dest_port"])
        self.assertIsNone(_event()["bytes"])

    def test_lookalikes_are_the_integer_error(self):
        for value in (FULLWIDTH, UNDERSCORE, PLUS, SUPERSCRIPT):
            with self.subTest(value=value):
                with self.assertRaises(EventError) as caught:
                    parse_int(value, "dest_port", 65535)
                self.assertEqual(str(caught.exception), "dest_port must be an integer")
                with self.assertRaises(EventError) as caught:
                    _event(dest_port=value)
                self.assertEqual(str(caught.exception), "dest_port must be an integer")
        for value in (BYTES_UNDER, BYTES_FULL, BYTES_PLUS, SUPERSCRIPT):
            with self.subTest(value=value):
                with self.assertRaises(EventError) as caught:
                    parse_int(value, "bytes", 10 ** 15)
                self.assertEqual(str(caught.exception), "bytes must be an integer")
                with self.assertRaises(EventError) as caught:
                    _event(bytes=value)
                self.assertEqual(str(caught.exception), "bytes must be an integer")
        with self.assertRaisesRegex(EventError, "dest_port must be an integer"):
            _event(dest_port=True)
        with self.assertRaisesRegex(EventError, "bytes must be an integer"):
            _event(bytes=False)
        with self.assertRaisesRegex(EventError, "dest_port must be between 0 and 65535"):
            _event(dest_port="99999")

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(parse_int)
        self.assertLess(source.index("isascii()"), source.index("int(text)"))
        self.assertIn("isdigit()", source)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)
        body = NORMALIZE.read_text().split("def parse_int", 1)[1].split("\ndef _pick", 1)[0]
        self.assertEqual(body.count("int(text)"), 1)
        self.assertLess(body.index("text.isascii()"), body.index("int(text)"))


class ParseIntApiTests(ServerTestCase):
    def _post(self, client, **fields):
        event = {"ts": TS, "type": "fw_deny", "message": "[SYNTHETIC] deny"}
        event.update(fields)
        return client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [event]})

    def test_bad_integers_are_not_stored(self):
        client = self.client("analyst")
        for fields, reason in (
            ({"user": "https", "dest_port": "443"}, None),
            ({"user": "zero", "dest_port": "0"}, None),
            ({"user": "json", "dest_port": 443}, None),
            ({"user": "wide", "dest_port": FULLWIDTH}, "dest_port must be an integer"),
            ({"user": "under", "dest_port": UNDERSCORE}, "dest_port must be an integer"),
            ({"user": "plus", "dest_port": PLUS}, "dest_port must be an integer"),
            ({"user": "sup", "dest_port": SUPERSCRIPT}, "dest_port must be an integer"),
            ({"user": "flag", "dest_port": True}, "dest_port must be an integer"),
            ({"user": "kilo", "bytes": "1000"}, None),
            ({"user": "none", "bytes": "0"}, None),
            ({"user": "score", "bytes": BYTES_UNDER}, "bytes must be an integer"),
            ({"user": "full", "bytes": BYTES_FULL}, "bytes must be an integer"),
            ({"user": "signed", "bytes": BYTES_PLUS}, "bytes must be an integer"),
            ({"user": "mark", "bytes": SUPERSCRIPT}, "bytes must be an integer"),
        ):
            status, body, headers = self._post(client, **fields)
            self.assertEqual(headers["Cache-Control"], "no-store")
            if reason is None:
                self.assertEqual(status, 201, body)
                self.assertEqual(body["accepted"], 1)
                self.assertEqual(body["rejected"], 0)
            else:
                self.assertEqual(status, 422, body)
                self.assertEqual(body["accepted"], 0)
                self.assertEqual(body["rejected"], 1)
                self.assertEqual(body["rejections"][0]["reason"], reason)

        status, page, _ = client.get("/api/events?limit=50")
        self.assertEqual(status, 200, page)
        users = {event["user"] for event in page["events"]}
        self.assertEqual(users, {"https", "zero", "json", "kilo", "none"})
        stored = {event["user"]: (event["dest_port"], event["bytes"]) for event in page["events"]}
        self.assertEqual(stored["https"], (443, None))
        self.assertEqual(stored["zero"], (0, None))
        self.assertEqual(stored["json"], (443, None))
        self.assertEqual(stored["kilo"], (None, 1000))
        self.assertEqual(stored["none"], (None, 0))
        self.assertEqual(page["total"], 5)
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 5)
        self.assertEqual(
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE user IN (?,?,?,?,?,?,?,?,?)",
                ("wide", "under", "plus", "sup", "flag", "score", "full", "signed", "mark"),
            ).fetchone()[0],
            0)

    def test_docs_name_the_ascii_digits(self):
        api = API.read_text()
        reference = REFERENCE.read_text()
        for text in (api, reference):
            self.assertIn('`"443"` and `"0"` store 443 and 0', text)
            self.assertIn("A JSON number 443 stores 443", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn('`"4_43"`', text)
            self.assertIn('`"+443"`', text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn("`dest_port must be an integer`", text)
            self.assertIn("store nothing", text)
            self.assertIn("A bool stays rejected", text)
            self.assertIn('`"1000"` and `"0"`', text)
            self.assertIn(BYTES_UNDER, text)
            self.assertIn(BYTES_FULL, text)
            self.assertIn('`"+1"`', text)
            self.assertIn("`bytes must be an integer`", text)
