"""Upload year accepts ASCII digits only.

year=2024 stays that year on a BSD syslog line. year=２０２４, year=², and
year=2_024 are 400 year must be between 2000 and 2100. A superscript is that
400, not a 500. Nothing is stored. int() runs only after isascii.
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost.server import ingest_upload

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
SERVER = Path(__file__).resolve().parent.parent / "watchpost" / "server.py"
LINE = (
    "Sep 28 10:00:01 web01 sshd[1]: Failed password for alice "
    "from 203.0.113.50 port 22 ssh2"
)
FULLWIDTH = "\uff12\uff10\uff12\uff14"  # ２０２４
SUPERSCRIPT = "\u00b2"  # ²
UNDERSCORE = "2_024"
MESSAGE = "year must be between 2000 and 2100"


class UploadYearTests(ServerTestCase):
    def _upload(self, client, year):
        path = "/api/ingest/upload?format=authlog&source=bastion&year=" + quote(year, safe="")
        return client.post(path, raw=(LINE + "\n").encode(), headers={"Content-Type": "text/plain"})

    def test_ascii_year_stores_and_lookalikes_store_nothing(self):
        client = self.client("analyst")
        for year in (FULLWIDTH, SUPERSCRIPT, UNDERSCORE, "1999", "2101"):
            with self.subTest(year=year):
                status, body, headers = self._upload(client, year)
                self.assertEqual(status, 400, body)
                self.assertEqual(body["error"], MESSAGE)
                self.assertNotIn("\u0307", body["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")

        status, empty, _ = client.get("/api/events")
        self.assertEqual(status, 200, empty)
        self.assertEqual(empty["total"], 0)
        status, batches, _ = client.get("/api/ingest/batches")
        self.assertEqual(status, 200, batches)
        self.assertEqual(batches, [])

        status, stored, headers = self._upload(client, "2024")
        self.assertEqual(status, 201, stored)
        self.assertEqual(stored["accepted"], 1)
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, page, _ = client.get("/api/events")
        self.assertEqual(status, 200, page)
        self.assertEqual(page["total"], 1)
        self.assertTrue(page["events"][0]["ts"].startswith("2024-09-28T10:00:01"))
        self.assertEqual(page["events"][0]["user"], "alice")

        status, again, _ = self._upload(client, SUPERSCRIPT)
        self.assertEqual(status, 400, again)
        self.assertEqual(again["error"], MESSAGE)
        status, still, _ = client.get("/api/events")
        self.assertEqual(still["total"], 1)

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(ingest_upload)
        self.assertLess(source.index("isascii()"), source.index("int("))
        self.assertIn("isdigit()", source)
        self.assertEqual(source.count("int("), 1)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)
        body = SERVER.read_text().split("def ingest_upload", 1)[1].split("\ndef _upload_synthetic", 1)[0]
        self.assertLess(body.index("isascii()"), body.index("int("))
        self.assertEqual(body.count("int("), 1)

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("`year=2024`", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn(UNDERSCORE, text)
            self.assertIn("`year must be between 2000 and 2100`", text)
            self.assertIn("not a 500", text)


if __name__ == "__main__":
    unittest.main()
