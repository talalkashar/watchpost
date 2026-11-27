"""Ingest and upload accept the hunt synthetic flag set.

`1`, `true`, `0`, and `false`, folded on ASCII letters only. JSON `true` and
`false`, and the integers `0` and `1`, are those words. Any other present
value is 400 naming those four. An absent flag stores the batch as not
synthetic. A labelled batch stays `synthetic=1` on the events and the batch.
"""

import json
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost.db import iso, utcnow

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
FLAG_ERROR = "synthetic must be 0, 1, true or false"


def recent():
    return iso(utcnow() - timedelta(minutes=5))


def event():
    return {"ts": recent(), "type": "login", "user": "ada", "src_ip": "203.0.113.10",
            "message": "[SYNTHETIC] labelled login"}


class SyntheticFlagTests(ServerTestCase):
    def stored(self, client, batch_source, event_source):
        status, batches, _ = client.get("/api/ingest/batches")
        self.assertEqual(status, 200, batches)
        match = [row for row in batches if row["source"] == batch_source]
        self.assertEqual(len(match), 1, batches)
        status, page, _ = client.get("/api/events?limit=20")
        self.assertEqual(status, 200, page)
        events = [row for row in page["events"] if row["source"] == event_source]
        self.assertEqual(len(events), 1, page)
        return match[0], events[0]

    def test_labelled_words_store_synthetic_on_the_event_and_the_batch(self):
        client = self.client("analyst")
        labelled = (
            ("bool-true", True),
            ("word-true", "true"),
            ("word-True", "True"),
            ("word-TRUE", "TRUE"),
            ("num-one", 1),
            ("str-one", "1"),
        )
        for name, flag in labelled:
            with self.subTest(flag=flag):
                status, body, _ = client.post("/api/ingest", {
                    "source": name, "synthetic": flag, "events": [event()]})
                self.assertEqual(status, 201, body)
                batch, stored = self.stored(client, name, "demo:" + name)
                self.assertEqual(batch["synthetic"], 1)
                self.assertEqual(stored["synthetic"], 1)
                self.assertEqual(stored["batch_id"], batch["id"])

    def test_absent_and_false_words_stay_not_synthetic(self):
        client = self.client("analyst")
        quiet = (
            ("word-false", "false"),
            ("word-False", "False"),
            ("word-FALSE", "FALSE"),
            ("num-zero", 0),
            ("str-zero", "0"),
            ("bool-false", False),
        )
        for name, flag in quiet:
            with self.subTest(flag=flag):
                status, body, _ = client.post("/api/ingest", {
                    "source": name, "synthetic": flag, "events": [event()]})
                self.assertEqual(status, 201, body)
                batch, stored = self.stored(client, name, name)
                self.assertEqual(batch["synthetic"], 0)
                self.assertEqual(stored["synthetic"], 0)
                self.assertFalse(stored["source"].startswith("demo:"))
        status, body, _ = client.post("/api/ingest", {"source": "absent", "events": [event()]})
        self.assertEqual(status, 201, body)
        batch, stored = self.stored(client, "absent", "absent")
        self.assertEqual((batch["synthetic"], stored["synthetic"]), (0, 0))
        status, body, _ = client.post("/api/ingest", [event()])
        self.assertEqual(status, 201, body)
        status, page, _ = client.get("/api/events?limit=20")
        bare = [row for row in page["events"] if row["source"] == "api"]
        self.assertEqual(len(bare), 1)
        self.assertEqual(bare[0]["synthetic"], 0)

    def test_any_other_present_value_is_400_and_stores_nothing(self):
        client = self.client("analyst")
        rejected = ("yes", 2, None, 1.0, "", "tr\u00fce", "tru\u0130e", " true", [1])
        for flag in rejected:
            with self.subTest(flag=flag):
                status, body, headers = client.post("/api/ingest", {
                    "source": "lab", "synthetic": flag, "events": [event()]})
                self.assertEqual(status, 400, body)
                self.assertEqual(body["error"], FLAG_ERROR)
                for word in ("0", "1", "true", "false"):
                    self.assertIn(word, body["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")
        status, page, _ = client.get("/api/events")
        self.assertEqual(page["total"], 0)
        self.assertEqual(client.get("/api/ingest/batches")[1], [])

    def test_upload_uses_the_same_flag_set(self):
        client = self.client("analyst")
        raw = json.dumps([event()]).encode()
        headers = {"Content-Type": "text/plain"}

        def upload(source, flag=None):
            query = "format=json&source=" + quote(source)
            if flag is not None:
                query += "&synthetic=" + quote(flag)
            return client.post("/api/ingest/upload?" + query, raw=raw, headers=headers)

        labelled = (("true", "up-true"), ("True", "up-True"), ("TRUE", "up-TRUE"), ("1", "up-1"))
        for flag, source in labelled:
            with self.subTest(flag=flag):
                status, body, _ = upload(source, flag)
                self.assertEqual(status, 201, body)
                batch, stored = self.stored(client, source, "demo:" + source)
                self.assertEqual(batch["synthetic"], 1)
                self.assertEqual(stored["synthetic"], 1)
        quiet = (("false", "up-false"), ("False", "up-False"), ("0", "up-0"))
        for flag, source in quiet:
            with self.subTest(flag=flag):
                status, body, _ = upload(source, flag)
                self.assertEqual(status, 201, body)
                batch, stored = self.stored(client, source, source)
                self.assertEqual((batch["synthetic"], stored["synthetic"]), (0, 0))
        status, body, _ = upload("up-absent")
        self.assertEqual(status, 201, body)
        batch, stored = self.stored(client, "up-absent", "up-absent")
        self.assertEqual((batch["synthetic"], stored["synthetic"]), (0, 0))
        for flag in ("yes", "2", "", "tr\u00fce"):
            with self.subTest(flag=flag):
                status, body, headers_out = upload("up-bad", flag)
                self.assertEqual(status, 400, body)
                self.assertEqual(body["error"], FLAG_ERROR)
                self.assertEqual(headers_out["Cache-Control"], "no-store")
        status, body, _ = client.post(
            "/api/ingest/upload?format=json&source=up-bad&synthetic=&synthetic=",
            raw=raw, headers=headers)
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"], "repeated query key 'synthetic'")
        bad = [row for row in client.get("/api/ingest/batches")[1] if row["source"] == "up-bad"]
        self.assertEqual(bad, [])

    def test_api_docs_name_the_four_flag_words(self):
        text = API.read_text()
        ingest = text.split("### `POST /api/ingest`", 1)[1].split("### `POST /api/ingest/upload", 1)[0]
        upload = text.split("### `POST /api/ingest/upload", 1)[1].split("### Live ingestion", 1)[0]
        for section in (ingest, upload):
            self.assertIn(FLAG_ERROR, section)
            self.assertIn("`0`, `1`, `true`, or `false`", section)


if __name__ == "__main__":
    unittest.main()
