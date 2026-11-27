"""Ingest says how many rejection reasons the 100-reason cap left out.

rejections stays the first 100. rejections_omitted is rejected minus that
array, and 0 when the list fits. The stored batch errors slice is those same
first 100. The cap does not rise.
"""

import json
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.engine import REJECTION_LIMIT, ingest, store_batch

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def reasons(count):
    return [{"index": i, "reason": f"bad record {i}"} for i in range(1, count + 1)]


class RejectionSampleTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def stored(self, batch_id):
        row = self.conn.execute(
            "SELECT rejected, errors FROM ingest_batches WHERE id = ?", (batch_id,)).fetchone()
        return row["rejected"], json.loads(row["errors"])

    def test_the_cap_stays_one_hundred(self):
        self.assertEqual(REJECTION_LIMIT, 100)

    def test_the_reason_past_the_cap_is_the_one_left_out(self):
        sample = reasons(REJECTION_LIMIT + 1)
        result = ingest(self.conn, [], sample, "lab", "json", "analyst", synthetic=True)
        self.assertEqual(result["rejected"], REJECTION_LIMIT + 1)
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["rejections_omitted"], 1)
        self.assertEqual(result["rejections"], sample[:REJECTION_LIMIT])
        self.assertNotIn(sample[-1], result["rejections"])
        self.assertEqual(result["detection"]["status"], "skipped")
        rejected, errors = self.stored(result["batch_id"])
        self.assertEqual(rejected, REJECTION_LIMIT + 1)
        self.assertEqual(errors, sample[:REJECTION_LIMIT])
        self.assertNotIn("rejections_omitted", json.dumps(errors))

    def test_a_short_list_and_an_exact_cap_omit_zero(self):
        none = ingest(self.conn, [], [], "lab", "json", "analyst", synthetic=True)
        self.assertEqual(none["rejections_omitted"], 0)
        self.assertEqual(none["rejections"], [])
        self.assertEqual(none["rejected"], 0)
        self.assertEqual(self.stored(none["batch_id"]), (0, []))
        exact = reasons(REJECTION_LIMIT)
        result = ingest(self.conn, [], exact, "lab", "json", "analyst", synthetic=True)
        self.assertEqual(result["rejections_omitted"], 0)
        self.assertEqual(result["rejected"], REJECTION_LIMIT)
        self.assertEqual(result["rejections"], exact)
        self.assertEqual(self.stored(result["batch_id"]), (REJECTION_LIMIT, exact))

    def test_one_accepted_event_still_names_the_leftover(self):
        event = {
            "ts": "2026-09-01T00:00:00.000Z", "source": "lab", "host": "web01",
            "event_type": "auth", "outcome": "failure", "severity": "low", "user": "alice",
            "src_ip": "203.0.113.10", "dest_ip": None, "dest_port": None, "bytes": None,
            "message": "[SYNTHETIC] one kept row", "raw": None,
        }
        sample = reasons(REJECTION_LIMIT + 1)
        result = ingest(self.conn, [event], sample, "lab", "json", "analyst", synthetic=True)
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(result["rejected"], REJECTION_LIMIT + 1)
        self.assertEqual(result["rejections_omitted"], 1)
        self.assertEqual(result["rejections"], sample[:REJECTION_LIMIT])
        self.assertEqual(result["detection"]["status"], "ok")
        rejected, errors = self.stored(result["batch_id"])
        self.assertEqual((rejected, errors), (REJECTION_LIMIT + 1, sample[:REJECTION_LIMIT]))
        stored = self.conn.execute("SELECT message FROM events").fetchone()[0]
        self.assertIn("[SYNTHETIC]", stored)

    def test_store_batch_keeps_the_first_hundred_when_called_alone(self):
        sample = reasons(REJECTION_LIMIT + 2)
        batch_id = store_batch(self.conn, [], sample, "lab", "json", "analyst", synthetic=True)
        rejected, errors = self.stored(batch_id)
        self.assertEqual(rejected, REJECTION_LIMIT + 2)
        self.assertEqual(errors, sample[:REJECTION_LIMIT])


class IngestRejectionTests(ServerTestCase):
    def test_a_batch_past_the_cap_returns_the_omitted_count(self):
        analyst = self.client("analyst")
        events = [{"ts": "not-a-time", "message": "[SYNTHETIC] dropped"} for _ in range(101)]
        status, data, headers = analyst.post("/api/ingest", {"source": "lab", "events": events})
        self.assertEqual(status, 422, data)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual((data["accepted"], data["rejected"]), (0, 101))
        self.assertEqual(data["rejections_omitted"], 1)
        self.assertEqual(len(data["rejections"]), 100)
        self.assertEqual([row["index"] for row in data["rejections"]], list(range(1, 101)))
        self.assertNotIn(101, [row["index"] for row in data["rejections"]])
        self.assertEqual(data["rejections"][0]["reason"], "unparseable timestamp 'not-a-time'")
        self.assertNotIn("[SYNTHETIC] dropped", json.dumps(data["rejections"]))
        batches = analyst.get("/api/ingest/batches")[1]
        self.assertEqual(batches[0]["rejected"], 101)
        self.assertEqual([row["index"] for row in batches[0]["errors"]], list(range(1, 101)))
        self.assertNotIn("rejections_omitted", batches[0])

    def test_a_batch_that_fits_omits_zero(self):
        analyst = self.client("analyst")
        status, data, _ = analyst.post("/api/ingest", {"source": "lab", "events": [
            {"ts": "2026-09-01T00:00:00Z", "type": "login_failed", "user": "a",
             "src_ip": "203.0.113.10", "message": "[SYNTHETIC] kept"},
            {"ts": "not-a-time"},
        ]})
        self.assertEqual(status, 207, data)
        self.assertEqual(data["rejections_omitted"], 0)
        self.assertEqual(data["rejected"], 1)
        self.assertEqual(len(data["rejections"]), 1)
        empty = analyst.post("/api/ingest", {"source": "lab", "events": []})
        self.assertEqual(empty[0], 422)
        self.assertEqual(empty[1]["rejections_omitted"], 0)
        self.assertEqual(empty[1]["rejections"], [])

    def test_the_docs_name_rejections_omitted(self):
        api = API.read_text()
        self.assertIn('"rejections_omitted": 0', api)
        self.assertIn(
            "`rejections` is the first 100 reasons. `rejections_omitted` is `rejected` minus that "
            "array (0 when every reason is listed). The stored batch `errors` field is that same "
            "first 100, not the full list.",
            api)


if __name__ == "__main__":
    unittest.main()
