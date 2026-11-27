"""A live ingest frame says how many events in that batch the cap left out.

The events stay the newest 50 by ts, then id. An older event with a higher id
is the one left out. The same timestamp keeps the higher ids. A batch that
fits returns events_omitted 0. count stays the accepted count. A batch of 0,
or a publish with no subscriber, sends no frame. A failed publish does not
fail the ingest.
"""

import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import ServerTestCase
from tests.test_dashboard import SSEClient, _cookie_from
from watchpost import stream
from watchpost.db import connect, init_schema
from watchpost.engine import STREAM_EVENT_LIMIT, _publish_events, ingest

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
NEW = "2026-09-01T00:00:00.000Z"
OLD = "2026-01-01T00:00:00.000Z"
BATCH = "batch-stream-omitted"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_event(conn, batch_id, ts=NEW):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, message,"
        " synthetic, batch_id) VALUES (?,?,?,?,?,?,?,?,?,1,?)",
        (ts, ts, "lab", "web01", "auth", "low", "alice", "203.0.113.10",
         "[SYNTHETIC] live batch", batch_id))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


class StreamEventsOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)
        self.sub = stream.BROKER.subscribe()
        self.addCleanup(stream.BROKER.unsubscribe, self.sub)

    def published(self, batch_id, count):
        _publish_events(self.conn, batch_id, count, True)
        kind, data = self.sub.get(timeout=1)
        self.assertEqual(kind, "event")
        return data

    def test_an_older_event_with_a_higher_id_is_the_one_left_out(self):
        kept = [add_event(self.conn, BATCH) for _ in range(STREAM_EVENT_LIMIT)]
        older = add_event(self.conn, BATCH, ts=OLD)
        data = self.published(BATCH, STREAM_EVENT_LIMIT + 1)
        self.assertEqual(data["events_omitted"], 1)
        self.assertEqual(data["count"], STREAM_EVENT_LIMIT + 1)
        self.assertTrue(data["synthetic"])
        self.assertEqual(data["batch_id"], BATCH)
        ids = [row["id"] for row in data["events"]]
        self.assertEqual(ids, list(reversed(kept)))
        self.assertNotIn(older, ids)
        self.assertGreater(older, kept[-1])
        self.assertNotIn("raw", data["events"][0])
        self.assertEqual(data["events"][0]["src_ip"], "203.0.113.10")
        self.assertIn("[SYNTHETIC]", data["events"][0]["message"])

    def test_the_same_timestamp_keeps_the_higher_ids(self):
        ids = [add_event(self.conn, BATCH, ts=OLD) for _ in range(STREAM_EVENT_LIMIT + 1)]
        data = self.published(BATCH, len(ids))
        shown = [row["id"] for row in data["events"]]
        self.assertEqual(data["events_omitted"], 1)
        self.assertEqual(data["count"], STREAM_EVENT_LIMIT + 1)
        self.assertEqual(shown, list(reversed(ids[1:])))
        self.assertNotIn(ids[0], shown)

    def test_a_short_batch_and_an_exact_cap_omit_zero(self):
        one = add_event(self.conn, "one")
        data = self.published("one", 1)
        self.assertEqual(data["events_omitted"], 0)
        self.assertEqual(data["count"], 1)
        self.assertEqual([row["id"] for row in data["events"]], [one])
        exact = [add_event(self.conn, "exact") for _ in range(STREAM_EVENT_LIMIT)]
        data = self.published("exact", STREAM_EVENT_LIMIT)
        self.assertEqual(data["events_omitted"], 0)
        self.assertEqual(data["count"], STREAM_EVENT_LIMIT)
        self.assertEqual([row["id"] for row in data["events"]], list(reversed(exact)))

    def test_a_batch_of_zero_or_no_subscriber_publishes_nothing(self):
        add_event(self.conn, BATCH)
        _publish_events(self.conn, BATCH, 0, True)
        self.assertTrue(self.sub.queue.empty())
        with mock.patch.object(stream.BROKER, "active", return_value=0), \
                mock.patch.object(stream.BROKER, "publish") as publish:
            _publish_events(self.conn, BATCH, 1, True)
            publish.assert_not_called()

    def test_a_failed_publish_does_not_fail_the_ingest(self):
        event = {
            "ts": NEW, "source": "lab", "host": "web01", "event_type": "auth", "outcome": "failure",
            "severity": "low", "user": "alice", "src_ip": "203.0.113.10", "dest_ip": None,
            "dest_port": None, "bytes": None, "message": "[SYNTHETIC] stream down", "raw": None,
        }
        with mock.patch.object(stream.BROKER, "publish", side_effect=RuntimeError("stream down")):
            result = ingest(self.conn, [event], [], "lab", "json", "analyst", synthetic=True)
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
        self.assertIn("[SYNTHETIC]", self.conn.execute("SELECT message FROM events").fetchone()[0])
        row = self.conn.execute(
            "SELECT component, message FROM error_log WHERE component = 'stream'").fetchone()
        self.assertEqual(row["component"], "stream")
        self.assertIn("RuntimeError", row["message"])

    def test_the_docs_name_events_omitted(self):
        api = API.read_text()
        self.assertIn(
            "`events_omitted` is `count` minus the events array (0 when the batch fits). "
            "The events stay the newest 50 by `ts`, then `id`",
            api)


class StreamEventsOmittedApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.port = self.server.server_address[1]
        self.streams = []

    def tearDown(self):
        for client in self.streams:
            client.close()
        super().tearDown()

    def test_a_fitting_batch_sends_events_omitted_zero(self):
        client = self.client("analyst")
        live = SSEClient(self.port, _cookie_from(client))
        self.streams.append(live)
        live.frame()
        live.frame()
        status, _body, _headers = client.post("/api/ingest", {
            "source": "lab", "synthetic": True,
            "events": [{
                "ts": NEW, "type": "login_failed", "user": "alice",
                "src_ip": "203.0.113.10", "host": "web01", "message": "[SYNTHETIC] one",
            }],
        })
        self.assertEqual(status, 201)
        data = live.until("event")
        self.assertEqual(data["events_omitted"], 0)
        self.assertEqual(data["count"], 1)
        self.assertEqual(len(data["events"]), 1)
        self.assertTrue(data["synthetic"])
        self.assertNotIn("raw", data["events"][0])
        self.assertEqual(data["events"][0]["src_ip"], "203.0.113.10")
        self.assertIn("[SYNTHETIC]", data["events"][0]["message"])
