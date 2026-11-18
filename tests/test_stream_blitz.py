"""Broker delivery and SSE framing for the live stream.

A full subscriber queue drops the new message and answers `resync` once, then
the oldest queued message. Later publishes must still be readable: a producer
that keeps going cannot pin the reader on resync. Frames stay one SSE record.
"""

import json
import queue
import threading
import time
import unittest

from watchpost import stream

RESYNC = {"reason": "client fell behind; refetch current state"}


def parse_frames(raw):
    """SSE records in `raw`, each a {field: value} map. One record per blank line."""
    frames = []
    for record in raw.split("\n\n"):
        if not record:
            continue
        fields = {}
        for line in record.split("\n"):
            if not line:
                continue
            key, sep, value = line.partition(":")
            if sep and value.startswith(" "):
                value = value[1:]
            fields[key] = value
        frames.append(fields)
    return frames


def drain(sub):
    out = []
    while True:
        try:
            out.append(sub.get(timeout=0))
        except queue.Empty:
            return out


class BrokerTests(unittest.TestCase):
    def test_publish_order_is_kept_and_an_idle_get_times_out(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        self.assertEqual(broker.active(), 1)
        for i in range(3):
            broker.publish("alert", {"i": i})
        self.assertEqual(
            [sub.get(timeout=0) for _ in range(3)],
            [("alert", {"i": i}) for i in range(3)])
        started = time.monotonic()
        with self.assertRaises(queue.Empty):
            sub.get(timeout=0.05)
        self.assertGreaterEqual(time.monotonic() - started, 0.04)
        broker.unsubscribe(sub)
        self.assertEqual(broker.active(), 0)

    def test_publish_with_nobody_listening_and_a_second_unsubscribe_are_safe(self):
        broker = stream.Broker()
        broker.publish("event", {"i": 1})
        broker.unsubscribe(object())
        sub = broker.subscribe()
        broker.unsubscribe(sub)
        broker.unsubscribe(sub)
        broker.publish("event", {"i": 2})
        with self.assertRaises(queue.Empty):
            sub.get(timeout=0)
        self.assertEqual(broker.active(), 0)

    def test_two_subscribers_each_get_a_private_snapshot(self):
        broker = stream.Broker()
        first = broker.subscribe()
        second = broker.subscribe()
        payload = {"n": 1, "events": [{"id": 7}]}
        broker.publish("event", payload)
        payload["n"] = 9
        payload["events"].append({"id": 8})
        _, left = first.get(timeout=0)
        _, right = second.get(timeout=0)
        self.assertEqual(left["n"], 1)
        self.assertEqual(right["n"], 1)
        left["n"] = 3
        self.assertEqual(right["n"], 1)
        self.assertIsNot(left, right)

    def test_unsubscribe_keeps_what_was_already_queued(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        broker.publish("event", {"i": 1})
        broker.unsubscribe(sub)
        broker.publish("event", {"i": 2})
        self.assertEqual(sub.get(timeout=0), ("event", {"i": 1}))
        with self.assertRaises(queue.Empty):
            sub.get(timeout=0)

    def test_unknown_kind_is_delivered(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        broker.publish("notice", {"ok": True})
        self.assertEqual(sub.get(timeout=0), ("notice", {"ok": True}))

    def test_subscriber_cap_is_enforced_until_one_leaves(self):
        broker = stream.Broker()
        subs = [broker.subscribe() for _ in range(stream.MAX_SUBSCRIBERS)]
        self.assertEqual(broker.active(), stream.MAX_SUBSCRIBERS)
        with self.assertRaises(stream.TooManySubscribers):
            broker.subscribe()
        self.assertEqual(broker.active(), stream.MAX_SUBSCRIBERS)
        broker.unsubscribe(subs[0])
        broker.subscribe()
        self.assertEqual(broker.active(), stream.MAX_SUBSCRIBERS)

    def test_ids_belong_to_one_broker_and_start_at_one(self):
        broker = stream.Broker()
        self.assertEqual([broker.next_id() for _ in range(3)], [1, 2, 3])
        self.assertEqual(stream.Broker().next_id(), 1)

    def test_overflow_is_one_resync_then_the_oldest_queued_message(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        for i in range(stream.QUEUE_SIZE + 5):
            broker.publish("event", {"i": i})
        kind, data = sub.get(timeout=0)
        self.assertEqual(kind, "resync")
        self.assertEqual(data, RESYNC)
        self.assertEqual(sub.get(timeout=0), ("event", {"i": 0}))
        kinds = [item[0] for item in drain(sub)]
        self.assertEqual(kinds, ["event"] * (stream.QUEUE_SIZE - 1))
        self.assertNotIn("resync", kinds)

    def test_a_publish_after_resync_is_not_lost_behind_a_full_queue(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        for i in range(stream.QUEUE_SIZE):
            broker.publish("event", {"i": i})
        broker.publish("event", {"i": "dropped"})
        self.assertEqual(sub.get(timeout=0)[0], "resync")
        broker.publish("event", {"i": "fresh"})
        got = [data["i"] for kind, data in drain(sub) if kind == "event"]
        self.assertEqual(got, list(range(stream.QUEUE_SIZE)) + ["fresh"])
        self.assertNotIn("dropped", got)

    def test_a_steady_publisher_cannot_pin_the_reader_on_resync(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        for i in range(stream.QUEUE_SIZE):
            broker.publish("event", {"i": i})
        broker.publish("event", {"i": "dropped"})
        saw_event = False
        for n in range(8):
            broker.publish("event", {"i": f"live-{n}"})
            kind, data = sub.get(timeout=0)
            if kind == "event":
                saw_event = True
                self.assertIn("i", data)
                break
            self.assertEqual((kind, data), ("resync", RESYNC))
        self.assertTrue(saw_event)

    def test_one_slow_subscriber_does_not_drop_the_other(self):
        broker = stream.Broker()
        slow = broker.subscribe()
        for i in range(stream.QUEUE_SIZE):
            broker.publish("event", {"i": i})
        fast = broker.subscribe()
        broker.publish("event", {"i": "extra"})
        self.assertEqual(slow.get(timeout=0)[0], "resync")
        self.assertEqual(fast.get(timeout=0), ("event", {"i": "extra"}))
        self.assertEqual(slow.get(timeout=0), ("event", {"i": 0}))
        with self.assertRaises(queue.Empty):
            fast.get(timeout=0)

    def test_reader_keeps_up_with_a_publisher_thread(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        total = stream.QUEUE_SIZE + 40
        errors = []

        def produce():
            try:
                for i in range(total):
                    broker.publish("event", {"i": i})
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=produce)
        thread.start()
        got = []
        resyncs = 0
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                kind, data = sub.get(timeout=0.05)
            except queue.Empty:
                if not thread.is_alive():
                    break
                continue
            if kind == "resync":
                resyncs += 1
                continue
            self.assertEqual(kind, "event")
            got.append(data["i"])
        thread.join(timeout=1)
        for kind, data in drain(sub):
            if kind == "resync":
                resyncs += 1
            else:
                self.assertEqual(kind, "event")
                got.append(data["i"])
        self.assertEqual(errors, [])
        self.assertFalse(thread.is_alive())
        self.assertEqual(got, sorted(got))
        self.assertEqual(got, [i for i in range(total) if i in set(got)])
        self.assertGreater(len(got), 0)
        if got != list(range(total)):
            self.assertGreater(resyncs, 0)


class FrameTests(unittest.TestCase):
    def test_frame_format(self):
        raw = stream.frame("alert", {"title": "a\nb"}, 7).decode()
        self.assertEqual(raw, 'id: 7\nevent: alert\ndata: {"title":"a\\nb"}\n\n')
        self.assertEqual(parse_frames(raw), [{
            "id": "7", "event": "alert", "data": '{"title":"a\\nb"}',
        }])

    def test_id_zero_is_kept_and_a_missing_id_is_omitted(self):
        self.assertTrue(stream.frame("heartbeat", {"n": 1}, 0).decode().startswith("id: 0\n"))
        raw = stream.frame("heartbeat", {"n": 1}).decode()
        self.assertTrue(raw.startswith("event: heartbeat\n"))
        self.assertNotIn("id:", raw)

    def test_line_breaks_in_kind_or_id_cannot_inject_a_frame(self):
        raw = stream.frame(
            "alert\n\nevent: injected", {"title": "a\nb"}, "4\n\ndata: {}").decode()
        frames = parse_frames(raw)
        self.assertEqual(len(frames), 1)
        self.assertEqual(json.loads(frames[0]["data"]), {"title": "a\nb"})
        self.assertNotEqual(frames[0].get("event"), "injected")
        self.assertNotIn("\n\n", raw[:-2])
        for nasty in ("a\rb", "a\0b", "a\r\nb"):
            framed = stream.frame(nasty, {"n": 1}, nasty).decode()
            self.assertEqual(len(parse_frames(framed)), 1, nasty)
            self.assertNotIn("\0", framed)
            self.assertNotIn("\r", framed)

    def test_non_finite_numbers_become_null_and_unknown_objects_use_str(self):
        class Box:
            def __str__(self):
                return "box\nline"

        raw = stream.frame("health", {
            "box": Box(), "x": float("nan"), "y": [float("inf"), {"z": float("-inf")}],
        }).decode()
        self.assertNotIn("NaN", raw)
        self.assertNotIn("Infinity", raw)
        self.assertEqual(len(parse_frames(raw)), 1)
        self.assertEqual(json.loads(parse_frames(raw)[0]["data"]), {
            "box": "box\nline", "x": None, "y": [None, {"z": None}],
        })

    def test_a_line_separator_in_data_stays_on_the_data_line(self):
        raw = stream.frame("event", {"m": "a\u2028b"}).decode()
        self.assertEqual(len(parse_frames(raw)), 1)
        self.assertIn("\\u2028", raw)
        self.assertNotIn("\u2028", raw)

    def test_kinds_cover_every_frame_the_stream_sends(self):
        self.assertEqual(
            stream.KINDS,
            ("hello", "event", "alert", "incident", "health", "heartbeat", "resync"))
