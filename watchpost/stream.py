"""In-process publish/subscribe for the Server-Sent Events stream (GET /api/stream).

The engine publishes after ingest (`event`), after detection (`alert`, `incident`,
`health`). Each SSE connection holds one Subscriber with a bounded queue. A slow
client never blocks the publisher: when its queue is full the message is dropped
and the client is told to `resync` (refetch the dashboard) instead.
"""

import itertools
import json
import queue
import threading

HEARTBEAT_SECONDS = 15.0
MAX_SUBSCRIBERS = 64
QUEUE_SIZE = 500
KINDS = ("hello", "event", "alert", "incident", "health", "heartbeat", "resync")


class TooManySubscribers(Exception):
    pass


class Subscriber:
    def __init__(self):
        self.queue = queue.Queue(maxsize=QUEUE_SIZE)
        self.overflow = False

    def get(self, timeout):
        """Next (kind, data), ('resync', ...) after an overflow, or raises queue.Empty."""
        if self.overflow:
            self.overflow = False
            return "resync", {"reason": "client fell behind; refetch current state"}
        return self.queue.get(timeout=timeout)


class Broker:
    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers = set()
        self._ids = itertools.count(1)

    def subscribe(self):
        with self._lock:
            if len(self._subscribers) >= MAX_SUBSCRIBERS:
                raise TooManySubscribers()
            sub = Subscriber()
            self._subscribers.add(sub)
            return sub

    def unsubscribe(self, sub):
        with self._lock:
            self._subscribers.discard(sub)

    def active(self):
        with self._lock:
            return len(self._subscribers)

    def publish(self, kind, data):
        with self._lock:
            targets = list(self._subscribers)
        for sub in targets:
            try:
                sub.queue.put_nowait((kind, data))
            except queue.Full:
                sub.overflow = True

    def next_id(self):
        return next(self._ids)


BROKER = Broker()


def frame(kind, data, event_id=None):
    """One SSE frame. json.dumps never emits raw newlines, so one data line is enough."""
    head = f"id: {event_id}\n" if event_id is not None else ""
    return f"{head}event: {kind}\ndata: {json.dumps(data, default=str, separators=(',', ':'))}\n\n".encode()
