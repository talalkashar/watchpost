"""In-process publish/subscribe for the Server-Sent Events stream (GET /api/stream).

The engine publishes after ingest (`event`), after detection (`alert`, `incident`,
`health`). Each SSE connection holds one Subscriber with a bounded queue. A slow
client never blocks the publisher: when its queue is full the message is dropped
and the client is told to `resync` (refetch the dashboard) instead. That resync
is delivered ahead of the backlog, and one queued message is held aside so the
queue is not left full.
"""

import itertools
import json
import queue
import threading

HEARTBEAT_SECONDS = 15.0
MAX_SUBSCRIBERS = 64
QUEUE_SIZE = 500
KINDS = ("hello", "event", "alert", "incident", "health", "heartbeat", "resync")
_RESYNC_REASON = "client fell behind; refetch current state"


class TooManySubscribers(Exception):
    pass


def _snapshot(data):
    """Top-level copy so one subscriber cannot change what another will read."""
    if isinstance(data, dict):
        return dict(data)
    if isinstance(data, list):
        return list(data)
    return data


class Subscriber:
    def __init__(self):
        self.queue = queue.Queue(maxsize=QUEUE_SIZE)
        self.overflow = False
        self._lock = threading.Lock()
        self._next = None

    def get(self, timeout):
        """Next (kind, data), ('resync', ...) after an overflow, or raises queue.Empty."""
        with self._lock:
            # The message set aside for the last resync has to go out before a
            # newer overflow. Checking overflow first lets a publisher that
            # refills the queue turn every read into resync.
            if self._next is not None:
                item = self._next
                self._next = None
                return item
            if self.overflow:
                self.overflow = False
                try:
                    self._next = self.queue.get_nowait()
                except queue.Empty:
                    pass
                return "resync", {"reason": _RESYNC_REASON}
        return self.queue.get(timeout=timeout)

    def _offer(self, item):
        with self._lock:
            try:
                self.queue.put_nowait(item)
            except queue.Full:
                self.overflow = True


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
            sub._offer((kind, _snapshot(data)))

    def next_id(self):
        return next(self._ids)


BROKER = Broker()


def _sse_field(value):
    """Field text with CR, LF, and NUL removed so one frame stays one record."""
    text = value if isinstance(value, str) else str(value)
    if "\0" not in text and "\r" not in text and "\n" not in text:
        return text
    return text.replace("\0", "").replace("\r", "").replace("\n", "")


def _json_safe(value):
    """Replace non-finite floats with None. Leave other objects for default=str."""
    if isinstance(value, float):
        if value != value or value == float("inf") or value == float("-inf"):
            return None
        return value
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_json_safe(item) for item in value)
    return value


def frame(kind, data, event_id=None):
    """One SSE frame. json.dumps never emits raw newlines, so one data line is enough."""
    kind_text = _sse_field(kind)
    head = f"id: {_sse_field(event_id)}\n" if event_id is not None else ""
    try:
        payload = json.dumps(
            data, default=str, separators=(",", ":"), allow_nan=False)
    except ValueError as exc:
        if "Out of range float values are not JSON compliant" not in str(exc):
            raise
        payload = json.dumps(
            _json_safe(data), default=str, separators=(",", ":"), allow_nan=False)
    return f"{head}event: {kind_text}\ndata: {payload}\n\n".encode()
