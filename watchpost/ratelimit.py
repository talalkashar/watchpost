"""In-memory per-client token buckets for request rate limiting.

Each key (a client IP) gets a bucket of `burst` tokens that refills at `per_minute / 60`
tokens a second. A request spends one token; an empty bucket means HTTP 429 with a
Retry-After of the seconds until the next token. State lives in this process only, which
fits a single-node deployment; a restart forgets it.
"""

import math
import threading
import time


class TokenBucketLimiter:
    def __init__(self, burst, per_minute, max_keys=10000, clock=time.monotonic):
        if burst < 1 or per_minute <= 0:
            raise ValueError("burst must be >= 1 and per_minute > 0")
        self.burst = float(burst)
        self.rate = per_minute / 60.0
        self.max_keys = max_keys
        self.clock = clock
        self._buckets = {}  # key -> [tokens, last_refill]
        self._lock = threading.Lock()

    def allow(self, key):
        """Spend one token for `key`. Returns (allowed, retry_after_seconds)."""
        now = self.clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._prune(now)
                bucket = self._buckets[key] = [self.burst, now]
            tokens = min(self.burst, bucket[0] + (now - bucket[1]) * self.rate)
            bucket[1] = now
            if tokens >= 1:
                bucket[0] = tokens - 1
                return True, 0
            bucket[0] = tokens
            return False, max(1, math.ceil(round((1 - tokens) / self.rate, 6)))

    def _prune(self, now):
        """Drop buckets that have refilled completely; if none have, drop the oldest half."""
        full = [k for k, (tokens, last) in self._buckets.items()
                if tokens + (now - last) * self.rate >= self.burst]
        for key in full:
            del self._buckets[key]
        if len(self._buckets) >= self.max_keys:
            oldest = sorted(self._buckets, key=lambda k: self._buckets[k][1])
            for key in oldest[: len(oldest) // 2 or 1]:
                del self._buckets[key]

    def __len__(self):
        return len(self._buckets)
