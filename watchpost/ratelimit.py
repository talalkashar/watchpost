"""In-memory per-client token buckets for request rate limiting.

Each key (a client IP) gets a bucket of `burst` tokens that refills at `per_minute / 60`
tokens a second. A request spends one token; an empty bucket means HTTP 429 with a
Retry-After of the seconds until the next token. State lives in this process only, which
fits a single-node deployment; a restart forgets it.
"""

import math
import threading
import time

# Seconds that do not fit in a finite Retry-After. A subnormal rate can make the true
# wait overflow; denying with this cap beats raising (a 500 would skip the limit).
_MAX_RETRY_AFTER = 2**31 - 1


class TokenBucketLimiter:
    def __init__(self, burst, per_minute, max_keys=10000, clock=time.monotonic):
        if burst < 1 or per_minute <= 0 or not _finite(burst) or not _finite(per_minute):
            raise ValueError("burst must be >= 1 and per_minute > 0")
        self.burst = float(burst)
        self.rate = per_minute / 60.0
        if not math.isfinite(self.rate) or self.rate <= 0:
            raise ValueError("burst must be >= 1 and per_minute > 0")
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys < 1:
            raise ValueError("max_keys must be an integer >= 1")
        self.max_keys = max_keys
        self.clock = clock
        self._buckets = {}  # key -> [tokens, last_refill]
        self._lock = threading.Lock()

    def allow(self, key, cost=1):
        """Spend `cost` tokens for `key`, all or none. Returns (allowed, retry_after_seconds)."""
        if not 1 <= cost <= self.burst:
            raise ValueError("cost must be between 1 and the burst size")
        with self._lock:
            now = self._now()
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._prune(now)
                bucket = self._buckets[key] = [self.burst, now]
            elapsed = now - bucket[1]
            # Ignore a backwards step. Overlapping calls sample time independently, and a
            # clock can jump back; applying an older sample rewound `last` and deleted tokens.
            if elapsed > 0:
                bucket[0] = min(self.burst, bucket[0] + elapsed * self.rate)
                bucket[1] = now
            if bucket[0] >= cost:
                bucket[0] -= cost
                return True, 0
            return False, self._retry_after(bucket[0], cost, bucket[1])

    def _now(self):
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            raise ValueError("clock must return a finite number")
        now = float(now)
        if not math.isfinite(now):
            raise ValueError("clock must return a finite number")
        return now

    def _retry_after(self, tokens, cost, last):
        seconds = (cost - tokens) / self.rate
        if not math.isfinite(seconds):
            return _MAX_RETRY_AFTER
        try:
            retry = math.ceil(round(seconds, 6))
        except (OverflowError, ValueError):
            return _MAX_RETRY_AFTER
        if retry < 1:
            retry = 1
        # The next allow refills by `(last + wait) - last`, which can be a ulp
        # under the integer, and round(..., 6) can shave a long 0.999... down
        # to the second below. Either one leaves the bucket a hair under `cost`.
        for _ in range(3):
            if _wait_covers(tokens, self.rate, cost, last, retry):
                return retry
            if retry >= _MAX_RETRY_AFTER:
                return _MAX_RETRY_AFTER
            retry += 1
        return retry

    def _prune(self, now):
        """Drop buckets that have refilled completely; if none have, drop the oldest half."""
        full = [k for k, (tokens, last) in self._buckets.items()
                if tokens + max(0.0, now - last) * self.rate >= self.burst]
        for key in full:
            del self._buckets[key]
        if len(self._buckets) >= self.max_keys:
            oldest = sorted(self._buckets, key=lambda k: self._buckets[k][1])
            for key in oldest[: len(oldest) // 2 or 1]:
                del self._buckets[key]

    def __len__(self):
        with self._lock:
            return len(self._buckets)


def _wait_covers(tokens, rate, cost, last, retry):
    """True when `retry` seconds refills `cost` on a float clock."""
    try:
        landed = (last + retry) - last
    except OverflowError:
        return True
    if not math.isfinite(landed):
        return True
    gained = tokens + landed * rate
    # A huge finite wait can overflow the product. That still grants the request.
    return not math.isfinite(gained) or gained >= cost


def _finite(value):
    try:
        return math.isfinite(value)
    except (TypeError, OverflowError):
        return False
