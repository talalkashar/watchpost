"""Token-bucket edges: clock steps, non-finite rates, and the key cap."""

import threading
import unittest

from watchpost.ratelimit import TokenBucketLimiter


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class TokenBucketBlitzTests(unittest.TestCase):
    def test_burst_refills_and_never_above_the_cap(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=2, per_minute=60, clock=clock)  # one token a second
        self.assertEqual([limiter.allow("a")[0] for _ in range(2)], [True, True])
        self.assertFalse(limiter.allow("a")[0])
        clock.now += 1000
        self.assertEqual([limiter.allow("a")[0] for _ in range(3)], [True, True, False])

    def test_retry_after_tracks_the_deficit_and_is_enough(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=1, per_minute=2, clock=clock)  # one token every 30 s
        self.assertTrue(limiter.allow("a")[0])
        self.assertEqual(limiter.allow("a"), (False, 30))
        clock.now += 20
        allowed, retry = limiter.allow("a")
        self.assertEqual((allowed, retry), (False, 10))
        self.assertIsInstance(retry, int)
        clock.now += 9
        allowed, retry = limiter.allow("a")
        self.assertFalse(allowed)
        clock.now += retry
        self.assertEqual(limiter.allow("a"), (True, 0))

    def test_float_dust_does_not_make_retry_after_too_short(self):
        # 20s then 9s stores 0.9666...6666. One more second lands a hair under a token,
        # so a Retry-After of 1 would still be denied.
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=1, per_minute=2, clock=clock)
        self.assertTrue(limiter.allow("a")[0])
        limiter.allow("a")
        clock.now += 20
        self.assertEqual(limiter.allow("a"), (False, 10))
        clock.now += 9
        allowed, retry = limiter.allow("a")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry, 2)
        clock.now += retry
        self.assertEqual(limiter.allow("a"), (True, 0))

    def test_fractional_timestamp_wait_is_not_a_ulp_short(self):
        # (last + 90) - last is 89.99999999999994 at this timestamp, so an
        # integer projection of 90 still leaves the bucket under the cost.
        samples = (
            (3, 2, 3, 422.6951853601291, 90),
            (1, 2, 1, 1018.4676476832639, 30),
        )
        for burst, per_minute, cost, start, nominal in samples:
            clock = FakeClock(start)
            limiter = TokenBucketLimiter(burst=burst, per_minute=per_minute, clock=clock)
            self.assertEqual(limiter.allow("a", cost=cost), (True, 0))
            allowed, retry = limiter.allow("a", cost=cost)
            self.assertFalse(allowed)
            self.assertIn(retry, (nominal, nominal + 1))
            clock.now += retry
            self.assertEqual(limiter.allow("a", cost=cost), (True, 0))

    def test_awkward_rate_is_ready_on_the_advertised_second(self):
        clock = FakeClock(0)
        early = TokenBucketLimiter(burst=1, per_minute=7, clock=clock)
        self.assertTrue(early.allow("a")[0])
        allowed, retry = early.allow("a")
        self.assertFalse(allowed)
        self.assertGreater(retry, 1)
        clock.now += retry - 1
        self.assertFalse(early.allow("a")[0])

        clock = FakeClock(0)
        limiter = TokenBucketLimiter(burst=1, per_minute=7, clock=clock)
        self.assertTrue(limiter.allow("a")[0])
        _, retry = limiter.allow("a")
        clock.now += retry
        self.assertEqual(limiter.allow("a"), (True, 0))

    def test_a_refused_cost_spends_nothing(self):
        clock = FakeClock(0)
        limiter = TokenBucketLimiter(5, 60, clock=clock)
        self.assertEqual(limiter.allow("a", cost=5), (True, 0))
        clock.now = 2  # two tokens back, short of a cost of 3
        self.assertEqual(limiter.allow("a", cost=3), (False, 1))
        self.assertEqual(limiter.allow("a", cost=2), (True, 0))
        self.assertFalse(limiter.allow("a")[0])

    def test_keys_do_not_share_a_bucket(self):
        limiter = TokenBucketLimiter(burst=1, per_minute=1, clock=FakeClock())
        self.assertTrue(limiter.allow("198.51.100.1")[0])
        self.assertFalse(limiter.allow("198.51.100.1")[0])
        self.assertTrue(limiter.allow("198.51.100.2")[0])

    def test_backwards_clock_does_not_steal_tokens(self):
        clock = FakeClock(100)
        limiter = TokenBucketLimiter(burst=4, per_minute=60, clock=clock)
        self.assertTrue(limiter.allow("a")[0])
        clock.now = 97
        # Four tokens, one already spent. A backwards step must not eat the rest.
        self.assertEqual([limiter.allow("a")[0] for _ in range(4)], [True, True, True, False])

    def test_backwards_clock_does_not_rewind_the_bucket(self):
        clock = FakeClock(50)
        limiter = TokenBucketLimiter(burst=1, per_minute=60, clock=clock)
        self.assertTrue(limiter.allow("a")[0])
        clock.now = 40
        self.assertEqual(limiter.allow("a"), (False, 1))
        clock.now = 50  # back at the spend, still one second short of a token
        self.assertFalse(limiter.allow("a")[0])
        clock.now = 51
        self.assertTrue(limiter.allow("a")[0])

    def test_non_finite_clock_does_not_poison_the_bucket(self):
        clock = FakeClock(10)
        limiter = TokenBucketLimiter(burst=1, per_minute=60, clock=clock)
        self.assertTrue(limiter.allow("a")[0])
        for bad in (float("inf"), float("nan"), None, "10"):
            clock.now = bad
            with self.assertRaises(ValueError):
                limiter.allow("a")
        self.assertEqual(len(limiter), 1)
        clock.now = 11
        self.assertTrue(limiter.allow("a")[0])
        self.assertFalse(limiter.allow("a")[0])

    def test_non_finite_rates_are_rejected(self):
        for burst, per_minute in (
            (float("nan"), 10), (float("inf"), 10), (float("-inf"), 10),
            (5, float("nan")), (5, float("inf")), (5, float("-inf")),
            (0, 10), (5, 0), (5, -1),
        ):
            with self.assertRaises(ValueError):
                TokenBucketLimiter(burst, per_minute)
        for max_keys in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                TokenBucketLimiter(5, 10, max_keys=max_keys)

    def test_tiny_rate_denies_instead_of_raising(self):
        limiter = TokenBucketLimiter(burst=1, per_minute=1e-320, clock=FakeClock())
        self.assertEqual(limiter.allow("a"), (True, 0))
        allowed, retry = limiter.allow("a")
        self.assertFalse(allowed)
        self.assertIsInstance(retry, int)
        self.assertGreaterEqual(retry, 1)

    def test_invalid_cost_is_rejected_without_spending(self):
        limiter = TokenBucketLimiter(3, 60, clock=FakeClock())
        for cost in (0, 0.5, 4, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                limiter.allow("a", cost=cost)
        self.assertEqual(len(limiter), 0)
        self.assertTrue(limiter.allow("a", cost=3)[0])
        self.assertFalse(limiter.allow("a")[0])

    def test_full_buckets_are_dropped_before_active_ones(self):
        clock = FakeClock(0)
        limiter = TokenBucketLimiter(burst=1, per_minute=60, max_keys=2, clock=clock)
        self.assertTrue(limiter.allow("idle")[0])
        clock.now = 10  # idle has refilled; active spends its only token now
        self.assertTrue(limiter.allow("active")[0])
        self.assertTrue(limiter.allow("new")[0])
        self.assertFalse(limiter.allow("active")[0])
        self.assertTrue(limiter.allow("idle")[0])  # the idle key was evicted, so it is new again

    def test_oldest_half_is_evicted_when_nothing_has_refilled(self):
        clock = FakeClock(0)
        limiter = TokenBucketLimiter(burst=1, per_minute=1, max_keys=4, clock=clock)
        for name in ("k0", "k1", "k2", "k3"):
            self.assertTrue(limiter.allow(name)[0])
            clock.now += 1
        self.assertTrue(limiter.allow("k4")[0])
        self.assertTrue(limiter.allow("k0")[0])  # oldest, evicted, fresh burst
        self.assertFalse(limiter.allow("k3")[0])  # newest, still empty
        self.assertLessEqual(len(limiter), 4)

    def test_len_never_exceeds_max_keys(self):
        for max_keys in (1, 2, 3, 7):
            clock = FakeClock(0)
            limiter = TokenBucketLimiter(1, 60, max_keys=max_keys, clock=clock)
            for i in range(max_keys * 5):
                limiter.allow(f"k{i}")
                clock.now += 0.01
                self.assertLessEqual(len(limiter), max_keys)

    def test_parallel_allows_cannot_exceed_the_burst(self):
        limiter = TokenBucketLimiter(burst=10, per_minute=60, clock=lambda: 50.0)
        ok = []
        guard = threading.Lock()

        def once():
            allowed, _retry = limiter.allow("ip")
            with guard:
                ok.append(allowed)

        threads = [threading.Thread(target=once) for _ in range(40)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sum(ok), 10)

    def test_parallel_allows_do_not_go_negative(self):
        state = {"t": 1000.0}
        gate = threading.Lock()

        def clock():
            with gate:
                state["t"] += 0.0001
                return state["t"]

        limiter = TokenBucketLimiter(burst=4, per_minute=60, clock=clock)
        errors = []

        def worker():
            try:
                for _ in range(40):
                    limiter.allow("ip")
            except Exception as exc:  # pragma: no cover - the assertion reports it
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        tokens, last = limiter._buckets["ip"]
        self.assertGreaterEqual(tokens, 0)
        self.assertLessEqual(tokens, limiter.burst)
        self.assertGreaterEqual(last, 1000.0)


if __name__ == "__main__":
    unittest.main()
