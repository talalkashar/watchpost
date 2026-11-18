"""Token-bucket edges not asserted by tests/test_ratelimit.py or tests/test_portability.py."""

import unittest

from watchpost.ratelimit import TokenBucketLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TokenBucketEdgeTests(unittest.TestCase):
    def test_constructor_rejects_negative_and_fractional_burst(self):
        with self.assertRaises(ValueError):
            TokenBucketLimiter(burst=-1, per_minute=10)
        with self.assertRaises(ValueError):
            TokenBucketLimiter(burst=0.5, per_minute=10)
        with self.assertRaises(ValueError):
            TokenBucketLimiter(burst=2, per_minute=-1)

    def test_cost_boundaries_do_not_mutate_the_bucket(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=4, per_minute=60, clock=clock)  # one token a second
        for cost in (0, -1, 5):
            with self.assertRaises(ValueError):
                limiter.allow("new", cost=cost)
        self.assertEqual(len(limiter), 0)  # a rejected cost never inserts a key
        self.assertEqual(limiter.allow("a", cost=4), (True, 0))  # cost may equal the burst
        with self.assertRaises(ValueError):
            limiter.allow("a", cost=0)
        self.assertEqual(limiter.allow("a"), (False, 1))  # still empty: one second until a single token
        clock.now += 4
        self.assertEqual(limiter.allow("a", cost=1.5), (True, 0))
        self.assertEqual(limiter.allow("a", cost=2.5), (True, 0))  # fractional costs spend exactly
        self.assertEqual(limiter.allow("a"), (False, 1))

    def test_empty_key_is_its_own_bucket(self):
        limiter = TokenBucketLimiter(burst=1, per_minute=1, clock=FakeClock())
        self.assertEqual(len(limiter), 0)
        self.assertTrue(limiter.allow("")[0])
        self.assertFalse(limiter.allow("")[0])
        self.assertTrue(limiter.allow(" ")[0])
        self.assertEqual(len(limiter), 2)
        self.assertFalse(limiter.allow("")[0])
        self.assertEqual(len(limiter), 2)  # repeating a key does not grow the map

    def test_retry_after_ceils_fractional_seconds_and_is_at_least_one(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=4, per_minute=60, clock=clock)
        self.assertEqual(limiter.allow("a", cost=4), (True, 0))
        clock.now += 1.25  # 2.75s short of four tokens
        self.assertEqual(limiter.allow("a", cost=4), (False, 3))

        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=1, per_minute=60, clock=clock)
        limiter.allow("b")
        clock.now += 1 - 1e-8  # deficit rounds to 0 at 6 decimals, then ceil, then floors at 1
        self.assertEqual(limiter.allow("b"), (False, 1))
        clock.now += 1e-8
        self.assertEqual(limiter.allow("b"), (True, 0))

    def test_prune_drops_full_buckets_before_the_oldest_half(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=2, per_minute=60, max_keys=2, clock=clock)
        limiter.allow("idle")
        clock.now += 1  # idle has refilled; hot is spent at this instant
        limiter.allow("hot")
        self.assertTrue(limiter.allow("new")[0])
        self.assertEqual(len(limiter), 2)
        self.assertEqual([limiter.allow("hot")[0] for _ in range(2)], [True, False])
        self.assertEqual([limiter.allow("idle")[0] for _ in range(3)], [True, True, False])

        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=3, per_minute=60, max_keys=4, clock=clock)
        for name in ("older", "mid", "newer", "newest"):
            limiter.allow(name)
            clock.now += 0.01  # not long enough for a spent token to refill
        self.assertEqual(len(limiter), 4)
        self.assertTrue(limiter.allow("extra")[0])
        self.assertEqual(len(limiter), 3)  # oldest half dropped, then the new key added
        self.assertEqual([limiter.allow("newest")[0] for _ in range(3)], [True, True, False])
        self.assertEqual([limiter.allow("older")[0] for _ in range(4)], [True, True, True, False])

        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=1, per_minute=60, max_keys=1, clock=clock)
        limiter.allow("only")
        self.assertFalse(limiter.allow("only")[0])
        self.assertTrue(limiter.allow("other")[0])
        self.assertEqual(len(limiter), 1)
        self.assertTrue(limiter.allow("only")[0])  # one key: drop that oldest slot, not zero
        self.assertEqual(len(limiter), 1)


if __name__ == "__main__":
    unittest.main()
