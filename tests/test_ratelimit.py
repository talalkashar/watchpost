"""Per-IP token-bucket rate limiting (Watchpost 2.0 / F)."""

import unittest
import urllib.error
import urllib.request

from tests.helpers import ADMIN_PW, ServerTestCase
from watchpost.config import Config
from watchpost.ratelimit import TokenBucketLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TokenBucketTests(unittest.TestCase):
    def test_burst_then_refill(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=3, per_minute=60, clock=clock)  # one token a second
        self.assertEqual([limiter.allow("a")[0] for _ in range(3)], [True, True, True])
        self.assertEqual(limiter.allow("a"), (False, 1))
        clock.now += 0.5
        self.assertEqual(limiter.allow("a"), (False, 1))
        clock.now += 0.6
        self.assertEqual(limiter.allow("a"), (True, 0))
        clock.now += 3600
        self.assertEqual([limiter.allow("a")[0] for _ in range(4)], [True, True, True, False])

    def test_retry_after_reflects_the_refill_rate(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=1, per_minute=2, clock=clock)  # one token every 30 s
        self.assertTrue(limiter.allow("a")[0])
        self.assertEqual(limiter.allow("a"), (False, 30))
        clock.now += 20
        self.assertEqual(limiter.allow("a"), (False, 10))

    def test_keys_are_independent(self):
        limiter = TokenBucketLimiter(burst=1, per_minute=1, clock=FakeClock())
        self.assertTrue(limiter.allow("198.51.100.1")[0])
        self.assertFalse(limiter.allow("198.51.100.1")[0])
        self.assertTrue(limiter.allow("198.51.100.2")[0])

    def test_memory_is_bounded(self):
        clock = FakeClock()
        limiter = TokenBucketLimiter(burst=2, per_minute=60, max_keys=100, clock=clock)
        for i in range(1000):
            limiter.allow(f"k{i}")
            clock.now += 0.001
        self.assertLessEqual(len(limiter), 100)

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            TokenBucketLimiter(burst=0, per_minute=10)
        with self.assertRaises(ValueError):
            TokenBucketLimiter(burst=5, per_minute=0)

    def test_env_configuration(self):
        import os
        from unittest import mock
        env = {"SIEM_RATE_LIMIT": "0", "SIEM_LOGIN_RATE_BURST": "4", "SIEM_LOGIN_RATE_PER_MIN": "2",
               "SIEM_RATE_BURST": "50", "SIEM_RATE_PER_MIN": "600", "SIEM_TRUST_PROXY": "1"}
        with mock.patch.dict(os.environ, env):
            config = Config.from_env()
        self.assertEqual((config.rate_limit_enabled, config.login_rate_burst, config.login_rate_per_minute,
                          config.rate_burst, config.rate_per_minute, config.trust_proxy),
                         (False, 4, 2.0, 50, 600.0, True))
        with mock.patch.dict(os.environ, {}, clear=True):
            config = Config.from_env()
        self.assertEqual((config.rate_limit_enabled, config.trust_proxy), (True, False))


def raw_get(base, path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.headers


class LoginRateLimitTests(ServerTestCase):
    def config_overrides(self):
        return {"login_rate_burst": 3, "login_rate_per_minute": 1}

    def test_login_is_limited_per_ip_with_retry_after(self):
        c = self.client()
        for _ in range(3):
            self.assertEqual(c.login("admin", "wrong-password-123")[0], 401)
        status, data, headers = c.post("/api/auth/login", {"username": "admin", "password": ADMIN_PW})
        self.assertEqual(status, 429)
        self.assertIn("too many login attempts", data["error"])
        self.assertEqual(headers["Retry-After"], str(data["retry_after"]))
        self.assertTrue(1 <= data["retry_after"] <= 60)
        self.assertEqual(headers["Content-Type"], "application/json")
        # The limit applies before credentials are checked, so the right password is refused too...
        self.assertEqual(c.login("admin", ADMIN_PW)[0], 429)
        # ...but other requests from the same IP use the looser bucket.
        self.assertEqual(raw_get(self.base, "/api/health")[0], 200)


class RequestRateLimitTests(ServerTestCase):
    def config_overrides(self):
        return {"rate_burst": 5, "rate_per_minute": 1}

    def test_all_other_requests_share_the_looser_bucket(self):
        for path in ["/api/health", "/", "/api/alerts", "/app.js", "/api/health"]:
            self.assertNotEqual(raw_get(self.base, path)[0], 429, path)
        status, headers = raw_get(self.base, "/api/health")
        self.assertEqual(status, 429)
        self.assertGreaterEqual(int(headers["Retry-After"]), 1)
        self.assertEqual(raw_get(self.base, "/index.html")[0], 429)
        # Login has its own bucket.
        self.assertEqual(self.client().login("admin", ADMIN_PW)[0], 200)

    def test_forwarded_for_is_ignored_unless_proxy_is_trusted(self):
        for i in range(5):
            raw_get(self.base, "/api/health", {"X-Forwarded-For": f"198.51.100.{i}"})
        self.assertEqual(raw_get(self.base, "/api/health", {"X-Forwarded-For": "198.51.100.99"})[0], 429)


class TrustedProxyRateLimitTests(ServerTestCase):
    def config_overrides(self):
        return {"rate_burst": 2, "rate_per_minute": 1, "trust_proxy": True}

    def test_client_ip_comes_from_the_last_forwarded_entry(self):
        a = {"X-Forwarded-For": "203.0.113.7"}
        spoofed = {"X-Forwarded-For": "192.0.2.1, 203.0.113.7"}  # a client-supplied first entry changes nothing
        self.assertEqual(raw_get(self.base, "/api/health", a)[0], 200)
        self.assertEqual(raw_get(self.base, "/api/health", spoofed)[0], 200)
        self.assertEqual(raw_get(self.base, "/api/health", a)[0], 429)
        self.assertEqual(raw_get(self.base, "/api/health", {"X-Forwarded-For": "203.0.113.8"})[0], 200)
        # A malformed header falls back to the peer address.
        self.assertEqual(raw_get(self.base, "/api/health", {"X-Forwarded-For": "not-an-ip"})[0], 200)


class RateLimitDisabledTests(ServerTestCase):
    def config_overrides(self):
        return {"rate_limit_enabled": False, "rate_burst": 1, "login_rate_burst": 1}

    def test_disabled(self):
        self.assertIsNone(self.app.request_limiter)
        for _ in range(5):
            self.assertEqual(raw_get(self.base, "/api/health")[0], 200)
            self.assertEqual(self.client().login("admin", "wrong-password-123")[0], 401)


if __name__ == "__main__":
    unittest.main()
