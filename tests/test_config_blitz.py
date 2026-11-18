"""Load-time edges for watchpost.config. Isolated from the process environment."""

import dataclasses
import os
import unittest
from unittest import mock

from watchpost.config import BASE_DIR, Config
from watchpost.ratelimit import TokenBucketLimiter


class ConfigBlitzTests(unittest.TestCase):
    def load(self, env=None, **overrides):
        with mock.patch.dict(os.environ, env or {}, clear=True):
            return Config.from_env(**overrides)

    def assert_bad(self, env=None, prefix="", **overrides):
        with mock.patch.dict(os.environ, env or {}, clear=True):
            with self.assertRaises(ValueError) as caught:
                Config.from_env(**overrides)
        message = str(caught.exception)
        if prefix:
            self.assertTrue(message.startswith(prefix), message)
        return message

    def direct(self, **overrides):
        fields = dict(
            db_path=":memory:",
            host="127.0.0.1",
            port=8080,
            session_ttl_seconds=28800,
            secure_cookies=False,
            max_upload_bytes=1024,
            max_batch_events=10,
            admin_password=None,
            analyst_password=None,
        )
        fields.update(overrides)
        return Config(**fields)

    def test_defaults_when_env_is_empty(self):
        cfg = self.load()
        self.assertEqual(cfg.db_path, str(BASE_DIR / "data" / "watchpost.db"))
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 8080)
        self.assertEqual(cfg.session_ttl_seconds, 28800)
        self.assertFalse(cfg.secure_cookies)
        self.assertEqual(cfg.max_upload_bytes, 5 * 1024 * 1024)
        self.assertEqual(cfg.max_batch_events, 20000)
        self.assertIsNone(cfg.admin_password)
        self.assertIsNone(cfg.analyst_password)
        self.assertFalse(cfg.syslog_enabled)
        self.assertEqual(cfg.syslog_bind, "127.0.0.1")
        self.assertEqual(cfg.syslog_port, 5514)
        self.assertEqual(cfg.syslog_allow, "")
        self.assertIsNone(cfg.viewer_password)
        self.assertTrue(cfg.rate_limit_enabled)
        self.assertEqual((cfg.login_rate_burst, cfg.login_rate_per_minute), (10, 10.0))
        self.assertEqual((cfg.rate_burst, cfg.rate_per_minute), (300, 1200.0))
        self.assertFalse(cfg.trust_proxy)
        self.assertEqual((cfg.demo_loop_minutes, cfg.demo_loop_speed), (0, 1.0))
        self.assertIsNone(cfg.audit_key)

    def test_rate_limit_env_matches_existing_contract(self):
        cfg = self.load({
            "SIEM_RATE_LIMIT": "0",
            "SIEM_LOGIN_RATE_BURST": "4",
            "SIEM_LOGIN_RATE_PER_MIN": "2",
            "SIEM_RATE_BURST": "50",
            "SIEM_RATE_PER_MIN": "600",
            "SIEM_TRUST_PROXY": "1",
        })
        self.assertEqual(
            (cfg.rate_limit_enabled, cfg.login_rate_burst, cfg.login_rate_per_minute,
             cfg.rate_burst, cfg.rate_per_minute, cfg.trust_proxy),
            (False, 4, 2.0, 50, 600.0, True))
        cleared = self.load()
        self.assertEqual((cleared.rate_limit_enabled, cleared.trust_proxy), (True, False))

    def test_syslog_env_matches_existing_contract(self):
        cfg = self.load({
            "SIEM_SYSLOG": "1",
            "SIEM_SYSLOG_BIND": "::1",
            "SIEM_SYSLOG_PORT": "6514",
            "SIEM_SYSLOG_ALLOW": "10.0.0.0/8",
        })
        self.assertEqual(
            (cfg.syslog_enabled, cfg.syslog_bind, cfg.syslog_port, cfg.syslog_allow),
            (True, "::1", 6514, "10.0.0.0/8"))
        self.assertFalse(self.load().syslog_enabled)

    def test_port_fallback_and_range(self):
        self.assertEqual(self.load({"PORT": "9090"}).port, 9090)
        self.assertEqual(self.load({"SIEM_PORT": "  ", "PORT": "9090"}).port, 9090)
        self.assertEqual(self.load({"SIEM_PORT": "", "PORT": ""}).port, 8080)
        self.assertEqual(self.load({"SIEM_PORT": "9090", "PORT": "1"}).port, 9090)
        self.assertEqual(self.load({"SIEM_PORT": " 9091 "}).port, 9091)
        self.assertEqual(self.load({"SIEM_PORT": "0"}).port, 0)
        self.assertEqual(self.load({"SIEM_PORT": "65535"}).port, 65535)
        self.assertEqual(self.load({"SIEM_SYSLOG_PORT": "0"}).syslog_port, 0)
        self.assert_bad({"SIEM_PORT": "70000"}, "SIEM_PORT ")
        self.assert_bad({"SIEM_PORT": "-1"}, "SIEM_PORT ")
        self.assert_bad({"SIEM_PORT": "nope"}, "SIEM_PORT ")
        self.assert_bad({"SIEM_PORT": "0x50"}, "SIEM_PORT ")
        self.assert_bad({"PORT": "nope"}, "PORT ")
        self.assert_bad({"SIEM_PORT": "nope", "PORT": "8080"}, "SIEM_PORT ")
        self.assert_bad({"SIEM_PORT": "   ", "PORT": "nope"}, "PORT ")
        message = self.assert_bad({"SIEM_PORT": "8080abc"}, "SIEM_PORT ")
        self.assertNotIn("8080abc", message)
        self.assert_bad({}, "SIEM_PORT ", port=True)
        self.assert_bad({}, "SIEM_PORT ", port=99999)
        self.assert_bad({}, "SIEM_PORT ", port=-1)

    def test_blank_bind_stays_on_loopback(self):
        for raw in ("", "   ", "''", '""', "  ''  "):
            cfg = self.load({"SIEM_HOST": raw, "SIEM_SYSLOG_BIND": raw})
            self.assertEqual(cfg.host, "127.0.0.1", repr(raw))
            self.assertEqual(cfg.syslog_bind, "127.0.0.1", repr(raw))
        cfg = self.load({}, host="", syslog_bind="   ")
        self.assertEqual((cfg.host, cfg.syslog_bind), ("127.0.0.1", "127.0.0.1"))
        for raw, expected in (
            ("0.0.0.0", "0.0.0.0"),
            ("::", "::"),
            (" 127.0.0.1 ", "127.0.0.1"),
            (" ::1 ", "::1"),
            ("[::1]", "::1"),
            ("localhost", "localhost"),
        ):
            self.assertEqual(self.load({"SIEM_HOST": raw}).host, expected, repr(raw))
        self.assertEqual(self.load({}, host="0.0.0.0").host, "0.0.0.0")
        for raw in ("bad host", "http://127.0.0.1", "/tmp", "127.0.0.1/32"):
            self.assert_bad({"SIEM_HOST": raw}, "SIEM_HOST ")

    def test_flags_are_only_zero_or_one(self):
        for raw in ("1", "1 ", " 1", "'1'", '"1"', " '1' "):
            self.assertTrue(self.load({"SIEM_SECURE_COOKIES": raw}).secure_cookies, repr(raw))
            self.assertTrue(self.load({"SIEM_SYSLOG": raw}).syslog_enabled, repr(raw))
        for raw in ("0", "0 ", " 0", "'0'"):
            self.assertFalse(self.load({"SIEM_RATE_LIMIT": raw}).rate_limit_enabled, repr(raw))
            self.assertFalse(self.load({"SIEM_TRUST_PROXY": raw}).trust_proxy, repr(raw))
        self.assertTrue(self.load({"SIEM_RATE_LIMIT": "   "}).rate_limit_enabled)
        self.assertFalse(self.load({"SIEM_SECURE_COOKIES": ""}).secure_cookies)
        for token in ("true", "false", "yes", "no", "on", "off", "maybe", "+1", "01", "1.0"):
            self.assert_bad({"SIEM_SYSLOG": token}, "SIEM_SYSLOG ")
            self.assert_bad({"SIEM_RATE_LIMIT": token}, "SIEM_RATE_LIMIT ")
            self.assert_bad({"SIEM_TRUST_PROXY": token}, "SIEM_TRUST_PROXY ")
            self.assert_bad({"SIEM_SECURE_COOKIES": token}, "SIEM_SECURE_COOKIES ")
        cfg = self.load({}, rate_limit_enabled=0, secure_cookies=1, trust_proxy=0, syslog_enabled=1)
        self.assertEqual(
            (cfg.rate_limit_enabled, cfg.secure_cookies, cfg.trust_proxy, cfg.syslog_enabled),
            (False, True, False, True))

    def test_counters_and_rates_stay_in_range(self):
        self.assertEqual(self.load({"SIEM_SESSION_TTL": " 28800 "}).session_ttl_seconds, 28800)
        self.assertEqual(self.load({"SIEM_SESSION_TTL": str(2**31 - 1)}).session_ttl_seconds, 2**31 - 1)
        self.assert_bad({"SIEM_SESSION_TTL": "0"}, "SIEM_SESSION_TTL ")
        self.assert_bad({"SIEM_SESSION_TTL": "-1"}, "SIEM_SESSION_TTL ")
        self.assert_bad({"SIEM_SESSION_TTL": str(2**31)}, "SIEM_SESSION_TTL ")
        self.assertEqual(self.load({"SIEM_MAX_UPLOAD_BYTES": "1"}).max_upload_bytes, 1)
        self.assert_bad({"SIEM_MAX_UPLOAD_BYTES": "0"}, "SIEM_MAX_UPLOAD_BYTES ")
        self.assertEqual(self.load({"SIEM_MAX_BATCH_EVENTS": "1"}).max_batch_events, 1)
        self.assert_bad({"SIEM_MAX_BATCH_EVENTS": "0"}, "SIEM_MAX_BATCH_EVENTS ")
        self.assert_bad({"SIEM_LOGIN_RATE_BURST": "0"}, "SIEM_LOGIN_RATE_BURST ")
        self.assert_bad({"SIEM_RATE_BURST": "-1"}, "SIEM_RATE_BURST ")
        self.assertEqual(self.load({"SIEM_LOGIN_RATE_PER_MIN": "0.5"}).login_rate_per_minute, 0.5)
        self.assertEqual(self.load({"SIEM_RATE_PER_MIN": " 10 "}).rate_per_minute, 10.0)
        self.assertEqual(self.load({"SIEM_LOGIN_RATE_PER_MIN": "1e1"}).login_rate_per_minute, 10.0)
        cfg = self.load({}, login_rate_per_minute=1, rate_per_minute=1)
        self.assertEqual(cfg.login_rate_per_minute, 1.0)
        self.assertIsInstance(cfg.rate_per_minute, float)
        for raw in ("0", "nan", "inf", "Infinity", "1e-322", "-1"):
            self.assert_bad({"SIEM_LOGIN_RATE_PER_MIN": raw}, "SIEM_LOGIN_RATE_PER_MIN ")
            self.assert_bad({"SIEM_RATE_PER_MIN": raw}, "SIEM_RATE_PER_MIN ")
        cfg = self.load({"SIEM_LOGIN_RATE_BURST": "4", "SIEM_LOGIN_RATE_PER_MIN": "2"})
        TokenBucketLimiter(burst=cfg.login_rate_burst, per_minute=cfg.login_rate_per_minute)

    def test_demo_loop_bounds(self):
        self.assert_bad({"SIEM_DEMO_LOOP": "-1"}, "SIEM_DEMO_LOOP ")
        self.assertEqual(self.load({"SIEM_DEMO_LOOP": "0"}).demo_loop_minutes, 0)
        self.assertEqual(self.load({"SIEM_DEMO_LOOP": "15"}).demo_loop_minutes, 15)
        for raw in ("0", "10001", "nan", "inf", "-1"):
            self.assert_bad({"SIEM_DEMO_LOOP_SPEED": raw}, "SIEM_DEMO_LOOP_SPEED ")
        self.assertEqual(self.load({"SIEM_DEMO_LOOP_SPEED": "0.1"}).demo_loop_speed, 0.1)
        self.assertEqual(self.load({"SIEM_DEMO_LOOP_SPEED": "10000"}).demo_loop_speed, 10000.0)
        self.assert_bad({}, "SIEM_DEMO_LOOP_SPEED ", demo_loop_speed=True)

    def test_secrets_keep_real_values_and_drop_blanks(self):
        blank = self.load({
            "SIEM_ADMIN_PASSWORD": "   ",
            "SIEM_ANALYST_PASSWORD": "",
            "SIEM_VIEWER_PASSWORD": "short",
            "SIEM_AUDIT_KEY": " \t ",
        })
        self.assertIsNone(blank.admin_password)
        self.assertIsNone(blank.analyst_password)
        self.assertEqual(blank.viewer_password, "short")
        self.assertIsNone(blank.audit_key)
        kept = self.load({
            "SIEM_ADMIN_PASSWORD": "x y",
            "SIEM_ANALYST_PASSWORD": "  keep  ",
            "SIEM_VIEWER_PASSWORD": "0",
            "SIEM_AUDIT_KEY": "0",
        })
        self.assertEqual(kept.admin_password, "x y")
        self.assertEqual(kept.analyst_password, "  keep  ")
        self.assertEqual(kept.viewer_password, "0")
        self.assertEqual(kept.audit_key, "0")
        self.assertIsNone(self.load({}, admin_password=None, analyst_password=None).admin_password)

        class Marker:
            def __repr__(self):
                return "LEAKED-SECRET-MARKER"

        message = self.assert_bad({}, "SIEM_ADMIN_PASSWORD ", admin_password=Marker())
        self.assertNotIn("LEAKED-SECRET-MARKER", message)

    def test_db_path_expands_home_and_keeps_memory(self):
        cfg = self.load({"HOME": "/tmp/wp-home", "SIEM_DB": "~/wp.db"})
        self.assertEqual(cfg.db_path, "/tmp/wp-home/wp.db")
        self.assertEqual(self.load({"SIEM_DB": " :memory: "}).db_path, ":memory:")
        self.assertEqual(self.load({"SIEM_DB": ":memory:"}).db_path, ":memory:")
        self.assertEqual(self.load({"SIEM_DB": ""}).db_path, str(BASE_DIR / "data" / "watchpost.db"))
        self.assertEqual(self.load({"SIEM_DB": "data/custom.db"}).db_path, "data/custom.db")
        self.assertEqual(self.load({"SIEM_DB": "/tmp/my db/wp.db"}).db_path, "/tmp/my db/wp.db")
        self.assert_bad({}, "SIEM_DB ", db_path="bad\x00path")

    def test_syslog_allow_is_checked_at_load(self):
        self.assertEqual(
            self.load({"SIEM_SYSLOG_ALLOW": "10.0.0.0/8, 192.0.2.1"}).syslog_allow,
            "10.0.0.0/8, 192.0.2.1")
        self.assertEqual(self.load({"SIEM_SYSLOG_ALLOW": "  "}).syslog_allow, "")
        self.assertEqual(self.load({"SIEM_SYSLOG_ALLOW": "::1, fe80::/10"}).syslog_allow, "::1, fe80::/10")
        self.assertEqual(self.load({"SIEM_SYSLOG_ALLOW": "10.1.2.3/8"}).syslog_allow, "10.1.2.3/8")
        self.assertEqual(self.load({"SIEM_SYSLOG_ALLOW": "10.0.0.0/8,"}).syslog_allow, "10.0.0.0/8,")
        message = self.assert_bad({"SIEM_SYSLOG_ALLOW": "not-an-ip"}, "SIEM_SYSLOG_ALLOW ")
        self.assertIn("not-an-ip", message)

    def test_overrides_win_over_a_bad_environment(self):
        cfg = self.load(
            {
                "SIEM_PORT": "nope",
                "SIEM_HOST": "",
                "SIEM_RATE_LIMIT": "bogus",
                "SIEM_SYSLOG_PORT": "nope",
            },
            port=0,
            host="localhost",
            rate_limit_enabled=False,
            syslog_port=0,
            syslog_enabled=True,
            trust_proxy=True,
            viewer_password="short",
            admin_password=None,
            secure_cookies="1",
            db_path=":memory:",
        )
        self.assertEqual(cfg.port, 0)
        self.assertEqual(cfg.host, "localhost")
        self.assertFalse(cfg.rate_limit_enabled)
        self.assertEqual(cfg.syslog_port, 0)
        self.assertTrue(cfg.syslog_enabled)
        self.assertTrue(cfg.trust_proxy)
        self.assertEqual(cfg.viewer_password, "short")
        self.assertIsNone(cfg.admin_password)
        self.assertTrue(cfg.secure_cookies)
        self.assertEqual(cfg.db_path, ":memory:")

    def test_direct_construction_is_idempotent(self):
        with self.assertRaises(ValueError):
            self.direct(port=99999)
        with self.assertRaises(ValueError):
            self.direct(host="bad host")
        cfg = self.direct(host="", port=0, syslog_port=0, viewer_password="short")
        self.assertEqual(cfg.host, "127.0.0.1")
        again = Config(**dataclasses.asdict(cfg))
        self.assertEqual(dataclasses.asdict(cfg), dataclasses.asdict(again))
        loaded = self.load({
            "SIEM_DB": "data/custom.db",
            "SIEM_HOST": "[::1]",
            "SIEM_PORT": "9090",
            "SIEM_SYSLOG_ALLOW": "10.0.0.0/8, 192.0.2.1",
            "SIEM_ADMIN_PASSWORD": "  keep  ",
            "SIEM_DEMO_LOOP": "15",
            "SIEM_DEMO_LOOP_SPEED": "0.1",
        })
        self.assertEqual(dataclasses.asdict(loaded), dataclasses.asdict(Config(**dataclasses.asdict(loaded))))

    def test_from_env_does_not_mutate_environ_and_rejects_unknown_keys(self):
        with mock.patch.dict(os.environ, {"SIEM_PORT": "9090"}, clear=True):
            snapshot = os.environ.copy()
            cfg = Config.from_env()
            self.assertEqual(dict(os.environ), snapshot)
        self.assertEqual(cfg.port, 9090)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(TypeError):
                Config.from_env(not_a_field=1)
