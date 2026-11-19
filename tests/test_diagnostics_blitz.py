"""Edge cases for redaction and error recording.

The patterns locked by tests/test_normalize.py are repeated here so this file
can run on its own.
"""

import io
import json
import logging
import unittest

from watchpost.db import connect, init_schema
from watchpost.diagnostics import (
    RedactingFilter,
    configure_logging,
    describe_exception,
    log,
    record_error,
    redact,
    redact_cut,
)


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self._handlers = log.handlers[:]
        self._level = log.level
        self._propagate = log.propagate

    def tearDown(self):
        for handler in log.handlers:
            if handler not in self._handlers:
                handler.close()
        log.handlers[:] = self._handlers
        log.setLevel(self._level)
        log.propagate = self._propagate

    def memory(self):
        conn = connect(":memory:")
        init_schema(conn)
        self.addCleanup(conn.close)
        return conn

    def test_patterns_and_locked_json(self):
        for text in ["password=abc123", "Authorization: Bearer abcdefghijklmnop",
                     'body {"password": "abc123"}', "token wp_abcdefghijklmnopqrstuvwxyz",
                     "api_key: abc123"]:
            with self.subTest(text=text):
                out = redact(text)
                self.assertIn("REDACTED", out)
                self.assertNotIn("abc123", out)
                self.assertNotIn("abcdefghijklmnop", out)
        self.assertEqual(
            redact('{"password": "a\\"supersecret", "user": "alice"}'),
            '{"password": "[REDACTED]", "user": "alice"}',
        )
        self.assertEqual(redact('{"password" : "a\\"b\\"c"}'), '{"password" : "[REDACTED]"}')
        self.assertEqual(redact('{"password": ""}'), '{"password": "[REDACTED]"}')
        sample = "hunter2value"
        for key in ("pwd", "api-key", "apikey", "api_key", "authorization", "cookie", "session",
                    "API-KEY", "Session", "access_token", "refresh_token", "id_token",
                    "client_secret", "private_key", "Access_Token", "PRIVATE_KEY"):
            with self.subTest(key=key):
                raw = '{"%s": "a\\"%s", "user": "alice"}' % (key, sample)
                self.assertEqual(redact(raw), '{"%s": "[REDACTED]", "user": "alice"}' % key)
        for key in ("access_token", "refresh_token", "id_token", "client_secret", "private_key"):
            self.assertEqual(redact("%s=%s" % (key, sample)), "%s=[REDACTED]" % key)
            self.assertEqual(redact('%s: "%s"' % (key, sample)), "%s: [REDACTED]" % key)
        self.assertIn(sample, redact('{"session_id": "%s"}' % sample))
        self.assertEqual(redact("session_id=%s" % sample), "session_id=%s" % sample)
        self.assertIn(sample, redact('{"session_id": "a\\"%s"}' % sample))

    def test_escaped_key_value_does_not_leave_a_tail(self):
        self.assertEqual(redact('password="a\\"supersecret"'), "password=[REDACTED]")
        self.assertEqual(redact("password='a\\'supersecret'"), "password=[REDACTED]")
        self.assertEqual(redact('password: "a\\"b\\"c"'), "password: [REDACTED]")
        # A space used to end the value while the quote was still open.
        self.assertEqual(redact('password="unterminated secret tail'), "password=[REDACTED]")
        self.assertEqual(
            redact('note password="unterminated secret" tail'),
            "note password=[REDACTED] tail",
        )

    def test_python_repr_and_nested_containers(self):
        self.assertEqual(
            redact("{'password': 'hunter2', 'user': 'alice'}"),
            "{'password': [REDACTED], 'user': 'alice'}",
        )
        nested = {"password": {"k": "hunter2"}, "user": "alice"}
        self.assertEqual(
            redact(json.dumps(nested)),
            '{"password": [REDACTED], "user": "alice"}',
        )
        self.assertEqual(
            redact(repr(nested)),
            "{'password': [REDACTED], 'user': 'alice'}",
        )
        self.assertEqual(
            redact(json.dumps({"password": ["hunter2", "x"], "n": 1})),
            '{"password": [REDACTED], "n": 1}',
        )
        # A bracket inside a string is not the end of the container.
        self.assertEqual(
            redact('{"password": {"k": "a}b"}, "user": "alice"}'),
            '{"password": [REDACTED], "user": "alice"}',
        )
        both = '{"password": {"a": "hunter2"}, "token": ["sekret"], "user": "alice"}'
        out = redact(both)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("sekret", out)
        self.assertIn('"user": "alice"', out)
        kept = json.dumps({"user": {"name": "alice"}})
        self.assertEqual(redact(kept), kept)
        # An unclosed container fails closed: the rest of the line is redacted.
        self.assertEqual(redact('{"password": {"k": "hunter2"'), '{"password": [REDACTED]')

    def test_json_numbers_bearer_quotes_percent_and_urls(self):
        self.assertEqual(
            redact('{"password": 12345678, "user": "alice"}'),
            '{"password": [REDACTED], "user": "alice"}',
        )
        self.assertEqual(redact('{"token": -42, "user": "alice"}'),
                         '{"token": [REDACTED], "user": "alice"}')
        self.assertEqual(redact('{"password": null}'), '{"password": [REDACTED]}')
        self.assertEqual(redact('{"password": true}'), '{"password": [REDACTED]}')
        self.assertEqual(
            redact('{"authorization": "Bearer hunter2value", "user": "alice"}'),
            '{"authorization": "[REDACTED]", "user": "alice"}',
        )
        quoted = redact('Authorization: Bearer "abcdefghijklmnop"')
        self.assertNotIn("abcdefghijklmnop", quoted)
        self.assertEqual(redact("password%3Dhunter2"), "password%3D[REDACTED]")
        self.assertEqual(redact("password%3dhunter2extra"), "password%3d[REDACTED]")
        self.assertEqual(redact("password%253Dhunter2"), "password%253D[REDACTED]")
        self.assertEqual(redact("http://user:hunter2@host/path"), "http://user:[REDACTED]@host/path")
        self.assertEqual(redact("http://:secret@host/x"), "http://:[REDACTED]@host/x")
        self.assertEqual(redact("http://example.com:8080/path"), "http://example.com:8080/path")
        self.assertEqual(redact("note password = hunter2"), "note password = [REDACTED]")
        self.assertEqual(redact("Failed password for invalid user admin"),
                         "Failed password for invalid user admin")
        self.assertEqual(redact("set-cookie: session=abc; HttpOnly"),
                         "set-cookie: [REDACTED]; HttpOnly")
        self.assertEqual(redact("password=hunter2&token=abcdefghij"),
                         "password=[REDACTED]&token=[REDACTED]")
        query = redact("https://x.test/cb?access_token=ya29.secret&state=ok")
        self.assertNotIn("ya29.secret", query)
        self.assertIn("state=ok", query)
        self.assertEqual(redact("wp_" + "a" * 15), "wp_" + "a" * 15)
        self.assertEqual(redact("wp_" + "a" * 16), "wp_[REDACTED]")

    def test_redact_hides_a_secret_in_an_unclosed_container(self):
        for raw, secret in [
            ("password=[hunter2", "hunter2"),
            ("token={abc123def", "abc123def"),
            ("secret: [s3cr3t", "s3cr3t"),
        ]:
            with self.subTest(raw=raw):
                out = redact(raw)
                self.assertNotIn(secret, out)
                self.assertIn("[REDACTED]", out)

    def test_redact_is_idempotent_and_cuts_after_redacting(self):
        samples = [
            'password="a\\"supersecret"',
            "{'password': 'hunter2'}",
            "password%3Dhunter2",
            "http://user:hunter2@host/path",
            '{"password": 12345678}',
            '{"password": "[REDACTED]"}',
            "password=[REDACTED]",
            "Authorization: Bearer abcdefghijklmnop",
            json.dumps({"password": {"k": "hunter2"}, "user": "alice"}),
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertEqual(redact(redact(text)), redact(text))
        self.assertIsNone(redact(None))
        self.assertIsNone(redact_cut(None, 10))
        # The JSON value pattern needs the closing quote. A prefix cut keeps the secret.
        secret = "SUPERSECRET"
        value = 'a\\"' + secret + ("p" * 40)
        opener = '{"password": "'
        limit = 2000
        pad = limit - len(opener) - len('a\\"') - len(secret)
        message = ("n" * pad) + opener + value + '"}'
        cut = message[:limit]
        self.assertIn(secret, cut)
        self.assertIn(secret, redact(cut))
        self.assertNotIn(secret, redact(message))
        stored = redact_cut(message, limit)
        self.assertNotIn(secret, stored)
        self.assertLessEqual(len(stored), limit)
        self.assertIn("[REDACTED]", stored)

    def test_describe_exception_redacts_before_the_limit(self):
        text = describe_exception(RuntimeError("password=hunter2"))
        self.assertTrue(text.startswith("RuntimeError: "))
        self.assertNotIn("hunter2", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("File ", text)
        detail = describe_exception(RuntimeError("n" * 500)).split(": ", 1)[1]
        self.assertEqual(len(detail), 300)
        secret = "SUPERSECRET"
        opener = '{"password": "'
        raw = opener + 'a\\"' + secret + ("p" * 400) + '"}'
        self.assertIn(secret, raw[:300])
        self.assertNotIn(secret, describe_exception(RuntimeError(raw)))

        class Broken(Exception):
            def __str__(self):
                raise RuntimeError("nope")

            def __repr__(self):
                return "Broken(password=hunter2repr)"

        broken = describe_exception(Broken())
        self.assertTrue(broken.startswith("Broken: "))
        self.assertNotIn("hunter2repr", broken)

        class Silent(Exception):
            def __str__(self):
                raise RuntimeError("nope")

            def __repr__(self):
                raise RuntimeError("nope")

        self.assertEqual(describe_exception(Silent()), "Silent: ")

    def test_record_error_stores_redacted_text_only(self):
        conn = self.memory()
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.handlers[:] = [handler]
        log.setLevel(logging.INFO)
        log.propagate = False

        self.assertEqual(record_error(conn, "ingest", None), "None")
        self.assertEqual(
            record_error(conn, "ingest", RuntimeError("password=hunter2")),
            "RuntimeError: password=[REDACTED]",
        )
        self.assertEqual(
            record_error(conn, "ingest", "see", guidance="see password=hunter2"),
            "see",
        )
        self.assertEqual(record_error(conn, "detection", "plain", guidance="Check the stream."),
                         "plain")
        self.assertEqual(record_error(conn, "password=hunter2", "plain note"), "plain note")
        self.assertEqual(record_error(None, "ingest", "token=abcdefghij"), "token=[REDACTED]")
        long = record_error(conn, "ingest", "x" * 600)
        self.assertEqual(long, "x" * 500)

        rows = list(conn.execute(
            "SELECT component, message, guidance FROM error_log ORDER BY id"))
        self.assertEqual(rows[0]["message"], "None")
        self.assertIsNone(rows[0]["guidance"])
        self.assertNotIn("hunter2", rows[1]["message"])
        self.assertIn("RuntimeError:", rows[1]["message"])
        self.assertEqual(rows[2]["guidance"], "see password=[REDACTED]")
        self.assertEqual(rows[3]["guidance"], "Check the stream.")
        self.assertEqual(rows[4]["component"], "password=hunter2")
        self.assertEqual(rows[4]["message"], "plain note")
        self.assertEqual(len(rows[5]["message"]), 500)
        lines = buf.getvalue().splitlines()
        self.assertIn("[ingest] RuntimeError: password=[REDACTED]", lines)
        self.assertIn("[ingest] token=[REDACTED]", lines)
        # component is stored as given. The log line is the only place that word remains.
        self.assertIn("[password=hunter2] plain note", lines)
        for line in lines:
            if line.startswith("[ingest]") or line.startswith("[detection]"):
                self.assertNotIn("hunter2", line)
                self.assertNotIn("abcdefghij", line)

    def test_record_error_survives_a_write_failure(self):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.handlers[:] = [handler]
        log.setLevel(logging.INFO)
        log.propagate = False
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        message = record_error(conn, "ingest", "password=hunter2")
        self.assertEqual(message, "password=[REDACTED]")
        closed = self.memory()
        closed.close()
        self.assertEqual(record_error(closed, "ingest", "password=hunter2"), "password=[REDACTED]")
        self.assertNotIn("hunter2", buf.getvalue())
        self.assertIn("could not persist error", buf.getvalue())

    def test_filter_redacts_args_traceback_and_a_bad_format(self):
        logger = logging.getLogger("watchpost.diagnostics.blitz")
        logger.handlers.clear()
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
        self.addCleanup(logger.handlers.clear)

        logger.error("login %s", "password=hunter2")
        self.assertIn("password=[REDACTED]", buf.getvalue())
        self.assertNotIn("hunter2", buf.getvalue())

        buf.seek(0)
        buf.truncate(0)
        try:
            raise ValueError("token=hunter2value")
        except ValueError:
            logger.exception("boom")
        logged = buf.getvalue()
        self.assertIn("ValueError", logged)
        self.assertIn("Traceback", logged)
        self.assertNotIn("hunter2value", logged)

        record = logging.LogRecord(
            "watchpost.diagnostics.blitz", logging.ERROR, __file__, 1,
            "value %s %s", ("password=hunter2",), None,
        )
        record.stack_info = "stack password=hunter2"
        self.assertTrue(RedactingFilter().filter(record))
        self.assertNotIn("hunter2", record.msg)
        self.assertNotIn("hunter2", record.stack_info)
        self.assertEqual(record.args, ())
        self.assertIsNone(record.exc_info)

        empty = logging.LogRecord(
            "watchpost.diagnostics.blitz", logging.ERROR, __file__, 1, "ok", (), None,
        )
        empty.exc_info = (None, None, None)
        self.assertTrue(RedactingFilter().filter(empty))
        self.assertEqual(empty.msg, "ok")
        self.assertIsNone(empty.exc_info)

    def test_configure_logging_redacts_the_stream(self):
        configure_logging()
        buf = io.StringIO()
        log.handlers[0].setStream(buf)
        log.error("password=%s", "hunter2")
        log.debug("password=debugsecret")
        try:
            raise RuntimeError("token=hunter2value")
        except RuntimeError:
            log.exception("failed")
        text = buf.getvalue()
        self.assertNotIn("hunter2", text)
        self.assertNotIn("debugsecret", text)
        self.assertIn("password=[REDACTED]", text)
        self.assertIn("RuntimeError", text)
        self.assertIn("watchpost", text)
        self.assertFalse(log.propagate)


if __name__ == "__main__":
    unittest.main()
