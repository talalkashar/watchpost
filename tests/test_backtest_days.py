"""Rule backtest days accepts ASCII digits only.

days=7 stays a window of 7. A missing days stays the default 7. days=１０,
days=², and days=1_0 are 400 days must be an integer between 1 and 30.
A superscript is that 400, not a 500. int() runs only after isascii.
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost.server import rule_backtest

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
SERVER = Path(__file__).resolve().parent.parent / "watchpost" / "server.py"
FULLWIDTH = "\uff11\uff10"  # １０
SUPERSCRIPT = "\u00b2"  # ²
UNDERSCORE = "1_0"
MESSAGE = "days must be an integer between 1 and 30"
RULE = "brute_force_ip"


class BacktestDaysTests(ServerTestCase):
    def _get(self, client, days=None):
        path = f"/api/rules/{RULE}/backtest"
        if days is not None:
            path += "?days=" + quote(days, safe="")
        return client.get(path)

    def test_ascii_seven_stays_and_lookalikes_are_not_a_window(self):
        client = self.client("analyst")
        status, missing, headers = self._get(client)
        self.assertEqual(status, 200, missing)
        self.assertEqual(missing["window_days"], 7)
        self.assertEqual(missing["rule"], RULE)
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, seven, _ = self._get(client, "7")
        self.assertEqual(status, 200, seven)
        self.assertEqual(seven["window_days"], 7)

        for days in (FULLWIDTH, SUPERSCRIPT, UNDERSCORE, "0", "31"):
            with self.subTest(days=days):
                status, body, headers = self._get(client, days)
                self.assertEqual(status, 400, body)
                self.assertNotEqual(status, 500)
                self.assertEqual(body["error"], MESSAGE)
                self.assertNotIn("window_days", body)
                self.assertNotIn("\u0307", body["error"])
                self.assertEqual(headers["Cache-Control"], "no-store")

        status, changes, _ = client.get("/api/changes")
        self.assertEqual(status, 200, changes)
        self.assertEqual(changes, [])

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(rule_backtest)
        self.assertLess(source.index("isascii()"), source.index("int("))
        self.assertIn("isdigit()", source)
        self.assertEqual(source.count("int("), 1)
        self.assertNotIn(".lower(", source)
        self.assertNotIn("casefold(", source)
        body = SERVER.read_text().split("def rule_backtest", 1)[1].split("\n@route", 1)[0]
        self.assertLess(body.index("isascii()"), body.index("int("))
        self.assertEqual(body.count("int("), 1)

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("`days=7`", text)
            self.assertIn("missing `days`", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn(UNDERSCORE, text)
            self.assertIn("`days must be an integer between 1 and 30`", text)
            self.assertIn("not a 500", text)


if __name__ == "__main__":
    unittest.main()
