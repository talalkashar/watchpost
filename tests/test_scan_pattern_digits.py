"""Web scan injection digits are ASCII only.

sleep(4) and ' or 1 stay web_scan. sleep(４) and ' or ４ stay web_request.
int("４") is 4, and the pattern does not use \\d. UNION SELECT, /.ENV, and
Nikto stay web_scan. niKto stays not a scan.
"""

import re
import unittest
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.normalize import classify_web_request, normalize_weblog_line
from watchpost import normalize

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
NOW = datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc)
FULLWIDTH_FOUR = "\uff14"  # ４
KELVIN_LOOKALIKE = "ni\u212ato"  # niKto
LINE = ('203.0.113.80 - - [15/Sep/2026:10:00:00 +0000] "GET {path} HTTP/1.1" '
        '{status} 162 "-" "{agent}"')


def _line(path, status=200, agent="Mozilla/5.0"):
    return LINE.format(path=path, status=status, agent=agent)


class ScanPatternDigitTests(unittest.TestCase):
    def test_ascii_digits_stay_web_scan(self):
        self.assertEqual(int(FULLWIDTH_FOUR), 4)
        self.assertEqual(classify_web_request("sleep(4)", 200), "web_scan")
        self.assertEqual(classify_web_request("' or 1", 200), "web_scan")
        self.assertEqual(classify_web_request("UNION SELECT", 200), "web_scan")
        self.assertEqual(classify_web_request("/.ENV", 200), "web_scan")
        self.assertEqual(classify_web_request("/", 200, "Nikto"), "web_scan")
        sleep = normalize_weblog_line(_line("/q?s=sleep(4)"), "nginx", now=NOW)
        quoted = normalize_weblog_line(_line("/%27+or+1"), "nginx", now=NOW)
        self.assertEqual(sleep["event_type"], "web_scan")
        self.assertEqual(quoted["event_type"], "web_scan")
        self.assertIn("sleep(4)", sleep["message"])
        self.assertIn("%27+or+1", quoted["message"])

    def test_fullwidth_digits_stay_web_request(self):
        sleep_path = f"sleep({FULLWIDTH_FOUR})"
        quoted = f"' or {FULLWIDTH_FOUR}"
        self.assertEqual(classify_web_request(sleep_path, 200), "web_request")
        self.assertEqual(classify_web_request(quoted, 200), "web_request")
        self.assertNotEqual(classify_web_request(sleep_path, 200), "web_scan")
        self.assertNotEqual(classify_web_request(quoted, 200), "web_scan")
        self.assertEqual(classify_web_request(sleep_path, 500), "web_error")
        self.assertEqual(classify_web_request(quoted, 500), "web_error")
        self.assertIsNone(normalize._SCAN_PATTERN.search(sleep_path))
        self.assertIsNone(normalize._SCAN_PATTERN.search(quoted))
        self.assertIsNotNone(normalize._SCAN_PATTERN.search("sleep(4)"))
        self.assertIsNotNone(normalize._SCAN_PATTERN.search("' or 1"))
        stored = normalize_weblog_line(_line(f"/q?s={sleep_path}"), "nginx", now=NOW)
        self.assertEqual(stored["event_type"], "web_request")
        self.assertIn(FULLWIDTH_FOUR, stored["message"])
        self.assertNotIn("web_scan", stored["event_type"])
        later = normalize_weblog_line(_line("/q?s=sleep(4)"), "nginx", now=NOW)
        self.assertEqual(later["event_type"], "web_scan")

    def test_pattern_is_ascii_digits(self):
        self.assertIn("[0-9]", normalize._SCAN_PATTERN.pattern)
        self.assertNotIn(r"\d", normalize._SCAN_PATTERN.pattern)
        self.assertFalse(normalize._SCAN_PATTERN.flags & re.IGNORECASE)

    def test_known_scans_and_agent_lookalike_stay(self):
        self.assertEqual(classify_web_request("UNION SELECT password", 200), "web_scan")
        self.assertEqual(classify_web_request("/.ENV", 404), "web_scan")
        self.assertEqual(classify_web_request("/", 200, "Nikto/2.1"), "web_scan")
        self.assertEqual(classify_web_request("/", 200, KELVIN_LOOKALIKE), "web_request")
        self.assertNotEqual(
            classify_web_request("/", 200, KELVIN_LOOKALIKE),
            classify_web_request("/", 200, "nikto"))
        self.assertEqual(classify_web_request("/", 500, KELVIN_LOOKALIKE), "web_error")

    def test_docs_name_the_ascii_digits(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("`sleep(4)` and `' or 1` are `web_scan`", text)
            self.assertIn("`sleep(４)` and `' or ４` are `web_request`", text)
            self.assertIn("The pattern is `[0-9]`, not `\\d`", text)
            self.assertIn("`UNION SELECT` and `/.ENV` are `web_scan`", text)
            self.assertIn("`Nikto` and `sqlmap` are `web_scan`", text)
            self.assertIn("`ni\u212ato` is not", text)


class ScanPatternDigitApiTests(ServerTestCase):
    def _upload(self, client, line):
        return client.post(
            "/api/ingest/upload?format=weblog&source=nginx&synthetic=true",
            raw=(line + "\n").encode(),
            headers={"Content-Type": "text/plain"})

    def test_upload_stores_fullwidth_sleep_as_web_request(self):
        client = self.client("analyst")
        wide = _line(f"/q?s=sleep({FULLWIDTH_FOUR})")
        status, body, headers = self._upload(client, wide)
        self.assertEqual(status, 201, body)
        self.assertNotEqual(status, 500)
        self.assertEqual(body["accepted"], 1)
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, page, _ = client.get("/api/events")
        self.assertEqual(page["total"], 1)
        event = page["events"][0]
        self.assertEqual(event["event_type"], "web_request")
        self.assertNotEqual(event["event_type"], "web_scan")
        self.assertIn(FULLWIDTH_FOUR, event["message"])
        self.assertEqual(event["synthetic"], 1)

        status, quoted, _ = self._upload(client, _line(f"/%27+or+{FULLWIDTH_FOUR}"))
        self.assertEqual(status, 201, quoted)
        status, page, _ = client.get("/api/events?q=" + quote(FULLWIDTH_FOUR))
        types = {row["event_type"] for row in page["events"]}
        self.assertEqual(types, {"web_request"})

        status, scan, _ = self._upload(client, _line("/q?s=sleep(4)"))
        self.assertEqual(status, 201, scan)
        status, page, _ = client.get("/api/events")
        by_message = {row["message"]: row["event_type"] for row in page["events"]}
        sleep_rows = [kind for message, kind in by_message.items() if "sleep(4)" in message]
        wide_rows = [kind for message, kind in by_message.items() if FULLWIDTH_FOUR in message]
        self.assertEqual(sleep_rows, ["web_scan"])
        self.assertEqual(set(wide_rows), {"web_request"})

        for path, agent, expected in (
            ("/q?s=UNION+SELECT+password", "Mozilla/5.0", "web_scan"),
            ("/.ENV", "Mozilla/5.0", "web_scan"),
            ("/", "Nikto/2.1", "web_scan"),
            ("/", KELVIN_LOOKALIKE, "web_request"),
        ):
            status, stored, _ = self._upload(client, _line(path, agent=agent))
            self.assertEqual(status, 201, stored)
            status, page, _ = client.get("/api/events?limit=1")
            self.assertEqual(page["events"][0]["event_type"], expected)
