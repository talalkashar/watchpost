"""Numeric path ids are ASCII digits.

`\\d` matches ４, and int() of that character is 4, so the old route loaded
event 4. `[0-9]+` does not match. GET /api/events/４ is 404 and does not
return event 4. An ASCII id still returns that row. Session ids stay
[0-9a-f]{16}. A fullwidth id is not a 500.
"""

import io
import json
import re
from email.parser import Parser
from pathlib import Path

from tests.helpers import ServerTestCase
from tests.test_viewer import sample_path
from watchpost import server
from watchpost.db import connect, now_iso

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
SERVER = Path(__file__).resolve().parent.parent / "watchpost" / "server.py"
FULLWIDTH = "\uff14"  # ４
MARK = "[SYNTHETIC] path-id-four"


def _cookie(client):
    jar = next(handler.cookiejar for handler in client.opener.handlers if hasattr(handler, "cookiejar"))
    return "; ".join(f"{c.name}={c.value}" for c in jar)


class PathIdDigitTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        ts = now_iso()
        for event_id, user in ((1, "one"), (2, "two"), (3, "three"), (4, "four")):
            conn.execute(
                "INSERT INTO events(id, ts, ingested_at, source, host, event_type, severity, user,"
                " message, synthetic) VALUES (?,?,?,?,?,?,?,?,?,1)",
                (event_id, ts, ts, "lab", "web01", "auth_success", "low", user,
                 MARK if event_id == 4 else "[SYNTHETIC] other"),
            )
        conn.commit()

    def _handle(self, method, path, cookie):
        """Run Handler._handle with a path string. The HTTP parser cannot deliver ４."""
        handler = server.Handler.__new__(server.Handler)
        handler.path = path
        handler.command = method
        handler.request_version = "HTTP/1.1"
        handler.protocol_version = "HTTP/1.1"
        handler.requestline = f"{method} {path} HTTP/1.1"
        handler.headers = Parser().parsestr(f"Cookie: {cookie}\r\n\r\n")
        handler.client_address = ("127.0.0.1", 9)
        handler.app = self.app
        handler.wfile = io.BytesIO()
        handler.close_connection = False
        handler._headers_buffer = []
        handler._handle()
        raw = handler.wfile.getvalue()
        head, _, body = raw.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        text = head.decode("iso-8859-1")
        return status, json.loads(body.decode() or "null"), text

    def test_ascii_event_id_returns_the_row(self):
        status, body, headers = self.admin.get("/api/events/4")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["id"], 4)
        self.assertEqual(body["user"], "four")
        self.assertEqual(body["message"], MARK)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_fullwidth_event_id_is_404_and_is_not_event_four(self):
        self.assertEqual(int(FULLWIDTH), 4)
        status, body, headers = self._handle("GET", f"/api/events/{FULLWIDTH}", _cookie(self.admin))
        self.assertEqual(status, 404, body)
        self.assertNotEqual(status, 500)
        self.assertEqual(body, {"error": "not found"})
        self.assertNotIn("four", json.dumps(body))
        self.assertNotIn(MARK, json.dumps(body))
        self.assertNotIn("internal error", body["error"])
        self.assertIn("Cache-Control: no-store", headers)
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM error_log").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT user FROM events WHERE id = 4").fetchone()[0], "four")

    def test_every_numeric_route_rejects_a_fullwidth_id(self):
        numeric = 0
        sessions = 0
        for _method, pattern, _fn, _role, _csrf in server.ROUTES:
            self.assertNotIn(r"\d", pattern.pattern)
            if "[0-9a-f]{16}" in pattern.pattern:
                sessions += 1
                self.assertIsNone(pattern.match(f"/api/sessions/{FULLWIDTH * 16}/revoke"))
                continue
            if "[0-9]+" not in pattern.pattern:
                continue
            numeric += 1
            ascii_path = sample_path(pattern)
            self.assertIsNotNone(pattern.match(ascii_path))
            full_path = ascii_path.replace("1", FULLWIDTH, 1)
            self.assertNotEqual(full_path, ascii_path)
            self.assertIsNone(pattern.match(full_path))
        self.assertEqual(numeric, 23)
        self.assertEqual(sessions, 2)

    def test_route_decorators_use_ascii_digits(self):
        decorators = "\n".join(re.findall(r"^@route\((.*)\)$", SERVER.read_text(), re.M))
        self.assertNotIn(r"\d", decorators)
        self.assertEqual(decorators.count("[0-9]+"), 23)
        self.assertEqual(decorators.count("[0-9a-f]{16}"), 2)
        self.assertIn("([0-9]+)", decorators)
        self.assertNotIn("(\\d+)", decorators)

    def test_docs_name_the_ascii_path_id(self):
        for text in (API.read_text(), REFERENCE.read_text()):
            self.assertIn("ASCII digits", text)
            self.assertIn("`[0-9]+`", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn("`GET /api/events/４` is 404 and does not return event 4", text)
            self.assertIn("An ASCII id still returns that row", text)
            self.assertIn("`[0-9a-f]{16}`", text)
            self.assertIn("not a 500", text)
