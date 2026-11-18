"""Hunt dest_port accepts ASCII digits only.

dest_port:443 and dest_port:0 stay those ports. dest_port:01 stays port 1.
dest_port:４４３ and dest_port:١٠ are the existing port error, not port 443 or 10.
dest_port:² and dest_port:① are that same 400, not a 500.
int() runs only after the value is ASCII digits.
"""

import inspect
import unittest
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
HUNT = Path(__file__).resolve().parent.parent / "watchpost" / "hunt.py"
PORT_ERROR = "dest_port must be an integer between 0 and 65535"
FULLWIDTH = "\uff14\uff14\uff13"  # ４４３
ARABIC = "\u0661\u0660"  # ١٠
SUPERSCRIPT = "\u00b2"  # ²
CIRCLED = "\u2460"  # ①


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = ((443, "https"), (0, "zero"), (1, "ssh"))
    for port, user in rows:
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, dest_port,"
            " message, synthetic) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("2026-10-07T12:00:00.000Z", "2026-10-07T12:00:00.000Z", "lab", "fw01", "fw_deny", "info",
             user, port, "[SYNTHETIC] deny", 1))
    return conn


class HuntDestPortTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, query):
        page = hunt.run(self.conn, {"q": query})
        return sorted(event["user"] for event in page["events"])

    def test_ascii_digits_stay_those_ports(self):
        for query, port, user in (
            ("dest_port:443", 443, "https"),
            ("dest_port:0", 0, "zero"),
            ("dest_port:01", 1, "ssh"),
        ):
            with self.subTest(query=query):
                where, args = hunt.compile_query(query)
                self.assertEqual((where, args), (["dest_port = ?"], [port]))
                self.assertEqual(hunt.explain(query)[0]["text"], f"dest_port = {port}")
                self.assertEqual(self.users(query), [user])
        self.assertNotEqual(self.users("dest_port:443"), ["ssh"])

    def test_non_ascii_digits_stay_the_existing_error(self):
        for query in (
            f"dest_port:{FULLWIDTH}",
            f"dest_port:{ARABIC}",
            f"dest_port:{SUPERSCRIPT}",
            f"dest_port:{CIRCLED}",
        ):
            with self.subTest(query=query):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(query)
                self.assertEqual(str(caught.exception), PORT_ERROR)
                self.assertEqual(caught.exception.status, 400)
        self.assertEqual(self.users("dest_port:443"), ["https"])
        self.assertEqual(self.users("dest_port:0"), ["zero"])
        self.assertEqual(self.users("dest_port:01"), ["ssh"])

    def test_int_runs_only_on_ascii_digits(self):
        source = inspect.getsource(hunt._term_sql)
        port = source.split('if kind == "port":', 1)[1].split('if kind == "bytes":', 1)[0]
        self.assertIn("isascii()", port)
        self.assertIn("isdigit()", port)
        self.assertLess(port.index("isascii()"), port.index("int("))
        self.assertNotIn(".lower(", port)
        self.assertNotIn("casefold(", port)
        body = HUNT.read_text()
        branch = body.split('if kind == "port":', 1)[1].split('if kind == "bytes":', 1)[0]
        self.assertIn("value.isascii()", branch)
        self.assertLess(branch.index("value.isascii()"), branch.index("int(value)"))


class HuntDestPortApiTests(ServerTestCase):
    def test_hunt_rejects_non_ascii_digits(self):
        client = self.client("analyst")
        for port, user in ((443, "https"), (0, "zero"), (1, "ssh")):
            status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [{
                "ts": "2026-10-07T12:00:00Z", "type": "fw_deny", "user": user, "dest_port": port,
                "message": "[SYNTHETIC] deny",
            }]})
            self.assertEqual(status, 201, body)

        def users(query):
            status, data, headers = client.get("/api/hunt?q=" + quote(query))
            self.assertEqual(status, 200, data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            return sorted(event["user"] for event in data["events"])

        self.assertEqual(users("dest_port:443"), ["https"])
        self.assertEqual(users("dest_port:0"), ["zero"])
        self.assertEqual(users("dest_port:01"), ["ssh"])

        for query in (
            f"dest_port:{FULLWIDTH}",
            f"dest_port:{ARABIC}",
            f"dest_port:{SUPERSCRIPT}",
            f"dest_port:{CIRCLED}",
        ):
            with self.subTest(query=query):
                status, data, headers = client.get("/api/hunt?q=" + quote(query))
                self.assertEqual(status, 400, data)
                self.assertEqual(data["error"], PORT_ERROR)
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(users("dest_port:443"), ["https"])

    def test_docs_name_the_ascii_digits(self):
        hunt_row = next(line for line in API.read_text().splitlines()
                        if line.startswith("| `GET /api/hunt?q="))
        port_row = next(line for line in REFERENCE.read_text().splitlines()
                        if "`dest_port:443`" in line)
        for text in (hunt_row, port_row):
            self.assertIn("ASCII digits only", text)
            self.assertIn("`dest_port:443`", text)
            self.assertIn("`dest_port:0`", text)
            self.assertIn("`dest_port:01`", text)
            self.assertIn(FULLWIDTH, text)
            self.assertIn(ARABIC, text)
            self.assertIn(SUPERSCRIPT, text)
            self.assertIn(CIRCLED, text)
            self.assertIn(PORT_ERROR, text)
            self.assertIn("not a 500", text)
