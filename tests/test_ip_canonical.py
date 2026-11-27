"""Hunt and event search bind a complete IP in the form ingest stores.

`2001:DB8::1` matches a row stored as `2001:db8::1`. A trailing * stays the typed text.
Anything that is neither a prefix nor one address is 400.
"""

import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt, queries, search_rules
from watchpost.db import connect, init_schema, iso, utcnow

ROOT = Path(__file__).resolve().parent.parent
STORED = "2001:db8::1"
EXPANDED = "2001:0db8:0000:0000:0000:0000:0000:0001"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    rows = [
        ("2001:db8::1", None, "src"),
        (None, "2001:db8::1", "dest"),
        ("203.0.113.10", None, "other"),
        ("2001:DB8::1", None, "raw-spelling"),
    ]
    for n, (src, dest, user) in enumerate(rows):
        ts = f"2026-10-07T11:{n:02d}:00.000Z"
        conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, dest_ip,"
            " message, synthetic) VALUES (?,?,?,?,?,?,?,?,?,?,1)",
            (ts, ts, "lab", "web01", "process_start", "low", user, src, dest, "[SYNTHETIC] ip form"))
    return conn


class IpCanonicalTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def users(self, text):
        page = hunt.run(self.conn, {"q": text})
        return sorted(e["user"] for e in page["events"])

    def test_a_complete_address_binds_as_the_stored_form(self):
        where, args = hunt.compile_query(f"src_ip:{EXPANDED}")
        self.assertEqual((where, args), (["src_ip = ?"], [STORED]))
        where, args = hunt.compile_query("ip:2001:DB8::1")
        self.assertEqual((where, args), (["(src_ip = ? OR dest_ip = ?)"], [STORED, STORED]))
        where, args = hunt.compile_query('dest_ip:"2001:DB8::1"')
        self.assertEqual(args, [STORED])
        self.assertEqual(hunt.explain("src_ip:2001:DB8::1")[0]["text"], f"src_ip = {STORED}")
        self.assertEqual(hunt.explain("NOT ip:2001:DB8::1")[0]["text"], f"NOT src_ip or dest_ip = {STORED}")

        # The uppercase row was inserted past ingest. Equality matches only the stored form.
        self.assertEqual(self.users("src_ip:2001:DB8::1"), ["src"])
        self.assertEqual(self.users("ip:2001:DB8::1"), ["dest", "src"])
        self.assertEqual(self.users("dest_ip:2001:0db8::1"), ["dest"])
        self.assertEqual(self.users("NOT src_ip:2001:DB8::1"), ["dest", "other", "raw-spelling"])

        found = queries.search_events(self.conn, {"ip": EXPANDED})
        self.assertEqual(sorted(e["user"] for e in found["events"]), ["dest", "src"])

    def test_a_prefix_stays_text_and_a_bad_address_is_400(self):
        where, args = hunt.compile_query("src_ip:2001:DB8*")
        self.assertEqual((where, args), (["src_ip LIKE ? ESCAPE '\\'"], ["2001:DB8%"]))
        self.assertEqual(hunt.explain("ip:2001:DB8*")[0]["text"], "src_ip or dest_ip starts with 2001:DB8")
        # LIKE folds ASCII, so the typed prefix still finds both spellings. It is not rewritten.
        self.assertEqual(self.users("src_ip:2001:DB8*"), ["raw-spelling", "src"])
        where, args = hunt.compile_query("src_ip:not-an-ip*")
        self.assertEqual(args, ["not-an-ip%"])

        for text, field in (("src_ip:999.1.1.1", "src_ip"), ("ip:not-an-ip", "ip"),
                            ('dest_ip:"2001:DB8::*"', "dest_ip")):
            with self.subTest(text=text):
                with self.assertRaises(hunt.HuntError) as caught:
                    hunt.compile_query(text)
                self.assertEqual(caught.exception.status, 400)
                self.assertIn(f"{field} must be a valid IP address", str(caught.exception))

        with self.assertRaises(queries.QueryError) as caught:
            queries.search_events(self.conn, {"ip": "2001:DB8*"})
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("ip must be a valid IP address", str(caught.exception))
        self.assertEqual(queries.search_events(self.conn, {"ip": "203.0.113.10"})["total"], 1)

    def test_a_detection_rule_uses_the_same_address(self):
        match = search_rules.matcher(search_rules.parse_filter("src_ip:2001:DB8::1")[1])
        self.assertTrue(match({"src_ip": STORED}))
        self.assertFalse(match({"src_ip": "2001:DB8::1"}))
        self.assertFalse(match({"src_ip": "2001:db8::2"}))
        prefix = search_rules.matcher(search_rules.parse_filter("src_ip:2001:DB8*")[1])
        self.assertTrue(prefix({"src_ip": STORED}))
        with self.assertRaises(search_rules.SearchRuleError) as caught:
            search_rules.parse_filter("src_ip:999.1.1.1")
        self.assertIn("src_ip must be a valid IP address", str(caught.exception))

    def test_the_docs_name_the_stored_form(self):
        for path in (ROOT / "docs" / "API.md", ROOT / "docs" / "REFERENCE.md"):
            text = path.read_text()
            self.assertIn("`2001:DB8::1` matches `2001:db8::1`", text)
            self.assertIn("400", text)


class IpCanonicalApiTests(ServerTestCase):
    def test_events_and_hunt_accept_either_spelling(self):
        client = self.client("analyst")
        base = utcnow() - timedelta(hours=1)
        status, body, _ = client.post("/api/ingest", {"source": "lab", "synthetic": True, "events": [
            {"ts": iso(base), "type": "process", "src_ip": EXPANDED, "message": "[SYNTHETIC] src"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "process", "dest_ip": "2001:DB8::1",
             "message": "[SYNTHETIC] dest"},
        ]})
        self.assertEqual(status, 201, body)
        status, data, _ = client.get("/api/events?ip=" + quote("2001:DB8::1"))
        self.assertEqual(status, 200, data)
        self.assertEqual(sorted(e["src_ip"] or e["dest_ip"] for e in data["events"]), [STORED, STORED])
        status, hunt_page, _ = client.get("/api/hunt?q=" + quote("src_ip:2001:DB8::1"))
        self.assertEqual(status, 200, hunt_page)
        self.assertEqual([e["src_ip"] for e in hunt_page["events"]], [STORED])
        self.assertEqual(hunt_page["terms"][0]["text"], f"src_ip = {STORED}")

        status, data, headers = client.get("/api/events?ip=999.1.1.1")
        self.assertEqual(status, 400)
        self.assertIn("ip must be a valid IP address", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, data, headers = client.get("/api/hunt?q=" + quote("dest_ip:not-an-ip"))
        self.assertEqual(status, 400, data)
        self.assertIn("dest_ip must be a valid IP address", data["error"])
        self.assertEqual(headers["Cache-Control"], "no-store")
