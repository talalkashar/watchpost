import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)

# (ts, event_type, severity, user, src_ip, dest_ip, host, source, message, dest_port, synthetic)
EVENTS = [
    ("2026-10-07T11:00:00.000Z", "auth_failure", "low", "alice", "10.0.0.5", "10.0.0.9", "web01", "lab",
     "Failed password: invalid password for alice", 22, 0),
    ("2026-10-07T10:00:00.000Z", "auth_failure", "low", "alice", "203.0.113.45", "10.0.0.9", "web02", "lab",
     "invalid password for alice", 22, 1),
    ("2026-10-06T09:00:00.000Z", "auth_success", "info", "Alice", "203.0.113.45", None, "db01", "lab",
     "Accepted password for alice", 22, 0),
    ("2026-09-20T09:00:00.000Z", "auth_failure", "low", "bob", "198.51.100.7", None, "web01", "other",
     "invalid user bob", None, 0),
    ("2026-10-07T11:30:00.000Z", "process_start", "high", None, None, None, "web01", "lab",
     "100% done_now", None, 0),
    ("2026-10-07T11:40:00.000Z", "auth_failure", "low", "x' OR 1=1 --", "10.0.0.6", None, "web01", "lab",
     "odd user", None, 0),
]


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    for (ts, et, sv, user, src, dst, host, source, msg, port, syn) in EVENTS:
        conn.execute("INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, dest_ip,"
                     " message, dest_port, synthetic) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (ts, ts, source, host, et, sv, user, src, dst, msg, port, syn))
    return conn


class ParserTests(unittest.TestCase):
    def test_field_terms_bare_and_quoted(self):
        terms = hunt.parse('user:alice host:"web 01" invalid "bad password"')
        self.assertEqual([(t["field"], t["value"], t["negate"], t["quoted"]) for t in terms], [
            ("user", "alice", False, False), ("host", "web 01", False, True),
            ("message", "invalid", False, False), ("message", "bad password", False, True)])

    def test_not_and_dash_negate_one_term(self):
        terms = hunt.parse('NOT src_ip:10.0.0.5 -host:web01 -"bad thing" user:a-b')
        self.assertEqual([(t["field"], t["value"], t["negate"]) for t in terms], [
            ("src_ip", "10.0.0.5", True), ("host", "web01", True), ("message", "bad thing", True),
            ("user", "a-b", False)])

    def test_lowercase_not_is_a_word_and_and_is_ignored(self):
        terms = hunt.parse("not AND user:a")
        self.assertEqual([(t["field"], t["value"]) for t in terms], [("message", "not"), ("user", "a")])

    def test_or_is_refused(self):
        with self.assertRaisesRegex(hunt.HuntError, "OR is not supported"):
            hunt.parse("user:a OR user:b")

    def test_quote_escapes(self):
        self.assertEqual(hunt.parse(r'message:"say \"hi\" \\ now"')[0]["value"], r'say "hi" \ now')

    def test_syntax_errors(self):
        for text, message in [('user:"open', "unterminated quote"), ("user:", "needs a value"),
                              ("NOT", "must be followed by a term"), ("NOT NOT user:a", "must be followed by a term"),
                              ("- user:a", "must be followed by a term"), ('user:"a"b', "after a closing quote")]:
            with self.subTest(text=text), self.assertRaisesRegex(hunt.HuntError, message):
                hunt.parse(text)

    def test_unknown_field_names_the_allowed_fields(self):
        with self.assertRaises(hunt.HuntError) as caught:
            hunt.parse("usr:alice")
        self.assertIn("unknown field 'usr'", str(caught.exception))
        for field in ("user", "host", "src_ip", "event_type", "last", "since"):
            self.assertIn(field, str(caught.exception))

    def test_length_and_term_caps(self):
        with self.assertRaisesRegex(hunt.HuntError, "at most 500 characters"):
            hunt.parse("a" * 501)
        with self.assertRaisesRegex(hunt.HuntError, "at most 20 terms"):
            hunt.parse(" ".join(["x"] * 21))
        self.assertEqual(len(hunt.parse(" ".join(["x"] * 20))), 20)

    def test_value_validation(self):
        for text, message in [("event_type:nope", "event_type must be one of"), ("severity:huge", "severity must be"),
                              ("dest_port:http", "dest_port must be"), ("dest_port:70000", "dest_port must be"),
                              ("synthetic:maybe", "synthetic must be"), ("last:2y", "last must be"),
                              ("last:0h", "last must be"), ("last:400d", "last must be"),
                              ("since:yesterday", "since: unparseable"), ("NOT last:1h", "cannot be negated")]:
            with self.subTest(text=text), self.assertRaisesRegex(hunt.HuntError, message):
                hunt.compile_query(text, now=NOW)

    def test_compiled_sql_never_contains_user_input(self):
        where, args = hunt.compile_query('user:"x\' OR 1=1 --" host:web* "50%_off"', now=NOW)
        sql = " AND ".join(where)
        self.assertNotIn("1=1", sql)
        self.assertNotIn("web", sql)
        self.assertIn("x' OR 1=1 --", args)
        self.assertIn("web%", args)
        self.assertIn("%50\\%\\_off%", args)

    def test_time_ranges(self):
        where, args = hunt.compile_query("last:24h", now=NOW)
        self.assertEqual((where, args), (["ts >= ?"], ["2026-10-06T12:00:00.000Z"]))
        where, args = hunt.compile_query("last:15m since:2026-10-01 until:2026-10-07T00:00:00Z", now=NOW)
        self.assertEqual(where, ["ts >= ?", "ts >= ?", "ts <= ?"])
        self.assertEqual(args, ["2026-10-07T11:45:00.000Z", "2026-10-01T00:00:00.000Z", "2026-10-07T00:00:00.000Z"])

    def test_describe_echoes_how_terms_were_read(self):
        terms = hunt.explain('user:alice NOT src_ip:10.0.0.5 host:web* "invalid password" last:7d', now=NOW)
        self.assertEqual([t["text"] for t in terms], [
            "user = alice", "NOT src_ip = 10.0.0.5", "host starts with web", 'message contains "invalid password"',
            "time >= 2026-09-30T12:00:00.000Z (last 7d)"])


class SemanticsTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()

    def tearDown(self):
        self.conn.close()

    def hits(self, text):
        return [(e["user"], e["host"], e["ts"]) for e in hunt.run(self.conn, {"q": text}, now=NOW)["events"]]

    def users(self, text):
        return [e["user"] for e in hunt.run(self.conn, {"q": text}, now=NOW)["events"]]

    def test_example_query(self):
        rows = self.hits('user:alice event_type:auth_failure NOT src_ip:10.0.0.5 host:web* "invalid password" last:24h')
        self.assertEqual(rows, [("alice", "web02", "2026-10-07T10:00:00.000Z")])

    def test_user_is_case_insensitive_like_event_search(self):
        self.assertEqual(self.users("user:alice"), ["alice", "alice", "Alice"])

    def test_not_keeps_events_where_the_field_is_empty(self):
        # An event with no user is "not alice": NULL must not silently drop out of a negation.
        self.assertIn(None, self.users("NOT user:alice"))
        self.assertEqual(sorted(u for u in self.users("NOT user:alice") if u), ["bob", "x' OR 1=1 --"])

    def test_ip_matches_source_or_destination(self):
        self.assertEqual(len(self.hits("ip:10.0.0.9")), 2)
        self.assertEqual(len(self.hits("-ip:10.0.0.9")), len(EVENTS) - 2)
        self.assertEqual(len(self.hits("ip:203.0.*")), 2)

    def test_injection_attempt_matches_literally(self):
        self.assertEqual(self.users("user:\"x' OR 1=1 --\""), ["x' OR 1=1 --"])
        self.assertEqual(self.users("user:\"x' OR 1=1\""), [])
        self.assertEqual(self.users('"\' OR \'1\'=\'1"'), [])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], len(EVENTS))

    def test_like_wildcards_in_values_are_literal(self):
        self.assertEqual([e["message"] for e in hunt.run(self.conn, {"q": '"100%"'}, now=NOW)["events"]], ["100% done_now"])
        self.assertEqual(self.hits('"0% d"'), self.hits('"0% done"'))
        self.assertEqual(self.hits("message:_one"), [])
        self.assertEqual(self.hits("host:w_b*"), [])

    def test_quoted_star_is_literal_and_bare_star_is_a_prefix(self):
        self.assertEqual(self.hits('host:"web*"'), [])
        self.assertEqual(len(self.hits("host:web*")), 5)

    def test_other_fields(self):
        self.assertEqual(len(self.hits("dest_port:22")), 3)
        self.assertEqual(len(self.hits("synthetic:1")), 1)
        self.assertEqual(len(self.hits("synthetic:false")), len(EVENTS) - 1)
        self.assertEqual(len(self.hits("severity:high")), 1)
        self.assertEqual(len(self.hits("source:oth*")), 1)
        self.assertEqual(len(self.hits("event_type:auth_*")), 5)
        self.assertEqual(len(self.hits("last:7d")), len(EVENTS) - 1)
        self.assertEqual(len(self.hits("until:2026-09-30")), 1)

    def test_ordering_and_pagination_follow_event_search(self):
        page = hunt.run(self.conn, {"q": "host:web*", "limit": "2", "offset": "1"}, now=NOW)
        self.assertEqual((page["total"], page["limit"], page["offset"]), (5, 2, 1))
        self.assertEqual([e["ts"] for e in page["events"]], ["2026-10-07T11:30:00.000Z", "2026-10-07T11:00:00.000Z"])
        with self.assertRaisesRegex(hunt.HuntError, "limit must be between"):
            hunt.run(self.conn, {"q": "", "limit": "5000"}, now=NOW)

    def test_empty_query_lists_everything(self):
        page = hunt.run(self.conn, {"q": "  "}, now=NOW)
        self.assertEqual((page["total"], page["terms"]), (len(EVENTS), []))


class HuntApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        with sqlite3.connect(self.db_path) as db:
            for (ts, et, sv, user, src, dst, host, source, msg, port, syn) in EVENTS:
                db.execute("INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip,"
                           " dest_ip, message, dest_port, synthetic) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (ts, ts, source, host, et, sv, user, src, dst, msg, port, syn))

    def audit_actions(self, action):
        with sqlite3.connect(self.db_path) as db:
            return [(r[0], r[1], json.loads(r[2])) for r in db.execute(
                "SELECT actor, target, detail FROM audit_log WHERE action = ? ORDER BY id", (action,))]

    def test_viewer_runs_a_hunt_and_sees_the_parsed_terms(self):
        status, data, _ = self.client("viewer").get("/api/hunt?q=" + quote('user:alice NOT host:db01 "invalid"'))
        self.assertEqual(status, 200, data)
        self.assertEqual(data["total"], 2)
        self.assertEqual([t["text"] for t in data["terms"]], ["user = alice", "NOT host = db01", 'message contains "invalid"'])
        self.assertEqual(data["query"], 'user:alice NOT host:db01 "invalid"')

    def test_bad_query_returns_400_with_the_message(self):
        client = self.client("viewer")
        status, data, _ = client.get("/api/hunt?q=" + quote("usr:alice"))
        self.assertEqual(status, 400)
        self.assertIn("unknown field 'usr'", data["error"])
        status, data, _ = client.get("/api/hunt?q=" + quote("x" * 501))
        self.assertEqual((status, "at most 500" in data["error"]), (400, True))

    def test_hunt_requires_login(self):
        self.assertEqual(self.client().get("/api/hunt?q=x")[0], 401)

    def test_viewer_lists_but_cannot_save_or_delete(self):
        analyst = self.client("analyst")
        status, saved, _ = analyst.post("/api/hunt/saved", {"name": "Alice failures", "query": "user:alice last:24h"})
        self.assertEqual(status, 201, saved)
        viewer = self.client("viewer")
        status, listed, _ = viewer.get("/api/hunt/saved")
        self.assertEqual((status, [s["name"] for s in listed]), (200, ["Alice failures"]))
        self.assertEqual(viewer.post("/api/hunt/saved", {"name": "v", "query": "user:a"})[0], 403)
        self.assertEqual(viewer.post(f"/api/hunt/saved/{saved['id']}/delete")[0], 403)
        self.assertEqual(len(viewer.get("/api/hunt/saved")[1]), 1)
        self.assertEqual(len(self.audit_actions("saved_search_created")), 1)
        self.assertEqual(self.audit_actions("saved_search_deleted"), [])

    def test_analyst_saves_and_deletes_with_audit_entries(self):
        analyst = self.client("analyst")
        status, saved, _ = analyst.post("/api/hunt/saved", {"name": "Web brute force", "query": "host:web* event_type:auth_failure",
                                                            "description": "failures on web tier"})
        self.assertEqual(status, 201, saved)
        self.assertEqual((saved["owner"], saved["description"]), ("analyst", "failures on web tier"))
        self.assertEqual(self.audit_actions("saved_search_created"),
                         [("analyst", "Web brute force", {"id": saved["id"], "query": "host:web* event_type:auth_failure"})])
        status, data, _ = analyst.post(f"/api/hunt/saved/{saved['id']}/delete")
        self.assertEqual((status, data), (200, {"ok": True}))
        self.assertEqual(self.audit_actions("saved_search_deleted"),
                         [("analyst", "Web brute force", {"id": saved["id"], "query": "host:web* event_type:auth_failure"})])
        self.assertEqual(analyst.get("/api/hunt/saved")[1], [])
        self.assertEqual(analyst.post(f"/api/hunt/saved/{saved['id']}/delete")[0], 404)

    def test_save_validates_the_query_and_fields(self):
        analyst = self.client("analyst")
        for body, message in [({"name": "x", "query": "usr:a"}, "unknown field"),
                              ({"name": "x", "query": "  "}, "query is required"),
                              ({"name": " ", "query": "user:a"}, "name is required"),
                              ({"name": "n" * 81, "query": "user:a"}, "name must be at most 80"),
                              ({"name": "x", "query": "user:a", "description": "d" * 301}, "description must be at most 300"),
                              ({"name": "x", "query": ["user:a"]}, "query is required")]:
            with self.subTest(body=body):
                status, data, _ = analyst.post("/api/hunt/saved", body)
                self.assertEqual(status, 400, data)
                self.assertIn(message, data["error"])
        self.assertEqual(analyst.post("/api/hunt/saved", {"name": "dup", "query": "user:a"})[0], 201)
        status, data, _ = analyst.post("/api/hunt/saved", {"name": "DUP", "query": "user:b"})
        self.assertEqual((status, "already exists" in data["error"]), (409, True))
        self.assertEqual(len(self.audit_actions("saved_search_created")), 1)

    def test_only_the_owner_or_an_admin_deletes(self):
        admin = self.client("admin")
        saved = admin.post("/api/hunt/saved", {"name": "Admin hunt", "query": "severity:high"})[1]
        status, data, _ = self.client("analyst").post(f"/api/hunt/saved/{saved['id']}/delete")
        self.assertEqual(status, 403, data)
        mine = self.client("analyst").post("/api/hunt/saved", {"name": "Mine", "query": "user:bob"})[1]
        self.assertEqual(admin.post(f"/api/hunt/saved/{mine['id']}/delete")[0], 200)
        self.assertEqual(self.audit_actions("saved_search_deleted")[0][:2], ("admin", "Mine"))

    def test_v4_database_upgrades_with_a_saved_searches_table(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DROP TABLE saved_searches")
            db.execute("UPDATE meta SET value = '4' WHERE key = 'schema_version'")
        from watchpost.server import App
        App(self.config)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "9")
            columns = [r[1] for r in db.execute("PRAGMA table_info(saved_searches)")]
        self.assertEqual(columns, ["id", "name", "query", "description", "owner", "created_at"])
        self.assertEqual(self.client("analyst").post("/api/hunt/saved", {"name": "after", "query": "user:a"})[0], 201)


class HuntUiTests(unittest.TestCase):
    """No JS runtime in CI: check the hunt state is an encoded hash and pivots are wired."""

    def test_hunt_view_is_linked_and_encoded(self):
        static = Path(__file__).resolve().parent.parent / "static"
        app = (static / "app.js").read_text()
        self.assertIn('<button data-view="hunt">', (static / "index.html").read_text())
        self.assertIn("const huntHref = (q) => `#hunt/${encodeURIComponent(q)}`;", app)
        self.assertIn("hunt: () => huntView(huntQueryFromHash(", app)
        # Entity pages and the event detail pivot into a prefilled hunt; values with spaces or quotes are quoted.
        self.assertIn("huntLink(e.kind, e.value,", app)
        self.assertIn('huntLink(k, e[k], "Hunt",', app)
        self.assertIn('`"${v.replace(/[\\\\"]/g, "\\\\$&")}"`', app)
        self.assertNotIn(".innerHTML", app)


if __name__ == "__main__":
    unittest.main()
