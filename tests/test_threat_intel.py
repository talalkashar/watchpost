"""Threat intelligence: feeds of hostile addresses tag events, raise alerts, and never list the inside.

Every address here is in a documentation range. No test reaches the internet: the URL feeds and the OTX
API are stood in for by servers on loopback.
"""

import ipaddress
import json
import threading
import unittest
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from watchpost import engine, threat_intel
from watchpost.config import Config
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.normalize import parse_payload
from watchpost.server import App

from .helpers import ServerTestCase

ROOT = Path(__file__).resolve().parent.parent
BAD, C2, NET = "203.0.113.45", "198.51.100.77", "198.51.100.128/25"
FEED = f"# comment\n{BAD} # brute force\n{NET} ; SBL123\n{C2},botnet C2\n"


def failures(ip=BAD, n=12):
    start = utcnow().replace(microsecond=0) - timedelta(minutes=10)
    return [{"ts": iso(start + timedelta(seconds=5 * i)), "type": "login_failed", "user": f"user{i % 4}", "src_ip": ip,
             "host": "web01"} for i in range(n)]


class ParseTests(unittest.TestCase):
    def test_the_formats_open_feeds_use(self):
        text = ("# a comment\n; another\n\n203.0.113.45\n198.51.100.0/24 ; SBL1 \n203.0.113.9 # botnet C2\n"
                "203.0.113.10,Feodo,2026-01-01\n203.0.113.11\t5\n203.0.113.12 | note\n2001:db8:bad::1\n2001:db8:f00::/48 # v6 net\n"
                "198.51.100.200/32\n203.0.113.45 # listed twice: the later note wins\n")
        entries, refused = threat_intel.parse(text)
        self.assertEqual(refused, [])
        self.assertEqual(entries, {
            "203.0.113.45": "listed twice: the later note wins", "198.51.100.0/24": "SBL1", "203.0.113.9": "botnet C2",
            "203.0.113.10": "Feodo,2026-01-01", "203.0.113.11": "5", "203.0.113.12": "note", "2001:db8:bad::1": None,
            "2001:db8:f00::/48": "v6 net", "198.51.100.200": None})

    def test_internal_broad_and_malformed_entries_are_refused_and_the_rest_kept(self):
        text = ("10.0.0.5\n192.168.1.0/24\n127.0.0.1\n169.254.1.1\nfc00::1\n::1\n10.0.0.0/8 # would mark the whole office\n"
                "203.0.0.0/8\n198.51.0.0/15\n2001:db8::/31\n0.0.0.0\n224.0.0.5\nexample.com\n999.1.1.1\n203.0.113.45/40\n"
                "<html>\n198.51.0.0/16\n203.0.113.45\n")
        entries, refused = threat_intel.parse(text)
        self.assertEqual(sorted(entries), ["198.51.0.0/16", "203.0.113.45"])
        self.assertEqual(len(refused), 16)
        reasons = {r.split(": ", 1)[1] for r in refused}
        self.assertEqual(reasons, {"an internal address", "broader than a /16", "broader than a /32", "not a host address",
                                   "not an address or network"})
        self.assertEqual(refused[0], "line 1: an internal address")
        note = threat_intel.parse("203.0.113.45 # " + "x" * 500 + "\x07")[0]["203.0.113.45"]
        self.assertEqual(len(note), threat_intel.MAX_NOTE)
        too_many = "\n".join(str(ipaddress.ip_address("198.18.0.0") + n) for n in range(threat_intel.MAX_INDICATORS + 1))
        with self.assertRaises(threat_intel.ThreatIntelError):
            threat_intel.parse(too_many)

    def test_matcher(self):
        matcher = threat_intel.Matcher([("drop", NET, "SBL123"), ("feodo", BAD, "C2"), ("mine", BAD, None),
                                        ("v6", "2001:db8:bad::/48", None), ("drop", "198.51.0.0/16", "wide")])
        self.assertEqual(matcher.label(BAD), "feodo: C2; mine")
        self.assertEqual(matcher.label("198.51.100.129"), "drop: SBL123; drop: wide")
        self.assertEqual(matcher.label("198.51.100.127"), "drop: wide")
        self.assertEqual(matcher.label("2001:db8:bad:1::5"), "v6")
        for unlisted in ("203.0.113.46", "198.52.0.1", "2001:db8:bae::1", "not-an-address", "", None):
            self.assertIsNone(matcher.label(unlisted))
        self.assertFalse(threat_intel.Matcher())
        self.assertIsNone(threat_intel.Matcher().label(BAD))

    def test_presets_and_the_bundled_sample(self):
        for name, preset in threat_intel.PRESETS.items():
            self.assertRegex(name, threat_intel.FEED_NAME)
            self.assertTrue(preset["url"].startswith("https://") and preset["terms"].startswith("https://"), name)
            self.assertTrue(preset["about"] and preset["use"])
        self.assertIn("non-commercial", threat_intel.PRESETS["otx"]["use"])
        text = (ROOT / "samples" / "threat_intel.txt").read_text()
        self.assertIn("[SYNTHETIC]", text.splitlines()[0])
        entries, refused = threat_intel.parse(text)
        self.assertEqual((len(entries), refused), (7, []))
        documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
        for value, note in entries.items():
            network = ipaddress.ip_network(value)
            self.assertTrue(any(network.version == d.version and network.subnet_of(d) for d in documentation), value)
            self.assertIn("[SYNTHETIC]", note)

    def test_feeds_from_config(self):
        def feeds(value, **kw):
            return threat_intel.feeds_from_config(Config.from_env(db_path=":memory:", threat_feeds=value, **kw))

        self.assertEqual(feeds(None), {})
        self.assertEqual(feeds(" spamhaus_drop , mine=https://intel.example.internal/bad.txt,"), {
            "spamhaus_drop": {"kind": "list", "url": threat_intel.PRESETS["spamhaus_drop"]["url"]},
            "mine": {"kind": "list", "url": "https://intel.example.internal/bad.txt"}})
        self.assertEqual(feeds("feodo=http://127.0.0.1:9/mirror.txt")["feodo"]["url"], "http://127.0.0.1:9/mirror.txt")
        self.assertEqual(feeds("otx", otx_api_key="k" * 64)["otx"], {"kind": "otx", "url": "https://otx.alienvault.com"})
        for bad, problem in (("otx", "SIEM_OTX_API_KEY"), ("nosuchfeed", "is not a preset"), ("Bad Name=https://x.example", "a name is"),
                             ("mine=http://intel.example.internal/x", "must use https"), ("mine=ftp://x.example/x", "must use https"),
                             ("mine=https://user:pw@x.example/x", "user name or password"), ("mine=", "no usable URL")):
            with self.assertRaisesRegex(ValueError, problem, msg=bad):
                feeds(bad)
        with self.assertRaisesRegex(ValueError, "at least 60"):
            feeds("ipsum", threat_feed_minutes=15)
        self.assertEqual(feeds(None, threat_feed_minutes=15), {})                   # no feed, no complaint
        with self.assertRaisesRegex(ValueError, "must use https"):
            App(Config.from_env(db_path=":memory:", admin_password="admin-test-password-1",
                                analyst_password="analyst-test-password-1", threat_feeds="mine=http://intel.example.internal/x"))


class TaggingTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def ingest(self, records):
        events, rejections = parse_payload(json.dumps(records), "json", "test")
        self.assertEqual(rejections, [])
        return engine.ingest(self.conn, events, rejections, "test", "json", "tester")

    def tags(self):
        return [(r["src_ip"], r["dest_ip"], r["threat"]) for r in self.conn.execute("SELECT src_ip, dest_ip, threat FROM events ORDER BY id")]

    def now(self):
        return iso(utcnow() - timedelta(minutes=5))

    def test_events_are_tagged_as_they_arrive_and_a_sender_cannot_tag_its_own(self):
        self.ingest([{"ts": self.now(), "type": "login", "src_ip": BAD, "threat": "made up by the sender"}])
        self.assertEqual(self.tags(), [(BAD, None, None)])                      # no feed yet: nothing is listed
        result = threat_intel.replace_feed(self.conn, "demo", FEED, "admin", synthetic=True)
        self.assertEqual({k: result[k] for k in ("feed", "indicators", "refused", "events_tagged")},
                         {"feed": "demo", "indicators": 3, "refused": 0, "events_tagged": 1})
        self.ingest([{"ts": self.now(), "type": "login", "src_ip": "203.0.113.46"},
                     {"ts": self.now(), "type": "fw_allow", "src_ip": "10.0.1.5", "dest_ip": C2, "dest_port": 443},
                     {"ts": self.now(), "type": "fw_deny", "src_ip": "198.51.100.200", "dest_ip": "10.0.1.5"},
                     {"ts": self.now(), "type": "fw_allow", "src_ip": BAD, "dest_ip": C2}])
        self.assertEqual(self.tags(), [(BAD, None, "demo: brute force"), ("203.0.113.46", None, None),
                                       ("10.0.1.5", C2, "demo: botnet C2"), ("198.51.100.200", "10.0.1.5", "demo: SBL123"),
                                       (BAD, C2, "demo: brute force")])              # the source is named first

    def test_a_changed_feed_tags_what_is_already_stored(self):
        self.ingest([{"ts": self.now(), "type": "fw_allow", "src_ip": "10.0.1.5", "dest_ip": C2},
                     {"ts": self.now(), "type": "login", "src_ip": BAD}])
        self.assertEqual([t[2] for t in self.tags()], [None, None])
        threat_intel.replace_feed(self.conn, "one", f"{C2} # C2\n", "admin")
        threat_intel.replace_feed(self.conn, "two", f"{BAD}\n{C2} # also here\n", "admin")
        self.assertEqual([t[2] for t in self.tags()], ["one: C2; two: also here", "two"])
        self.assertEqual(threat_intel.replace_feed(self.conn, "two", "203.0.113.99\n", "admin")["events_tagged"], 1)
        self.assertEqual([t[2] for t in self.tags()], ["one: C2", None])            # the feed is replaced, not added to
        self.assertEqual(threat_intel.delete_feed(self.conn, "one", "admin")["events_tagged"], 0)
        self.assertEqual([t[2] for t in self.tags()], [None, None])
        with self.assertRaises(threat_intel.ThreatIntelError) as raised:
            threat_intel.delete_feed(self.conn, "one", "admin")
        self.assertEqual(raised.exception.status, 404)
        for name, text in (("Bad Name", FEED), ("ok", ""), ("ok", "   \n"), ("ok", "10.0.0.1\nexample.com\n"), ("ok", None)):
            with self.assertRaises(threat_intel.ThreatIntelError, msg=(name, text)):
                threat_intel.replace_feed(self.conn, name, text, "admin")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM threat_indicators").fetchone()[0], 1)

    def test_an_alert_on_a_listed_address_is_raised_one_level_and_says_why(self):
        self.ingest(failures("203.0.113.46"))
        plain = self.conn.execute("SELECT severity, severity_note FROM alerts WHERE rule_id = 'brute_force_ip'").fetchone()
        self.assertEqual((plain["severity"], plain["severity_note"]), ("high", None))
        threat_intel.replace_feed(self.conn, "demo", FEED, "admin")
        self.ingest(failures(BAD))
        listed = self.conn.execute("SELECT severity, base_severity, severity_note FROM alerts WHERE group_key = ?", (BAD,)).fetchone()
        self.assertEqual((listed["severity"], listed["base_severity"]), ("critical", "high"))
        self.assertEqual(listed["severity_note"], "evidence touches an address listed by threat intelligence (demo: brute force)")
        weighed = threat_intel.raise_severity({"severity": "critical", "severity_note": "critical asset db01"}, ["a: x", "b"])
        self.assertEqual((weighed["severity"], weighed["severity_note"]),
                         ("critical", "critical asset db01; already critical; evidence touches an address listed by threat intelligence (a: x and 1 more)"))

    def test_the_matcher_is_reloaded_when_a_feed_changes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            first, second = connect(f"{tmp}/t.db"), connect(f"{tmp}/t.db")
            self.addCleanup(first.close)
            self.addCleanup(second.close)
            init_schema(first)
            self.assertFalse(threat_intel.load(second))
            threat_intel.replace_feed(first, "demo", FEED, "admin")
            self.assertEqual(threat_intel.load(second).label(BAD), "demo: brute force")   # another connection sees it
            self.assertIs(threat_intel.load(second), threat_intel.load(first))             # and the load is shared
            threat_intel.delete_feed(first, "demo", "admin")
            self.assertIsNone(threat_intel.load(second).label(BAD))


class FeedServer:
    """A feed publisher and an OTX stand-in on loopback."""

    def __init__(self):
        self.requests, self.status, self.text, self.pulses, self.next_host = [], 200, FEED, [], None
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fake.requests.append((self.path, dict(self.headers)))
                url = urlsplit(self.path)
                if url.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/list.txt")
                    self.send_header("Content-Length", "0")
                    return self.end_headers()
                if url.path == "/api/v1/pulses/subscribed":
                    if self.headers.get("X-OTX-API-KEY") != "otx-test-key":
                        return self.answer(403, b'{"detail": "Authentication required"}')
                    page = int(parse_qs(url.query).get("page", ["1"])[0])
                    following = None
                    if page < len(fake.pulses):
                        host = fake.next_host or f"http://127.0.0.1:{fake.server.server_address[1]}"
                        following = f"{host}/api/v1/pulses/subscribed?limit=50&page={page + 1}"
                    return self.answer(200, json.dumps({"results": fake.pulses[page - 1], "next": following}).encode())
                body = fake.text.encode() if isinstance(fake.text, str) else fake.text
                self.answer(fake.status, body)

            def answer(self, status, body):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        self.publisher = FeedServer()
        self.addCleanup(self.publisher.close)
        self.feeds = {"mine": {"kind": "list", "url": f"{self.publisher.base}/list.txt"}}

    def feed(self, name="mine"):
        return dict(self.conn.execute("SELECT * FROM threat_feeds WHERE name = ?", (name,)).fetchone())

    def test_a_url_feed_is_fetched_and_a_failure_keeps_the_last_good_copy(self):
        results = threat_intel.refresh(self.conn, self.feeds)
        self.assertEqual((results[0]["feed"], results[0]["indicators"]), ("mine", 3))
        self.assertEqual((self.feed()["source"], self.feed()["last_error"], self.feed()["updated_by"]), ("url", None, "threat-intel"))
        self.assertIn("Watchpost/", self.publisher.requests[0][1]["User-Agent"])
        for status, text, problem in ((500, "oops", "HTTP 500"), (200, "<html>sorry</html>", "no usable entry"),
                                      (200, b"x" * (threat_intel.MAX_FEED_BYTES + 5), "larger than")):
            self.publisher.status, self.publisher.text = status, text
            with self.assertLogs("watchpost.threat_intel", "WARNING"):
                results = threat_intel.refresh(self.conn, self.feeds)
            self.assertIn(problem, results[0]["error"])
            self.assertIn(problem, self.feed()["last_error"])
            self.assertEqual(threat_intel.load(self.conn).label(BAD), "mine: brute force")   # still the last good list
        self.publisher.status, self.publisher.text = 200, FEED
        redirecting = {"mine": {"kind": "list", "url": f"{self.publisher.base}/redirect"}}
        with self.assertLogs("watchpost.threat_intel", "WARNING"):
            self.assertIn("HTTP 302", threat_intel.refresh(self.conn, redirecting)[0]["error"])   # not followed
        with self.assertLogs("watchpost.threat_intel", "WARNING"):
            dead = threat_intel.refresh(self.conn, {"gone": {"kind": "list", "url": "http://127.0.0.1:9/x"}}, timeout=2)
        self.assertIn("error", dead[0])
        self.assertEqual((self.feed("gone")["indicators"], bool(self.feed("gone")["last_error"])), (0, True))

    def test_otx_subscribed_pulses_become_a_feed(self):
        self.publisher.pulses = [
            [{"name": "Botnet C2 servers\nline two", "indicators": [
                {"indicator": BAD, "type": "IPv4"}, {"indicator": "evil.example", "type": "domain"},
                {"indicator": "2001:db8:bad::1", "type": "IPv6"}, {"indicator": "10.9.9.9", "type": "IPv4"}]},
             {"name": None, "indicators": [{"indicator": NET, "type": "CIDR"}]}],
            [{"name": "Second page", "indicators": [{"indicator": C2, "type": "IPv4"}, "not an object"]}],
        ]
        feeds = {"otx": {"kind": "otx", "url": self.publisher.base}}
        results = threat_intel.refresh(self.conn, feeds, otx_api_key="otx-test-key", otx_days=7)
        self.assertEqual((results[0]["indicators"], results[0]["refused"]), (4, 1))        # the internal address is refused
        matcher = threat_intel.load(self.conn)
        self.assertEqual((matcher.label(BAD), matcher.label(C2), matcher.label("198.51.100.130")),
                         ("otx: Botnet C2 servers line two", "otx: Second page", "otx: OTX pulse"))
        path, headers = self.publisher.requests[0]
        query = parse_qs(urlsplit(path).query)
        sent = {name.lower(): value for name, value in headers.items()}   # header names are case-insensitive
        self.assertEqual((urlsplit(path).path, query["limit"], sent["x-otx-api-key"]),
                         ("/api/v1/pulses/subscribed", ["50"], "otx-test-key"))
        self.assertRegex(query["modified_since"][0], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$")
        self.assertEqual(len(self.publisher.requests), 2)

        with self.assertLogs("watchpost.threat_intel", "WARNING") as logged:
            wrong = threat_intel.refresh(self.conn, feeds, otx_api_key="wrong-key")
        self.assertIn("HTTP 403", wrong[0]["error"])
        self.assertNotIn("wrong-key", "".join(logged.output))
        self.assertEqual(threat_intel.load(self.conn).label(BAD), "otx: Botnet C2 servers line two")

        # A next page on another host is refused, and the key is never sent there.
        elsewhere = FeedServer()
        self.addCleanup(elsewhere.close)
        self.publisher.next_host = elsewhere.base
        with self.assertLogs("watchpost.threat_intel", "WARNING"):
            moved = threat_intel.refresh(self.conn, feeds, otx_api_key="otx-test-key")
        self.assertIn("another host", moved[0]["error"])
        self.assertEqual(elsewhere.requests, [])
        self.publisher.next_host, self.publisher.pulses = None, [[{"name": "empty", "indicators": []}]]
        with self.assertLogs("watchpost.threat_intel", "WARNING"):
            self.assertIn("no address in the subscribed pulses", threat_intel.refresh(self.conn, feeds, otx_api_key="otx-test-key")[0]["error"])

    def test_the_timer_fetches_in_its_own_thread(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/t.db"
            conn = connect(path)
            self.addCleanup(conn.close)
            init_schema(conn)
            fetcher = threat_intel.Fetcher(lambda: connect(path), self.feeds, interval_seconds=0.05).start()
            self.addCleanup(fetcher.stop)
            for _ in range(100):
                if conn.execute("SELECT COUNT(*) FROM threat_feeds").fetchone()[0]:
                    break
                threading.Event().wait(0.05)
            fetcher.stop()
            self.assertEqual(conn.execute("SELECT indicators FROM threat_feeds WHERE name = 'mine'").fetchone()[0], 3)


class ApiTests(ServerTestCase):
    def test_roles_import_lookup_hunt_and_delete(self):
        admin, analyst, viewer = self.client("admin"), self.client("analyst"), self.client("viewer")
        self.assertEqual(analyst.post("/api/ingest", failures())[0], 201)
        status, empty, _ = viewer.get("/api/threat-intel")
        self.assertEqual((status, empty["feeds"], empty["indicators"], empty["tagged_events"], empty["url_feeds"]), (200, [], 0, 0, []))
        self.assertEqual({p["name"] for p in empty["presets"]}, set(threat_intel.PRESETS))
        self.assertFalse(any(p["enabled"] for p in empty["presets"]))
        for client in (viewer, analyst):
            self.assertEqual(client.post("/api/threat-intel/feeds/demo", {"text": FEED})[0], 403)
            self.assertEqual(client.post("/api/threat-intel/feeds/demo/delete")[0], 403)
            self.assertEqual(client.post("/api/threat-intel/refresh")[0], 403)
        self.assertEqual(admin.post("/api/threat-intel/refresh")[0], 409)              # no URL feed configured
        self.assertEqual(admin.post("/api/threat-intel/feeds/Bad%20Name", {"text": FEED})[0], 404)
        self.assertEqual(admin.post("/api/threat-intel/feeds/demo", {"text": ""})[0], 400)
        status, result, _ = admin.post("/api/threat-intel/feeds/demo", {"text": FEED + "10.0.0.1\n", "synthetic": True})
        self.assertEqual((status, result["indicators"], result["refused"], result["refusals"], result["events_tagged"]),
                         (200, 3, 1, ["line 5: an internal address"], 12))
        overview = viewer.get(f"/api/threat-intel?ip={BAD}")[1]
        self.assertEqual([(f["name"], f["source"], f["synthetic"], f["indicators"], f["refused"]) for f in overview["feeds"]],
                         [("demo", "import", 1, 3, 1)])
        self.assertEqual((overview["tagged_events"], len(overview["recent"]), overview["recent"][0]["threat"]), (12, 12, "demo: brute force"))
        self.assertEqual(overview["lookup"], {"ip": BAD, "listed": "demo: brute force"})
        self.assertEqual(viewer.get("/api/threat-intel?ip=203.0.113.46")[1]["lookup"]["listed"], None)
        self.assertEqual(viewer.get("/api/threat-intel?ip=nonsense")[0], 400)
        # The tag is on events wherever they are read, and can be hunted.
        self.assertEqual(analyst.get("/api/events?limit=1")[1]["events"][0]["threat"], "demo: brute force")
        for query, count in (("threat:*", 12), ("threat:demo*", 12), ("threat:other*", 0), ("NOT threat:*", 0)):
            self.assertEqual(analyst.get("/api/hunt?q=" + query.replace(" ", "%20"))[1]["total"], count, query)
        alert = next(a for a in analyst.get("/api/alerts")[1] if a["rule_id"] == "brute_force_ip")
        self.assertEqual(analyst.get(f"/api/alerts/{alert['id']}")[1]["evidence"][0]["threat"], "demo: brute force")
        self.assertEqual(admin.post("/api/threat-intel/feeds/demo/delete")[1], {"feed": "demo", "events_tagged": 0})
        self.assertEqual(admin.post("/api/threat-intel/feeds/demo/delete")[0], 404)
        audit = admin.get("/api/audit?limit=50")[1]
        actions = [e["action"] for e in (audit["entries"] if isinstance(audit, dict) else audit)]
        self.assertTrue({"threat_feed_updated", "threat_feed_deleted"} <= set(actions))
        self.assertTrue(admin.get("/api/audit/verify")[1]["ok"])

    def test_a_hunt_for_listed_addresses_can_be_promoted_to_a_reviewed_detection(self):
        admin, analyst = self.client("admin"), self.client("analyst")
        self.assertEqual(admin.post("/api/threat-intel/feeds/demo", {"text": FEED, "synthetic": True})[0], 200)
        status, saved, _ = analyst.post("/api/hunt/saved", {"name": "Listed address seen", "query": "threat:*"})
        self.assertEqual(status, 201, saved)
        sample = {"malicious": [{"event_type": "fw_allow", "src_ip": "10.0.1.5", "dest_ip": C2, "threat": "demo: botnet C2"}],
                  "benign": [{"event_type": "fw_allow", "src_ip": "10.0.1.5", "dest_ip": "203.0.113.46"}]}
        status, change, _ = analyst.post(f"/api/hunt/saved/{saved['id']}/promote", {
            "group_by": "dest_ip", "threshold": 1, "window_minutes": 60, "severity": "high", "sample": sample})
        self.assertEqual(status, 201, change)
        self.assertTrue(change["evaluation"]["sample"]["passes"], change["evaluation"])
        rule_id = change["target"]

        def approve(pending):
            status, data, _ = admin.post(f"/api/changes/{pending['id']}/review",
                                         {"decision": "approve", "evidence_digest": pending["evidence_digest"]})
            self.assertEqual(status, 200, data)

        approve(change)
        status, change, _ = analyst.post(f"/api/rules/{rule_id}/proposals", {"enabled": True, "reason": "alert on every sighting"})
        self.assertEqual(status, 201, change)
        approve(change)
        # A connection to a listed address now raises an alert; one to an unlisted address does not.
        now = iso(utcnow() - timedelta(minutes=5))
        self.assertEqual(analyst.post("/api/ingest", [
            {"ts": now, "type": "fw_allow", "src_ip": "10.0.1.9", "dest_ip": C2, "dest_port": 443},
            {"ts": now, "type": "fw_allow", "src_ip": "10.0.1.9", "dest_ip": "203.0.113.46", "dest_port": 443}])[0], 201)
        alerts = [a for a in analyst.get("/api/alerts")[1] if a["rule_id"] == rule_id]
        self.assertEqual([(a["group_key"], a["severity"]) for a in alerts], [(C2, "critical")])   # high, raised: it is listed


class ConfiguredApiTests(ServerTestCase):
    def setUp(self):
        self.publisher = FeedServer()
        self.addCleanup(self.publisher.close)
        super().setUp()

    def config_overrides(self):
        return {"threat_feeds": f"feodo={self.publisher.base}/list.txt"}

    def test_an_admin_refreshes_the_configured_feeds(self):
        admin = self.client("admin")
        before = admin.get("/api/threat-intel")[1]
        self.assertEqual((before["url_feeds"], before["feeds"][0]["last_error"]), (["feodo"], "not fetched yet"))
        self.assertEqual([p["enabled"] for p in before["presets"] if p["name"] == "feodo"], [True])
        status, results, _ = admin.post("/api/threat-intel/refresh")
        self.assertEqual((status, results[0]["feed"], results[0]["indicators"]), (200, "feodo", 3))
        after = admin.get("/api/threat-intel")[1]
        self.assertEqual((after["feeds"][0]["source"], after["feeds"][0]["updated_by"], after["indicators"]), ("url", "admin", 3))
        # Asked again at once, the publisher is not contacted: a feed is fetched at most once an hour.
        again = admin.post("/api/threat-intel/refresh")[1]
        self.assertIn("at most once an hour", again[0]["skipped"])
        self.assertEqual(len(self.publisher.requests), 1)


if __name__ == "__main__":
    unittest.main()
