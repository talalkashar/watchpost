import json
import re
import socket
import time
import unittest
from datetime import timedelta
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import geo, stream
from watchpost.db import iso, utcnow

STATIC = Path(__file__).resolve().parent.parent / "static"


def recent(minutes_ago=30):
    return iso(utcnow() - timedelta(minutes=minutes_ago))


class SSEClient:
    """Minimal raw-socket SSE reader, so the test sees exactly what the server writes."""

    def __init__(self, port, cookie=None):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        headers = "GET /api/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n"
        if cookie:
            headers += f"Cookie: {cookie}\r\n"
        self.sock.sendall((headers + "\r\n").encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            self._recv()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        self.status = int(lines[0].split()[1])
        self.headers = {k.lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:])}

    def _recv(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("stream closed")
        self.buf += chunk

    def frame(self):
        while b"\n\n" not in self.buf:
            self._recv()
        raw, self.buf = self.buf.split(b"\n\n", 1)
        fields = {}
        for line in raw.decode().split("\n"):
            key, _, value = line.partition(": ")
            fields[key] = value
        return fields.get("event"), json.loads(fields.get("data", "null")), fields

    def until(self, kind, limit=50):
        for _ in range(limit):
            got, data, _ = self.frame()
            if got == kind:
                return data
        raise AssertionError(f"no {kind} frame")

    def close(self):
        self.sock.close()


def _cookie_from(client):
    for handler in client.opener.handlers:
        jar = getattr(handler, "cookiejar", None)
        if jar is not None:
            return "; ".join(f"{c.name}={c.value}" for c in jar)
    raise AssertionError("no cookie jar")


class StreamTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self._heartbeat = stream.HEARTBEAT_SECONDS
        self.port = self.server.server_address[1]
        self.streams = []

    def tearDown(self):
        for s in self.streams:
            s.close()
        stream.HEARTBEAT_SECONDS = self._heartbeat
        super().tearDown()

    def open(self, client=None):
        s = SSEClient(self.port, _cookie_from(client) if client else None)
        self.streams.append(s)
        return s

    def test_requires_login(self):
        s = self.open()
        self.assertEqual(s.status, 401)

    def test_first_two_frames_are_hello_and_health(self):
        s = self.open(self.client("analyst"))
        self.assertEqual(s.status, 200)
        self.assertTrue(s.headers["content-type"].startswith("text/event-stream"))
        self.assertIn("default-src 'self'", s.headers["content-security-policy"])
        self.assertEqual(s.headers["cache-control"], "no-store")
        kind, data, fields = s.frame()
        self.assertEqual(kind, "hello")
        self.assertEqual(data["user"], "analyst")
        self.assertEqual(fields.get("retry"), "3000")
        kind, data, _ = s.frame()
        self.assertEqual(kind, "health")
        self.assertEqual(set(data["checks"]), {"storage", "ingestion", "detection", "dependencies"})
        self.assertFalse(data["partial"])

    def test_ingest_publishes_events_alerts_and_health(self):
        c = self.client("analyst")
        s = self.open(c)
        s.frame(), s.frame()
        start = utcnow() - timedelta(hours=1)
        batch = [{"ts": iso(start + timedelta(seconds=i)), "type": "login_failed", "user": "root",
                  "src_ip": "203.0.113.77", "host": "web01"} for i in range(12)]
        self.assertEqual(c.post("/api/ingest", {"source": "sshd", "events": batch})[0], 201)
        data = s.until("event")
        self.assertEqual(data["count"], 12)
        self.assertEqual(len(data["events"]), 12)
        self.assertEqual(data["events"][0]["src_ip"], "203.0.113.77")
        self.assertNotIn("raw", data["events"][0])
        health = s.until("health")
        self.assertEqual(health, {"partial": True, "checks": {"detection": "ok"}, "error": None})
        alerts = {}
        while "brute_force_ip" not in alerts:
            alert = s.until("alert")
            alerts[alert["rule_id"]] = alert
        self.assertEqual(alerts["brute_force_ip"]["change"], "created")
        self.assertEqual(alerts["brute_force_ip"]["group_key"], "203.0.113.77")

    def test_heartbeat_and_disconnect_cleanup(self):
        stream.HEARTBEAT_SECONDS = 0.2
        s = self.open(self.client("analyst"))
        s.frame(), s.frame()
        beat = s.until("heartbeat", limit=3)
        self.assertGreaterEqual(beat["subscribers"], 1)
        before = stream.BROKER.active()
        s.close()
        self.streams.remove(s)
        for _ in range(50):  # the server notices on its next heartbeat write
            if stream.BROKER.active() < before:
                break
            time.sleep(0.1)
        self.assertLess(stream.BROKER.active(), before)


class BrokerTests(unittest.TestCase):
    def test_overflow_turns_into_resync(self):
        broker = stream.Broker()
        sub = broker.subscribe()
        for i in range(stream.QUEUE_SIZE + 5):
            broker.publish("event", {"i": i})
        self.assertEqual(sub.get(timeout=0)[0], "resync")
        self.assertEqual(sub.get(timeout=0), ("event", {"i": 0}))

    def test_subscriber_cap(self):
        broker = stream.Broker()
        subs = [broker.subscribe() for _ in range(stream.MAX_SUBSCRIBERS)]
        with self.assertRaises(stream.TooManySubscribers):
            broker.subscribe()
        broker.unsubscribe(subs[0])
        broker.subscribe()

    def test_frame_format(self):
        raw = stream.frame("alert", {"title": "a\nb"}, 7).decode()
        self.assertEqual(raw, 'id: 7\nevent: alert\ndata: {"title":"a\\nb"}\n\n')


class GeoTests(ServerTestCase):
    def test_table_ranges_only(self):
        for ip in ("192.0.2.10", "198.51.100.7", "203.0.113.45"):
            with self.subTest(ip=ip):
                loc = geo.locate(ip)
                self.assertTrue(loc["synthetic"])
                self.assertFalse(loc["internal"])
                self.assertTrue(-90 <= loc["lat"] <= 90 and -180 <= loc["lon"] <= 180)
                self.assertEqual(loc, geo.locate(ip))  # deterministic
        self.assertTrue(geo.locate("10.0.1.20")["internal"])
        self.assertTrue(geo.locate("172.16.4.1")["internal"])
        self.assertTrue(geo.locate("192.168.1.1")["internal"])
        for ip in ("8.8.8.8", "2001:db8::1", "not-an-ip", "", None, "172.32.0.1"):
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))

    def test_documentation_ranges_spread_over_several_places(self):
        cities = {geo.locate(f"203.0.113.{i}")["city"] for i in range(256)}
        self.assertGreater(len(cities), 3)

    def test_geo_route(self):
        self.assertEqual(self.client().get("/api/geo?ips=192.0.2.1")[0], 401)
        c = self.client("analyst")
        status, data, _ = c.get("/api/geo?ips=192.0.2.1,8.8.8.8,10.0.0.5")
        self.assertEqual(status, 200)
        self.assertEqual(data["label"], "synthetic geo")
        self.assertIsNone(data["ips"]["8.8.8.8"])
        self.assertTrue(data["ips"]["192.0.2.1"]["synthetic"])
        self.assertEqual(c.get("/api/geo?ips=")[1]["ips"], {})
        self.assertEqual(c.get("/api/geo?ips=1.2.3.4,<script>")[0], 400)
        many = ",".join(f"10.0.0.{i % 250}" for i in range(201))
        self.assertEqual(c.get("/api/geo?ips=" + many)[0], 400)


class DashboardTests(ServerTestCase):
    def test_empty_database(self):
        status, data, _ = self.client("analyst").get("/api/dashboard")
        self.assertEqual(status, 200)
        self.assertEqual(data["events_total"], 0)
        self.assertEqual(len(data["events_per_minute"]), 60)
        self.assertEqual(data["alert_timeline"]["bins"], [])
        self.assertEqual(data["attackers"], [])

    def test_demo_data(self):
        admin = self.client("admin")
        self.assertEqual(admin.post("/api/demo/load", {})[0], 200)
        status, d, _ = admin.get("/api/dashboard")
        self.assertEqual(status, 200)
        self.assertGreater(d["events_total"], 0)
        self.assertEqual(d["synthetic_events"], d["events_total"])
        self.assertGreater(sum(m["count"] for m in d["events_per_minute"]), 0)  # just ingested
        timeline = d["alert_timeline"]
        self.assertEqual(len(timeline["bins"]), 24)
        self.assertEqual(sum(b["critical"] + b["high"] + b["medium"] + b["low"] for b in timeline["bins"]),
                         d["alerts_total"])
        ips = {a["ip"] for a in d["attackers"]}
        self.assertIn("203.0.113.45", ips)
        self.assertTrue(all(a["max_severity"] in ("critical", "high", "medium", "low", "info")
                            for a in d["attackers"]))
        self.assertTrue(d["top_rules"] and d["top_rules"][0]["alerts"] >= d["top_rules"][-1]["alerts"])
        self.assertEqual(len(d["alerts"]), d["alerts_total"])
        self.assertTrue(d["recent_events"])
        self.assertNotIn("raw", d["recent_events"][0])

    def test_live_run_zooms_to_five_minute_buckets(self):
        c = self.client("analyst")
        c.post("/api/ingest", [{"ts": recent(3), "type": "login_failed", "user": "x", "src_ip": "192.0.2.9"}
                               for _ in range(12)])
        timeline = c.get("/api/dashboard")[1]["alert_timeline"]
        self.assertEqual(timeline["bucket_minutes"], 5)
        self.assertGreaterEqual(sum(b["high"] + b["critical"] + b["medium"] + b["low"] for b in timeline["bins"]), 1)

    def test_events_since_id_for_polling_fallback(self):
        c = self.client("analyst")
        c.post("/api/ingest", [{"ts": recent(5), "type": "login", "user": "a"}])
        first = c.get("/api/events?limit=50&since_id=0")[1]
        last_id = first["events"][0]["id"]
        c.post("/api/ingest", [{"ts": recent(600), "type": "login", "user": "old"},
                               {"ts": recent(1), "type": "login", "user": "new"}])
        data = c.get(f"/api/events?limit=50&since_id={last_id}")[1]
        self.assertEqual(data["total"], 2)  # back-dated events still count as new arrivals
        self.assertEqual({e["user"] for e in data["events"]}, {"old", "new"})
        self.assertGreater(data["events"][0]["id"], data["events"][1]["id"])
        self.assertEqual(c.get("/api/events?since_id=x")[0], 400)

    def test_viewer_can_read_dashboard(self):
        import sqlite3
        from watchpost.auth import hash_password
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES "
                       "('viewer1', ?, 'viewer', '2026-01-01')", (hash_password("viewer-password-1"),))
        v = self.client()
        self.assertEqual(v.login("viewer1", "viewer-password-1")[0], 200)
        self.assertEqual(v.get("/api/dashboard")[0], 200)
        self.assertEqual(v.get("/api/geo?ips=192.0.2.1")[0], 200)


class StaticAssetTests(unittest.TestCase):
    """No JS runtime in CI, so check the browser code's shape and CSP hygiene from Python."""

    def read(self, name):
        return (STATIC / name).read_text()

    def exported(self, name, namespace):
        match = re.search(namespace + r"\s*=\s*Object\.freeze\(\{([^}]*)\}\)", self.read(name))
        self.assertIsNotNone(match, f"{name} does not export {namespace}")
        return {part.split(":")[0].strip() for part in match.group(1).split(",") if part.strip()}

    def test_charts_exports(self):
        names = self.exported("charts.js", "globalThis.WPCharts")
        self.assertLessEqual({"esc", "bars", "stackedBars", "line", "sparkline", "hbars", "heatMatrix"}, names)
        for name in names:
            self.assertRegex(self.read("charts.js"), rf"function {name}\(")

    def test_map_exports(self):
        names = self.exported("map.js", "globalThis.WPMap")
        self.assertLessEqual({"project", "baseMap", "arcPath", "LAND"}, names)

    def test_index_has_no_inline_code_and_scripts_exist(self):
        html = self.read("index.html")
        scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.S)
        self.assertTrue(scripts)
        for attrs, body in scripts:
            self.assertEqual(body.strip(), "", "inline script body")
            src = re.search(r'src="/([^"]+)"', attrs).group(1)
            self.assertTrue((STATIC / src).is_file(), src)
        self.assertNotRegex(html, r"\sstyle=", "inline style attribute")
        self.assertNotRegex(html, r"\son[a-z]+=", "inline event handler")
        self.assertNotIn("<style", html)
        for sheet in re.findall(r'href="/([^"]+\.css)"', html):
            self.assertTrue((STATIC / sheet).is_file(), sheet)

    def test_js_never_uses_html_injection_or_eval(self):
        for path in STATIC.glob("*.js"):
            text = path.read_text()
            for bad in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
                with self.subTest(file=path.name, pattern=bad):
                    self.assertNotIn(bad, text)
        # SVG strings are parsed as SVG and must not carry style attributes (blocked by the CSP).
        for name in ("charts.js", "map.js", "dashboard.js"):
            self.assertNotIn(' style="', self.read(name), name)

    def test_csp_is_still_strict(self):
        from watchpost.server import SECURITY_HEADERS
        csp = SECURITY_HEADERS["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)


if __name__ == "__main__":
    unittest.main()
