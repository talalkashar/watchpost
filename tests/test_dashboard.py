import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import geo, stream
from watchpost.db import iso, utcnow
from watchpost.static_assets import CONSOLE_STYLES

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
        self.assertEqual(set(data["checks"]), {"storage", "ingestion", "detection", "dependencies", "storyline"})
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
        self.assertEqual(health, {
            "partial": True, "checks": {"detection": "ok"}, "error": None,
            "alerts_omitted": 0, "incidents_omitted": 0,
        })
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
                self.assertFalse(geo.is_internal(ip))
                self.assertTrue(-90 <= loc["lat"] <= 90 and -180 <= loc["lon"] <= 180)
                self.assertEqual(loc, geo.locate(ip))  # deterministic
        self.assertTrue(geo.locate("10.0.1.20") and geo.is_internal("10.0.1.20"))
        self.assertTrue(geo.locate("172.16.4.1") and geo.is_internal("172.16.4.1"))
        self.assertTrue(geo.locate("192.168.1.1") and geo.is_internal("192.168.1.1"))
        for ip in ("8.8.8.8", "2001:db8::1", "not-an-ip", "", None, "172.32.0.1"):
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))

    def test_documentation_ranges_spread_over_several_places(self):
        for prefix in ("192.0.2.", "198.51.100.", "203.0.113."):
            with self.subTest(prefix=prefix):
                cities = {geo.locate(f"{prefix}{i}")["city"] for i in range(256)}
                self.assertGreaterEqual(len(cities), 2)

    def test_geo_route(self):
        self.assertEqual(self.client().get("/api/geo?ips=192.0.2.1")[0], 401)
        c = self.client("analyst")
        status, data, _ = c.get("/api/geo?ips=192.0.2.1,8.8.8.8,10.0.0.5")
        self.assertEqual(status, 200)
        self.assertEqual(data["label"], "synthetic geo")
        self.assertIsNone(data["ips"]["8.8.8.8"])
        self.assertTrue(data["ips"]["192.0.2.1"]["synthetic"])
        self.assertFalse(data["ips"]["192.0.2.1"]["internal"])
        self.assertTrue(data["ips"]["10.0.0.5"]["internal"])
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
            sources = CONSOLE_STYLES if sheet == "console.css" else (sheet,)
            for source in sources:
                self.assertTrue((STATIC / source).is_file(), source)

    def test_login_is_safe_before_scripts_run(self):
        form = re.search(r'<form\b([^>]*\bid="login-form"[^>]*)>(.*?)</form>', self.read("index.html"), re.S)
        self.assertIsNotNone(form)
        self.assertRegex(form[1], r'\bmethod="post"')
        button = re.search(r'<button\b([^>]*\btype="submit"[^>]*)>', form[2])
        self.assertIsNotNone(button)
        self.assertIn("disabled", button[1].split())

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


class HeatMatrixLevelTests(unittest.TestCase):
    """The dashboard matrix must color by evidence level. Node runs the chart function; CI images have it."""

    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")

    def svg(self, columns, **opts):
        script = r"""
const fs = require("fs");
const vm = require("vm");
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), sandbox);
const input = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(sandbox.WPCharts.heatMatrix(input.columns, input.opts));
"""
        payload = json.dumps({"columns": columns, "opts": opts})
        out = subprocess.run(
            [self.node, "-e", script, str(STATIC / "charts.js")],
            input=payload, capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def cell_class(self, svg, technique_id):
        match = re.search(
            rf'class="cell ([^"]+)"[^>]*/>\s*<text class="cid [^"]*"[^>]*>{re.escape(technique_id)}</text>',
            svg)
        self.assertIsNotNone(match, svg)
        return match.group(1)

    def test_mapped_is_not_painted_as_a_gap(self):
        svg = self.svg([{"name": "Initial Access", "short": "Init", "cells": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "value": 4,
             "covered": False, "level": "mapped", "rules": ["web_scanner"]},
            {"id": "T1078", "name": "Valid Accounts", "value": 9,
             "covered": True, "level": "validated", "crit": True, "rules": ["success_after_failures"]},
        ]}])
        self.assertEqual(self.cell_class(svg, "T1190"), "mapped")
        self.assertNotIn('class="cell gap"', svg)
        self.assertIn("mapped only; no labeled scenario proves detection", svg)
        self.assertEqual(self.cell_class(svg, "T1078"), "h5 crit")

    def test_disabled_and_unleveled_gap_keep_their_classes(self):
        svg = self.svg([
            {"name": "Persistence", "short": "Persist", "cells": [
                {"id": "T1136.003", "value": 0, "covered": False, "level": "disabled", "rules": ["old_rule"]}]},
            {"name": "Impact", "short": "Impact", "cells": [
                {"id": "T1486", "value": 2, "covered": False, "rules": []}]},
        ])
        self.assertEqual(self.cell_class(svg, "T1136.003"), "disabled")
        self.assertEqual(self.cell_class(svg, "T1486"), "gap")

    def test_rows_past_max_are_named_instead_of_dropped(self):
        cells = [{"id": f"T100{i}", "value": 0, "covered": True, "level": "validated"} for i in range(5)]
        clipped = self.svg([{"name": "Initial Access", "short": "Init", "cells": cells}], maxRows=4)
        self.assertIn(">T1003</text>", clipped)
        self.assertNotIn(">T1004</text>", clipped)
        self.assertIn('class="more"', clipped)
        self.assertIn(">T1004</title>", clipped)
        full = self.svg([{"name": "Initial Access", "short": "Init", "cells": cells}], maxRows=5)
        self.assertIn(">T1004</text>", full)
        self.assertNotIn('class="more"', full)

    def test_empty_tactic_stays_on_the_kill_chain(self):
        svg = self.svg([
            {"name": "Reconnaissance", "short": "Recon", "cells": [
                {"id": "T1595.002", "value": 1, "covered": True, "level": "validated"}]},
            {"name": "Resource Development", "short": "Res Dev", "cells": []},
        ])
        self.assertIn('class="th quiet"', svg)
        self.assertIn(">Res Dev<", svg)
        self.assertIn(">0 tech", svg)

    def test_dashboard_asks_for_every_row_and_a_legend(self):
        src = (STATIC / "dashboard.js").read_text()
        start = src.index("renderMatrix()")
        chunk = src[start:src.index("// --- incident board")]
        self.assertNotIn("Math.min(4", chunk)
        self.assertIn("maxRows: Math.max(tallest, 1)", chunk)
        self.assertNotIn("columns.filter", chunk)
        self.assertIn("Empty tactics stay", chunk)
        self.assertIn("Mapped only", chunk)
        self.assertIn('id: "attack-legend"', src)
        css = (STATIC / "style.css").read_text()
        self.assertIn(".heat .cell.mapped", css)
        self.assertIn(".heat .cell.disabled", css)
        self.assertIn(".heat .cell.h5.crit", css)
        self.assertNotRegex(css, r"\.heat \.cell\.crit \{[^}]*fill:")


class MapSideTests(unittest.TestCase):
    """The attack-map side list names the fictional city on each busiest arc and counts unknown source IPs."""

    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.source = (STATIC / "dashboard.js").read_text()

    def summary(self, sources, locations):
        prelude = []
        for name in ("SEV_RANK", "sevOf", "maxSev"):
            match = re.search(rf"^const {name} = .*$", self.source, re.M)
            self.assertIsNotNone(match, name)
            prelude.append(match.group(0))
        body = re.search(r"^function mapSide\(.*?^\}$", self.source, re.S | re.M)
        self.assertIsNotNone(body, "function mapSide not found")
        script = "\n".join(prelude) + "\n" + body.group(0) + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const table = new Map(Object.entries(input.locations));
const out = mapSide(input.sources, (ip) => table.has(ip) ? table.get(ip) : undefined);
process.stdout.write(JSON.stringify(out));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"sources": sources, "locations": locations}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_busiest_arc_is_named_by_fictional_city(self):
        ironvale = {"city": "Ironvale", "internal": False, "synthetic": True}
        kestrel = {"city": "Kestrel Bay", "internal": False, "synthetic": True}
        out = self.summary([
            {"ip": "203.0.113.10", "events": 10, "sev": "medium"},
            {"ip": "203.0.113.20", "events": 4, "sev": "low"},
            {"ip": "198.51.100.8", "events": 9, "sev": "critical"},
            {"ip": "10.0.0.5", "events": 40, "sev": "critical"},
        ], {
            "203.0.113.10": ironvale,
            "203.0.113.20": ironvale,
            "198.51.100.8": kestrel,
            "10.0.0.5": {"city": "Riverton HQ", "internal": True, "synthetic": True},
        })
        self.assertEqual(out["locations"], 2)
        self.assertEqual([(a["city"], a["events"], a["ips"]) for a in out["arcs"]],
                         [("Ironvale", 14, 2), ("Kestrel Bay", 9, 1)])
        self.assertEqual(out["arcs"][1]["sev"], "critical")
        self.assertEqual(out["unknown"], 0)

    def test_unknown_source_ips_are_counted_not_plotted_as_arcs(self):
        out = self.summary([
            {"ip": "203.0.113.10", "events": 2, "sev": "low"},
            {"ip": "8.8.8.8", "events": 50, "sev": "critical"},
            {"ip": "1.1.1.1", "events": 3, "sev": "high"},
            {"ip": "198.51.100.4", "events": 1, "sev": "info"},
        ], {
            "203.0.113.10": {"city": "Ironvale", "internal": False},
            "8.8.8.8": None,
            "1.1.1.1": None,
        })
        self.assertEqual([a["city"] for a in out["arcs"]], ["Ironvale"])
        self.assertEqual(out["unknown"], 2)
        self.assertEqual(out["locations"], 1)

    def test_ties_break_by_severity_then_city_and_the_list_stops_at_five(self):
        cities = ["Northhaven", "Saltmere", "Kestrel Bay", "Duskport", "Ironvale", "Emberfield"]
        sources = [{"ip": f"192.0.2.{i}", "events": 5, "sev": "high" if i == 5 else "low"} for i in range(6)]
        locations = {s["ip"]: {"city": cities[i], "internal": False} for i, s in enumerate(sources)}
        out = self.summary(sources, locations)
        self.assertEqual(out["locations"], 6)
        self.assertEqual([a["city"] for a in out["arcs"]],
                         ["Emberfield", "Duskport", "Ironvale", "Kestrel Bay", "Northhaven"])
        self.assertEqual(out["arcs"][0]["sev"], "high")

    def test_side_list_renders_cities_and_the_unknown_count(self):
        start = self.source.index("renderMarks()")
        chunk = self.source[start:self.source.index("pulse(e)")]
        self.assertIn("mapSide(this.sources()", chunk)
        self.assertIn("this.mapView.update(ranked, hq, summary.unknown)", chunk)
        view = (STATIC / "map-view.js").read_text()
        self.assertIn("Busiest arcs", view)
        self.assertIn('"data-city": r.city', view)
        self.assertIn('el("button", { class: "ms-row"', view)
        self.assertIn("ms-city", view)
        self.assertIn("no geo entry", view)
        self.assertNotIn("Top sources", view)
        self.assertNotIn("unknown.slice", chunk)
        css = (STATIC / "style.css").read_text()
        self.assertIn("grid-template-columns: 12px minmax(0, 1fr) auto", css)
        self.assertIn(".ms-row .ms-city", css)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class OrbitGeometryTests(unittest.TestCase):
    def test_geographic_axes_and_shortest_beams(self):
        # Load the shipped ES modules with Node, including releases where .js
        # defaults to CommonJS outside a package. No browser or package install.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"type":"module"}')
            shutil.copy(STATIC / "orbit.js", root)
            shutil.copytree(STATIC / "vendor" / "three", root / "vendor" / "three")
            script = """
import assert from "node:assert/strict";
import { position, track } from "./orbit.js";
const near = (a, b) => assert.ok(Math.abs(a-b) < 1e-6, a + " differs from " + b);
const loc = (lon, lat = 0) => ({ lon, lat });
near(position(loc(0)).x, 1);
near(position(loc(90)).z, -1);
near(position(loc(10, 90)).y, 1);

for (const [from, to] of [[loc(-179), loc(179)], [loc(0), loc(180)],
                         [loc(20, 90), loc(20, -90)], [loc(55, 30), loc(55, 30)]]) {
    const beam = track(from, to);
    near(beam[0].clone().normalize().distanceTo(position(from)), 0);
    near(beam.at(-1).clone().normalize().distanceTo(position(to)), 0);
    for (const point of beam) assert.ok(point.length() >= 1 && point.length() < 1.13);
}
const dateline = track(loc(-179), loc(179));
near(dateline[32].clone().normalize().distanceTo(position(loc(180))), 0);
assert.ok(dateline[32].length() > dateline[0].length());
"""
            subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                           cwd=root, check=True, capture_output=True, text=True)


class MapRedrawTests(unittest.TestCase):
    """A dashboard refresh replaces arcs and city marks and leaves the land-dot layer alone."""

    def setUp(self):
        self.source = (STATIC / "dashboard.js").read_text()

    def method(self, name, until):
        start = self.source.index(f"\n  {name}() {{")
        end = self.source.index(f"\n  {until}")
        self.assertLess(start, end)
        return self.source[start:end]

    def test_land_layer_rebuilds_only_when_the_box_size_changes(self):
        body = self.method("renderMap", "sources()")
        gate = body.index("if (this.mapSize !== size)")
        rebuild = body.index("mountSvg(box, WPMap.baseMap(")
        stored = body.index("this.mapSize = size")
        marks = body.index("this.renderMarks()")
        self.assertLess(gate, rebuild)
        self.assertLess(rebuild, stored)
        self.assertLess(stored, marks)
        self.assertEqual(body.count("baseMap"), 1)
        self.assertEqual(body.count("mountSvg"), 1)
        self.assertNotIn("landDots", body)

    def test_marks_replace_arcs_and_cities_not_the_land_group(self):
        body = self.method("renderMarks", "pulse(e)")
        self.assertIn('setSvgChildren(svg.querySelector("g.arcs"), arcs)', body)
        self.assertIn('setSvgChildren(svg.querySelector("g.marks"), marks)', body)
        for banned in ("baseMap", "mountSvg", "landDots", 'g.land', 'querySelector("g.land")'):
            self.assertNotIn(banned, body)

    def test_redraw_updates_the_map_through_that_guard(self):
        body = self.method("redraw", "async loadViews")
        self.assertIn("this.renderMap()", body)
        self.assertNotIn("baseMap", body)
        self.assertNotIn("mountSvg", body)


class CoverageChipTests(unittest.TestCase):
    """Layouts that hide the matrix still state validated, mapped, disabled, and gap counts."""

    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.source = (STATIC / "dashboard.js").read_text()

    def call(self, names, expression, payload):
        script = "\n".join(function_body(self.source, name) for name in names) + f"""
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify({expression}));
"""
        out = subprocess.run(
            [self.node, "-e", script], input=json.dumps(payload),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_counts_keep_mapped_and_disabled_out_of_the_gap(self):
        counts = self.call(
            ["coverageLevel", "coverageCounts"],
            "coverageCounts(input)",
            [
                {"id": "T1078", "level": "validated", "covered": True},
                {"id": "T1190", "level": "mapped", "covered": False, "hits": 4},
                {"id": "T1110", "level": "disabled", "rules": ["off"]},
                {"id": "T1003", "level": "gap"},
                {"id": "T1059", "covered": True},
                {"id": "T1021", "rules": []},
            ])
        self.assertEqual(counts, {"validated": 2, "mapped": 1, "disabled": 1, "gap": 2})

    def test_chip_is_one_line_of_evidence_counts(self):
        text = self.call(
            ["coverageChipText"],
            "coverageChipText(input)",
            {"validated": 18, "mapped": 6, "disabled": 2, "gap": 4})
        self.assertEqual(text, "18 validated · 6 mapped · 2 disabled · 4 gap")
        self.assertNotIn("\n", text)

    def test_triage_and_telemetry_hide_the_matrix_and_full_does_not(self):
        triage = ["p-board", "p-timeline", "p-feed", "p-entities"]
        telemetry = ["p-map", "p-feed", "p-attackers", "p-health"]
        self.assertTrue(self.call(["layoutHidesMatrix"], "layoutHidesMatrix(input)", triage))
        self.assertTrue(self.call(["layoutHidesMatrix"], "layoutHidesMatrix(input)", telemetry))
        self.assertFalse(self.call(["layoutHidesMatrix"], "layoutHidesMatrix(input)", ["p-attack", "p-board"]))
        self.assertTrue(self.call(["layoutHidesMatrix"], "layoutHidesMatrix(input)", None))

    def test_label_waits_and_then_uses_the_counts(self):
        names = ["coverageLevel", "coverageCounts", "coverageChipText", "coverageChipLabel"]
        self.assertEqual(self.call(names, "coverageChipLabel(input)", {"state": "loading"}), "coverage loading")
        self.assertEqual(self.call(names, "coverageChipLabel(input)", {"state": "error", "error": "down"}), "coverage unavailable")
        label = self.call(names, "coverageChipLabel(input)", {
            "state": "ok",
            "list": [{"level": "validated"}, {"level": "mapped"}, {"level": "gap"}],
        })
        self.assertEqual(label, "1 validated · 1 mapped · 0 disabled · 1 gap")

    def test_view_bar_mounts_the_chip_only_when_the_matrix_is_hidden(self):
        start = self.source.index("renderViewBar()")
        chunk = self.source[start:self.source.index("\n  applyView()")]
        self.assertIn("layoutHidesMatrix(this.layout)", chunk)
        self.assertIn('id: "coverage-chip"', chunk)
        self.assertIn('href: "#coverage"', chunk)
        self.assertIn("coverageChipLabel(this.coverage)", chunk)
        matrix = self.source[self.source.index("renderMatrix()"):self.source.index("// --- incident board")]
        self.assertIn("coverageChipLabel(this.coverage)", matrix)
        css = (STATIC / "style.css").read_text()
        self.assertIn("a.chip.coverage-chip", css)


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


if __name__ == "__main__":
    unittest.main()
