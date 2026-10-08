"""Viewer data masking (milestone 20): pseudonyms for usernames and internal IPs in viewer responses.

The route walk is the point: with `viewer_masking` on, every GET route a viewer can call (filled with real ids
from the seeded demo database), every download, and the live stream must be free of seeded usernames and
internal IPs. Analyst and admin responses stay byte-for-byte unchanged.
"""

import http.client
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import time
import unittest
import urllib.error
from unittest import mock
import urllib.request
from urllib.parse import quote

from tests.helpers import VIEWER_PW, ServerTestCase
from tests.pdfparse import ParsedPDF
from watchpost import masking, server
from watchpost.auth import create_user
from watchpost.db import connect, init_schema

PSEUDO_USER = re.compile(r"user-[0-9a-f]{8}")
PSEUDO_IP = re.compile(r"internal-[0-9a-f]{8}")


def second_admin(case):
    """A second admin account, signed in. Two-person review needs one."""
    conn = connect(case.db_path)
    if not conn.execute("SELECT 1 FROM users WHERE username = 'admin2'").fetchone():
        create_user(conn, "admin2", "second-admin-password", "admin")
    conn.close()
    client = case.client()
    case.assertEqual(client.login("admin2", "second-admin-password")[0], 200)
    return client


def set_masking(case, value):
    """Change viewer_masking through the reviewed setting_update change request, as an operator would."""
    admin = case.client("admin")
    status, change, _ = admin.post("/api/settings/viewer_masking/proposals",
                                   {"value": value, "reason": "mask the public demo"})
    case.assertEqual(status, 201, change)
    case.assertEqual(admin.post(f"/api/changes/{change['id']}/review", {"decision": "approve"})[0], 403)
    case.assertEqual(second_admin(case).post(f"/api/changes/{change['id']}/review",
                                             {"decision": "approve"})[0], 200)


def strings(value):
    """Every string (dict keys included) inside a decoded JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


class PureMaskerTests(unittest.TestCase):
    def setUp(self):
        self.m = masking.Masker(b"k" * 32, ["alice", "ops-admin", "admin", "dave"], self_name="viewer")

    def test_usernames_by_exact_known_value(self):
        text = self.m.text("Failed password for alice. ALICE again; ops-admin and admin, not alicex or hr_admin")
        self.assertNotRegex(text.lower(), r"(?<![\w.@-])(alice|ops-admin|admin)(?![\w@-])")
        self.assertIn("alicex", text)
        self.assertIn("hr_admin", text)
        self.assertEqual(self.m.text("alice"), self.m.text("Alice"))  # usernames compare case-insensitively
        self.assertEqual(self.m.text("ops-admin").count("user-"), 1)  # longest name wins

    def test_internal_ips_masked_public_ips_kept(self):
        for ip in ("10.0.1.20", "172.16.4.5", "192.168.1.1", "127.0.0.1", "169.254.10.10", "::1", "fe80::1",
                   "fd00::5", "::ffff:10.0.0.1"):
            with self.subTest(ip=ip):
                out = self.m.text(f"from {ip}.")
                self.assertRegex(out, r"^from internal-[0-9a-f]{8}\.$")
        for text in ("203.0.113.45", "198.51.100.23", "8.8.8.8", "2001:db8::1", "14:05:00", "aa:bb:cc:dd:ee:ff",
                     "2026-10-07T14:05:00.000Z", "v10.0.1"):
            with self.subTest(text=text):
                self.assertEqual(self.m.text(text), text)
        self.assertEqual(self.m.text("src_ip:10.0.0.5 dave|10.0.1.23|192.0.2.77").count("internal-"), 2)

    def test_pseudonyms_are_stable_and_keyed(self):
        other = masking.Masker(b"j" * 32, ["alice"])
        self.assertEqual(self.m.user("alice"), self.m.user("alice"))
        self.assertNotEqual(self.m.user("alice"), other.user("alice"))
        self.assertRegex(self.m.user("alice"), r"^user-[0-9a-f]{8}$")

    def test_walks_structures_and_keys(self):
        out = self.m.mask({"10.0.0.5": {"user": "dave", "n": 3}, "list": ("alice", None, 1.5)})
        self.assertEqual(list(out), [self.m.text("10.0.0.5"), "list"])
        self.assertEqual(out[self.m.text("10.0.0.5")], {"user": self.m.user("dave"), "n": 3})
        self.assertEqual(out["list"], (self.m.user("alice"), None, 1.5))

    def test_own_name_is_not_masked(self):
        self.assertEqual(self.m.mask({"username": "viewer", "role": "viewer"}), {"username": "viewer", "role": "viewer"})


class MaskingKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def conn(self, name, audit_key=None):
        conn = connect(os.path.join(self.tmp.name, name), audit_key)
        init_schema(conn)
        return conn

    def test_key_comes_from_audit_key_or_a_random_per_database_secret(self):
        a, b = self.conn("a.db"), self.conn("b.db")
        self.assertEqual(masking.key(a), masking.key(a))  # persisted, so pseudonyms survive restarts
        self.assertNotEqual(masking.key(a), masking.key(b))  # random, never a constant in code
        k1, k2 = self.conn("k1.db", "first-audit-key"), self.conn("k2.db", "second-audit-key")
        self.assertNotEqual(masking.key(k1), masking.key(k2))
        self.assertEqual(masking.key(k1), masking.key(self.conn("k3.db", "first-audit-key")))
        self.assertNotIn(b"first-audit-key", masking.key(k1))  # derived, not the audit key itself
        for c in (a, b, k1, k2):
            c.close()


class MaskingServerTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        self.assertEqual(self.admin.post("/api/demo/load")[0], 200)
        self.analyst = self.client("analyst")
        self.viewer = self.client("viewer")
        self._seed_free_text()

    def _seed_free_text(self):
        """Usernames and internal IPs in analyst-written text: notes, saved searches, incident notes."""
        alerts = self.analyst.get("/api/alerts")[1]
        alert = next(a for a in alerts if "dave" in a["title"])
        self.assertEqual(self.analyst.post(f"/api/alerts/{alert['id']}/notes",
                                           {"body": "Called dave; he was not on 10.0.1.23 at the time"})[0], 201)
        self.assertEqual(self.analyst.post(f"/api/alerts/{alert['id']}/assign", {"assignee": "analyst"})[0], 200)
        self.assertEqual(self.analyst.post("/api/hunt/saved", {"name": "dave on 10.0.1.23",
                                                               "query": "user:dave src_ip:10.0.1.23"})[0], 201)
        incident = self.analyst.get("/api/incidents")[1][0]
        self.analyst.post(f"/api/incidents/{incident['id']}/status",
                          {"status": "investigating", "note": "alice and 10.0.1.20 involved"})

    def seeded(self):
        with sqlite3.connect(self.db_path) as db:
            users = {r[0].lower() for r in db.execute("SELECT DISTINCT user FROM events WHERE user IS NOT NULL")}
            accounts = {r[0].lower() for r in db.execute("SELECT username FROM users")}
            ips = {r[0] for r in db.execute("SELECT src_ip FROM events UNION SELECT dest_ip FROM events") if r[0]}
        # Role-named accounts ("analyst") are product vocabulary in text; identity fields are checked in leaks().
        users |= accounts - {"viewer", "analyst", "admin"}
        self.accounts = accounts - {"viewer"}  # the signed-in viewer's own name is not hidden from them
        internal = {ip for ip in ips if masking.is_internal(ipaddress.ip_address(ip))}
        self.assertGreater(len(users), 10)
        self.assertGreater(len(internal), 5)
        return users, internal

    def leaks(self, text, users, ips):
        found = [u for u in users if re.search(rf"(?<![\w.@-]){re.escape(u)}(?![\w@-])", text, re.IGNORECASE)]
        found += [ip for ip in ips if re.search(rf"(?<![\w.:]){re.escape(ip)}(?!\w|\.\d)", text)]
        return found

    def identity_leaks(self, value, field=None):
        """Raw account names left in identity fields (assignee, author, actor, ...) of a decoded JSON body."""
        if isinstance(value, dict):
            return [x for k, v in value.items() for x in self.identity_leaks(v, k)]
        if isinstance(value, list):
            return [x for v in value for x in self.identity_leaks(v)]
        return [value] if field in masking.USER_FIELDS and isinstance(value, str) and \
            value.lower() in self.accounts else []

    def get_raw(self, client, path):
        req = urllib.request.Request(self.base + path)
        try:
            with client.opener.open(req, timeout=30) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers.get("Content-Type", ""), exc.read()

    def body_text(self, ctype, body):
        if ctype.startswith("application/json"):
            return "\n".join(strings(json.loads(body)))
        if ctype.startswith("application/pdf"):
            return ParsedPDF(body).text()  # the raw bytes hold PDF syntax such as /Root
        return re.sub(r"\\(.)", r"\1", body.decode("utf-8"))  # Markdown escapes: admin\_action is a rule id

    def read_stream(self, client, trigger, want="alert", seconds=10):
        """Open /api/stream as `client`, run trigger(), and return the frames read (until `want` or timeout)."""
        jar = next(h.cookiejar for h in client.opener.handlers if hasattr(h, "cookiejar"))
        cookie = "; ".join(f"{c.name}={c.value}" for c in jar)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=seconds)
        conn.request("GET", "/api/stream", headers={"Cookie": cookie})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        frames, buf, deadline, triggered = [], b"", time.monotonic() + seconds, False
        try:
            while time.monotonic() < deadline:
                line = resp.fp.readline()
                if not line:
                    break
                buf += line
                if line == b"\n":
                    frames.append(buf.decode())
                    buf = b""
                    if not triggered and any("event: health" in f for f in frames):
                        trigger()
                        triggered = True
                    if any(f"event: {want}" in f for f in frames):
                        break
        finally:
            conn.close()
        return frames

    # --- the route walk ---------------------------------------------------------------------------------

    def fill(self, pattern, ids):
        """Concrete paths for one route pattern: each capture group filled with real ids (several where useful)."""
        source = pattern.pattern.strip("^$")
        paths = [source]
        for group in re.findall(r"\([^()]*\)", source):
            prefix = source.split(group, 1)[0]
            if group == r"(\d+)":
                kind = prefix.rstrip("/").rsplit("/", 1)[-1]
                values = ids[kind]
            elif group == "(md|pdf)":
                values = ["md", "pdf"]
            elif group == "([a-z_]+)":
                values = ids["rules"]
            elif group == "([^/]+)":
                values = ids["entities"][prefix.rstrip("/").rsplit("/", 1)[-1]]
            else:
                self.fail(f"no sample values for {group} in {pattern.pattern}")
            paths = [p.replace(group, quote(str(v), safe=""), 1) for p in paths for v in values]
        paths = [p.replace("\\.", ".") for p in paths]
        for p in paths:
            self.assertRegex(p, pattern)
        return paths

    def test_every_viewer_route_is_free_of_usernames_and_internal_ips(self):
        set_masking(self, 1)
        users, ips = self.seeded()
        events = self.analyst.get("/api/events?limit=500")[1]["events"]
        alerts = self.analyst.get("/api/alerts")[1]
        incidents = self.analyst.get("/api/incidents")[1]
        user_event = next(e for e in events if e["user"] == "dave")
        pseudo_dave = self.viewer.get(f"/api/events/{user_event['id']}")[1]["user"]
        pseudo_ip = self.viewer.get(f"/api/events/{user_event['id']}")[1]["src_ip"]
        self.assertRegex(pseudo_dave, PSEUDO_USER)
        ids = {
            "events": [user_event["id"]] + [e["id"] for e in events[:5]],
            "alerts": [a["id"] for a in alerts],
            "incidents": [i["id"] for i in incidents],
            "rules": sorted({a["rule_id"] for a in alerts}),
            "entities": {"user": ["dave", pseudo_dave, "ops-admin"], "src_ip": ["10.0.1.23", "203.0.113.45"],
                         "host": ["web01"]},
        }
        if PSEUDO_IP.fullmatch(pseudo_ip or ""):
            ids["entities"]["src_ip"].append(pseudo_ip)
        extra = {
            "/api/events": ["?user=dave", f"?user={pseudo_dave}", "?ip=10.0.1.23", "?q=dave", "?limit=500"],
            "/api/hunt": ["?q=" + quote("user:dave"), "?q=" + quote(f"user:{pseudo_dave}"),
                          "?q=" + quote("event_type:auth_failure | stats count, dc(src_ip) by user"),
                          "?q=" + quote("* | top 20 src_ip"), "?q=" + quote("* | top 20 dest_ip"),
                          "?q=" + quote("src_ip:10.0.1.23")],
            "/api/entities": ["?kind=user", "?kind=src_ip", "?kind=host", "?limit=100"],
            "/api/geo": ["?ips=" + ",".join(sorted(ips)[:20] + ["203.0.113.45"])],
            "/api/alerts": ["?status=open", "?limit=500"],
            "/api/changes": ["?status=approved", "?status=pending"],
        }
        walked = 0
        viewer_routes = [(p, fn, role) for m, p, fn, role, _ in server.ROUTES
                         if m == "GET" and role in ("public", "viewer")]
        self.assertGreaterEqual(len(viewer_routes), 35)
        for pattern, fn, _role in viewer_routes:
            if fn is server.event_stream:
                frames = self.read_stream(self.viewer, lambda: self.analyst.post(
                    "/api/demo/simulate", {"scenario": "impossible_travel", "seed": 11}))
                kinds = {re.search(r"event: (\w+)", f).group(1) for f in frames}
                self.assertTrue({"hello", "health", "event", "alert"} <= kinds, kinds)
                text = "\n".join(frames)
                self.assertRegex(text, PSEUDO_USER)
                self.assertEqual(self.leaks(text, users, ips), [], "stream")
                walked += 1
                continue
            paths = self.fill(pattern, ids)
            base = pattern.pattern.strip("^$")
            paths += [base + q for q in extra.get(base, [])]
            for path in paths:
                with self.subTest(path=path):
                    status, ctype, body = self.get_raw(self.viewer, path)
                    self.assertEqual(status, 200, (path, body[:200]))
                    self.assertEqual(self.leaks(self.body_text(ctype, body), users, ips), [], path)
                    if ctype.startswith("application/json"):
                        self.assertEqual(self.identity_leaks(json.loads(body)), [], path)
            walked += 1
        self.assertEqual(walked, len(viewer_routes))
        # Non-viewer GET routes answer 403 with nothing in the body worth masking.
        for m, pattern, _fn, role, _ in server.ROUTES:
            if m == "GET" and role not in ("public", "viewer"):
                status, _, body = self.get_raw(self.viewer, self.fill(pattern, ids)[0])
                self.assertEqual(status, 403)

    # --- behaviour --------------------------------------------------------------------------------------

    def test_off_by_default_and_listed_as_a_reviewed_setting(self):
        settings = {s["key"]: s for s in self.viewer.get("/api/settings")[1]}
        self.assertEqual((settings["viewer_masking"]["value"], settings["viewer_masking"]["max"]), ("0", 1))
        self.assertIn("dave", json.dumps(self.viewer.get("/api/alerts")[1]))
        self.assertNotIn("masked", self.viewer.get("/api/auth/me")[1])
        set_masking(self, 1)
        self.assertNotIn("dave", json.dumps(self.viewer.get("/api/alerts")[1]))
        self.assertIs(self.viewer.get("/api/auth/me")[1]["masked"], True)
        login = self.client().login("viewer", VIEWER_PW)[1]
        self.assertIs(login["masked"], True)
        audit = self.admin.get("/api/audit")[1]
        self.assertTrue(any(a["action"] == "setting_changed" and a["target"] == "viewer_masking" for a in audit))
        set_masking(self, 0)
        self.assertIn("dave", json.dumps(self.viewer.get("/api/alerts")[1]))

    def test_analyst_and_admin_responses_are_byte_for_byte_unchanged(self):
        alert = self.analyst.get("/api/alerts")[1][0]["id"]
        event = self.analyst.get("/api/events")[1]["events"][0]["id"]
        paths = [f"/api/events/{event}", f"/api/alerts/{alert}", "/api/entities/user/dave", "/api/events?user=dave",
                 "/api/hunt?q=" + quote("user:dave | stats count by src_ip"), "/api/entities/host/web01",
                 "/api/auth/me"]
        before = {(who, p): self.get_raw(c, p) for who, c in (("analyst", self.analyst), ("admin", self.admin))
                  for p in paths}
        set_masking(self, 1)
        for (who, path), expected in before.items():
            client = self.analyst if who == "analyst" else self.admin
            with self.subTest(who=who, path=path):
                self.assertEqual(self.get_raw(client, path), expected)

    def test_pseudonyms_are_consistent_across_endpoints(self):
        set_masking(self, 1)
        event = next(e for e in self.analyst.get("/api/events?user=dave")[1]["events"])
        masked_event = self.viewer.get(f"/api/events/{event['id']}")[1]
        pseudo = masked_event["user"]
        self.assertRegex(pseudo, PSEUDO_USER)
        self.assertEqual(self.viewer.get(f"/api/events/{event['id']}")[1]["user"], pseudo)
        alert_titles = " ".join(a["title"] for a in self.viewer.get("/api/alerts")[1])
        self.assertIn(pseudo, alert_titles)
        entities = self.viewer.get("/api/entities?kind=user")[1]["entities"]
        self.assertIn(pseudo, [e["value"] for e in entities])
        self.assertIn(pseudo, masked_event["message"])

    def test_pivots_on_pseudonyms_resolve_server_side(self):
        set_masking(self, 1)
        real = self.analyst.get("/api/hunt?q=" + quote("user:dave"))[1]
        event = self.analyst.get("/api/events?user=dave")[1]["events"][0]
        masked_event = self.viewer.get(f"/api/events/{event['id']}")[1]
        pseudo, pseudo_ip = masked_event["user"], masked_event["src_ip"]
        hunted = self.viewer.get("/api/hunt?q=" + quote(f"user:{pseudo}"))[1]
        self.assertGreater(real["total"], 0)
        self.assertEqual(hunted["total"], real["total"])
        self.assertEqual(self.viewer.get(f"/api/events?user={pseudo}")[1]["total"],
                         self.analyst.get("/api/events?user=dave")[1]["total"])
        entity = self.viewer.get(f"/api/entities/user/{pseudo}")
        self.assertEqual(entity[0], 200)
        self.assertEqual(len(entity[1]["alerts"]), len(self.analyst.get("/api/entities/user/dave")[1]["alerts"]))
        if PSEUDO_IP.fullmatch(pseudo_ip or ""):
            self.assertEqual(self.viewer.get(f"/api/events?ip={pseudo_ip}")[1]["total"],
                             self.analyst.get(f"/api/events?ip={event['src_ip']}")[1]["total"])
        # An unknown pseudonym resolves to nothing rather than erroring.
        self.assertEqual(self.viewer.get("/api/events?user=user-00000000")[1]["total"], 0)


    # --- fail closed (security review of the masking commit) --------------------------------------------

    def test_error_messages_do_not_echo_a_resolved_pivot(self):
        """A pivot resolves to the real value before the route runs; an error that echoes it must be masked."""
        set_masking(self, 1)
        event = self.analyst.get("/api/events?user=dave")[1]["events"][0]
        pseudo = self.viewer.get(f"/api/events/{event['id']}")[1]["user"]
        for q in (f"{pseudo}:x", f"* | stats {pseudo}", f"* | top 5 {pseudo}"):
            with self.subTest(q=q):
                status, body, _ = self.viewer.get("/api/hunt?q=" + quote(q))
                self.assertEqual(status, 400)
                self.assertNotIn("dave", body["error"])
                self.assertIn(pseudo, body["error"])

    def test_more_usernames_than_the_bound_refuses_the_masked_view(self):
        """Names past CANDIDATE_LIMIT cannot be matched in free text, so the viewer is refused, not shown them."""
        set_masking(self, 1)
        with mock.patch.object(masking, "CANDIDATE_LIMIT", 3):
            status, body, _ = self.viewer.get("/api/alerts")
            self.assertEqual(status, 503)
            self.assertNotIn("dave", json.dumps(body))
            self.assertEqual(self.analyst.get("/api/alerts")[0], 200)
        self.assertEqual(self.viewer.get("/api/alerts")[0], 200)

    def test_stream_opened_before_masking_was_turned_on_is_masked_after(self):
        def trigger():
            set_masking(self, 1)
            self.analyst.post("/api/demo/simulate", {"scenario": "impossible_travel", "seed": 11})
        frames = self.read_stream(self.viewer, trigger)
        data = "\n".join(f for f in frames if re.search(r"event: (event|alert)\n", f))
        self.assertIn("event: alert", data)
        self.assertRegex(data, PSEUDO_USER)
        self.assertEqual(self.leaks(data, *self.seeded()), [])

    def test_json_download_is_masked_as_data_not_as_text(self):
        """Masked as serialized text, a non-ASCII name escaped as \\u00e9 slipped past exact matching."""
        db = sqlite3.connect(self.db_path)
        with db:
            db.execute("INSERT INTO events(ts, ingested_at, source, event_type, severity, user) VALUES "
                       "('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'test', 'auth_success', 'low', 'jos\u00e9')")
            rule_id, params = db.execute("SELECT id, params FROM rules WHERE params LIKE '%ignore_users%'"
                                         " ORDER BY id").fetchone()
            params = dict(json.loads(params), ignore_users=["jos\u00e9"], ignore_ips=["10.0.1.23"])
            db.execute("UPDATE rules SET params = ? WHERE id = ?", (json.dumps(params), rule_id))
        db.close()
        set_masking(self, 1)
        status, _, body = self.get_raw(self.viewer, "/api/rules/export")
        self.assertEqual(status, 200)
        rule = next(r for r in json.loads(body)["rules"] if r["id"] == rule_id)
        self.assertRegex(rule["params"]["ignore_users"][0], PSEUDO_USER)
        self.assertRegex(rule["params"]["ignore_ips"][0], PSEUDO_IP)


if __name__ == "__main__":
    unittest.main()
