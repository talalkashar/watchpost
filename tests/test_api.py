import json
import sqlite3
import unittest
from datetime import timedelta

from tests.helpers import ADMIN_PW, ServerTestCase
from watchpost import attack
from watchpost.db import iso, utcnow
from watchpost.health import STATIC_DIR


def recent(minutes_ago=30):
    return iso(utcnow() - timedelta(minutes=minutes_ago))


class AuthTests(ServerTestCase):
    def test_protected_endpoints_require_login(self):
        anon = self.client()
        for path in ["/api/events", "/api/alerts", "/api/metrics", "/api/rules", "/api/health/details"]:
            with self.subTest(path=path):
                self.assertEqual(anon.get(path)[0], 401)
        self.assertEqual(anon.post("/api/ingest", [])[0], 401)

    def test_public_health_hides_details(self):
        status, data, headers = self.client().get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(set(data["checks"]), {"storage", "ingestion", "detection", "dependencies", "storyline"})
        self.assertNotIn("details", json.dumps(data))
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_login_cookie_flags_and_logout(self):
        c = self.client()
        status, data, headers = c.post("/api/auth/login", {"username": "admin", "password": ADMIN_PW})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        c.csrf = data["csrf_token"]
        self.assertEqual(c.get("/api/auth/me")[1]["user"]["role"], "admin")
        self.assertEqual(c.post("/api/auth/logout")[0], 200)
        self.assertEqual(c.get("/api/auth/me")[0], 401)

    def test_wrong_password_and_unknown_user_look_the_same(self):
        c = self.client()
        s1, d1 = c.login("admin", "wrong-password-123")
        s2, d2 = c.login("nobody", "wrong-password-123")
        self.assertEqual((s1, d1), (s2, d2))
        self.assertEqual(s1, 401)

    def test_lockout_after_repeated_failures(self):
        c = self.client()
        for _ in range(5):
            c.login("admin", "wrong-password-123")
        status, data = c.login("admin", ADMIN_PW)
        self.assertEqual(status, 429)
        self.assertIn("locked", data["error"])

    def test_csrf_required_for_session_posts(self):
        c = self.client("analyst")
        c.csrf = "forged"
        status, data, _ = c.post("/api/detection/run")
        self.assertEqual(status, 403)
        self.assertIn("CSRF", data["error"])

    def test_role_enforcement(self):
        analyst = self.client("analyst")
        for path, body in [("/api/tokens", {"name": "x"}), ("/api/demo/load", {}),
                           ("/api/changes/1/review", {"decision": "approve"}),
                           ("/api/settings/login_lockout_threshold/proposals", {"value": 6, "reason": "tighten"})]:
            with self.subTest(path=path):
                self.assertEqual(analyst.post(path, body)[0], 403)
        self.assertEqual(analyst.get("/api/audit")[0], 403)

        with sqlite3.connect(self.db_path) as db:
            from watchpost.auth import hash_password
            db.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES "
                       "('viewer1', ?, 'viewer', '2026-01-01')", (hash_password("viewer-password-1"),))
        viewer = self.client()
        self.assertEqual(viewer.login("viewer1", "viewer-password-1")[0], 200)
        self.assertEqual(viewer.get("/api/alerts")[0], 200)
        self.assertEqual(viewer.post("/api/ingest", [{"ts": recent()}])[0], 403)
        self.assertEqual(viewer.post("/api/alerts/1/notes", {"body": "x"})[0], 403)

    def test_api_token_lifecycle(self):
        admin = self.client("admin")
        status, data, _ = admin.post("/api/tokens", {"name": "collector"})
        self.assertEqual(status, 201)
        token = data["token"]
        bot = self.client()
        auth = {"Authorization": f"Bearer {token}"}
        status, result, _ = bot.post("/api/ingest", [{"ts": recent(), "type": "login"}], headers=auth)
        self.assertEqual(status, 201)
        self.assertEqual(result["accepted"], 1)
        # Tokens are ingest-only.
        self.assertEqual(bot.get("/api/events", headers=auth)[0], 403)
        # Only a hash is stored.
        with sqlite3.connect(self.db_path) as db:
            stored = db.execute("SELECT token_hash, prefix, last_used_at FROM api_tokens").fetchone()
        self.assertNotEqual(stored[0], token)
        self.assertIsNotNone(stored[2])
        token_id = admin.get("/api/tokens")[1][0]["id"]
        self.assertEqual(admin.post(f"/api/tokens/{token_id}/revoke")[0], 200)
        self.assertEqual(bot.post("/api/ingest", [{"ts": recent()}], headers=auth)[0], 401)
        self.assertEqual(bot.post("/api/ingest", [{"ts": recent()}], headers={"Authorization": "Bearer wp_x"})[0], 401)

    def test_role_scoped_tokens_have_explicit_capabilities_and_expiry(self):
        admin, bot = self.client("admin"), self.client()

        def create(body):
            status, data, _ = admin.post("/api/tokens", body)
            self.assertEqual(status, 201, data)
            return {"Authorization": f"Bearer {data['token']}"}

        viewer = create({"name": "readonly", "role": "viewer", "capabilities": ["read"],
                         "expires_in_days": 30})
        self.assertEqual(bot.get("/api/alerts", headers=viewer)[0], 200)
        self.assertEqual(bot.get("/api/auth/me", headers=viewer)[1]["user"]["role"], "viewer")
        self.assertEqual(bot.post("/api/ingest", [{"ts": recent()}], headers=viewer)[0], 403)
        self.assertEqual(bot.post("/api/alerts/1/notes", {"body": "x"}, headers=viewer)[0], 403)

        triage = create({"name": "soc-bot", "role": "analyst", "capabilities": ["read", "triage"]})
        alert = bot.get("/api/alerts", headers=triage)[1]
        if not alert:
            self.assertEqual(admin.post("/api/demo/load")[0], 200)
            alert = bot.get("/api/alerts", headers=triage)[1]
        alert_id = alert[0]["id"]
        self.assertEqual(bot.post(f"/api/alerts/{alert_id}/notes", {"body": "checked by automation"},
                                  headers=triage)[0], 201)
        self.assertEqual(bot.post("/api/ingest", [{"ts": recent()}], headers=triage)[0], 403)
        self.assertEqual(bot.post("/api/demo/load", {}, headers=triage)[0], 403)

        listed = {row["name"]: row for row in admin.get("/api/tokens")[1]}
        self.assertEqual((listed["readonly"]["role"], listed["readonly"]["capabilities"]),
                         ("viewer", ["read"]))
        self.assertIsNotNone(listed["readonly"]["expires_at"])
        self.assertIsNotNone(listed["readonly"]["last_used_at"])
        self.assertEqual((listed["soc-bot"]["role"], listed["soc-bot"]["capabilities"]),
                         ("analyst", ["read", "triage"]))

        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE api_tokens SET expires_at = '2000-01-01T00:00:00.000Z' WHERE name = 'readonly'")
        self.assertEqual(bot.get("/api/alerts", headers=viewer)[0], 401)
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE api_tokens SET role = 'admin', expires_at = NULL WHERE name = 'readonly'")
        self.assertEqual(bot.get("/api/tokens", headers=viewer)[0], 401)

    def test_api_token_scope_validation(self):
        admin = self.client("admin")
        bad = [
            {"name": "x", "role": "admin", "capabilities": ["read"]},
            {"name": "x", "role": "viewer", "capabilities": ["ingest"]},
            {"name": "x", "role": "analyst", "capabilities": ["admin"]},
            {"name": "x", "role": "analyst", "capabilities": []},
            {"name": "x", "role": "analyst", "capabilities": ["read", "read"]},
            {"name": "x", "role": "analyst", "capabilities": ["read"], "expires_in_days": 0},
            {"name": "x", "role": "analyst", "capabilities": ["read"], "expires_in_days": 366},
        ]
        for body in bad:
            with self.subTest(body=body):
                self.assertEqual(admin.post("/api/tokens", body)[0], 400)

    def test_static_files_and_traversal(self):
        import urllib.request
        with urllib.request.urlopen(self.base + "/") as resp:
            self.assertIn(b"Watchpost", resp.read())
        c = self.client()
        for path in ["/../watchpost/config.py", "/%2e%2e/watchpost/config.py", "/nope.js"]:
            with self.subTest(path=path):
                req = urllib.request.Request(self.base + path)
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 404)
        self.assertEqual(c.get("/api/nope")[0], 404)


class IngestTests(ServerTestCase):
    def test_partial_batch_reports_rejections(self):
        c = self.client("analyst")
        status, data, _ = c.post("/api/ingest", {"source": "fw01", "events": [
            {"ts": recent(), "type": "login_failed", "user": "a", "src_ip": "10.0.0.1"},
            {"ts": "garbage"},
            {"ts": recent(), "src_ip": "300.1.1.1"},
        ]})
        self.assertEqual(status, 207)
        self.assertEqual((data["accepted"], data["rejected"]), (1, 2))
        self.assertEqual(data["detection"]["status"], "ok")
        batches = c.get("/api/ingest/batches")[1]
        self.assertEqual(batches[0]["source"], "fw01")
        self.assertEqual(len(batches[0]["errors"]), 2)

    def test_all_rejected_is_422_and_bad_requests_are_400(self):
        c = self.client("analyst")
        self.assertEqual(c.post("/api/ingest", [{"ts": "bad"}])[0], 422)
        self.assertEqual(c.post("/api/ingest", raw=b"{not json", headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(c.post("/api/ingest", raw=b"[]", headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(c.post("/api/ingest", {"source": "bad source", "events": []})[0], 400)
        self.assertEqual(c.post("/api/ingest/upload", raw=b"", headers={"Content-Type": "text/plain"})[0], 400)
        self.assertEqual(c.post("/api/ingest/upload?format=authlog", raw=b"\xff\xfe",
                                headers={"Content-Type": "text/plain"})[0], 400)

    def test_body_size_limit(self):
        self.app.config.max_upload_bytes = 1000
        c = self.client("analyst")
        status, data, _ = c.post("/api/ingest/upload", raw=b"x" * 2000, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 413)

    def test_authlog_upload_detects_brute_force(self):
        c = self.client("analyst")
        now = utcnow() - timedelta(hours=1)
        lines = [f"{iso(now + timedelta(seconds=i))} web01 sshd[1]: Failed password for root from 203.0.113.99 "
                 f"port 22 ssh2" for i in range(12)]
        status, data, _ = c.post("/api/ingest/upload?format=authlog&source=web01-auth",
                                 raw="\n".join(lines).encode(), headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 201, data)
        self.assertEqual(data["accepted"], 12)
        self.assertGreaterEqual(data["detection"]["alerts_created"], 1)
        alerts = c.get("/api/alerts?rule_id=brute_force_ip")[1]
        self.assertEqual(alerts[0]["group_key"], "203.0.113.99")
        self.assertEqual(alerts[0]["synthetic"], 0)

    def test_repeat_ingest_extends_open_alert_instead_of_duplicating(self):
        c = self.client("analyst")
        start = utcnow() - timedelta(hours=1)
        batch = lambda offset: [{"ts": iso(start + timedelta(seconds=offset + i)), "type": "login_failed",
                                 "user": "x", "src_ip": "192.0.2.50"} for i in range(10)]
        c.post("/api/ingest", batch(0))
        second = c.post("/api/ingest", batch(20))[1]
        self.assertEqual(second["detection"]["alerts_created"], 0)
        self.assertGreaterEqual(second["detection"]["alerts_updated"], 1)
        alerts = c.get("/api/alerts?rule_id=brute_force_ip")[1]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 20)
        # A full rescan does not create duplicates either.
        rescan = c.post("/api/detection/run")[1]
        self.assertEqual((rescan["status"], rescan["alerts_created"], rescan["alerts_updated"]), ("ok", 0, 0))


class IncidentApiTests(ServerTestCase):
    def load_intrusion(self, client):
        start = utcnow() - timedelta(hours=2)
        at = lambda sec: iso(start + timedelta(seconds=sec))
        ip = "192.0.2.140"
        events = [{"ts": at(i), "type": "web_scan", "src_ip": ip, "message": f"GET /.env{i} -> 404"} for i in range(6)]
        events += [{"ts": at(100 + i * 10), "type": "login_failed", "user": "frank", "src_ip": ip} for i in range(3)]
        events += [{"ts": at(140), "type": "login", "user": "frank", "src_ip": ip},
                   {"ts": at(400), "type": "sudo", "user": "frank", "src_ip": ip, "host": "web01"},
                   {"ts": at(500), "type": "cloud_iam_change", "user": "frank", "src_ip": ip,
                    "message": "CreateAccessKey on iam.amazonaws.com"}]
        status, result, _ = client.post("/api/ingest", {"source": "intrusion", "events": events})
        self.assertEqual(status, 201, result)
        return result

    def test_incident_list_detail_and_status(self):
        analyst = self.client("analyst")
        result = self.load_intrusion(analyst)
        self.assertEqual(result["detection"]["correlation"]["incidents_created"], 1)
        status, incidents, _ = analyst.get("/api/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["severity"], "critical")
        self.assertEqual(incident["status"], "open")
        self.assertEqual(incident["stages"], ["Reconnaissance", "Initial Access", "Persistence",
                                              "Privilege Escalation"])

        status, detail, _ = analyst.get(f"/api/incidents/{incident['id']}")
        self.assertEqual(status, 200)
        self.assertEqual({a["rule_id"] for a in detail["alerts"]},
                         {"web_scanner", "privilege_escalation_after_login", "cloud_iam_change_by_new_principal"})
        self.assertTrue(detail["escalated"])
        self.assertEqual(len(detail["timeline"]), 3)
        self.assertEqual(detail["timeline"][0]["rule_id"], "web_scanner")
        self.assertEqual(len(detail["events"]), 6 + 3 + 1 + 1 + 1)
        self.assertTrue(all(e["alert_ids"] for e in detail["events"]))
        self.assertIn("T1548.003", {t["id"] for t in detail["techniques"]})
        self.assertEqual([g["tactic"] for g in detail["techniques_by_tactic"]], incident["stages"])

        # Filters and validation.
        self.assertEqual(len(analyst.get("/api/incidents?status=resolved")[1]), 0)
        self.assertEqual(analyst.get("/api/incidents?status=closed")[0], 400)
        self.assertEqual(analyst.get("/api/incidents/99999")[0], 404)

        # Status workflow: analyst can change it, bad values are rejected, and it is audited.
        path = f"/api/incidents/{incident['id']}/status"
        self.assertEqual(analyst.post(path, {"status": "closed"})[0], 400)
        status, updated, _ = analyst.post(path, {"status": "investigating"})
        self.assertEqual((status, updated["status"], updated["assignee"]), (200, "investigating", "analyst"))
        status, updated, _ = analyst.post(path, {"status": "resolved", "note": "contained"})
        self.assertEqual((updated["status"], updated["resolved_at"] is not None), ("resolved", True))
        self.assertEqual(analyst.post("/api/incidents/99999/status", {"status": "open"})[0], 404)
        actions = [a for a in self.client("admin").get("/api/audit")[1] if a["action"] == "incident_status_changed"]
        self.assertEqual(len(actions), 2)

    def test_viewer_reads_but_cannot_change_incidents(self):
        self.load_intrusion(self.client("analyst"))
        with sqlite3.connect(self.db_path) as db:
            from watchpost.auth import hash_password
            db.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES "
                       "('viewer1', ?, 'viewer', '2026-01-01')", (hash_password("viewer-password-1"),))
        viewer = self.client()
        self.assertEqual(viewer.login("viewer1", "viewer-password-1")[0], 200)
        incidents = viewer.get("/api/incidents")[1]
        self.assertEqual(viewer.get(f"/api/incidents/{incidents[0]['id']}")[0], 200)
        self.assertEqual(viewer.post(f"/api/incidents/{incidents[0]['id']}/status", {"status": "resolved"})[0], 403)
        anon = self.client()
        for path in ["/api/incidents", "/api/attack/coverage"]:
            self.assertEqual(anon.get(path)[0], 401)

    def test_attack_coverage_and_rule_techniques(self):
        analyst = self.client("analyst")
        rules = analyst.get("/api/rules")[1]
        self.assertEqual(len(rules), 15)
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                self.assertTrue(rule["techniques"])
        self.load_intrusion(analyst)
        status, coverage, _ = analyst.get("/api/attack/coverage")
        self.assertEqual(status, 200)
        self.assertEqual(coverage["tactics"][0]["name"], "Reconnaissance")
        by_id = {t["id"]: t for t in coverage["techniques"]}
        # Covered means validated on a labeled scenario; T1190 and T1048 are only mapped.
        self.assertEqual(coverage["summary"]["covered"], len(by_id) - 3)  # T1190, T1048, T1595.001 are only mapped
        self.assertEqual(by_id["T1548.003"]["hits"], 1)
        self.assertEqual(by_id["T1110.003"]["hits"], 0)
        self.assertEqual([r["id"] for r in by_id["T1046"]["rules"]], ["firewall_port_sweep"])

    def test_attack_coverage_evidence_levels(self):
        viewer = self.client("viewer")
        self.assertEqual(self.client().get("/api/attack/coverage")[0], 401)
        status, coverage, _ = viewer.get("/api/attack/coverage")
        self.assertEqual(status, 200)
        # The 2.x shape the dashboard and the Navigator export read is still there.
        self.assertLessEqual({"tactics", "techniques", "summary"}, set(coverage))
        self.assertLessEqual({"techniques", "covered", "with_hits"}, set(coverage["summary"]))
        self.assertEqual(coverage["levels"], ["validated", "mapped", "disabled", "gap"])
        by_id = {t["id"]: t for t in coverage["techniques"]}
        for t in by_id.values():
            with self.subTest(technique=t["id"]):
                self.assertLessEqual({"id", "name", "tactic", "rules", "hits", "covered", "level", "scenarios"}, set(t))
                self.assertEqual(t["covered"], t["level"] == "validated")
                for r in t["rules"]:
                    self.assertLessEqual({"id", "name", "enabled", "hits", "verdict", "lookalikes_fired", "proves"},
                                         set(r))
        self.assertEqual({i for i, t in by_id.items() if t["level"] == "mapped"}, {"T1190", "T1048", "T1595.001"})
        self.assertEqual(by_id["T1110.003"]["scenarios"], ["password_spray"])
        web = by_id["T1190"]["rules"][0]
        self.assertEqual((web["id"], web["verdict"], web["proves"]), ("web_scanner", "quiet", []))
        summary = coverage["summary"]
        self.assertEqual(summary["levels"], {"validated": len(by_id) - 3, "mapped": 3, "disabled": 0, "gap": 0})
        self.assertEqual(summary["covered"], summary["levels"]["validated"])

    def test_disabling_a_rule_moves_its_techniques_off_validated(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        change = analyst.post("/api/rules/web_scanner/proposals", {"enabled": False, "reason": "coverage test"})[1]
        self.assertEqual(admin.post(f"/api/changes/{change['id']}/review",
                                    {"decision": "approve", "evidence_digest": change["evidence_digest"],
                                     "acknowledge_detection_loss": True})[0], 200)
        by_id = {t["id"]: t for t in self.client("viewer").get("/api/attack/coverage")[1]["techniques"]}
        self.assertEqual([by_id[i]["level"] for i in ("T1595.002", "T1595.003", "T1190")], ["disabled"] * 3)
        self.assertEqual(by_id["T1595.002"]["rules"][0]["verdict"], "disabled")

    def test_navigator_layer_export(self):
        viewer = self.client("viewer")
        self.assertEqual(self.client().get("/api/attack/navigator.json")[0], 401)
        self.load_intrusion(self.client("analyst"))
        status, layer, headers = viewer.get("/api/attack/navigator.json")
        self.assertEqual((status, headers["Content-Type"].split(";")[0]), (200, "application/json"))
        self.assertEqual((layer["domain"], layer["versions"]), ("enterprise-attack", {"layer": "4.5"}))
        self.assertIn("synthetic", layer["description"].lower())
        coverage = {t["id"]: t for t in viewer.get("/api/attack/coverage")[1]["techniques"]}
        # Every technique, scored by hits and colored by the same level the Coverage view shows.
        self.assertEqual({t["techniqueID"]: t["score"] for t in layer["techniques"]},
                         {i: t["hits"] for i, t in coverage.items()})
        self.assertEqual({t["techniqueID"]: t["color"] for t in layer["techniques"]},
                         {i: attack.LEVEL_COLORS[t["level"]] for i, t in coverage.items()})
        for t in layer["techniques"]:
            self.assertTrue(t["comment"].startswith(coverage[t["techniqueID"]]["level"].capitalize()))
        self.assertIn("firewall_port_sweep", {t["techniqueID"]: t for t in layer["techniques"]}["T1046"]["comment"])
        self.assertEqual(layer["gradient"]["maxValue"], max(t["hits"] for t in coverage.values()))
        self.assertIn('href: "/api/attack/navigator.json"', (STATIC_DIR / "dashboard.js").read_text())

    def test_existing_database_upgrades_in_place(self):
        # A 1.0 database: no techniques column, no new event columns, no incidents tables.
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO api_tokens(name, token_hash, prefix, created_by, created_at)"
                       " VALUES ('legacy collector', 'legacy-hash', 'wp_old', 'admin', '2020-01-01T00:00:00.000Z')")
            db.execute("ALTER TABLE api_tokens DROP COLUMN role")
            db.execute("ALTER TABLE api_tokens DROP COLUMN capabilities")
            db.execute("ALTER TABLE api_tokens DROP COLUMN expires_at")
            db.execute("DROP TABLE incidents")
            db.execute("DROP TABLE incident_alerts")
            db.execute("ALTER TABLE rules DROP COLUMN techniques")
            db.execute("ALTER TABLE events DROP COLUMN bytes")
            db.execute("DELETE FROM rules WHERE id = 'web_scanner'")
            # A 2.0 database: no asset inventory and no asset weighting on alerts.
            db.execute("DROP TABLE assets")
            db.execute("ALTER TABLE alerts DROP COLUMN base_severity")
            # A 3.x database: an audit log with no hash chain.
            db.execute("ALTER TABLE audit_log DROP COLUMN prev_hash")
            db.execute("ALTER TABLE audit_log DROP COLUMN hash")
            old_entries = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        from watchpost.server import App
        App(self.config)
        with sqlite3.connect(self.db_path) as db:
            columns = {r[1] for r in db.execute("PRAGMA table_info(events)")}
            self.assertIn("bytes", columns)
            techniques = dict(db.execute("SELECT id, techniques FROM rules"))
            self.assertIn("web_scanner", techniques)
            self.assertTrue(all(json.loads(t) for t in techniques.values()))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 0)
            self.assertIn("base_severity", {r[1] for r in db.execute("PRAGMA table_info(alerts)")})
            legacy = db.execute("SELECT role, capabilities, expires_at FROM api_tokens"
                                " WHERE name = 'legacy collector'").fetchone()
            self.assertEqual(legacy, ("analyst", '["ingest"]', None))
            self.assertEqual(db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "13")
            actions = [r[0] for r in db.execute("SELECT action FROM audit_log ORDER BY id")]
            self.assertGreater(old_entries, 0)
            self.assertEqual(actions[old_entries], "audit_chain_started")
        verified = self.client("admin").get("/api/audit/verify")[1]
        # Pre-4.0 entries are counted but not vouched for, so an upgraded log is "partial", never "ok".
        self.assertEqual((verified["ok"], verified["status"]), (False, "partial"), verified["first_break"])
        self.assertEqual(verified["legacy"]["entries"], old_entries)
        self.assertEqual(verified["chain_started"]["id"], verified["legacy"]["last_id"] + 1)


class SearchTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.c = self.client("analyst")
        base = utcnow() - timedelta(hours=2)
        self.c.post("/api/ingest", {"source": "vpn", "events": [
            {"ts": iso(base), "type": "login_failed", "user": "Alice", "src_ip": "10.0.0.1", "message": "bad pw 50%"},
            {"ts": iso(base + timedelta(minutes=10)), "type": "login", "user": "bob", "src_ip": "10.0.0.2",
             "severity": "high"},
            {"ts": iso(base + timedelta(minutes=20)), "type": "process", "host": "db01", "dest_ip": "10.0.0.1"},
        ]})
        self.base_ts = base

    def total(self, query):
        status, data, _ = self.c.get("/api/events?" + query)
        self.assertEqual(status, 200, data)
        return data["total"]

    def test_filters(self):
        self.assertEqual(self.total(""), 3)
        self.assertEqual(self.total("user=alice"), 1)  # case-insensitive
        self.assertEqual(self.total("ip=10.0.0.1"), 2)  # matches src or dest
        self.assertEqual(self.total("event_type=auth_failure"), 1)
        self.assertEqual(self.total("severity=high"), 1)
        self.assertEqual(self.total("severity=low&severity_mode=min"), 2)
        self.assertEqual(self.total("source=vp*"), 3)
        self.assertEqual(self.total("host=db01"), 1)
        self.assertEqual(self.total("q=50%25"), 1)
        self.assertEqual(self.total("q=%25"), 1)  # literal percent, not a wildcard
        start = iso(self.base_ts + timedelta(minutes=5))
        self.assertEqual(self.total(f"start={start}"), 2)
        self.assertEqual(self.total(f"end={start}"), 1)
        self.assertEqual(self.total("synthetic=1"), 0)

    def test_pagination_and_validation(self):
        data = self.c.get("/api/events?limit=2&offset=2")[1]
        self.assertEqual((data["total"], len(data["events"])), (3, 1))
        for query in ["limit=0", "limit=abc", "severity=urgent", "event_type=x", "start=notadate"]:
            with self.subTest(query=query):
                self.assertEqual(self.c.get("/api/events?" + query)[0], 400)

    def test_sql_injection_attempts_are_inert(self):
        from urllib.parse import quote
        self.assertEqual(self.total("user=" + quote("' OR '1'='1")), 0)
        self.assertEqual(self.total("q=" + quote("'; DROP TABLE events;--")), 0)
        self.assertEqual(self.total(""), 3)

    def test_event_detail(self):
        event_id = self.c.get("/api/events?limit=1")[1]["events"][0]["id"]
        status, data, _ = self.c.get(f"/api/events/{event_id}")
        self.assertEqual(status, 200)
        self.assertIn("raw", data)
        self.assertEqual(self.c.get("/api/events/999999")[0], 404)


class ReportApiTests(ServerTestCase):
    def download(self, client, path):
        import urllib.error
        import urllib.request
        try:
            with client.opener.open(urllib.request.Request(self.base + path), timeout=30) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read(), exc.headers

    def setUp(self):
        super().setUp()
        self.assertEqual(self.client("admin").post("/api/demo/load")[0], 200)
        self.analyst = self.client("analyst")
        alerts = self.analyst.get("/api/alerts?rule_id=success_after_failures")[1]
        self.alert = alerts[0]

    def test_alert_reports_download(self):
        from tests.pdfparse import ParsedPDF
        aid = self.alert["id"]
        status, body, headers = self.download(self.analyst, f"/api/alerts/{aid}/report.pdf")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/pdf")
        self.assertEqual(headers["Content-Disposition"], f'attachment; filename="watchpost-alert-{aid}-report.pdf"')
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(self.alert["title"], ParsedPDF(body).text())

        status, body, headers = self.download(self.analyst, f"/api/alerts/{aid}/report.md")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/markdown"))
        self.assertIn("attachment;", headers["Content-Disposition"])
        text = body.decode("utf-8")
        self.assertTrue(text.startswith("# Alert report: "))
        self.assertIn("SYNTHETIC DATA", text)
        audit = self.client("admin").get("/api/audit")[1]
        self.assertEqual({(a["action"], a["target"]) for a in audit if a["action"] == "report_downloaded"},
                         {("report_downloaded", f"alert:{aid}")})

    def test_report_access_and_errors(self):
        aid = self.alert["id"]
        self.assertEqual(self.download(self.client(), f"/api/alerts/{aid}/report.pdf")[0], 401)
        with sqlite3.connect(self.db_path) as db:
            from watchpost.auth import hash_password
            db.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES "
                       "('viewer1', ?, 'viewer', '2026-01-01')", (hash_password("viewer-password-1"),))
        viewer = self.client()
        self.assertEqual(viewer.login("viewer1", "viewer-password-1")[0], 200)
        # Viewers are read-only but may download reports (Watchpost 2.0 / F).
        self.assertEqual(self.download(viewer, f"/api/alerts/{aid}/report.md")[0], 200)
        status, body, _ = self.download(self.analyst, "/api/alerts/999999/report.pdf")
        self.assertEqual((status, json.loads(body)["error"]), (404, "alert not found"))
        self.assertEqual(self.download(self.analyst, f"/api/alerts/{aid}/report.html")[0], 404)
        status, body, _ = self.download(self.analyst, "/api/incidents/999999/report.pdf")
        self.assertEqual((status, json.loads(body)["error"]), (404, "incident not found"))
        incident = self.analyst.get("/api/incidents")[1][0]
        status, body, _ = self.download(viewer, f"/api/incidents/{incident['id']}/report.pdf")
        self.assertEqual((status, body[:8]), (200, b"%PDF-1.4"))
        self.assertEqual(self.download(self.client(), f"/api/incidents/{incident['id']}/report.md")[0], 401)
        self.assertEqual(self.download(self.analyst, f"/api/incidents/{incident['id']}/report.txt")[0], 404)

    def test_incident_reports_download(self):
        from tests.pdfparse import ParsedPDF
        incident = next(i for i in self.analyst.get("/api/incidents")[1] if "Exfiltration" in i["stages"])
        iid = incident["id"]
        detail = self.analyst.get(f"/api/incidents/{iid}")[1]
        status, body, headers = self.download(self.analyst, f"/api/incidents/{iid}/report.pdf")
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(headers["Content-Type"], "application/pdf")
        self.assertEqual(headers["Content-Disposition"], f'attachment; filename="watchpost-incident-{iid}-report.pdf"')
        text = ParsedPDF(body).text()
        self.assertIn(f"Watchpost incident report #{iid}", text)
        for t in detail["techniques"]:
            self.assertIn(t["id"], text)

        status, body, headers = self.download(self.analyst, f"/api/incidents/{iid}/report.md")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/markdown"))
        text = body.decode("utf-8")
        self.assertTrue(text.startswith(f"# Incident report: {detail['title']}"))
        self.assertIn("SYNTHETIC DATA", text)
        self.assertIn("**Kill-chain stages:** " + " -> ".join(detail["stages"]), text)
        for group in detail["techniques_by_tactic"]:
            line = next(l for l in text.splitlines() if l.startswith(f"- **{group['tactic']}:**"))
            for t in group["techniques"]:
                self.assertIn(t["id"], line)
        for alert in detail["alerts"]:
            self.assertIn(f"### Alert #{alert['id']}:", text)
        audit = self.client("admin").get("/api/audit")[1]
        self.assertEqual({a["target"] for a in audit if a["action"] == "report_downloaded"}, {f"incident:{iid}"})

if __name__ == "__main__":
    unittest.main()
