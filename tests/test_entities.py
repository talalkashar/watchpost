"""Entity risk (Watchpost 3.0 / item 5) and the SOC metrics added to /api/metrics (item 6)."""

import os
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import entities
from watchpost.db import connect, init_schema, iso, parse_iso, utcnow

STATIC = Path(__file__).resolve().parent.parent / "static"
ANCHOR = "2026-09-15T12:00:00.000Z"


def ago(hours):
    return iso(parse_iso(ANCHOR) - timedelta(hours=hours))


def add_event(conn, ts, user=None, src_ip=None, host=None, synthetic=1):
    return conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,?)", (ts, ts, "test", host, "auth_failure", "low", user, src_ip, synthetic)).lastrowid


def add_alert(conn, severity, last_seen, event_ids, status="open", disposition=None, created_at=None,
              resolved_at=None, rule_id="brute_force_ip"):
    created_at = created_at or last_seen
    alert_id = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status, disposition,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at, resolved_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rule_id, 1, "k", severity, f"{severity} alert", "why", status, disposition, last_seen, last_seen,
         len(event_ids), 1, created_at, created_at, resolved_at)).lastrowid
    conn.executemany("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", [(alert_id, e) for e in event_ids])
    return alert_id


class RiskScoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = connect(os.path.join(self.tmp.name, "t.db"))
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_score_is_severity_weight_decayed_from_the_newest_event(self):
        fresh = add_event(self.conn, ANCHOR, user="Alice", src_ip="198.51.100.7", host="web01")
        old = add_event(self.conn, ago(24), user="alice", src_ip="198.51.100.7")
        a1 = add_alert(self.conn, "high", ANCHOR, [fresh])
        a2 = add_alert(self.conn, "critical", ago(24), [old])
        detail = entities.get_entity(self.conn, "src_ip", "198.51.100.7")
        self.assertEqual(detail["anchor"], ANCHOR)
        by_alert = {c["alert_id"]: c for c in detail["contributions"]}
        self.assertEqual((by_alert[a1]["base_weight"], by_alert[a1]["decay"], by_alert[a1]["weight"]), (20, 1.0, 20.0))
        self.assertEqual((by_alert[a2]["base_weight"], by_alert[a2]["age_hours"], by_alert[a2]["decay"],
                          by_alert[a2]["weight"]), (40, 24.0, 0.5, 20.0))
        self.assertEqual(detail["score"], 40.0)
        # Accounts are matched case-insensitively, like the correlation engine does.
        self.assertEqual(entities.get_entity(self.conn, "user", "ALICE")["score"], 40.0)
        self.assertEqual(entities.get_entity(self.conn, "host", "web01")["score"], 20.0)

    def test_asset_weight_shows_in_the_breakdown(self):
        ev = add_event(self.conn, ANCHOR, host="db01")
        raised = add_alert(self.conn, "high", ANCHOR, [ev])
        self.conn.execute("UPDATE alerts SET base_severity = 'medium', severity_note = ? WHERE id = ?",
                          ("raised 1 level(s): db01 is a high-criticality asset", raised))
        plain = add_alert(self.conn, "low", ANCHOR, [ev])
        by_alert = {c["alert_id"]: c for c in entities.get_entity(self.conn, "host", "db01")["contributions"]}
        self.assertEqual((by_alert[raised]["base_severity"], by_alert[raised]["severity"], by_alert[raised]["weight"]),
                         ("medium", "high", 20.0))
        self.assertIn("high-criticality", by_alert[raised]["asset_note"])
        self.assertEqual((by_alert[plain]["base_severity"], by_alert[plain]["asset_note"]), ("low", None))

    def test_false_positive_and_benign_alerts_do_not_count_but_are_listed(self):
        e = add_event(self.conn, ANCHOR, src_ip="10.0.50.5")
        fp = add_alert(self.conn, "critical", ANCHOR, [e], "resolved", "false_positive")
        benign = add_alert(self.conn, "high", ANCHOR, [e], "resolved", "benign")
        tp = add_alert(self.conn, "medium", ANCHOR, [e], "resolved", "true_positive")
        detail = entities.get_entity(self.conn, "src_ip", "10.0.50.5")
        self.assertEqual(detail["score"], 10.0)
        counted = {c["alert_id"]: (c["counted"], c["weight"]) for c in detail["contributions"]}
        self.assertEqual(counted, {fp: (False, 0.0), benign: (False, 0.0), tp: (True, 10.0)})
        self.assertEqual(len(detail["alerts"]), 3)

    def test_list_ranks_by_score_and_explains_every_score(self):
        loud = add_event(self.conn, ANCHOR, user="mallory", src_ip="203.0.113.9")
        quiet = add_event(self.conn, ANCHOR, user="bob", src_ip="203.0.113.10")
        cleared = add_event(self.conn, ANCHOR, src_ip="10.0.50.5")
        add_alert(self.conn, "critical", ANCHOR, [loud])
        add_alert(self.conn, "low", ANCHOR, [quiet])
        add_alert(self.conn, "critical", ANCHOR, [cleared], "resolved", "false_positive")
        result = entities.list_entities(self.conn, {})
        self.assertEqual(result["half_life_hours"], entities.HALF_LIFE_HOURS)
        self.assertEqual(result["severity_weights"], entities.SEVERITY_WEIGHTS)
        rows = result["entities"]
        self.assertEqual([r["score"] for r in rows], sorted((r["score"] for r in rows), reverse=True))
        self.assertEqual({(r["kind"], r["value"]) for r in rows},
                         {("user", "mallory"), ("src_ip", "203.0.113.9"), ("user", "bob"), ("src_ip", "203.0.113.10")})
        for r in rows:
            self.assertEqual(r["score"], round(sum(c["weight"] for c in r["contributions"]), 2))
            self.assertTrue(all(c["counted"] for c in r["contributions"]))
        only_ips = entities.list_entities(self.conn, {"kind": "src_ip", "limit": "1"})["entities"]
        self.assertEqual([(r["kind"], r["value"]) for r in only_ips], [("src_ip", "203.0.113.9")])

    def test_empty_database_and_unknown_entity(self):
        self.assertEqual(entities.list_entities(self.conn, {})["entities"], [])
        detail = entities.get_entity(self.conn, "user", "nobody")
        self.assertEqual((detail["score"], detail["contributions"], detail["first_seen"], detail["event_count"]),
                         (0.0, [], None, 0))


class EntityApiTests(ServerTestCase):
    def test_requires_login_and_validates_input(self):
        self.assertEqual(self.client().get("/api/entities")[0], 401)
        self.assertEqual(self.client().get("/api/entities/user/alice")[0], 401)
        analyst = self.client("analyst")
        self.assertEqual(analyst.get("/api/entities?kind=planet")[0], 400)
        self.assertEqual(analyst.get("/api/entities?limit=0")[0], 400)
        self.assertEqual(analyst.get("/api/entities/planet/mars")[0], 404)

    def test_values_with_dots_colons_and_pipes_round_trip_through_the_url(self):
        values = {"user": "CORP\\svc|deploy tmp", "src_ip": "2001:db8::1", "host": "web01.corp.example:22/a%b"}
        with sqlite3.connect(self.db_path) as db:
            e = add_event(db, ANCHOR, user=values["user"], src_ip=values["src_ip"], host=values["host"])
            add_alert(db, "high", ANCHOR, [e])
        analyst = self.client("analyst")
        for kind, value in values.items():
            with self.subTest(kind=kind):
                status, detail, _ = analyst.get(f"/api/entities/{kind}/{quote(value, safe='')}")
                self.assertEqual(status, 200)
                self.assertEqual((detail["kind"], detail["score"], detail["event_count"]), (kind, 20.0, 1))
                self.assertEqual(detail["value"], value.lower() if kind == "user" else value)

    def test_demo_data_entity_page(self):
        self.assertEqual(self.client("admin").post("/api/demo/load", {})[0], 200)
        viewer = self.client("viewer")
        status, top, _ = viewer.get("/api/entities?limit=50")
        self.assertEqual(status, 200)
        self.assertIn(("src_ip", "203.0.113.45"), {(r["kind"], r["value"]) for r in top["entities"]})
        self.assertEqual({r["kind"] for r in viewer.get("/api/entities?kind=user")[1]["entities"]}, {"user"})

        status, d, _ = viewer.get("/api/entities/src_ip/203.0.113.45")
        self.assertEqual(status, 200)
        self.assertGreater(d["score"], 0)
        self.assertEqual(d["score"], round(sum(c["weight"] for c in d["contributions"]), 2))
        self.assertEqual({c["alert_id"] for c in d["contributions"]}, {a["id"] for a in d["alerts"]})
        self.assertTrue(d["synthetic"])
        self.assertTrue(d["recent_events"] and all(e["src_ip"] == "203.0.113.45" for e in d["recent_events"]))
        self.assertNotIn("raw", d["recent_events"][0])
        self.assertLessEqual(d["first_seen"], d["last_seen"])
        linked = {i["id"] for i in d["incidents"]}
        self.assertTrue(linked)
        self.assertLessEqual(linked, {i["id"] for i in viewer.get("/api/incidents")[1]})

        # Closing an alert as a false positive takes its weight out of the score.
        analyst = self.client("analyst")
        target = d["contributions"][0]
        analyst.post(f"/api/alerts/{target['alert_id']}/status", {"status": "resolved", "disposition": "false_positive"})
        after = viewer.get("/api/entities/src_ip/203.0.113.45")[1]
        self.assertEqual(after["score"], round(d["score"] - target["weight"], 2))

    def test_dashboard_lists_riskiest_entities(self):
        admin = self.client("admin")
        self.assertEqual(admin.get("/api/dashboard")[1]["risky_entities"], [])
        admin.post("/api/demo/load", {})
        rows = admin.get("/api/dashboard")[1]["risky_entities"]
        self.assertTrue(0 < len(rows) <= 8)
        self.assertEqual(rows, admin.get("/api/entities?limit=8")[1]["entities"])


class SocMetricsTests(ServerTestCase):
    def test_empty_database(self):
        m = self.client("analyst").get("/api/metrics")[1]
        self.assertEqual(m["time_to_resolve_by_severity"], [])
        self.assertEqual(m["false_positive_rate_by_rule"], [])
        self.assertEqual(sum(b["count"] for b in m["open_alert_aging"]["buckets"]), 0)
        self.assertIsNone(m["open_alert_aging"]["oldest_minutes"])

    def test_resolve_time_false_positive_rate_and_aging(self):
        now = utcnow()
        t = lambda minutes: iso(now - timedelta(minutes=minutes))
        with sqlite3.connect(self.db_path) as db:
            e = add_event(db, ANCHOR, src_ip="203.0.113.9")
            add_alert(db, "high", ANCHOR, [e], "resolved", "true_positive", created_at=t(100), resolved_at=t(90))
            add_alert(db, "high", ANCHOR, [e], "resolved", "false_positive", created_at=t(100), resolved_at=t(70))
            add_alert(db, "low", ANCHOR, [e], "resolved", "benign", created_at=t(50), resolved_at=t(45),
                      rule_id="web_scan")
            add_alert(db, "medium", ANCHOR, [e], "open", created_at=t(30))
            add_alert(db, "medium", ANCHOR, [e], "investigating", created_at=t(60 * 30))
        m = self.client("viewer").get("/api/metrics")[1]
        self.assertEqual(m["time_to_resolve_by_severity"],
                         [{"severity": "high", "resolved": 2, "mean_minutes": 20.0, "max_minutes": 30.0},
                          {"severity": "low", "resolved": 1, "mean_minutes": 5.0, "max_minutes": 5.0}])
        self.assertEqual(m["false_positive_rate_by_rule"],
                         [{"rule_id": "brute_force_ip", "reviewed": 2, "false_positive": 1, "benign": 0,
                           "false_positive_rate": 0.5},
                          {"rule_id": "web_scan", "reviewed": 1, "false_positive": 0, "benign": 1,
                           "false_positive_rate": 0.0}])
        aging = m["open_alert_aging"]
        self.assertEqual({b["label"]: b["count"] for b in aging["buckets"]},
                         {"under 1h": 1, "1-4h": 0, "4-24h": 0, "1-7d": 1, "over 7d": 0})
        self.assertAlmostEqual(aging["oldest_minutes"], 60 * 30, delta=1)
        # Metrics that replayed timestamps would distort are named, not silently dropped.
        self.assertIn("time_to_detect", {o["metric"] for o in m["omitted_metrics"]})
        self.assertTrue(all(o["reason"] for o in m["omitted_metrics"]))


class EntityUiTests(unittest.TestCase):
    """No JS runtime in CI: check that the entity links are built with encoded values."""

    def test_entity_links_encode_the_value(self):
        app = (STATIC / "app.js").read_text()
        self.assertIn("#entity/${kind}/${encodeURIComponent(value)}", app)
        self.assertIn("/api/entities/${kind}/${encodeURIComponent(value)}", app)
        self.assertIn("entityLink(", (STATIC / "dashboard.js").read_text())
        # The kind comes from location.hash: it is checked before it reaches the API path ("#entity/../audit").
        self.assertIn('if (!Object.hasOwn(ENTITY_KINDS, kind)) throw new Error("Unknown entity kind");\n'
                      "  const e = await api(`/api/entities/${kind}/", app)
        self.assertIn("#p-entities", (STATIC / "style.css").read_text())


if __name__ == "__main__":
    unittest.main()
