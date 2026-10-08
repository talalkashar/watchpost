"""Saved searches as detections: the Python matcher (cross-checked against the hunt's SQL), the threshold
window, and the reviewed promote -> sample -> enable workflow."""

import json
import unittest
from datetime import timedelta

from watchpost import engine, hunt
from watchpost import rules as rules_mod
from watchpost import search_rules
from watchpost.db import connect, init_schema, iso, parse_iso, utcnow

from .helpers import ServerTestCase

T0 = parse_iso("2025-03-01T12:00:00.000Z")


def definition(**kw):
    return {"group_by": "src_ip", "threshold": 3, "window_minutes": 5, "severity": "high", **kw}


def compiled(query, **kw):
    return search_rules.compile_rule("Test rule", query, definition(**kw))


def ev(n, seconds, **fields):
    return {"id": n, "ts": iso(T0 + timedelta(seconds=seconds)), "event_type": "web_request",
            "src_ip": "203.0.113.9", **fields}


# A varied event set: mixed case, non-ASCII, LIKE metacharacters, missing fields, ports, synthetic flags.
USERS = ["alice", "Alice", "ALICE", "bob", None, "Émile", "émile", "al_ice", "al%x", ""]
HOSTS = ["web01", "WEB02", "db01", None, "Web-03"]
SRC = ["203.0.113.5", "10.0.0.5", None, "10.1.2.3"]
DEST = ["10.0.0.5", "198.51.100.1", None]
PORTS = [22, 443, None, 8080]
TYPES = ["auth_failure", "auth_success", "web_request", "fw_deny"]
SOURCES = ["ssh", "web", "FW", "SSH-gw"]
MESSAGES = ["Invalid password for alice", "GET /admin 100% done", "under_score here", None, "ÉCOLE fermée",
            "invalid PASSWORD", "back\\slash", "GET /Admin/login"]

QUERIES = [
    "user:alice", "user:ALICE", "user:émile", "user:Émile", "user:al*", "user:AL*", 'user:"al*"', "user:al_ice",
    "NOT user:alice", "-user:bob", "host:web*", "host:WEB*", "host:web01", "host:WEB01", "host:*", "NOT host:*",
    "src_ip:10.0.0.5", "ip:10.0.0.5", "ip:10.*", "NOT ip:10.*", "dest_ip:198.51.100.1", "dest_port:22",
    "NOT dest_port:22", "event_type:auth_failure", "event_type:auth*", "NOT event_type:web_request",
    "synthetic:1", "synthetic:false", "password", "PASSWORD", '"100%"', "under_score", '"under_"', "école",
    "ÉCOLE", "message:admin*", "message:*", '"back\\\\slash"', "source:ssh", "source:SSH", "source:s*",
    'user:alice event_type:auth_failure NOT src_ip:10.0.0.5', "dest_ip:198.51.100.1 NOT user:al*",
    '"invalid password"', "-message:admin host:w*", "user:* NOT user:a*",
]


class MatcherCrossCheckTests(unittest.TestCase):
    """The rule matcher runs in Python over event dicts; the hunt runs in SQL. They must agree."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        for synthetic in (False, True):
            batch = []
            for n in range(80):
                k = n + (7 if synthetic else 0)
                batch.append({"ts": iso(T0 + timedelta(seconds=n)), "source": SOURCES[k % 4], "severity": "low",
                              "host": HOSTS[k % 5], "event_type": TYPES[k % 4], "user": USERS[k % 10],
                              "src_ip": SRC[k % 4], "dest_ip": DEST[k % 3], "dest_port": PORTS[k % 4],
                              "message": MESSAGES[k % 8]})
            engine.store_batch(self.conn, batch, [], "test", "json", "test", synthetic=synthetic)
        self.events = [dict(r) for r in self.conn.execute(f"SELECT {engine.RULE_EVENT_FIELDS} FROM events")]

    def test_python_matcher_agrees_with_sql(self):
        nonempty = 0
        for query in QUERIES:
            with self.subTest(query=query):
                where, args = hunt.compile_query(query)
                sql_ids = {r[0] for r in self.conn.execute("SELECT id FROM events WHERE " + " AND ".join(where),
                                                           args)}
                _, terms = search_rules.parse_filter(query)
                match = search_rules.matcher(terms)
                py_ids = {e["id"] for e in self.events if match(e)}
                self.assertEqual(py_ids, sql_ids)
                nonempty += 0 < len(sql_ids) < len(self.events)
        self.assertGreater(nonempty, len(QUERIES) // 2)  # most queries split the set, so agreement means something

    def test_case_rules(self):
        match = search_rules.matcher(search_rules.parse_filter("user:ALICE")[1])
        self.assertTrue(match({"user": "alice"}))
        self.assertFalse(match({"user": "alicex"}))
        # NOCASE folds ASCII only, as SQLite does.
        self.assertFalse(search_rules.matcher(search_rules.parse_filter("user:émile")[1])({"user": "Émile"}))
        # Equality on other text fields is exact; prefixes (LIKE) ignore ASCII case.
        self.assertFalse(search_rules.matcher(search_rules.parse_filter("host:WEB01")[1])({"host": "web01"}))
        self.assertTrue(search_rules.matcher(search_rules.parse_filter("host:WEB*")[1])({"host": "web01"}))
        # NOT keeps events that lack the field.
        self.assertTrue(search_rules.matcher(search_rules.parse_filter("NOT host:web*")[1])({"host": None}))


class DefinitionTests(unittest.TestCase):
    def test_time_terms_are_refused(self):
        for query in ("event_type:auth_failure last:24h", "since:2025-01-01 user:a", "user:a until:2025-01-01",
                      "last:15m"):
            with self.subTest(query=query):
                with self.assertRaises(search_rules.SearchRuleError) as ctx:
                    compiled(query)
                self.assertIn("time terms", str(ctx.exception))

    def test_other_refusals(self):
        cases = {"event_type:auth_failure | stats count by src_ip": "filter only",
                 "outcome:failure": "not available to detection rules",
                 "severity:high": "not available", "batch_id:x": "not available",
                 "": "query is required", "user:a OR user:b": "OR is not supported",
                 "event_type:nope": "event_type must be one of", "dest_port:99999": "dest_port"}
        for query, reason in cases.items():
            with self.subTest(query=query):
                with self.assertRaises(search_rules.SearchRuleError) as ctx:
                    compiled(query)
                self.assertIn(reason, str(ctx.exception))
        bad = {"group_by": "message", "threshold": 0, "window_minutes": 0, "severity": "info",
               "techniques": ["T9999"]}
        for key, value in bad.items():
            with self.subTest(key=key):
                with self.assertRaises(search_rules.SearchRuleError):
                    compiled("user:a", **{key: value})
        with self.assertRaises(search_rules.SearchRuleError):
            search_rules.compile_rule("x", "user:a", {**definition(), "query": "user:b"})  # unknown key

    def test_compiled_form(self):
        c = compiled("event_type:web_request NOT src_ip:10.0.0.5", techniques=["t1190"], name="Web Burst!")
        self.assertEqual(c["rule_id"], "search_web_burst")
        self.assertEqual([t["id"] for t in c["techniques"]], ["T1190"])
        self.assertEqual(c["params"]["window_seconds"], 300)
        self.assertIn("at least 3 event(s)", c["conditions"])
        self.assertIn("NOT src_ip = 10.0.0.5", c["conditions"])
        params = json.loads(json.dumps(c["params"]))  # as stored
        self.assertEqual(rules_mod.validate_params(c["rule_id"], params), params)
        self.assertIs(rules_mod.rule_function(c["rule_id"]), search_rules.run)
        # Stored terms that disagree with the query, or a window that is not whole minutes, are refused.
        for tampered in ({**params, "terms": []}, {**params, "query": "user:b"}, {**params, "window_seconds": 90},
                         {**params, "group_by": "message"}, {**params, "extra": 1}):
            with self.assertRaises(rules_mod.RuleConfigError):
                rules_mod.validate_params(c["rule_id"], tampered)


class WindowTests(unittest.TestCase):
    params = compiled("event_type:web_request")["params"]  # threshold 3, window 300 s, by src_ip

    def run_rule(self, offsets, params=None, **fields):
        return search_rules.run([ev(n + 1, s, **fields) for n, s in enumerate(offsets)], params or self.params)

    def test_threshold_and_window_edges(self):
        self.assertEqual(len(self.run_rule([0, 150, 300])), 1)          # exactly the window: inclusive
        self.assertEqual(self.run_rule([0, 150, 300.001]), [])          # one millisecond past it
        self.assertEqual(self.run_rule([0, 100]), [])                   # below the threshold
        finding, = self.run_rule([0, 301, 302, 303])                    # the first event is in no full window
        self.assertEqual(finding["event_ids"], [2, 3, 4])
        self.assertEqual((finding["group_key"], finding["first_seen"]), ("203.0.113.9", iso(T0 + timedelta(seconds=301))))
        # Two bursts further apart than the window are two findings; overlapping windows are one.
        self.assertEqual(len(self.run_rule([0, 1, 2, 1000, 1001, 1002])), 2)
        self.assertEqual(len(self.run_rule([0, 1, 2, 200, 250, 400])), 1)
        one = {**self.params, "threshold": 1}
        self.assertEqual(len(self.run_rule([0, 1000], one)), 2)
        wide = {**self.params, "window_seconds": 3600}
        self.assertEqual(len(self.run_rule([0, 1000, 2000], wide)), 1)
        # Events that do not match the filter do not count.
        self.assertEqual(self.run_rule([0, 1, 2], event_type="auth_failure"), [])

    def test_group_by(self):
        events = [ev(1, 0), ev(2, 1, src_ip="198.51.100.4"), ev(3, 2), ev(4, 3), ev(5, 4, src_ip=None),
                  ev(6, 5, src_ip="198.51.100.4")]
        finding, = search_rules.run(events, self.params)
        self.assertEqual((finding["group_key"], finding["event_ids"]), ("203.0.113.9", [1, 3, 4]))
        by_port = {**compiled("event_type:web_request", group_by="dest_port")["params"]}
        port_events = [ev(n, n, dest_port=22) for n in range(1, 4)] + [ev(9, 9, dest_port=None)]
        finding, = search_rules.run(port_events, by_port)
        self.assertEqual(finding["group_key"], "22")
        by_user = compiled("event_type:web_request", group_by="user")["params"]
        self.assertEqual(search_rules.run([ev(n, n, user=u) for n, u in enumerate(["a", "a", "b"], 1)], by_user), [])
        # Varying an account's case does not split it under the threshold.
        finding, = search_rules.run([ev(n, n, user=u) for n, u in enumerate(["alice", "Alice", "ALICE"], 1)], by_user)
        self.assertEqual((finding["group_key"], finding["event_ids"]), ("alice", [1, 2, 3]))

    def test_sample_result(self):
        malicious = [{"event_type": "web_request", "src_ip": "203.0.113.9"}] * 3
        benign = [{"event_type": "web_request", "src_ip": "203.0.113.9"}] * 2
        r = search_rules.sample_result(self.params, search_rules.validate_sample(
            {"malicious": malicious, "benign": benign}))
        self.assertTrue(r["passes"], r)
        r = search_rules.sample_result(self.params, {"malicious": benign, "benign": malicious})
        self.assertFalse(r["passes"])
        self.assertEqual((r["missed"], r["fired"]), ([0, 1], [0, 1, 2]))
        spread = [{"event_type": "web_request", "src_ip": "1.2.3.4", "ts": iso(T0 + timedelta(minutes=10 * n))}
                  for n in range(3)]
        self.assertFalse(search_rules.sample_result(self.params, search_rules.validate_sample(
            {"malicious": spread, "benign": benign}))["passes"])
        with self.assertRaises(search_rules.SearchRuleError):
            search_rules.validate_sample({"malicious": [{"ts": "yesterday-ish"}], "benign": benign})


WEB_QUERY = 'event_type:web_request message:"/cgi-bin/"'
RULE_ID = "search_cgi_probe_burst"
GOOD_SAMPLE = {"malicious": [{"event_type": "web_request", "src_ip": "203.0.113.9", "message": "GET /cgi-bin/x"}] * 3,
               "benign": [{"event_type": "web_request", "src_ip": "203.0.113.9", "message": "GET /cgi-bin/x"}] * 2
               + [{"event_type": "web_request", "src_ip": "203.0.113.9", "message": "GET /index.html"}] * 3}
BAD_SAMPLE = {"malicious": GOOD_SAMPLE["malicious"][:2], "benign": GOOD_SAMPLE["benign"]}


class PromoteWorkflowTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        analyst = self.client("analyst")
        base = utcnow() - timedelta(hours=2)
        events = [{"ts": iso(base + timedelta(seconds=30 * n)), "type": "web_request", "src_ip": "203.0.113.9",
                   "message": f"GET /cgi-bin/probe{n}"} for n in range(4)]
        events += [{"ts": iso(base + timedelta(seconds=n)), "type": "web_request", "src_ip": "198.51.100.4",
                    "message": "GET /cgi-bin/status"} for n in range(2)]
        events += [{"ts": iso(base + timedelta(seconds=n)), "type": "web_request", "src_ip": "192.0.2.1",
                    "message": "GET /index.html"} for n in range(5)]
        status, data, _ = analyst.post("/api/ingest", {"source": "web", "events": events})
        self.assertEqual((status, data["accepted"]), (201, 11), data)
        status, saved, _ = analyst.post("/api/hunt/saved", {"name": "CGI probe burst", "query": WEB_QUERY})
        self.assertEqual(status, 201, saved)
        self.saved = saved

    def promote(self, client, saved_id=None, dry_run=False, **kw):
        body = {**definition(techniques=["T1190"]), **kw}
        return client.post(f"/api/hunt/saved/{saved_id or self.saved['id']}/promote"
                           + ("?dry_run=1" if dry_run else ""), body)

    def approve(self, admin, change):
        status, data, _ = admin.post(f"/api/changes/{change['id']}/review",
                                     {"decision": "approve", "evidence_digest": change["evidence_digest"]})
        self.assertEqual(status, 200, data)
        return data

    def rule(self, client, rule_id=RULE_ID):
        return next((r for r in client.get("/api/rules")[1] if r["id"] == rule_id), None)

    def technique(self, client, tid):
        return next(t for t in client.get("/api/attack/coverage")[1]["techniques"] if t["id"] == tid)

    def add_rule(self, analyst, admin, **kw):
        status, change, _ = self.promote(analyst, **kw)
        self.assertEqual(status, 201, change)
        self.approve(admin, change)
        return change

    def test_viewer_is_read_only(self):
        viewer = self.client("viewer")
        self.assertEqual(self.promote(viewer)[0], 403)
        self.assertEqual(self.promote(viewer, dry_run=True)[0], 403)
        self.add_rule(self.client("analyst"), self.client("admin"))
        status, rules, _ = viewer.get("/api/rules")
        self.assertEqual(status, 200)
        self.assertEqual(next(r for r in rules if r["id"] == RULE_ID)["search"]["query"], WEB_QUERY)
        self.assertEqual(viewer.post(f"/api/rules/{RULE_ID}/search-sample", {"sample": GOOD_SAMPLE})[0], 403)

    def test_dry_run_previews_findings_and_creates_nothing(self):
        analyst = self.client("analyst")
        status, data, _ = self.promote(analyst, dry_run=True)
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["compiled"]["rule_id"], data["compiled"]["query"]), (RULE_ID, WEB_QUERY))
        bt = data["backtest"]
        self.assertEqual((bt["matched_events"], bt["findings"], bt["group_keys"]), (6, 1, ["203.0.113.9"]))
        self.assertEqual(bt["sample_findings"][0]["event_count"], 4)
        self.assertIsNone(data["sample"])
        self.assertEqual(analyst.get("/api/changes")[1], [])
        self.assertIsNone(self.rule(analyst))
        # A saved search with a time term (fine for hunting) is refused as a rule, with the reason.
        status, timed, _ = analyst.post("/api/hunt/saved", {"name": "Timed", "query": WEB_QUERY + " last:24h"})
        status, data, _ = self.promote(analyst, timed["id"], dry_run=True)
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])
        self.assertIn("time terms", data["refused"])
        status, data, _ = self.promote(analyst, timed["id"])
        self.assertEqual(status, 400)
        self.assertIn("time terms", data["error"])
        self.assertEqual(self.promote(analyst, 9999, dry_run=True)[0], 404)
        self.assertEqual(self.promote(analyst, dry_run=True, query="user:x")[0], 400)  # not a definition key

    def test_two_person_review_adds_the_rule_disabled(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        status, change, _ = self.promote(analyst)
        self.assertEqual(status, 201, change)
        self.assertEqual((change["kind"], change["target"], change["status"]), ("search_add", RULE_ID, "pending"))
        self.assertEqual(change["payload"]["query"], WEB_QUERY)
        self.assertEqual(change["evaluation"]["backtest"]["findings"], 1)
        self.assertIsNone(self.rule(admin))
        # The proposer cannot approve their own promotion.
        status, own, _ = self.promote(admin, name="Admin own")
        self.assertEqual(status, 201, own)
        status, data, _ = admin.post(f"/api/changes/{own['id']}/review",
                                     {"decision": "approve", "evidence_digest": own["evidence_digest"]})
        self.assertEqual(status, 403, data)
        # Deleting the saved search after proposing does not change what gets added.
        self.assertEqual(analyst.post(f"/api/hunt/saved/{self.saved['id']}/delete")[0], 200)
        self.approve(admin, change)
        rule = self.rule(admin)
        self.assertFalse(rule["enabled"])
        self.assertEqual((rule["severity"], [t["id"] for t in rule["techniques"]]), ("high", ["T1190"]))
        self.assertEqual(rule["search"]["query"], WEB_QUERY)
        self.assertEqual(rule["params"]["threshold"], 3)
        status, again, _ = analyst.post("/api/hunt/saved", {"name": "CGI probe burst", "query": WEB_QUERY})
        self.assertEqual(self.promote(analyst, again["id"])[0], 409)  # same name: the id exists

    def test_enable_needs_a_passing_sample_and_coverage_follows_it(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.add_rule(analyst, admin)
        status, data, _ = analyst.post(f"/api/rules/{RULE_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 400, data)
        self.assertIn("no sample attached", data["error"])

        status, change, _ = analyst.post(f"/api/rules/{RULE_ID}/search-sample",
                                         {"sample": BAD_SAMPLE, "reason": "labeled sample"})
        self.assertEqual(status, 201, change)
        self.assertFalse(change["evaluation"]["sample"]["passes"])
        self.approve(admin, change)
        status, data, _ = analyst.post(f"/api/rules/{RULE_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 400, data)
        self.assertIn("raise no finding", data["error"])

        status, change, _ = analyst.post(f"/api/rules/{RULE_ID}/search-sample",
                                         {"sample": GOOD_SAMPLE, "reason": "fixed sample"})
        self.approve(admin, change)
        self.assertEqual(self.technique(admin, "T1190")["level"], "mapped")
        status, change, _ = analyst.post(f"/api/rules/{RULE_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 201, change)
        self.approve(admin, change)
        self.assertTrue(self.rule(admin)["enabled"])
        t = self.technique(admin, "T1190")
        self.assertEqual((t["level"], t["scenarios"]), ("validated", [f"search_sample:{RULE_ID}"]))
        lab = next(r for r in admin.get("/api/noise-lab")[1]["rules"] if r["rule_id"] == RULE_ID)
        self.assertTrue(lab["sample"]["passes"])

        # Enabled, it alerts in the engine's normal scan.
        base = utcnow() - timedelta(minutes=20)
        analyst.post("/api/ingest", {"source": "web", "events": [
            {"ts": iso(base + timedelta(seconds=n)), "type": "web_request", "src_ip": "198.51.100.77",
             "message": "GET /cgi-bin/x"} for n in range(3)]})
        alerts = [a for a in analyst.get("/api/alerts")[1] if a["rule_id"] == RULE_ID]
        self.assertEqual({a["group_key"] for a in alerts}, {"198.51.100.77", "203.0.113.9"}, alerts)

    def test_threshold_and_window_tune_through_rule_update(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.add_rule(analyst, admin)
        status, data, _ = analyst.get(f"/api/rules/{RULE_ID}/backtest?params="
                                      + json.dumps({"threshold": 2}).replace(" ", ""))
        self.assertEqual(status, 200, data)
        status, change, _ = analyst.post(f"/api/rules/{RULE_ID}/proposals",
                                         {"params": {"threshold": 2, "window_seconds": 600}, "reason": "tune the window"})
        self.assertEqual(status, 201, change)
        self.assertIn("backtest", change["evaluation"])
        self.assertEqual(change["evaluation"]["backtest"]["running"], {"today": False, "proposed": False})
        self.approve(admin, change)
        rule = self.rule(admin)
        self.assertEqual((rule["params"]["threshold"], rule["params"]["window_seconds"], rule["version"]), (2, 600, 2))
        self.assertEqual(rule["params"]["query"], WEB_QUERY)
        # The query (and the rest of the definition) is not tunable; a window must be whole minutes.
        for params, reason in (({"query": "user:x"}, "only threshold and window_seconds"),
                               ({"terms": []}, "only threshold and window_seconds"),
                               ({"group_by": "user"}, "only threshold and window_seconds"),
                               ({"window_seconds": 90}, "multiple of 60"), ({"threshold": 0}, "threshold")):
            with self.subTest(params=params):
                status, data, _ = analyst.post(f"/api/rules/{RULE_ID}/proposals", {"params": params, "reason": "x" * 5})
                self.assertEqual(status, 400, data)
                self.assertIn(reason, data["error"])

    def test_promotions_spend_the_change_backtest_bucket(self):
        analyst = self.client("analyst")
        codes = [self.promote(analyst, dry_run=True)[0] for _ in range(21)]
        self.assertEqual(codes[:20], [200] * 20)  # the rule-proposal bucket (burst 20)
        self.assertEqual(codes[-1], 429)
        self.assertEqual(self.promote(analyst)[0], 429)
        # The preview bucket is separate.
        self.assertEqual(analyst.get("/api/rules/brute_force_ip/backtest")[0], 200)


if __name__ == "__main__":
    unittest.main()
