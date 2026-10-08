"""Sigma subset import: the YAML-subset parser, the compiled detection, and the reviewed import workflow."""

import json
import time
import unittest
from datetime import timedelta
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma
from watchpost.db import iso, utcnow

from .helpers import ServerTestCase

EXAMPLE = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "failed_logins_from_external_source.yml"


def rule_yaml(detection, title="Test Rule", tags=("attack.t1190",), level="high"):
    tag_lines = "".join(f"  - {t}\n" for t in tags)
    return (f"title: {title}\nstatus: test\nlevel: {level}\ntags:\n{tag_lines}"
            f"logsource:\n  category: webserver\ndetection:\n{detection}")


def compiled(detection):
    return sigma.compile_rule(rule_yaml(detection))["params"]


class YamlSubsetTests(unittest.TestCase):
    def test_supported_subset(self):
        doc = sigma.parse_yaml(
            "---\n"
            "# a comment\n"
            "title: 'It''s quoted'   # trailing comment\n"
            "plain: some text\n"
            "dq: \"a\\\\b \\\"c\\\"\"\n"
            "num: 4625\n"
            "nothing: null\n"
            "flag: true\n"
            "flow: [a, 'b c', 3]\n"
            "text: |\n"
            "  line one\n"
            "  line two # kept\n"
            "folded: >-\n"
            "  one\n"
            "  two\n"
            "list:\n"
            "- x\n"
            "- y\n"
            "nested:\n"
            "  CommandLine|contains|all:\n"
            "    - foo\n"
            "    - bar\n"
            "  maps:\n"
            "    - a: 1\n"
            "      b: 2\n"
            "    - c: 3\n")
        self.assertEqual(doc["title"], "It's quoted")
        self.assertEqual(doc["plain"], "some text")
        self.assertEqual(doc["dq"], 'a\\b "c"')
        self.assertEqual((doc["num"], doc["nothing"], doc["flag"]), (4625, None, True))
        self.assertEqual(doc["flow"], ["a", "b c", 3])
        self.assertEqual(doc["text"], "line one\nline two # kept\n")
        self.assertEqual(doc["folded"], "one two")
        self.assertEqual(doc["list"], ["x", "y"])
        self.assertEqual(doc["nested"]["CommandLine|contains|all"], ["foo", "bar"])
        self.assertEqual(doc["nested"]["maps"], [{"a": 1, "b": 2}, {"c": 3}])

    def test_refusals(self):
        cases = {
            "a: &anchor x\nb: 1\n": "anchors",
            "a: x\nb: *alias\n": "aliases",
            "a: 1\n---\nb: 2\n": "multiple YAML documents",
            "a: !!str 1\n": "tags",
            "a: {b: 1}\n": "flow mappings",
            "a:\n\t- x\n": "tabs",
            "a: 1\na: 2\n": "duplicate key",
            "a: [b, [c]]\n": "simple [a, b] lists",
            "a: 'open\n": "unterminated",
            "? complex\n": "complex keys",
            "%YAML 1.2\na: 1\n": "directives",
            "- a\n- b\n": "mapping",
        }
        for text, reason in cases.items():
            with self.subTest(text=text):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    sigma.parse_yaml(text)
                self.assertIn(reason, str(ctx.exception))

    def test_size_cap(self):
        with self.assertRaises(sigma.SigmaError) as ctx:
            sigma.parse_yaml("a: " + "x" * sigma.MAX_SOURCE_BYTES)
        self.assertIn("at most", str(ctx.exception))


class CompileTests(unittest.TestCase):
    def test_modifiers(self):
        p = compiled("  sel:\n    message|contains: Union Select\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "id=1 UNION SELECT pw"}))  # case-insensitive
        self.assertFalse(sigma.matches(p, {"message": "select"}))
        p = compiled("  sel:\n    message|startswith: GET /admin\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "GET /admin/login"}))
        self.assertFalse(sigma.matches(p, {"message": "POST GET /admin"}))
        p = compiled("  sel:\n    message|endswith: .php\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "GET /wp-login.php"}))
        self.assertFalse(sigma.matches(p, {"message": "GET /wp-login.php?x"}))
        p = compiled("  sel:\n    message|contains|all:\n      - ../\n      - etc/passwd\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "GET /../../etc/passwd"}))
        self.assertFalse(sigma.matches(p, {"message": "GET /etc/passwd"}))
        p = compiled("  sel:\n    src_ip|cidr: 203.0.113.0/24\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"src_ip": "203.0.113.9"}))
        self.assertFalse(sigma.matches(p, {"src_ip": "198.51.100.1"}))
        self.assertFalse(sigma.matches(p, {"src_ip": "not-an-ip"}))
        # Plain values: exact (case-insensitive), with * and ? wildcards; null matches an empty field.
        p = compiled("  sel:\n    user: adm?n*\n    dest_port: 22\n    host: null\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"user": "Admin01", "dest_port": 22}))
        self.assertFalse(sigma.matches(p, {"user": "Admin01", "dest_port": 22, "host": "web01"}))
        self.assertFalse(sigma.matches(p, {"user": "xadmin", "dest_port": 22}))
        p = compiled("  sel:\n    message: 'a\\*b'\n  condition: sel\n")  # an escaped star is literal
        self.assertTrue(sigma.matches(p, {"message": "a*b"}))
        self.assertFalse(sigma.matches(p, {"message": "axxb"}))

    def test_conditions(self):
        det = ("  sel_a:\n    user: alice\n  sel_b:\n    src_ip: 203.0.113.9\n  other:\n    host: web01\n"
               "  condition: {}\n")
        events = {"a": {"user": "alice"}, "b": {"src_ip": "203.0.113.9"}, "ab": {"user": "alice", "src_ip": "203.0.113.9"},
                  "abo": {"user": "alice", "src_ip": "203.0.113.9", "host": "web01"}, "o": {"host": "web01"}}
        cases = {
            "sel_a": {"a", "ab", "abo"},
            "sel_a and sel_b": {"ab", "abo"},
            "sel_a or sel_b": {"a", "b", "ab", "abo"},
            "not sel_a": {"b", "o"},
            "(sel_a or sel_b) and not other": {"a", "b", "ab"},
            "1 of sel_*": {"a", "b", "ab", "abo"},
            "all of sel_*": {"ab", "abo"},
            "all of them": {"abo"},
            "1 of them": {"a", "b", "ab", "abo", "o"},
        }
        for cond, want in cases.items():
            with self.subTest(condition=cond):
                p = compiled(det.format(cond))
                self.assertEqual({k for k, e in events.items() if sigma.matches(p, e)}, want)

    def test_list_of_maps_and_keywords(self):
        p = compiled("  sel:\n    - user: alice\n    - user: bob\n      host: web01\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"user": "alice"}))
        self.assertTrue(sigma.matches(p, {"user": "bob", "host": "web01"}))
        self.assertFalse(sigma.matches(p, {"user": "bob"}))
        p = compiled("  keywords:\n    - sqlmap\n    - nikto\n  condition: keywords\n")
        self.assertTrue(sigma.matches(p, {"message": "UA: Nikto/2.5"}))
        self.assertFalse(sigma.matches(p, {"message": "curl"}))

    def test_field_names_map_from_ecs_and_sigma(self):
        p = compiled("  sel:\n    source.ip: 1.2.3.4\n    DestinationPort: 3389\n    TargetUserName: bob\n"
                     "    Computer: dc01\n    event.action: auth_failure\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"src_ip": "1.2.3.4", "dest_port": 3389, "user": "bob", "host": "dc01",
                                          "event_type": "auth_failure"}))

    def test_refusals(self):
        cases = {
            "  sel:\n    CommandLine: x\n  condition: sel\n": "field 'CommandLine'",
            "  sel:\n    EventID: 4625\n  condition: sel\n": "field 'EventID'",
            "  sel:\n    message|re: '.*'\n  condition: sel\n": "'re' refused",
            "  sel:\n    message|base64: x\n  condition: sel\n": "base64",
            "  sel:\n    message|foo: x\n  condition: sel\n": "'foo' is not supported",
            "  sel:\n    user: x\n  condition: sel | count() by src_ip > 5\n": "aggregations",
            "  sel:\n    user: x\n  condition: sel near other\n": "near",
            "  sel:\n    user: x\n  timeframe: 5m\n  condition: sel\n": "timeframe",
            "  sel:\n    user: x\n  condition: nope\n": "unknown selection 'nope'",
            "  sel:\n    user: x\n  condition: 2 of sel*\n": "only '1 of' and 'all of'",
            "  sel:\n    user: x\n  condition: 1 of foo*\n": "matches no selection",
            "  sel:\n    user: x\n  condition: (sel\n": "ends too early",
            "  sel:\n    user: x\n  condition:\n    - sel\n": "lists of conditions",
            "  sel:\n    src_ip|cidr: banana\n  condition: sel\n": "not a CIDR",
        }
        for det, reason in cases.items():
            with self.subTest(detection=det):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    sigma.compile_rule(rule_yaml(det))
                self.assertIn(reason, str(ctx.exception))

    def test_metadata(self):
        c = sigma.compile_rule(rule_yaml("  sel:\n    user: x\n  condition: sel\n", title="Brute Force IP!",
                                         tags=("attack.t1190", "attack.t9999", "attack.initial_access"),
                                         level="informational"))
        self.assertEqual(c["rule_id"], "sigma_brute_force_ip")  # namespaced: never a built-in id
        self.assertNotIn(c["rule_id"], rules_mod.RULE_FUNCTIONS)
        self.assertEqual(c["severity"], "low")
        self.assertEqual([t["id"] for t in c["techniques"]], ["T1190"])
        self.assertIn("attack.t9999", c["warnings"][0])
        self.assertTrue(any("logsource is informational" in w for w in c["warnings"]))
        self.assertEqual(rules_mod.validate_params(c["rule_id"], c["params"]), c["params"])
        with self.assertRaises(rules_mod.RuleConfigError):
            rules_mod.validate_params(c["rule_id"], {**c["params"], "threshold": 3})

    def test_glob_is_linear(self):
        p = compiled("  sel:\n    message: '*a*a*a*a*a*a*a*a*a*a*b'\n  condition: sel\n")
        started = time.monotonic()
        self.assertFalse(sigma.matches(p, {"message": "a" * 1024}))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_example_rule_compiles(self):
        c = sigma.compile_rule(EXAMPLE.read_text())
        self.assertEqual(c["rule_id"], "sigma_failed_admin_login_from_external_source")
        self.assertEqual([t["id"] for t in c["techniques"]], ["T1110.001"])
        self.assertTrue(sigma.matches(c["params"], {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.5"}))
        self.assertFalse(sigma.matches(c["params"], {"event_type": "auth_failure", "user": "root", "src_ip": "10.1.2.3"}))
        self.assertFalse(sigma.matches(c["params"], {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.5"}))


WEB_RULE = rule_yaml("  sel:\n    event_type: web_request\n    message|contains: /cgi-bin/.%2e/\n  condition: sel\n",
                     title="Path Traversal Probe")
WEB_ID = "sigma_path_traversal_probe"
GOOD_SAMPLE = {"malicious": [{"event_type": "web_request", "message": "GET /cgi-bin/.%2e/.%2e/bin/sh"}],
               "benign": [{"event_type": "web_request", "message": "GET /cgi-bin/status"}]}
BAD_SAMPLE = {"malicious": [{"event_type": "web_request", "message": "GET /cgi-bin/../bin/sh"}],
              "benign": [{"event_type": "web_request", "message": "GET /cgi-bin/status"}]}


class ImportWorkflowTests(ServerTestCase):
    def import_rule(self, client, source=WEB_RULE, sample=None, dry_run=False):
        body = {"source": source, **({"sample": sample} if sample else {})}
        return client.post("/api/rules/sigma" + ("?dry_run=1" if dry_run else ""), body)

    def approve(self, admin, change):
        status, data, _ = admin.post(f"/api/changes/{change['id']}/review",
                                     {"decision": "approve", "evidence_digest": change["evidence_digest"]})
        self.assertEqual(status, 200, data)
        return data

    def rule(self, client, rule_id=WEB_ID):
        return next((r for r in client.get("/api/rules")[1] if r["id"] == rule_id), None)

    def technique(self, client, tid):
        return next(t for t in client.get("/api/attack/coverage")[1]["techniques"] if t["id"] == tid)

    def test_viewer_cannot_import(self):
        viewer = self.client("viewer")
        self.assertEqual(self.import_rule(viewer)[0], 403)
        self.assertEqual(self.import_rule(viewer, dry_run=True)[0], 403)
        self.assertEqual(viewer.post(f"/api/rules/{WEB_ID}/sigma-sample", {"sample": GOOD_SAMPLE})[0], 403)

    def test_dry_run_compiles_and_creates_nothing(self):
        analyst = self.client("analyst")
        status, data, _ = self.import_rule(analyst, sample=GOOD_SAMPLE, dry_run=True)
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["compiled"]["rule_id"], WEB_ID)
        self.assertIn("message contains '/cgi-bin/.%2e/'", data["compiled"]["conditions"])
        self.assertTrue(data["sample"]["passes"])
        self.assertIn("matched_events", data["backtest"])
        status, data, _ = self.import_rule(analyst, rule_yaml("  s:\n    message|re: x\n  condition: s\n"),
                                           dry_run=True)
        self.assertEqual(status, 200, data)
        self.assertFalse(data["ok"])
        self.assertIn("regular expressions are refused", data["refused"])
        self.assertEqual(analyst.get("/api/changes")[1], [])
        self.assertIsNone(self.rule(analyst))
        # A real import of a refused rule is a 400 naming the reason.
        status, data, _ = self.import_rule(analyst, rule_yaml("  s:\n    Image: x\n  condition: s\n"))
        self.assertEqual(status, 400)
        self.assertIn("field 'Image'", data["error"])

    def test_two_person_review_adds_the_rule_disabled(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        status, change, _ = self.import_rule(analyst)
        self.assertEqual(status, 201, change)
        self.assertEqual((change["kind"], change["target"], change["status"]), ("sigma_add", WEB_ID, "pending"))
        self.assertIsNone(change["evaluation"]["sample"])
        self.assertIsNone(self.rule(admin))  # nothing until approved
        # The proposer cannot approve their own import.
        status, own, _ = self.import_rule(admin, rule_yaml("  s:\n    user: x\n  condition: s\n", title="Other"))
        self.assertEqual(status, 201, own)
        status, data, _ = admin.post(f"/api/changes/{own['id']}/review",
                                     {"decision": "approve", "evidence_digest": own["evidence_digest"]})
        self.assertEqual(status, 403, data)
        self.approve(admin, change)
        rule = self.rule(admin)
        self.assertFalse(rule["enabled"])
        self.assertEqual(rule["sigma"]["source"], WEB_RULE)
        self.assertEqual(rule["sigma"]["sha256"], sigma.compile_rule(WEB_RULE)["sha256"])
        self.assertEqual(self.rule(self.client("viewer"))["sigma"]["source"], WEB_RULE)  # read-only for viewers
        # Same title again: refused, the id exists.
        self.assertEqual(self.import_rule(analyst)[0], 409)
        # Imported logic is not tuned in place.
        status, data, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals",
                                       {"params": {"title": "x"}, "reason": "rename it"})
        self.assertEqual(status, 400, data)
        # A tuning export carries it, and importing that export back changes nothing.
        doc = admin.get("/api/rules/export")[1]
        status, result, _ = admin.request("POST", "/api/rules/import?dry_run=1", raw=json.dumps(doc).encode(),
                                          headers={"Content-Type": "application/json"})
        self.assertEqual(next(r for r in result["rules"] if r["id"] == WEB_ID)["outcome"], "unchanged", result)

    def test_enable_needs_a_passing_sample_and_coverage_follows_it(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.approve(admin, self.import_rule(analyst)[1])
        status, data, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 400, data)
        self.assertIn("no sample attached", data["error"])

        # A failing sample still blocks.
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/sigma-sample",
                                         {"sample": BAD_SAMPLE, "reason": "labeled sample"})
        self.assertEqual(status, 201, change)
        self.assertFalse(change["evaluation"]["sample"]["passes"])
        self.approve(admin, change)
        status, data, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 400, data)
        self.assertIn("1 malicious event(s) not matched", data["error"])

        # A passing sample: the rule may be enabled. Before that T1190 is only mapped (web_scanner) and this rule
        # proves nothing.
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/sigma-sample",
                                         {"sample": GOOD_SAMPLE, "reason": "fixed sample"})
        self.approve(admin, change)
        t = self.technique(admin, "T1190")
        self.assertEqual(t["level"], "mapped")
        self.assertEqual(next(r for r in t["rules"] if r["id"] == WEB_ID)["proves"], [])
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 201, change)
        self.approve(admin, change)
        self.assertTrue(self.rule(admin)["enabled"])
        t = self.technique(admin, "T1190")
        self.assertEqual(t["level"], "validated")
        self.assertEqual(t["scenarios"], [f"sigma_sample:{WEB_ID}"])

        # Replacing the sample with one that fails drops it back to mapped: never coverage without proof.
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/sigma-sample",
                                         {"sample": BAD_SAMPLE, "reason": "new sample"})
        self.approve(admin, change)
        self.assertEqual(self.technique(admin, "T1190")["level"], "mapped")
        lab = next(r for r in admin.get("/api/noise-lab")[1]["rules"] if r["rule_id"] == WEB_ID)
        self.assertEqual(lab["verdict"], "blind")

    def test_enabled_rule_alerts_on_ingested_events(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.approve(admin, self.import_rule(analyst, sample=GOOD_SAMPLE)[1])
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.approve(admin, change)
        base = utcnow() - timedelta(minutes=30)
        analyst.post("/api/ingest", {"source": "web", "events": [
            {"ts": iso(base), "type": "web_request", "src_ip": "198.51.100.7", "message": "GET /cgi-bin/.%2e/x"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "web_request", "src_ip": "198.51.100.7",
             "message": "GET /index.html"}]})
        alerts = [a for a in analyst.get(f"/api/alerts?rule_id={WEB_ID}")[1] if a["rule_id"] == WEB_ID]
        self.assertEqual(len(alerts), 1, alerts)
        self.assertEqual((alerts[0]["group_key"], alerts[0]["event_count"]), ("198.51.100.7", 1))

    def test_example_rule_imports(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        sample = {"malicious": [{"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.5"}],
                  "benign": [{"event_type": "auth_failure", "user": "root", "src_ip": "10.0.0.8"},
                             {"event_type": "auth_failure", "user": "alice", "src_ip": "203.0.113.5"}]}
        status, change, _ = self.import_rule(analyst, EXAMPLE.read_text(), sample)
        self.assertEqual(status, 201, change)
        self.assertTrue(change["evaluation"]["sample"]["passes"])
        self.approve(admin, change)
        rule = self.rule(admin, "sigma_failed_admin_login_from_external_source")
        self.assertEqual((rule["severity"], rule["enabled"]), ("high", False))
        self.assertEqual([t["id"] for t in rule["techniques"]], ["T1110.001"])

    def test_imports_spend_the_backtest_buckets(self):
        analyst = self.client("analyst")
        codes = [self.import_rule(analyst, dry_run=True)[0] for _ in range(8)]
        self.assertEqual(codes[:6], [200] * 6)  # the preview bucket (burst 6)
        self.assertEqual(codes[-1], 429)
        # A real import spends from the rule-proposal bucket (burst 20), which previews did not touch.
        for i in range(20):
            src = rule_yaml("  s:\n    user: x\n  condition: s\n", title=f"Rule {'abcdefghijklmnopqrstu'[i]}")
            self.assertEqual(self.import_rule(analyst, src)[0], 201)
        status, data, _ = self.import_rule(analyst, rule_yaml("  s:\n    user: x\n  condition: s\n", title="Last"))
        self.assertEqual(status, 429, data)


if __name__ == "__main__":
    unittest.main()
