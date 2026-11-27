"""Example Sigma rules compile from their YAML and match ingested events.

Each example is compiled from the file on disk. Scrubbed native lines (auth.log, combined
access log, UFW, firewall CSV) and supported structured records (CloudTrail, Windows
Security) are ingested into one store. Matching uses the stored rows engine projection
returns. Log source and the example directory do not filter that scan.
"""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from watchpost import engine, sigma
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload

EXAMPLES = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples"
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
LOGSOURCE_WARNING = "logsource is informational only: the rule runs on every stored event"

# filename, rule id, sigma uuid, severity, techniques, labels that must match.
CASES = [
    (
        "successful_privileged_ssh_from_internet.yml",
        "sigma_successful_privileged_ssh_from_internet",
        "a5718903-eba2-470f-98b6-824fe9e38772",
        "high",
        ("T1133", "T1078.003"),
        {"ssh-root", "ssh-admin-v6", "ssh-administrator", "ssh-port"},
    ),
    (
        "privileged_account_lockout.yml",
        "sigma_privileged_account_lockout",
        "139b3a55-0936-4826-9857-978d2275371d",
        "medium",
        ("T1110.001",),
        {"lock-admin", "lock-root"},
    ),
    (
        "sudo_or_su_to_root.yml",
        "sigma_sudo_or_su_to_root",
        "e4e6de47-792d-4dca-a1da-9fbb50e34e82",
        "high",
        ("T1548.003",),
        {"sudo-root", "su-root"},
    ),
    (
        "web_path_traversal.yml",
        "sigma_web_request_path_traversal",
        "f4be1c96-f7a5-4991-89c3-08a4cedf7341",
        "high",
        ("T1190",),
        {"trav-passwd", "trav-encoded", "trav-dots", "trav-winini"},
    ),
    (
        "web_sql_injection.yml",
        "sigma_web_request_sql_injection",
        "ba07a3fa-bb6e-4c33-9393-2138c3ea9701",
        "high",
        ("T1190",),
        {"sqli-union", "sqli-plus", "sqli-schema", "sqli-or"},
    ),
    (
        "web_scanner_user_agent.yml",
        "sigma_web_scanner_user_agent",
        "c1f6a8af-b27f-4416-a6d1-20a4a28e8381",
        "medium",
        ("T1595.002",),
        {"scan-sqlmap", "scan-nmap"},
    ),
    (
        "web_sensitive_path_probe.yml",
        "sigma_web_sensitive_path_probe",
        "1450c5b8-db7d-4bc2-8657-b842b231870e",
        "medium",
        ("T1595.003",),
        {"trav-passwd", "env-curl", "git-config", "wp-login", "env-bak", "env-query", "direct-passwd"},
    ),
    (
        "remote_admin_allowed_from_internet.yml",
        "sigma_remote_admin_port_allowed_from_internet",
        "ff1d8ba5-5b71-47a8-b380-cc413460b0ae",
        "high",
        ("T1133",),
        {"fw-rdp", "fw-ssh", "fw-vnc", "fw-telnet"},
    ),
    (
        "cloud_iam_user_or_key_created.yml",
        "sigma_cloud_iam_user_or_access_key_creation_requested",
        "c31342f9-c756-4868-b9ab-330ffa2c2c78",
        "high",
        ("T1136.003", "T1098.001"),
        {"iam-user", "iam-key"},
    ),
    (
        "cloud_audit_logging_stopped.yml",
        "sigma_cloud_audit_logging_stop_or_deletion_requested",
        "84cc5745-a86f-4a51-8cdf-90fcd87cb05c",
        "critical",
        # The file still tags revoked T1562.008. The compiler stores the current technique.
        ("T1685.002",),
        {"audit-stop", "audit-delete", "audit-flow", "audit-config"},
    ),
]


def _web(path, status, agent="-"):
    return (f'203.0.113.80 - - [14/Sep/2026:13:00:00 +0000] "GET {path} HTTP/1.1" '
            f'{status} 120 "-" "{agent}"')


def _trail(name, source, user, ip, when, error=None):
    record = {
        "eventTime": when,
        "eventSource": source,
        "eventName": name,
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "userName": user},
        "recipientAccountId": "123456789012",
    }
    if error:
        record["errorCode"] = error
    return record


def _win(event_id, user, when, ip=None, dest_port=None, message="An account event."):
    record = {
        "EventID": event_id,
        "TimeCreated": when,
        "TargetUserName": user,
        "Computer": "dc01",
        "Channel": "Security",
        "message": message,
    }
    if ip:
        record["IpAddress"] = ip
    if dest_port is not None:
        record["dest_port"] = dest_port
    return record


class SigmaExampleTests(unittest.TestCase):
    def test_each_example_matches_ingested_events(self):
        self.assertEqual(len(CASES), 10)
        compiled = {}
        seen = set()
        for filename, rule_id, sigma_id, severity, techniques, hits in CASES:
            path = EXAMPLES / filename
            self.assertTrue(path.is_file(), filename)
            rule = sigma.compile_rule(path.read_text())
            self.assertEqual(rule["rule_id"], rule_id)
            self.assertEqual(rule["sigma_id"], sigma_id)
            self.assertNotIn(rule_id, seen)
            seen.add(rule_id)
            self.assertEqual(rule["severity"], severity)
            self.assertEqual(tuple(t["id"] for t in rule["techniques"]), techniques)
            self.assertTrue(rule["logsource"])
            self.assertIn(LOGSOURCE_WARNING, rule["warnings"])
            compiled[rule_id] = rule
            self.assertTrue(hits)

        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        ids = {}
        ids.update(self._ingest(conn, "authlog", "auth-lab", _AUTHLOG))
        ids.update(self._ingest(conn, "weblog", "web-edge", _WEBLOG))
        ids.update(self._ingest(conn, "json", "win-dc", json.dumps([record for _, record in _WINDOWS])))
        ids.update(self._ingest(conn, "json", "cloud-lab", json.dumps([record for _, record in _CLOUD])))
        ids.update(self._ingest(conn, "csv", "fw-csv", _FIREWALL_CSV))

        max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        projected, history, _ = engine.scan_events(conn, [], max_id)
        self.assertEqual(history, [])
        self.assertEqual({e["id"] for e in projected}, set(ids.values()))
        # ssh-port is a Windows logon. The SSH example's logsource says linux; the scan still sees it.
        self.assertEqual(compiled["sigma_successful_privileged_ssh_from_internet"]["logsource"]["product"], "linux")

        for filename, rule_id, sigma_id, severity, techniques, hits in CASES:
            with self.subTest(rule=filename):
                matched = set()
                for finding in sigma.run(projected, compiled[rule_id]["params"]):
                    matched.update(finding["event_ids"])
                labels = {label for label, event_id in ids.items() if event_id in matched}
                self.assertEqual(labels, hits)

    def _ingest(self, conn, fmt, source, text):
        events, rejections = parse_payload(text, fmt, source, year=2026, now=NOW)
        self.assertEqual(rejections, [], rejections)
        labels = [label for label, _ in _BATCHES[fmt if fmt != "json" else source]]
        self.assertEqual(len(events), len(labels), source)
        result = engine.ingest(conn, events, rejections, source, fmt, "tester")
        self.assertEqual(result["detection"]["status"], "ok", result["detection"])
        rows = conn.execute("SELECT id FROM events WHERE batch_id = ? ORDER BY id",
                            (result["batch_id"],)).fetchall()
        self.assertEqual(len(rows), len(labels))
        return {label: row["id"] for label, row in zip(labels, rows)}


_AUTH_LINES = [
    ("ssh-root", "Sep 14 10:00:00 bastion01 sshd[2101]: Accepted password for root from 203.0.113.50 port 50122 ssh2"),
    ("ssh-admin-v6", "Sep 14 10:01:00 bastion01 sshd[2102]: Accepted publickey for admin from 2001:db8::5 port 50122 ssh2"),
    ("ssh-administrator", "Sep 14 10:02:00 bastion01 sshd[2103]: Accepted password for administrator from 198.51.100.74 port 44000 ssh2"),
    ("ssh-internal-10", "Sep 14 10:03:00 bastion01 sshd[2104]: Accepted password for root from 10.1.2.3 port 50122 ssh2"),
    ("ssh-internal-172", "Sep 14 10:04:00 bastion01 sshd[2105]: Accepted password for root from 172.16.4.4 port 50122 ssh2"),
    ("ssh-internal-192", "Sep 14 10:05:00 bastion01 sshd[2106]: Accepted password for root from 192.168.1.9 port 50122 ssh2"),
    ("ssh-loopback", "Sep 14 10:06:00 bastion01 sshd[2107]: Accepted password for root from 127.0.0.1 port 50122 ssh2"),
    ("ssh-ula", "Sep 14 10:07:00 bastion01 sshd[2108]: Accepted password for root from fd00::1 port 50122 ssh2"),
    ("ssh-linklocal", "Sep 14 10:08:00 bastion01 sshd[2109]: Accepted password for root from fe80::1 port 50122 ssh2"),
    ("ssh-localhost-v6", "Sep 14 10:09:00 bastion01 sshd[2110]: Accepted password for root from ::1 port 50122 ssh2"),
    ("ssh-failed", "Sep 14 10:10:00 bastion01 sshd[2111]: Failed password for root from 203.0.113.50 port 50122 ssh2"),
    ("ssh-alice", "Sep 14 10:11:00 bastion01 sshd[2112]: Accepted password for alice from 203.0.113.50 port 50122 ssh2"),
    ("ssh-admin1", "Sep 14 10:12:00 bastion01 sshd[2113]: Accepted password for admin1 from 203.0.113.50 port 50122 ssh2"),
    ("cron-root", "Sep 14 10:15:00 bastion01 CRON[2200]: pam_unix(cron:session): session opened for user root"),
    ("sudo-root", "Sep 14 16:05:00 web01 sudo: frank : TTY=pts/1 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash"),
    ("sudo-postgres", "Sep 14 16:06:00 web01 sudo: frank : TTY=pts/1 ; PWD=/home/frank ; USER=postgres ; COMMAND=/usr/bin/psql"),
    ("sudo-rootkit", "Sep 14 16:07:00 web01 sudo: frank : TTY=pts/1 ; PWD=/tmp ; USER=rootkit ; COMMAND=/bin/id"),
    ("su-root", "Sep 14 16:09:00 web01 su: (to root) frank on /dev/pts/1"),
    ("su-rooty", "Sep 14 16:10:00 web01 su: (to rooty) frank on /dev/pts/1"),
    ("sudo-session", "Sep 14 16:11:00 web01 sudo: pam_unix(sudo:session): session opened for user root by frank(uid=0)"),
    ("file-passwd", 'Sep 14 11:00:00 web01 audit: type=PATH msg=audit(1): name="/etc/passwd" inode=1'),
    ("fw-rdp", "Sep 14 12:30:00 fw01 kernel: [1.0] [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.20 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50000 DPT=3389"),
    ("fw-ssh", "Sep 14 12:31:00 fw01 kernel: [1.1] [UFW ALLOW] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50001 DPT=22"),
    ("fw-vnc", "Sep 14 12:32:00 fw01 kernel: [1.2] [UFW ALLOW] IN=eth0 OUT= SRC=2001:db8::20 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50002 DPT=5900"),
    ("fw-telnet", "Sep 14 12:33:00 fw01 kernel: [1.3] [UFW ALLOW] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50003 DPT=23"),
    ("fw-internal-10", "Sep 14 12:34:00 fw01 kernel: [1.4] [UFW ALLOW] IN=eth0 OUT= SRC=10.8.8.8 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50004 DPT=3389"),
    ("fw-internal-172", "Sep 14 12:35:00 fw01 kernel: [1.5] [UFW ALLOW] IN=eth0 OUT= SRC=172.16.0.4 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50005 DPT=22"),
    ("fw-internal-192", "Sep 14 12:36:00 fw01 kernel: [1.6] [UFW ALLOW] IN=eth0 OUT= SRC=192.168.50.2 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50006 DPT=23"),
    ("fw-ula", "Sep 14 12:37:00 fw01 kernel: [1.7] [UFW ALLOW] IN=eth0 OUT= SRC=fd00::20 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50007 DPT=5900"),
    ("fw-loopback", "Sep 14 12:38:00 fw01 kernel: [1.8] [UFW ALLOW] IN=eth0 OUT= SRC=127.0.0.1 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50008 DPT=22"),
    ("fw-linklocal", "Sep 14 12:39:00 fw01 kernel: [1.9] [UFW ALLOW] IN=eth0 OUT= SRC=fe80::1 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50009 DPT=22"),
    ("fw-localhost-v6", "Sep 14 12:40:00 fw01 kernel: [2.0] [UFW ALLOW] IN=eth0 OUT= SRC=::1 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50010 DPT=22"),
    ("fw-https", "Sep 14 12:41:00 fw01 kernel: [2.1] [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.20 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50011 DPT=443"),
    ("fw-block-rdp", "Sep 14 12:42:00 fw01 kernel: [2.2] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.20 DST=10.0.0.10 LEN=60 PROTO=TCP SPT=50012 DPT=3389"),
]
_AUTHLOG = "\n".join(line for _, line in _AUTH_LINES)

_WEB_LINES = [
    ("trav-passwd", _web("/../../etc/passwd", 400)),
    ("trav-encoded", _web("/..%2f..%2fetc/passwd", 400)),
    ("trav-dots", _web("/%2e%2e%2fetc%2fpasswd", 400)),
    ("trav-winini", _web("/..%5c..%5cwin.ini", 500)),
    ("walk-logo", _web("/static/../../logo.png", 200)),
    ("direct-passwd", _web("/etc/passwd", 404)),
    ("sqli-union", _web("/search?q=1%20UNION%20SELECT%20null", 200)),
    ("sqli-plus", _web("/search?q=1+UNION+SELECT+1", 200)),
    ("sqli-schema", _web("/x?q=information_schema.tables", 500)),
    ("sqli-or", _web("/x?q=1%27+or+1%3d1", 500)),
    ("sqli-benefits", _web("/plans/select-union-benefits", 200)),
    ("sqli-union-word", _web("/search?q=union", 200)),
    ("scan-sqlmap", _web("/", 404, "sqlmap/1.8.5")),
    ("scan-nmap", _web("/", 200, "Mozilla/5.0 (compatible; Nmap Scripting Engine)")),
    ("scan-blog", _web("/blog/nikto-vs-zap", 200, "Mozilla/5.0")),
    ("env-curl", _web("/.env", 404, "curl/8.0")),
    ("git-config", _web("/.git/config", 404)),
    ("wp-login", _web("/wp-login.php", 404)),
    ("env-bak", _web("/app/.env.bak", 200)),
    ("env-query", _web("/.env?debug=1", 404)),
    ("env-environment", _web("/.environment", 200)),
    ("env-file", _web("/blog/.env-file", 200)),
    ("web-login", _web("/login", 200, "Mozilla/5.0")),
]
_WEBLOG = "\n".join(line for _, line in _WEB_LINES)

_WINDOWS = [
    ("lock-admin", _win(4740, "Administrator", "2026-09-14T15:00:00Z", "203.0.113.9",
                        message="A user account was locked out.")),
    ("lock-root", _win(4740, "ROOT", "2026-09-14T15:01:00Z", "203.0.113.9",
                       message="A user account was locked out.")),
    ("lock-jsmith", _win(4740, "jsmith", "2026-09-14T15:02:00Z", "203.0.113.9",
                         message="A user account was locked out.")),
    ("lock-admin1", _win(4740, "admin1", "2026-09-14T15:03:00Z", "203.0.113.9",
                         message="A user account was locked out.")),
    ("fail-admin", _win(4625, "administrator", "2026-09-14T15:04:00Z", "203.0.113.9",
                        message="An account failed to log on.")),
    # Port 22 is stored from structured Windows JSON. auth.log does not record the server port.
    ("ssh-port", _win(4624, "Administrator", "2026-09-14T15:05:00Z", "198.51.100.8", 22,
                      "An account was successfully logged on.")),
    ("ssh-noport", _win(4624, "Administrator", "2026-09-14T15:06:00Z", "203.0.113.50",
                        message="An account was successfully logged on.")),
    ("ssh-https", _win(4624, "root", "2026-09-14T15:07:00Z", "203.0.113.50", 443,
                       "console login")),
    ("ssh-nosrc", _win(4624, "root", "2026-09-14T15:08:00Z", dest_port=22,
                       message="Accepted password for root port 22 ssh2")),
    ("win-jsmith", _win(4624, "jsmith", "2026-09-14T15:09:00Z", "198.51.100.60",
                        message="An account was successfully logged on.")),
]

_CLOUD = [
    ("iam-user", _trail("CreateUser", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:00:00Z")),
    ("iam-key", _trail("CreateAccessKey", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:01:00Z")),
    ("iam-user-denied", _trail("CreateUser", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:02:00Z", "AccessDenied")),
    ("iam-key-denied", _trail("CreateAccessKey", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:03:00Z", "AccessDenied")),
    ("iam-attach", _trail("AttachUserPolicy", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:04:00Z")),
    ("iam-login", _trail("CreateLoginProfile", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:05:00Z")),
    ("iam-delete", _trail("DeleteUser", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:06:00Z")),
    ("iam-put-policy", _trail("PutUserPolicy", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:07:00Z")),
    ("iam-get", _trail("GetUser", "iam.amazonaws.com", "ops-admin", "10.0.1.30", "2026-09-14T17:08:00Z")),
    ("iam-extra", _trail("CreateUserExtra", "iam.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T17:09:00Z")),
    ("audit-stop", _trail("StopLogging", "cloudtrail.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:00:00Z")),
    ("audit-delete", _trail("DeleteTrail", "cloudtrail.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:01:00Z")),
    ("audit-flow", _trail("DeleteFlowLogs", "ec2.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:02:00Z")),
    ("audit-config", _trail("StopConfigurationRecorder", "config.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:03:00Z")),
    ("audit-delete-denied", _trail("DeleteTrail", "cloudtrail.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:04:00Z", "AccessDenied")),
    ("audit-stop-denied", _trail("StopLogging", "cloudtrail.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:05:00Z", "AccessDenied")),
    ("audit-describe", _trail("DescribeTrails", "cloudtrail.amazonaws.com", "ops-admin", "10.0.1.30", "2026-09-14T18:06:00Z")),
    ("audit-update", _trail("UpdateTrail", "cloudtrail.amazonaws.com", "ops-admin", "203.0.113.40", "2026-09-14T18:07:00Z")),
    ("cloud-describe", _trail("DescribeInstances", "ec2.amazonaws.com", "ops-admin", "10.0.1.30", "2026-09-14T09:00:00Z")),
    ("cloud-object", _trail("GetObject", "s3.amazonaws.com", "svc-deploy-tmp", "203.0.113.150", "2026-09-14T18:08:00Z")),
]

_FIREWALL_CSV = """timestamp,action,src_ip,dest_ip,dest_port,proto,bytes,host,message
2026-09-14T12:50:00Z,allow,,10.0.0.10,22,tcp,60,fw01,allow with no source address
"""
_CSV_LINES = [("fw-nosrc", _FIREWALL_CSV)]

# json batches are keyed by source so Windows and CloudTrail stay separate.
_BATCHES = {
    "authlog": _AUTH_LINES,
    "weblog": _WEB_LINES,
    "win-dc": _WINDOWS,
    "cloud-lab": _CLOUD,
    "csv": _CSV_LINES,
}
