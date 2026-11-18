"""Example Sigma rules load, then match their events and reject look-alikes."""

import unittest
from pathlib import Path

from watchpost import sigma

EXAMPLES = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples"

SUDO_ROOT = "frank : TTY=pts/1 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash"
SUDO_DB = "frank : TTY=pts/1 ; PWD=/home/frank ; USER=postgres ; COMMAND=/usr/bin/psql"
SUDO_KIT = "frank : TTY=pts/1 ; PWD=/tmp ; USER=rootkit ; COMMAND=/bin/id"

# filename, rule id, severity, techniques, hits, misses.
CASES = [
    (
        "successful_privileged_ssh_from_internet.yml",
        "sigma_successful_privileged_ssh_from_internet",
        "high",
        ("T1133", "T1078.003"),
        [
            {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.50"},
            {"event_type": "auth_success", "user": "Administrator",
             "src_ip": "198.51.100.8", "dest_port": 22},
            {"event_type": "auth_success", "user": "admin", "src_ip": "2001:db8::5"},
            {"event_type": "auth_success", "user": "root", "src_ip": "172.32.4.4"},
        ],
        [
            {"event_type": "auth_success", "user": "root", "src_ip": "10.1.2.3"},
            {"event_type": "auth_success", "user": "root", "src_ip": "172.16.4.4"},
            {"event_type": "auth_success", "user": "root", "src_ip": "192.168.1.9"},
            {"event_type": "auth_success", "user": "root", "src_ip": "127.0.0.1"},
            {"event_type": "auth_success", "user": "root", "src_ip": "fd00::1"},
            {"event_type": "auth_success", "user": "root", "src_ip": "fe80::1"},
            {"event_type": "auth_success", "user": "root", "src_ip": "::1"},
            {"event_type": "auth_success", "user": "root"},
            {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.50"},
            {"event_type": "auth_success", "user": "alice", "src_ip": "203.0.113.50"},
            {"event_type": "auth_success", "user": "admin1", "src_ip": "203.0.113.50"},
            {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.50",
             "dest_port": 443},
        ],
    ),
    (
        "privileged_account_lockout.yml",
        "sigma_privileged_account_lockout",
        "medium",
        ("T1110.001",),
        [
            {"event_type": "account_lockout", "user": "administrator"},
            {"event_type": "account_lockout", "user": "ROOT", "src_ip": "203.0.113.9"},
        ],
        [
            {"event_type": "account_lockout", "user": "jsmith"},
            {"event_type": "account_lockout", "user": "admin1"},
            {"event_type": "auth_failure", "user": "administrator",
             "src_ip": "203.0.113.9"},
        ],
    ),
    (
        "sudo_or_su_to_root.yml",
        "sigma_sudo_or_su_to_root",
        "high",
        ("T1548.003",),
        [
            {"event_type": "privilege_escalation", "user": "frank",
             "message": SUDO_ROOT},
            {"event_type": "privilege_escalation", "user": "frank",
             "message": "(to root) frank on /dev/pts/1"},
        ],
        [
            {"event_type": "privilege_escalation", "user": "frank", "message": SUDO_DB},
            {"event_type": "privilege_escalation", "user": "frank",
             "message": SUDO_KIT},
            {"event_type": "privilege_use", "user": "root",
             "message": "pam_unix(sudo:session): session opened for user root"},
            {"event_type": "privilege_escalation", "user": "frank",
             "message": "(to rooty) frank on /dev/pts/1"},
        ],
    ),
    (
        "web_path_traversal.yml",
        "sigma_web_request_path_traversal",
        "high",
        ("T1190",),
        [
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /../../etc/passwd -> 400"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /..%2f..%2fetc/passwd -> 400"},
            {"event_type": "web_request", "src_ip": "203.0.113.80",
             "message": "GET /%2e%2e%2fetc%2fpasswd -> 400"},
            {"event_type": "web_error", "src_ip": "203.0.113.80",
             "message": "GET /..%5c..%5cwin.ini -> 500"},
        ],
        [
            {"event_type": "web_request",
             "message": "GET /docs/etc/passwd-rotation -> 200"},
            {"event_type": "web_request",
             "message": "GET /static/../../logo.png -> 200"},
            {"event_type": "web_scan", "message": "GET /etc/passwd -> 404"},
            {"event_type": "file_access", "message": "name=\"/etc/passwd\""},
        ],
    ),
    (
        "web_sql_injection.yml",
        "sigma_web_request_sql_injection",
        "high",
        ("T1190",),
        [
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /search?q=1%20UNION%20SELECT%20password -> 200"},
            {"event_type": "web_request", "src_ip": "203.0.113.80",
             "message": "GET /search?q=1+UNION+SELECT+1 -> 200"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /x?q=information_schema.tables -> 500"},
            {"event_type": "web_error", "src_ip": "203.0.113.80",
             "message": "GET /x?q=1%27+or+1%3d1 -> 500"},
        ],
        [
            {"event_type": "web_request",
             "message": "GET /plans/select-union-benefits -> 200"},
            {"event_type": "web_request", "message": "GET /search?q=union -> 200"},
            {"event_type": "file_access", "message": "union select password"},
        ],
    ),
    (
        "web_scanner_user_agent.yml",
        "sigma_web_scanner_user_agent",
        "medium",
        ("T1595.002",),
        [
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET / -> 404 ua=sqlmap/1.8.5"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET / -> 200 ua=Mozilla/5.0 "
             "(compatible; Nmap Scripting Engine)"},
            {"event_type": "web_request", "src_ip": "203.0.113.80",
             "message": "sqlmap/1.7"},
        ],
        [
            {"event_type": "web_request", "src_ip": "203.0.113.80",
             "message": "GET /blog/nikto-vs-zap -> 200 ua=Mozilla/5.0"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /.env -> 404 ua=curl/8.0"},
            {"event_type": "auth_success", "message": "ua=sqlmap/1.8.5"},
        ],
    ),
    (
        "web_sensitive_path_probe.yml",
        "sigma_web_sensitive_path_probe",
        "medium",
        ("T1595.003",),
        [
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /.env -> 404"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /.git/config -> 404"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /wp-login.php -> 404"},
            {"event_type": "web_request", "src_ip": "203.0.113.80",
             "message": "GET /app/.env.bak -> 200"},
            {"event_type": "web_scan", "src_ip": "203.0.113.80",
             "message": "GET /.env?AWS_SECRET=1 -> 404"},
        ],
        [
            {"event_type": "web_request", "message": "GET /.environment -> 200"},
            {"event_type": "web_request", "message": "GET /login -> 200"},
            {"event_type": "web_request", "message": "GET /blog/.env-file -> 200"},
            {"event_type": "file_access", "message": "name=\"/.env\""},
        ],
    ),
    (
        "remote_admin_allowed_from_internet.yml",
        "sigma_remote_admin_port_allowed_from_internet",
        "high",
        ("T1133",),
        [
            {"event_type": "fw_allow", "src_ip": "198.51.100.20", "dest_port": 3389},
            {"event_type": "fw_allow", "src_ip": "203.0.113.9", "dest_port": 22},
            {"event_type": "fw_allow", "src_ip": "2001:db8::20", "dest_port": 5900},
            {"event_type": "fw_allow", "src_ip": "203.0.113.9", "dest_port": "23"},
        ],
        [
            {"event_type": "fw_allow", "src_ip": "10.8.8.8", "dest_port": 3389},
            {"event_type": "fw_allow", "src_ip": "172.16.0.4", "dest_port": 22},
            {"event_type": "fw_allow", "src_ip": "192.168.50.2", "dest_port": 23},
            {"event_type": "fw_allow", "src_ip": "fd00::20", "dest_port": 5900},
            {"event_type": "fw_allow", "src_ip": "127.0.0.1", "dest_port": 22},
            {"event_type": "fw_allow", "src_ip": "fe80::1", "dest_port": 22},
            {"event_type": "fw_allow", "src_ip": "::1", "dest_port": 22},
            {"event_type": "fw_allow", "src_ip": "198.51.100.20", "dest_port": 443},
            {"event_type": "fw_deny", "src_ip": "198.51.100.20", "dest_port": 3389},
            {"event_type": "fw_allow", "dest_port": 22},
        ],
    ),
    (
        "cloud_iam_user_or_key_created.yml",
        "sigma_cloud_iam_user_or_access_key_created",
        "high",
        ("T1136.003", "T1098.001"),
        [
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp",
             "message": "CreateAccessKey on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp",
             "message": "CreateUser on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp",
             "message": "AttachUserPolicy on iam.amazonaws.com (AccessDenied)"},
        ],
        [
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp",
             "message": "DeleteUser on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp",
             "message": "CreateUserExtra on iam.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "svc-deploy-tmp",
             "message": "GetUser on iam.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "svc-deploy-tmp",
             "message": "CreateUser on iam.amazonaws.com"},
        ],
    ),
    (
        "cloud_audit_logging_stopped.yml",
        "sigma_cloud_audit_logging_stopped",
        "critical",
        ("T1562.008",),
        [
            {"event_type": "cloud_api_call", "user": "ops-admin",
             "message": "StopLogging on cloudtrail.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "ops-admin",
             "message": "DeleteTrail on cloudtrail.amazonaws.com (AccessDenied)"},
            {"event_type": "cloud_api_call", "user": "ops-admin",
             "message": "DeleteFlowLogs on ec2.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "ops-admin",
             "message": "StopConfigurationRecorder on config.amazonaws.com"},
        ],
        [
            {"event_type": "cloud_api_call", "user": "ops-admin",
             "message": "DescribeTrails on cloudtrail.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "ops-admin",
             "message": "UpdateTrail on cloudtrail.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "ops-admin",
             "message": "StopLogging on cloudtrail.amazonaws.com"},
        ],
    ),
]


class SigmaExampleTests(unittest.TestCase):
    def test_each_example_loads_and_matches(self):
        self.assertEqual(len(CASES), 10)
        seen = set()
        for filename, rule_id, severity, techniques, hits, misses in CASES:
            with self.subTest(rule=filename):
                path = EXAMPLES / filename
                self.assertTrue(path.is_file(), filename)
                compiled = sigma.compile_rule(path.read_text())
                self.assertEqual(compiled["rule_id"], rule_id)
                self.assertNotIn(rule_id, seen)
                seen.add(rule_id)
                self.assertEqual(compiled["severity"], severity)
                found = tuple(t["id"] for t in compiled["techniques"])
                self.assertEqual(found, techniques)
                params = compiled["params"]
                for event in hits:
                    self.assertTrue(sigma.matches(params, event), event)
                for event in misses:
                    self.assertFalse(sigma.matches(params, event), event)
