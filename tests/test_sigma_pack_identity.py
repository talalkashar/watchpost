"""Identity Sigma pack: each rule loads, maps one catalog technique, fires, and stays quiet on a look-alike."""

import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "identity"

# Messages follow the text Watchpost stores: sshd/sudo/su lines, and "<action> on <service>" for CloudTrail.
CASES = (
    {
        "file": "privileged_ssh_success_external.yml",
        "rule_id": "sigma_privileged_ssh_success_from_external_address",
        "technique": "T1078.003",
        "severity": "high",
        "malicious": {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.5", "dest_port": 22,
                      "message": "Accepted password for root from 203.0.113.5 port 51022 ssh2"},
        "benign": (
            {"event_type": "auth_success", "user": "root", "src_ip": "10.0.1.24", "dest_port": 22,
             "message": "Accepted password for root from 10.0.1.24 port 51022 ssh2"},
            {"event_type": "auth_success", "user": "grace", "src_ip": "203.0.113.5", "dest_port": 22,
             "message": "Accepted publickey for grace from 203.0.113.5 port 50100 ssh2"},
            {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.5", "dest_port": 22,
             "message": "Failed password for root from 203.0.113.5 port 40100 ssh2"},
        ),
    },
    {
        "file": "privileged_vpn_login_external.yml",
        "rule_id": "sigma_privileged_vpn_login_from_external_address",
        "technique": "T1133",
        "severity": "high",
        "malicious": {"event_type": "vpn_login", "user": "administrator", "src_ip": "203.0.113.9",
                      "message": "203.0.113.9:51234 [administrator] Peer Connection Initiated with [AF_INET]203.0.113.9:51234"},
        "benign": (
            {"event_type": "vpn_login", "user": "administrator", "src_ip": "10.0.1.5",
             "message": "10.0.1.5:51234 [administrator] Peer Connection Initiated with [AF_INET]10.0.1.5:51234"},
            {"event_type": "vpn_login", "user": "erin", "src_ip": "203.0.113.150",
             "message": "203.0.113.150:51234 [erin] Peer Connection Initiated with [AF_INET]203.0.113.150:51234"},
        ),
    },
    {
        "file": "cloud_credential_created_external.yml",
        "rule_id": "sigma_cloud_credential_created_from_external_address",
        "technique": "T1098.001",
        "severity": "critical",
        "malicious": {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
                      "message": "CreateAccessKey on iam.amazonaws.com"},
        "also": (
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "198.51.100.8",
             "message": "CreateLoginProfile on iam.amazonaws.com"},
        ),
        "benign": (
            {"event_type": "cloud_iam_change", "user": "ops-admin", "src_ip": "10.0.1.30",
             "message": "CreateAccessKey on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "CreateUser on iam.amazonaws.com"},
        ),
    },
    {
        "file": "cloud_user_created_external.yml",
        "rule_id": "sigma_cloud_user_created_from_external_address",
        "technique": "T1136.003",
        "severity": "high",
        "malicious": {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
                      "message": "CreateUser on iam.amazonaws.com"},
        "benign": (
            {"event_type": "cloud_iam_change", "user": "ops-admin", "src_ip": "10.0.1.30",
             "message": "CreateUser on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "CreateAccessKey on iam.amazonaws.com"},
        ),
    },
    {
        "file": "interactive_root_shell.yml",
        "rule_id": "sigma_interactive_root_shell_via_sudo_or_su",
        "technique": "T1548.003",
        "severity": "high",
        "malicious": {"event_type": "privilege_escalation", "user": "frank", "host": "web01",
                      "message": "frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash"},
        "also": (
            {"event_type": "privilege_escalation", "user": "frank", "host": "web01",
             "message": "(to root) frank on pts/0"},
            {"event_type": "privilege_escalation", "user": "frank", "host": "web01",
             "message": "frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/sh -c id"},
        ),
        "benign": (
            {"event_type": "privilege_escalation", "user": "grace", "host": "web01",
             "message": "grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"},
            {"event_type": "privilege_escalation", "user": "grace", "host": "web01",
             "message": "grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; COMMAND=/bin/shutdown -h now"},
            {"event_type": "privilege_escalation", "user": "grace", "host": "web01",
             "message": "(to postgres) grace on pts/0"},
        ),
    },
    {
        "file": "external_cloud_console_or_role.yml",
        "rule_id": "sigma_external_cloud_console_or_role_assumption",
        "technique": "T1078.004",
        "severity": "medium",
        "malicious": {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "203.0.113.40",
                      "message": "ConsoleLogin on signin.amazonaws.com"},
        "also": (
            {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "198.51.100.20",
             "message": "AssumeRoleWithSAML on sts.amazonaws.com"},
        ),
        "benign": (
            {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "203.0.113.40",
             "message": "DescribeInstances on ec2.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "10.0.1.30",
             "message": "ConsoleLogin on signin.amazonaws.com"},
        ),
    },
)


def _stamp(event, n):
    return {"id": n, "ts": "2026-11-18T12:00:00+00:00", **event}


class IdentityPackTests(unittest.TestCase):
    def test_pack_is_six_rules(self):
        names = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(names, sorted(case["file"] for case in CASES))

    def test_each_rule_loads_matches_and_ignores_benign(self):
        self.assertEqual(len(CASES), 6)
        for n, case in enumerate(CASES):
            with self.subTest(rule=case["file"]):
                compiled = sigma.compile_rule((PACK / case["file"]).read_text())
                self.assertEqual(compiled["rule_id"], case["rule_id"])
                self.assertEqual(compiled["severity"], case["severity"])
                self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])
                params = compiled["params"]
                malicious = _stamp(case["malicious"], n)
                self.assertTrue(sigma.matches(params, malicious))
                self.assertEqual(len(sigma.run([malicious], params)), 1)
                for extra in case.get("also", ()):
                    self.assertTrue(sigma.matches(params, extra), extra["message"])
                for benign in case["benign"]:
                    self.assertFalse(sigma.matches(params, benign), benign.get("message"))
                    self.assertEqual(sigma.run([_stamp(benign, n)], params), [])


if __name__ == "__main__":
    unittest.main()
