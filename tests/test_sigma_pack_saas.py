"""SaaS Sigma examples: each rule loads, maps one catalog technique, matches an attack, and ignores a look-alike."""

import unittest
from pathlib import Path

from watchpost import sigma

EXAMPLES = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples"
PACK = EXAMPLES / "saas"

# filename, technique, events that must match, look-alikes that must not
CASES = (
    (
        "admin_signin_from_public_address.yml",
        "T1078.004",
        (
            {"event_type": "auth_success", "user": "alice", "src_ip": "203.0.113.10",
             "message": "UserLoggedIn to Microsoft 365 admin center"},
            {"event_type": "auth_success", "user": "alice", "src_ip": "203.0.113.10",
             "message": "user.session.start Okta Admin Console"},
        ),
        (
            {"event_type": "auth_success", "user": "alice", "src_ip": "10.8.0.4",
             "message": "UserLoggedIn to Microsoft 365 admin center"},
            {"event_type": "auth_success", "user": "bob", "src_ip": "203.0.113.10",
             "message": "UserLoggedIn to Outlook Web"},
            {"event_type": "auth_failure", "user": "alice", "src_ip": "203.0.113.10",
             "message": "UserLoginFailed to Microsoft 365 admin center"},
        ),
    ),
    (
        "idp_password_spray_alert.yml",
        "T1110.003",
        (
            {"event_type": "auth_failure", "src_ip": "198.51.100.8",
             "message": "Azure AD Identity Protection riskEventType=passwordSpray user=alice"},
            {"event_type": "other", "src_ip": "198.51.100.8",
             "message": "Okta ThreatInsight security.threat.detected password spray against 40 accounts"},
        ),
        (
            {"event_type": "auth_failure", "user": "alice", "src_ip": "198.51.100.8",
             "message": "Invalid username or password"},
            {"event_type": "other", "message": "ticket: possible password spray, no product named"},
            {"event_type": "other", "message": "Identity Protection user risk: unfamiliar sign-in features"},
        ),
    ),
    (
        "oauth_credential_created.yml",
        "T1098.001",
        (
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "CreateAccessKey on iam.amazonaws.com"},
            {"event_type": "other", "user": "octocat", "src_ip": "203.0.113.40",
             "message": "action oauth_authorization.create repo=acme/app"},
        ),
        (
            {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "10.0.1.30",
             "message": "ListAccessKeys on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "CreateUser on iam.amazonaws.com"},
            {"event_type": "other", "message": "reviewed the oauth_authorization policy for the GitHub org"},
        ),
    ),
    (
        "cloud_account_created_externally.yml",
        "T1136.003",
        (
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "CreateUser on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "okta-admin", "src_ip": "203.0.113.44",
             "message": "user.lifecycle.create target=guest@example.com"},
        ),
        (
            {"event_type": "cloud_iam_change", "user": "ops-admin", "src_ip": "172.16.4.4",
             "message": "CreateUser on iam.amazonaws.com"},
            {"event_type": "cloud_iam_change", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "AttachUserPolicy on iam.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "CreateUser on iam.amazonaws.com"},
        ),
    ),
    (
        "audit_logging_disabled.yml",
        "T1562.008",
        (
            {"event_type": "cloud_api_call", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "StopLogging on cloudtrail.amazonaws.com"},
            {"event_type": "other", "user": "m365-admin", "src_ip": "203.0.113.15",
             "message": "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false"},
        ),
        (
            {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "10.0.1.30",
             "message": "StartLogging on cloudtrail.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "ops-admin", "src_ip": "10.0.1.30",
             "message": "DescribeTrails on cloudtrail.amazonaws.com"},
            {"event_type": "other", "user": "m365-admin",
             "message": "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true"},
        ),
    ),
    (
        "cloud_storage_download_from_public.yml",
        "T1530",
        (
            {"event_type": "cloud_data_access", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "GetObject on s3.amazonaws.com"},
            {"event_type": "cloud_data_access", "user": "alice", "src_ip": "198.51.100.20",
             "message": "FileDownloaded site=contoso.sharepoint.com"},
        ),
        (
            {"event_type": "cloud_data_access", "user": "analytics", "src_ip": "192.168.1.20",
             "message": "GetObject on s3.amazonaws.com"},
            {"event_type": "cloud_data_access", "user": "analytics", "src_ip": "127.0.0.1",
             "message": "GetObject on s3.amazonaws.com"},
            {"event_type": "cloud_api_call", "user": "svc-deploy-tmp", "src_ip": "203.0.113.150",
             "message": "ListBuckets on s3.amazonaws.com"},
        ),
    ),
)


def _header(path, key):
    prefix = key + ": "
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip().strip("'\"").strip()
    return None


class SaasSigmaPackTests(unittest.TestCase):
    def test_each_rule_loads_matches_and_ignores_a_lookalike(self):
        names = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(names, sorted(case[0] for case in CASES))
        seen = set()
        for name, technique, hits, misses in CASES:
            with self.subTest(rule=name):
                compiled = sigma.compile_rule((PACK / name).read_text(encoding="utf-8"))
                self.assertEqual([t["id"] for t in compiled["techniques"]], [technique])
                self.assertNotIn(compiled["rule_id"], seen)
                seen.add(compiled["rule_id"])
                self.assertTrue(compiled["rule_id"].startswith("sigma_"))
                for event in hits:
                    self.assertTrue(sigma.matches(compiled["params"], event), event.get("message"))
                for event in misses:
                    self.assertFalse(sigma.matches(compiled["params"], event), event.get("message"))

    def test_titles_and_ids_do_not_collide(self):
        """Pack titles, Sigma ids, and compiled rule ids stay unique against other example rules."""
        ours = {}
        for name, _, _, _ in CASES:
            path = PACK / name
            title, sid = _header(path, "title"), _header(path, "id")
            self.assertTrue(title and sid)
            compiled = sigma.compile_rule(path.read_text(encoding="utf-8"))
            self.assertEqual(compiled["title"], title)
            self.assertEqual(compiled["sigma_id"], sid)
            ours[path] = (title, sid, compiled["rule_id"])
        self.assertEqual(len({t for t, _, _ in ours.values()}), 6)
        self.assertEqual(len({i for _, i, _ in ours.values()}), 6)
        self.assertEqual(len({r for _, _, r in ours.values()}), 6)

        for path in sorted(EXAMPLES.rglob("*.yml")):
            if path in ours or path.parent == PACK:
                continue
            title, sid = _header(path, "title"), _header(path, "id")
            if not title or not sid:
                continue
            for our_title, our_id, our_rule in ours.values():
                self.assertNotEqual(title, our_title, path.name)
                self.assertNotEqual(sid, our_id, path.name)
            try:
                other = sigma.compile_rule(path.read_text(encoding="utf-8"))
            except sigma.SigmaError:
                continue
            for _, _, our_rule in ours.values():
                self.assertNotEqual(other["rule_id"], our_rule, path.name)
