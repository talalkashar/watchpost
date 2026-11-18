"""Cloud Sigma examples load, map one catalog technique, and stay quiet on a look-alike."""

import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "cloud"


def _event(message, event_type="cloud_api_call", user="alice", src_ip="203.0.113.10"):
    event = {"event_type": event_type, "user": user, "message": message}
    if src_ip is not None:
        event["src_ip"] = src_ip
    return event


# Each rule lists every action it claims, and the near-miss that must not fire.
CASES = [
    {
        "file": "cloud_console_login_external.yml",
        "technique": "T1078.004",
        "level": "high",
        "malicious": [
            _event("ConsoleLogin on signin.amazonaws.com"),
            _event("ConsoleLogin on signin.amazonaws.com", src_ip="2001:db8::10"),
        ],
        "benign": [
            _event("ConsoleLogin on signin.amazonaws.com", src_ip="10.0.1.30"),
            _event("ConsoleLogin on signin.amazonaws.com", src_ip="172.31.5.5"),
            _event("ConsoleLogin on signin.amazonaws.com", src_ip="192.168.1.9"),
            _event("ConsoleLogin on signin.amazonaws.com", src_ip="127.0.0.1"),
            _event("ConsoleLogin on signin.amazonaws.com", src_ip="169.254.169.254"),
            _event("ConsoleLogin on signin.amazonaws.com", src_ip=None),
            _event("ConsoleLogin on signin.amazonaws.com (Failed authentication)"),
        ],
    },
    {
        "file": "cloud_credential_added.yml",
        "technique": "T1098.001",
        "level": "high",
        "malicious": [
            _event("CreateAccessKey on iam.amazonaws.com", "cloud_iam_change"),
            _event("CreateLoginProfile on iam.amazonaws.com", "cloud_iam_change"),
            _event(
                "CreateServiceSpecificCredential on iam.amazonaws.com",
                "cloud_iam_change",
            ),
            _event("UploadSigningCertificate on iam.amazonaws.com", "cloud_iam_change"),
            _event("UploadSSHPublicKey on iam.amazonaws.com", "cloud_iam_change"),
            _event(
                "CreateAccessKey on iam.amazonaws.com (AccessDenied)",
                "cloud_iam_change",
            ),
        ],
        "benign": [
            _event("DeleteAccessKey on iam.amazonaws.com", "cloud_iam_change"),
            _event("UpdateLoginProfile on iam.amazonaws.com", "cloud_iam_change"),
            _event("UpdateAccessKey on iam.amazonaws.com", "cloud_iam_change"),
            _event("CreateAccessKey on iam.amazonaws.com", "cloud_api_call"),
        ],
    },
    {
        "file": "cloud_account_created.yml",
        "technique": "T1136.003",
        "level": "high",
        "malicious": [
            _event("CreateUser on iam.amazonaws.com", "cloud_iam_change"),
            _event(
                "CreateUser on iam.amazonaws.com (EntityAlreadyExists)",
                "cloud_iam_change",
            ),
            _event("CreateAccount on organizations.amazonaws.com"),
            _event("CreateGovCloudAccount on organizations.amazonaws.com"),
        ],
        "benign": [
            _event("DeleteUser on iam.amazonaws.com", "cloud_iam_change"),
            _event("CreateUser on iam.amazonaws.com", "cloud_api_call"),
            _event("CreateAccount on organizations.amazonaws.com", "cloud_iam_change"),
            _event("CreateAccessKey on iam.amazonaws.com", "cloud_iam_change"),
        ],
    },
    {
        "file": "cloud_logging_disabled.yml",
        "technique": "T1562.008",
        "level": "high",
        "malicious": [
            _event("StopLogging on cloudtrail.amazonaws.com"),
            _event("StopLogging on cloudtrail.amazonaws.com (AccessDenied)"),
            _event("DeleteTrail on cloudtrail.amazonaws.com"),
            _event("DeleteFlowLogs on ec2.amazonaws.com"),
            _event("StopConfigurationRecorder on config.amazonaws.com"),
            _event("DeleteDeliveryChannel on config.amazonaws.com"),
            _event("DeleteLogGroup on logs.amazonaws.com"),
        ],
        "benign": [
            _event("StartLogging on cloudtrail.amazonaws.com"),
            _event("CreateTrail on cloudtrail.amazonaws.com"),
            _event("UpdateTrail on cloudtrail.amazonaws.com"),
            _event("PutEventSelectors on cloudtrail.amazonaws.com"),
            _event("StopLogging on cloudtrail.amazonaws.com", "cloud_iam_change"),
        ],
    },
    {
        "file": "cloud_storage_read_external.yml",
        "technique": "T1530",
        "level": "medium",
        "malicious": [
            _event("GetObject on s3.amazonaws.com", "cloud_data_access"),
            _event("SelectObjectContent on s3.amazonaws.com", "cloud_data_access"),
            _event(
                "CopyObject on s3.amazonaws.com",
                "cloud_data_access",
                src_ip="198.51.100.8",
            ),
        ],
        "benign": [
            _event(
                "GetObject on s3.amazonaws.com",
                "cloud_data_access",
                src_ip="10.0.1.30",
            ),
            _event("GetObject on s3.amazonaws.com", "cloud_data_access", src_ip=None),
            _event(
                "GetObject on s3.amazonaws.com (AccessDenied)",
                "cloud_data_access",
            ),
            _event(
                "GetSecretValue on secretsmanager.amazonaws.com",
                "cloud_data_access",
            ),
            _event("ListBuckets on s3.amazonaws.com"),
        ],
    },
    {
        "file": "cloud_threat_detection_disabled.yml",
        "technique": "T1562.006",
        "level": "high",
        "malicious": [
            _event("DeleteDetector on guardduty.amazonaws.com"),
            _event("DeleteMembers on guardduty.amazonaws.com"),
            _event("StopMonitoringMembers on guardduty.amazonaws.com"),
            _event("DeletePublishingDestination on guardduty.amazonaws.com"),
            _event("DisassociateFromMasterAccount on guardduty.amazonaws.com"),
            _event("DisassociateFromAdministratorAccount on guardduty.amazonaws.com"),
            _event("DisassociateMembers on guardduty.amazonaws.com"),
            _event("DisableSecurityHub on securityhub.amazonaws.com"),
            _event("DeleteMembers on securityhub.amazonaws.com"),
            _event("DisassociateFromAdministratorAccount on securityhub.amazonaws.com"),
            _event("DeleteDetector on guardduty.amazonaws.com (AccessDenied)"),
        ],
        "benign": [
            _event("CreateDetector on guardduty.amazonaws.com"),
            _event("EnableSecurityHub on securityhub.amazonaws.com"),
            _event("UpdateDetector on guardduty.amazonaws.com"),
            _event("GetDetector on guardduty.amazonaws.com"),
        ],
    },
    {
        "file": "cloud_console_login_failure.yml",
        "technique": "T1110.001",
        "level": "medium",
        "malicious": [
            _event("ConsoleLogin on signin.amazonaws.com (Failed authentication)"),
            _event("ConsoleLogin on signin.amazonaws.com (SigninFailure)"),
            _event(
                "ConsoleLogin on signin.amazonaws.com (Failed authentication)",
                src_ip="10.0.1.30",
            ),
        ],
        "benign": [
            _event("ConsoleLogin on signin.amazonaws.com"),
            _event("DescribeInstances on ec2.amazonaws.com (AccessDenied)"),
            _event(
                "ConsoleLogin on signin.amazonaws.com (Failed authentication)",
                "auth_failure",
            ),
        ],
    },
    {
        "file": "cloud_root_account_activity.yml",
        "technique": "T1078.004",
        "level": "high",
        "malicious": [
            _event(
                "DescribeInstances on ec2.amazonaws.com",
                user="root",
                src_ip="10.0.1.30",
            ),
            _event(
                "CreateAccessKey on iam.amazonaws.com",
                "cloud_iam_change",
                user="Root",
            ),
            _event(
                "GetObject on s3.amazonaws.com",
                "cloud_data_access",
                user="root",
            ),
        ],
        "benign": [
            _event(
                "CreateAccessKey on iam.amazonaws.com",
                "cloud_iam_change",
                user="ops-admin",
            ),
            _event(
                "Failed password for root",
                "auth_failure",
                user="root",
            ),
            _event("DescribeInstances on ec2.amazonaws.com", user="root-backup"),
        ],
    },
]


class CloudSigmaPackTests(unittest.TestCase):
    def test_each_rule_loads_matches_and_ignores_benign(self):
        found = sorted(path.name for path in PACK.glob("*.yml"))
        self.assertEqual(found, sorted(case["file"] for case in CASES))
        self.assertEqual(len(found), 8)
        seen = set()
        for case in CASES:
            with self.subTest(rule=case["file"]):
                compiled = sigma.compile_rule((PACK / case["file"]).read_text())
                self.assertEqual(compiled["level"], case["level"])
                self.assertEqual(
                    [item["id"] for item in compiled["techniques"]],
                    [case["technique"]],
                )
                self.assertTrue(compiled["rule_id"].startswith("sigma_"))
                self.assertNotIn(compiled["rule_id"], seen)
                seen.add(compiled["rule_id"])
                params = compiled["params"]
                for event in case["malicious"]:
                    self.assertTrue(sigma.matches(params, event), event)
                for event in case["benign"]:
                    self.assertFalse(sigma.matches(params, event), event)


if __name__ == "__main__":
    unittest.main()
