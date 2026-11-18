"""Azure Sigma examples: each rule loads, matches a hostile event, and stays quiet on a look-alike."""

import unittest
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "azure"
TAKEN_TITLE = "Failed Admin Login From External Source"
TAKEN_ID = "5d2c1a6e-8f3b-4c1e-9a77-0e4b2f6d9c10"


def _event(event_type, message, user="alice", src_ip="203.0.113.10"):
    return {"event_type": event_type, "user": user, "src_ip": src_ip, "message": message}


CASES = (
    {
        "file": "diagnostic_setting_deleted.yml",
        "rule_id": "sigma_azure_diagnostic_setting_deleted",
        "sigma_id": "c4a1e7b2-6d58-4f90-9c13-2b8e5a7d04f6",
        "technique": "T1562.008",
        "severity": "high",
        "hits": (
            _event("cloud_api_call", "Microsoft.Insights/diagnosticSettings/delete on insights.azure.com"),
            _event("cloud_iam_change", "Microsoft.Insights/logProfiles/delete on insights.azure.com"),
            _event("cloud_api_call", "Microsoft.Insights/activityLogAlerts/delete on insights.azure.com"),
        ),
        "miss": _event("cloud_api_call", "Microsoft.Insights/diagnosticSettings/write on insights.azure.com"),
    },
    {
        "file": "service_principal_credential_added.yml",
        "rule_id": "sigma_azure_ad_service_principal_credential_added",
        "sigma_id": "8e2b6d41-1c73-4a95-b0e8-5f3c9d2a71b4",
        "technique": "T1098.001",
        "severity": "high",
        "hits": (
            _event("cloud_iam_change", "Add service principal credentials on azure.activedirectory"),
            _event("cloud_api_call", "Update application Certificates and secrets management"),
        ),
        "miss": _event("cloud_iam_change", "Add service principal on azure.activedirectory"),
    },
    {
        "file": "cloud_user_created.yml",
        "rule_id": "sigma_azure_ad_cloud_user_created",
        "sigma_id": "3f7c1a90-5e24-4b68-8d17-a6c4e9b0d253",
        "technique": "T1136.003",
        "severity": "medium",
        "hits": (
            _event("user_created", "Add user on azure.activedirectory"),
        ),
        "miss": _event("cloud_iam_change", "Add user to group on azure.activedirectory"),
    },
    {
        "file": "high_risk_sign_in.yml",
        "rule_id": "sigma_azure_ad_high_risk_sign_in",
        "sigma_id": "b19d4e72-0a36-4c81-9f50-7d2e8b6a14c8",
        "technique": "T1078.004",
        "severity": "high",
        "hits": (
            _event("auth_success", 'Entra sign-in riskLevelDuringSignIn":"high"'),
            _event("auth_success", "Entra sign-in riskLevelDuringSignIn=high"),
            _event("auth_success", "Entra sign-in riskLevelDuringSignIn: high"),
        ),
        "miss": _event("auth_success", "Entra sign-in riskLevelDuringSignIn=none"),
    },
    {
        "file": "anonymous_blob_read.yml",
        "rule_id": "sigma_azure_storage_anonymous_blob_read",
        "sigma_id": "6a0c8e35-4d17-4b92-a6f1-3e9b2c7d50a4",
        "technique": "T1530",
        "severity": "medium",
        "hits": (
            _event("cloud_data_access", "GetBlob on blob.core.windows.net AuthenticationType=Anonymous"),
            _event("cloud_api_call", "ListBlobs on blob.core.windows.net AuthenticationType: Anonymous"),
            _event("cloud_data_access", 'GetBlob on blob.core.windows.net AuthenticationType":"Anonymous"'),
        ),
        "miss": _event("cloud_data_access", "GetBlob on blob.core.windows.net AuthenticationType=OAuth"),
    },
    {
        "file": "account_locked_sign_in.yml",
        "rule_id": "sigma_azure_ad_account_locked_by_sign_in_failures",
        "sigma_id": "d52e9b18-7f40-4a63-8c25-1b6d4e0a93f7",
        "technique": "T1110",
        "severity": "medium",
        "hits": (
            _event("auth_failure", "Azure AD sign-in failed AADSTS50053 account is locked"),
            _event("account_lockout", '{"errorCode":50053}'),
            _event("auth_failure", '{"errorCode": 50053}'),
            _event("account_lockout", "status errorCode: 50053"),
        ),
        "miss": _event("auth_failure", "Azure AD sign-in failed AADSTS50126 invalid password"),
    },
)


class AzureSigmaPackTests(unittest.TestCase):
    def test_pack_covers_six_rules(self):
        names = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(names, sorted(case["file"] for case in CASES))
        self.assertEqual(len(CASES), 6)

    def test_each_rule_loads_matches_and_ignores_benign(self):
        titles, ids = set(), set()
        for case in CASES:
            with self.subTest(rule=case["file"]):
                compiled = sigma.compile_rule((PACK / case["file"]).read_text())
                self.assertEqual(compiled["rule_id"], case["rule_id"])
                self.assertEqual(compiled["sigma_id"], case["sigma_id"])
                self.assertEqual(compiled["severity"], case["severity"])
                self.assertNotIn(compiled["rule_id"], rules_mod.RULE_FUNCTIONS)
                techniques = [t["id"] for t in compiled["techniques"]]
                self.assertEqual(techniques, [case["technique"]])
                self.assertNotIn(compiled["title"], titles)
                self.assertNotEqual(compiled["title"], TAKEN_TITLE)
                self.assertNotIn(compiled["sigma_id"], ids)
                self.assertNotEqual(compiled["sigma_id"], TAKEN_ID)
                titles.add(compiled["title"])
                ids.add(compiled["sigma_id"])
                params = compiled["params"]
                for hit in case["hits"]:
                    self.assertTrue(sigma.matches(params, hit), hit["message"])
                self.assertFalse(sigma.matches(params, case["miss"]), case["miss"]["message"])


if __name__ == "__main__":
    unittest.main()
