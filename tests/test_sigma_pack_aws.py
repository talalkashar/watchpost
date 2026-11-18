"""AWS Sigma examples: each rule loads, matches a CloudTrail-shaped event, and stays quiet on a benign one."""

import unittest
from pathlib import Path

from watchpost import sigma
from watchpost.normalize import from_cloudtrail

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "aws"
TAKEN_TITLE = "Failed Admin Login From External Source"
TAKEN_ID = "5d2c1a6e-8f3b-4c1e-9a77-0e4b2f6d9c10"


def trail(event_name, event_source, ip="203.0.113.150", user="ops-admin", error=None):
    """One CloudTrail record, flattened the way Watchpost stores it."""
    record = {
        "eventName": event_name,
        "eventSource": event_source,
        "sourceIPAddress": ip,
        "userIdentity": {
            "type": "IAMUser",
            "userName": user,
            "arn": f"arn:aws:iam::123456789012:user/{user}",
        },
        "recipientAccountId": "123456789012",
    }
    if error:
        record["errorCode"] = error
    return from_cloudtrail(record)


# hit fires. misses must not. The first miss is the benign twin of the hit.
CASES = [
    {
        "file": "cloudtrail_logging_stopped.yml",
        "technique": "T1562.008",
        "hit": trail("StopLogging", "cloudtrail.amazonaws.com"),
        "misses": [
            trail("DescribeTrails", "cloudtrail.amazonaws.com"),
            trail("UpdateTrail", "cloudtrail.amazonaws.com"),
            trail("LookupEvents", "cloudtrail.amazonaws.com"),
        ],
    },
    {
        "file": "iam_user_created_external.yml",
        "technique": "T1136.003",
        "hit": trail("CreateUser", "iam.amazonaws.com", user="svc-deploy-tmp"),
        "misses": [
            trail("CreateUser", "iam.amazonaws.com", ip="10.0.1.30"),
            trail("CreateUser", "iam.amazonaws.com", ip="iam.amazonaws.com"),
            trail("ListUsers", "iam.amazonaws.com"),
        ],
    },
    {
        "file": "iam_access_key_created_external.yml",
        "technique": "T1098.001",
        "hit": trail("CreateAccessKey", "iam.amazonaws.com", user="svc-deploy-tmp"),
        "misses": [
            trail("CreateAccessKey", "iam.amazonaws.com", ip="10.0.1.30"),
            trail("CreateAccessKey", "iam.amazonaws.com", ip="iam.amazonaws.com"),
            trail("ListAccessKeys", "iam.amazonaws.com"),
        ],
    },
    {
        "file": "root_console_signin.yml",
        "technique": "T1078.004",
        "hit": trail("ConsoleLogin", "signin.amazonaws.com", user="root"),
        "misses": [
            trail("ConsoleLogin", "signin.amazonaws.com", user="ops-admin"),
            trail("DescribeInstances", "ec2.amazonaws.com", user="root"),
        ],
    },
    {
        "file": "s3_object_read_external.yml",
        "technique": "T1530",
        "hit": trail("GetObject", "s3.amazonaws.com", user="svc-deploy-tmp"),
        "misses": [
            trail("GetObject", "s3.amazonaws.com", ip="10.0.1.30"),
            trail("GetObject", "s3.amazonaws.com", ip="s3.amazonaws.com", user="analytics",
                  error="AccessDenied"),
            trail("ListBuckets", "s3.amazonaws.com"),
        ],
    },
    {
        "file": "console_signin_failure.yml",
        "technique": "T1110.001",
        "hit": trail("ConsoleLogin", "signin.amazonaws.com", error="Failed authentication"),
        "misses": [
            trail("ConsoleLogin", "signin.amazonaws.com"),
            trail("GetObject", "s3.amazonaws.com", error="AccessDenied"),
        ],
    },
]


class AwsSigmaPackTests(unittest.TestCase):
    def test_pack_loads_matches_and_ignores_benign(self):
        files = sorted(PACK.glob("*.yml"))
        self.assertEqual([p.name for p in files], sorted(c["file"] for c in CASES))
        seen_titles, seen_ids = set(), set()
        for case in CASES:
            path = PACK / case["file"]
            with self.subTest(rule=case["file"]):
                compiled = sigma.compile_rule(path.read_text())
                doc = sigma.parse_yaml(path.read_text())
                self.assertEqual(compiled["title"], doc["title"])
                self.assertNotEqual(doc["title"], TAKEN_TITLE)
                self.assertNotEqual(doc["id"], TAKEN_ID)
                self.assertNotIn(doc["title"], seen_titles)
                self.assertNotIn(doc["id"], seen_ids)
                seen_titles.add(doc["title"])
                seen_ids.add(doc["id"])
                self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])
                self.assertTrue(compiled["rule_id"].startswith("sigma_"))
                self.assertTrue(sigma.matches(compiled["params"], case["hit"]))
                for event in case["misses"]:
                    self.assertFalse(sigma.matches(compiled["params"], event))

        # DeleteTrail is the second action on the logging rule, not only StopLogging.
        stopped = sigma.compile_rule((PACK / "cloudtrail_logging_stopped.yml").read_text())
        self.assertTrue(sigma.matches(stopped["params"], trail("DeleteTrail", "cloudtrail.amazonaws.com")))

        # A failed root console sign-in is still root usage, and also a sign-in failure.
        failed_root = trail("ConsoleLogin", "signin.amazonaws.com", user="root", error="Failed authentication")
        root = sigma.compile_rule((PACK / "root_console_signin.yml").read_text())
        failure = sigma.compile_rule((PACK / "console_signin_failure.yml").read_text())
        self.assertTrue(sigma.matches(root["params"], failed_root))
        self.assertTrue(sigma.matches(failure["params"], failed_root))
