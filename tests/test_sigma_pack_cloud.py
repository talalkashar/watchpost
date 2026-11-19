"""Cloud Sigma examples proved on raw CloudTrail records.

Each kept file is compiled, stored, and enabled. Built-in rules are turned off in this
database so only the pack can alert. A CloudTrail Records document is parsed and ingested.
The proof is the action on stored evidence and the evidence event ids.

Two donor examples are not files. responseElements.ConsoleLogin is not a detection field,
so a native failure with no errorCode is stored as the same action as a success. A root
ARN has no slash, so the stored user is the display name or the principal id.
"""

import ipaddress
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchpost import ecs, engine, queries, sigma
from watchpost.db import connect, init_schema, now_iso
from watchpost.normalize import parse_payload

CLOUD = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "cloud"
NOW = datetime(2026, 11, 18, 23, 0, tzinfo=timezone.utc)
START = datetime(2026, 11, 18, 15, 0, tzinfo=timezone.utc)
ACCOUNT = "123456789012"
LOGSOURCE_WARNING = "logsource is informational only: the rule runs on every stored event"
OMITTED = ("cloud_console_login_failure.yml", "cloud_root_account_activity.yml")

CRED = "sigma_cloud_credential_creation_requested"
ACCT = "sigma_cloud_organization_account_creation_requested"
CONSOLE = "sigma_cloud_console_sign_in_recorded_from_an_external"
STORE = "sigma_cloud_storage_read_from_an_external_address"
THREAT = "sigma_cloud_threat_detection_disable_requested"
LOGGING = "sigma_cloud_logging_channel_deletion_requested"

IAM = "iam.amazonaws.com"
ORG = "organizations.amazonaws.com"
SIGNIN = "signin.amazonaws.com"
S3 = "s3.amazonaws.com"
GUARD = "guardduty.amazonaws.com"
HUB = "securityhub.amazonaws.com"
TRAIL = "cloudtrail.amazonaws.com"
EC2 = "ec2.amazonaws.com"
CONFIG = "config.amazonaws.com"
LOGS = "logs.amazonaws.com"
SECRETS = "secretsmanager.amazonaws.com"

# filename, rule id, sigma uuid, severity, techniques after revocation.
PACK = (
    ("cloud_credential_added.yml", CRED, "4c8e2a17-5b60-4d3f-8e15-1a7c9d0e4f21", "high", ("T1098.001",)),
    ("cloud_account_created.yml", ACCT, "9a1b6d30-2e44-4c7e-b152-8d0e6f1a3c94", "high", ("T1136.003",)),
    ("cloud_console_login_external.yml", CONSOLE, "6e0f1b4a-8c55-4a1d-9c33-7b2e1d0a4f90", "high", ("T1078.004",)),
    ("cloud_storage_read_external.yml", STORE, "1d4a8c06-3f73-4b9e-95d8-0e6a3c5b1f22", "medium", ("T1530",)),
    ("cloud_threat_detection_disabled.yml", THREAT, "c2b8d491-5e62-4c8f-a0e5-6c9d2f8b1a37", "high", ("T1685",)),
    ("cloud_logging_disabled.yml", LOGGING, "e5f1a2b6-7c27-4d90-a6c3-2d9e7b2f0a11", "high", ("T1685.002",)),
)

THREAT_CALLS = (
    ("threat-delete-detector", "DeleteDetector", GUARD),
    ("threat-delete-members", "DeleteMembers", GUARD),
    ("threat-stop-members", "StopMonitoringMembers", GUARD),
    ("threat-delete-dest", "DeletePublishingDestination", GUARD),
    ("threat-leave-master", "DisassociateFromMasterAccount", GUARD),
    ("threat-leave-admin", "DisassociateFromAdministratorAccount", GUARD),
    ("threat-disassociate", "DisassociateMembers", GUARD),
    ("threat-disable-hub", "DisableSecurityHub", HUB),
    ("threat-hub-members", "DeleteMembers", HUB),
    ("threat-hub-admin", "DisassociateFromAdministratorAccount", HUB),
)


def _ip(value):
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _root(user):
    identity = {"type": "Root", "principalId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:root"}
    if user is not None:
        identity["userName"] = user
    return identity


def _specs():
    """Native records in ingest order. rule is the pack id that must cite the event, or None."""
    rows = []

    def add(**spec):
        spec.setdefault("event_type", "cloud_api_call")
        spec.setdefault("user", "alice")
        rows.append(spec)

    add(label="cred-login-ok", rule=CRED, name="CreateLoginProfile", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change")
    add(label="cred-login-deny", rule=CRED, name="CreateLoginProfile", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change", error="AccessDenied")
    add(label="cred-service", rule=CRED, name="CreateServiceSpecificCredential", source=IAM,
        ip="203.0.113.41", event_type="cloud_iam_change")
    add(label="cred-cert", rule=CRED, name="UploadSigningCertificate", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change")
    add(label="cred-ssh", rule=CRED, name="UploadSSHPublicKey", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change")

    add(label="org-account", rule=ACCT, name="CreateAccount", source=ORG, ip="203.0.113.42", user="bob")
    add(label="org-account-deny", rule=ACCT, name="CreateAccount", source=ORG, ip="203.0.113.42",
        user="bob", error="AccessDenied")
    add(label="org-gov", rule=ACCT, name="CreateGovCloudAccount", source=ORG, ip="203.0.113.42", user="bob")

    add(label="console-ok", rule=CONSOLE, name="ConsoleLogin", source=SIGNIN, ip="203.0.113.43",
        user="carol", response={"ConsoleLogin": "Success"})
    add(label="console-native-failure", rule=CONSOLE, name="ConsoleLogin", source=SIGNIN, ip="203.0.113.43",
        user="carol", response={"ConsoleLogin": "Failure"}, error_message="Failed authentication")
    add(label="console-v6", rule=CONSOLE, name="ConsoleLogin", source=SIGNIN, ip="2001:db8::60",
        user="carol", response={"ConsoleLogin": "Success"})

    add(label="store-get", rule=STORE, name="GetObject", source=S3, ip="198.51.100.8", user="dan",
        event_type="cloud_data_access", request={"bucketName": "finance-exports", "key": "q3.csv"})
    add(label="store-select", rule=STORE, name="SelectObjectContent", source=S3, ip="198.51.100.8",
        user="dan", event_type="cloud_data_access")
    add(label="store-copy", rule=STORE, name="CopyObject", source=S3, ip="198.51.100.8", user="dan",
        event_type="cloud_data_access")
    add(label="store-v6", rule=STORE, name="GetObject", source=S3, ip="2001:db8::50", user="dan",
        event_type="cloud_data_access")

    add(label="routine-error-mentions-action", rule=None, name="ListDetectors", source=GUARD,
        ip="203.0.113.60", error="DeleteDetector on guardduty.amazonaws.com")

    for label, name, source in THREAT_CALLS:
        add(label=label, rule=THREAT, name=name, source=source, ip="203.0.113.60", user="casey")
    add(label="threat-delete-denied", rule=THREAT, name="DeleteDetector", source=GUARD, ip="203.0.113.60",
        user="casey", error="AccessDenied")

    add(label="log-group", rule=LOGGING, name="DeleteLogGroup", source=LOGS, ip="203.0.113.70", user="erin")
    add(label="log-channel", rule=LOGGING, name="DeleteDeliveryChannel", source=CONFIG, ip="203.0.113.70",
        user="erin")
    add(label="log-channel-deny", rule=LOGGING, name="DeleteDeliveryChannel", source=CONFIG,
        ip="203.0.113.70", user="erin", error="AccessDenied")

    # Stock actions already covered by the shipped examples.
    add(label="stock-user", name="CreateUser", source=IAM, ip="203.0.113.10", event_type="cloud_iam_change",
        user="admin")
    add(label="stock-key", name="CreateAccessKey", source=IAM, ip="203.0.113.10", event_type="cloud_iam_change",
        user="admin")
    add(label="stock-key-deny", name="CreateAccessKey", source=IAM, ip="203.0.113.10",
        event_type="cloud_iam_change", user="admin", error="AccessDenied")
    add(label="stock-stop", name="StopLogging", source=TRAIL, ip="203.0.113.10", user="admin")
    add(label="stock-trail", name="DeleteTrail", source=TRAIL, ip="203.0.113.10", user="admin")
    add(label="stock-flow", name="DeleteFlowLogs", source=EC2, ip="203.0.113.10", user="admin")
    add(label="stock-config", name="StopConfigurationRecorder", source=CONFIG, ip="203.0.113.10", user="admin")

    add(label="look-delkey", name="DeleteAccessKey", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change")
    add(label="look-updlogin", name="UpdateLoginProfile", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change")
    add(label="look-updkey", name="UpdateAccessKey", source=IAM, ip="203.0.113.41",
        event_type="cloud_iam_change")
    add(label="look-getuser", name="GetUser", source=IAM, ip="203.0.113.41")

    for label, ip in (
        ("con-10", "10.1.2.3"),
        ("con-172", "172.16.4.4"),
        ("con-192", "192.168.1.9"),
        ("con-127", "127.0.0.1"),
        ("con-meta", "169.254.169.254"),
        ("con-ula", "fd00::1"),
        ("con-link", "fe80::1"),
        ("con-lo", "::1"),
    ):
        add(label=label, name="ConsoleLogin", source=SIGNIN, ip=ip, user="carol",
            response={"ConsoleLogin": "Success"})
    add(label="con-service", name="ConsoleLogin", source=SIGNIN, ip="AWS Internal", user="carol",
        response={"ConsoleLogin": "Success"})
    add(label="con-missing", name="ConsoleLogin", source=SIGNIN, ip=None, user="carol", drop_ip=True,
        response={"ConsoleLogin": "Success"})
    add(label="con-errcode", name="ConsoleLogin", source=SIGNIN, ip="203.0.113.43", user="carol",
        error="FailedAuthentication", response={"ConsoleLogin": "Failure"})

    add(label="store-10", name="GetObject", source=S3, ip="10.0.1.30", user="dan", event_type="cloud_data_access")
    add(label="store-ula", name="GetObject", source=S3, ip="fd00::20", user="dan", event_type="cloud_data_access")
    add(label="store-link", name="GetObject", source=S3, ip="fe80::20", user="dan", event_type="cloud_data_access")
    add(label="store-lo", name="GetObject", source=S3, ip="::1", user="dan", event_type="cloud_data_access")
    add(label="store-service", name="GetObject", source=S3, ip="s3.amazonaws.com", user="dan",
        event_type="cloud_data_access")
    add(label="store-deny", name="GetObject", source=S3, ip="198.51.100.8", user="dan",
        event_type="cloud_data_access", error="AccessDenied")
    add(label="store-list", name="ListBuckets", source=S3, ip="198.51.100.8", user="dan")
    add(label="store-secret", name="GetSecretValue", source=SECRETS, ip="198.51.100.8", user="dan",
        event_type="cloud_data_access")

    add(label="log-start", name="StartLogging", source=TRAIL, ip="203.0.113.70", user="erin")
    add(label="log-describe", name="DescribeTrails", source=TRAIL, ip="203.0.113.70", user="erin")
    add(label="log-update", name="UpdateTrail", source=TRAIL, ip="203.0.113.70", user="erin")
    add(label="threat-create", name="CreateDetector", source=GUARD, ip="203.0.113.60", user="casey")
    add(label="threat-get", name="GetDetector", source=GUARD, ip="203.0.113.60", user="casey")
    add(label="threat-update", name="UpdateDetector", source=GUARD, ip="203.0.113.60", user="casey")
    add(label="threat-enable-hub", name="EnableSecurityHub", source=HUB, ip="203.0.113.60", user="casey")
    add(label="org-describe", name="DescribeAccount", source=ORG, ip="203.0.113.42", user="bob")

    add(label="root-display", name="DescribeInstances", source=EC2, ip="203.0.113.80",
        identity=_root("break-glass"), expect_user="break-glass")
    add(label="root-unnamed", name="DescribeInstances", source=EC2, ip="203.0.113.81",
        identity=_root(None), expect_user=ACCOUNT)
    add(label="root-named", name="DescribeInstances", source=EC2, ip="203.0.113.82", user="root",
        expect_user="root")
    return rows


def _record(spec, when):
    identity = spec.get("identity")
    if identity is None:
        user = spec["user"]
        identity = {
            "type": "IAMUser",
            "userName": user,
            "principalId": "AIDAEXAMPLE",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
        }
    record = {
        "eventTime": when,
        "eventVersion": "1.08",
        "eventSource": spec["source"],
        "eventName": spec["name"],
        "awsRegion": "us-east-1",
        "userIdentity": identity,
        "recipientAccountId": ACCOUNT,
    }
    if not spec.get("drop_ip"):
        record["sourceIPAddress"] = spec["ip"]
    if spec.get("request"):
        record["requestParameters"] = spec["request"]
    if spec.get("response"):
        record["responseElements"] = spec["response"]
    if spec.get("error_message"):
        record["errorMessage"] = spec["error_message"]
    if spec.get("error"):
        record["errorCode"] = spec["error"]
    return record


def _message(spec):
    text = f"{spec['name']} on {spec['source']}"
    if spec.get("error"):
        text += f" ({spec['error']})"
    return text


class CloudSigmaPackTests(unittest.TestCase):
    def test_pack_on_native_cloudtrail(self):
        names = sorted(path.name for path in CLOUD.glob("*.yml"))
        self.assertEqual(names, sorted(row[0] for row in PACK))
        for name in OMITTED:
            self.assertFalse((CLOUD / name).exists(), name)

        compiled = {}
        for filename, rule_id, sigma_id, severity, techniques in PACK:
            source = (CLOUD / filename).read_text()
            rule = sigma.compile_rule(source)
            self.assertEqual(rule["rule_id"], rule_id)
            self.assertEqual(rule["sigma_id"], sigma_id)
            self.assertEqual(rule["severity"], severity)
            self.assertEqual(tuple(item["id"] for item in rule["techniques"]), techniques)
            self.assertIn(LOGSOURCE_WARNING, rule["warnings"])
            compiled[rule_id] = (rule, source)
        self.assertEqual(len(compiled), 6)

        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        for rule, source in compiled.values():
            sigma.add_rule(conn, rule, source, None, "analyst", "admin", None, now_iso())
        conn.execute("UPDATE rules SET enabled = 0 WHERE id NOT LIKE 'sigma_%'")
        conn.execute("UPDATE rules SET enabled = 1 WHERE id LIKE 'sigma_%'")
        enabled = [row["id"] for row in conn.execute("SELECT id FROM rules WHERE enabled = 1 ORDER BY id")]
        self.assertEqual(enabled, sorted(compiled))

        specs = _specs()
        records = []
        for index, spec in enumerate(specs):
            when = (START + timedelta(minutes=index)).strftime("%Y-%m-%dT%H:%M:%SZ")
            records.append(_record(spec, when))
        events, rejections = parse_payload(
            json.dumps({"Records": records}), "json", "cloud-lab", now=NOW)
        self.assertEqual(rejections, [])
        self.assertEqual(len(events), len(specs))
        result = engine.ingest(conn, events, rejections, "cloud-lab", "json", "tester")
        self.assertEqual(result["rejected"], 0)
        self.assertEqual(result["detection"]["status"], "ok", result["detection"])
        self.assertEqual(result["detection"]["events_scanned"], len(specs))
        self.assertEqual(result["detection"]["alerts_created"], 8)

        rows = list(conn.execute(
            "SELECT id, message, event_type, outcome, user, src_ip, raw FROM events ORDER BY id"))
        self.assertEqual(len(rows), len(specs))
        stored = {}
        for spec, row in zip(specs, rows):
            label = spec["label"]
            stored[label] = row
            with self.subTest(stored=label):
                self.assertEqual(row["message"], _message(spec))
                self.assertEqual(row["message"].split(" on ", 1)[0], spec["name"])
                self.assertEqual(row["event_type"], spec["event_type"])
                self.assertEqual(row["outcome"], "failure" if spec.get("error") else "success")
                self.assertEqual(row["user"], spec.get("expect_user", spec["user"]))
                self.assertEqual(row["src_ip"], None if spec.get("drop_ip") else _ip(spec["ip"]))

        self._lost_before_match(conn, stored)

        evidence = {rule_id: set() for rule_id in compiled}
        alerts = list(conn.execute("SELECT id, rule_id, title, event_count, group_key FROM alerts ORDER BY id"))
        self.assertEqual(len(alerts), 8)
        self.assertEqual({row["rule_id"] for row in alerts}, set(compiled))
        for alert in alerts:
            detail = queries.get_alert(conn, alert["id"])
            rule_id = alert["rule_id"]
            title = compiled[rule_id][0]["title"]
            with self.subTest(alert=rule_id, group=alert["group_key"]):
                self.assertEqual(detail["evidence_omitted"], 0)
                self.assertEqual(len(detail["evidence"]), alert["event_count"])
                self.assertEqual(
                    detail["title"],
                    f"{title}: {alert['event_count']} matching event(s) for {alert['group_key']}",
                )
                linked = {row["event_id"] for row in conn.execute(
                    "SELECT event_id FROM alert_events WHERE alert_id = ?", (alert["id"],))}
                self.assertEqual(linked, {item["id"] for item in detail["evidence"]})
                for item in detail["evidence"]:
                    self.assertEqual(item["message"].split(" on ", 1)[0],
                                     next(spec["name"] for spec in specs if stored[spec["label"]]["id"] == item["id"]))
                    doc = ecs.to_ecs(item)
                    self.assertEqual(doc["event"]["action"], item["event_type"])
                    self.assertEqual(doc["event"]["outcome"], item["outcome"])
                    self.assertIn(item["id"], {row["id"] for row in rows})
                evidence[rule_id].update(linked)

        expected = {rule_id: set() for rule_id in compiled}
        for spec in specs:
            if spec.get("rule"):
                expected[spec["rule"]].add(stored[spec["label"]]["id"])
        self.assertEqual(evidence, expected)
        cited = set().union(*evidence.values())
        for spec in specs:
            if not spec.get("rule"):
                self.assertNotIn(stored[spec["label"]]["id"], cited, spec["label"])
        self.assertEqual(len(cited), sum(len(ids) for ids in expected.values()))

        self.assertNotIn("finance-exports", stored["store-get"]["message"])
        self.assertIn("finance-exports", stored["store-get"]["raw"])

    def _lost_before_match(self, conn, stored):
        max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        projected, history, scan_start = engine.scan_events(conn, [], max_id)
        self.assertEqual(history, [])
        self.assertIsNone(scan_start)
        by_id = {row["id"]: row for row in projected}

        display = stored["root-display"]
        unnamed = stored["root-unnamed"]
        named = stored["root-named"]
        self.assertEqual(display["user"], "break-glass")
        self.assertIn('"type": "Root"', display["raw"])
        self.assertIn(":root", display["raw"])
        self.assertEqual(unnamed["user"], ACCOUNT)
        self.assertNotEqual(unnamed["user"], "root")
        self.assertIn(":root", unnamed["raw"])
        self.assertEqual(named["user"], "root")
        self.assertIn('"type": "IAMUser"', named["raw"])

        failure = stored["console-native-failure"]
        success = stored["console-ok"]
        self.assertEqual(failure["message"], success["message"])
        self.assertEqual(failure["message"], "ConsoleLogin on signin.amazonaws.com")
        self.assertEqual(failure["outcome"], "success")
        self.assertEqual(success["outcome"], "success")
        self.assertIn('"ConsoleLogin": "Failure"', failure["raw"])
        self.assertIn("Failed authentication", failure["raw"])
        self.assertIn('"ConsoleLogin": "Success"', success["raw"])

        for label in ("root-display", "root-unnamed", "root-named", "console-native-failure", "console-ok"):
            seen = by_id[stored[label]["id"]]
            self.assertNotIn("raw", seen)
            self.assertNotIn("outcome", seen)
            text = " ".join(str(value) for value in seen.values() if value is not None)
            self.assertNotIn("Root", text, label)
            self.assertNotIn(":root", text, label)
            self.assertNotIn("Failed authentication", text, label)
            self.assertNotIn("ConsoleLogin\": \"Failure", text, label)
            self.assertNotIn("ConsoleLogin\": \"Success", text, label)
