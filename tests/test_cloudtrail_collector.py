import contextlib
import importlib.util
import io
import json
import os
import re
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs

from tests.helpers import ServerTestCase

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("cloudtrail_collector", ROOT / "scripts" / "cloudtrail_collector.py")
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)

# The example credentials from the AWS Signature Version 4 documentation and test suite. Not real keys.
EXAMPLE = collector.Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
NOW = 1789034400.0  # 2026-09-10T10:00:00Z, the collector's clock in these tests
ROLE_A, ROLE_B = "arn:aws:iam::111111111111:role/WatchpostReadOnly", "arn:aws:iam::222222222222:role/WatchpostReadOnly"


def record(event_id, name, source="ec2.amazonaws.com", user="ops-admin", account="111111111111", at=NOW - 600):
    """One LookupEvents entry: the envelope, with the full CloudTrail record as a JSON string inside."""
    when = datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"eventVersion": "1.08", "eventID": event_id, "eventTime": when, "eventSource": source, "eventName": name,
            "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.30", "recipientAccountId": account,
            "userIdentity": {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::{account}:user/{user}"}}
    return {"EventId": event_id, "EventName": name, "EventTime": at, "CloudTrailEvent": json.dumps(body)}


class FakeAws:
    """CloudTrail LookupEvents and STS AssumeRole on one loopback port. Every request must carry a valid
    Signature Version 4 for the credentials it names, or it is refused the way AWS refuses it."""

    def __init__(self):
        self.secrets = {EXAMPLE.access_key: (EXAMPLE.secret_key, None)}  # access key -> (secret, session token)
        self.events = {}     # access key -> entries, newest first as LookupEvents returns them
        self.failures = []   # (status, error type) answered before anything else, one per request
        self.lookups, self.assumed = [], []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, status, payload, content_type="application/x-amz-json-1.1"):
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                access_key = fake.verify(self.headers, body)
                if access_key is None:
                    return self.answer(403, {"__type": "InvalidSignatureException", "message": "signature mismatch"})
                if fake.failures:
                    status, kind = fake.failures.pop(0)
                    return self.answer(status, {"__type": kind, "message": "scripted failure"})
                if self.headers.get("X-Amz-Target") == collector.LOOKUP_TARGET:
                    query = json.loads(body)
                    fake.lookups.append({**query, "access_key": access_key})
                    entries = [e for e in fake.events.get(access_key, [])
                               if query["StartTime"] <= e["EventTime"] <= query["EndTime"]]
                    offset = int(query.get("NextToken") or 0)
                    page = {"Events": entries[offset:offset + 2]}  # two per page, so paging is always exercised
                    if offset + 2 < len(entries):
                        page["NextToken"] = str(offset + 2)
                    return self.answer(200, page)
                form = parse_qs(body.decode())
                if form.get("Action") == ["AssumeRole"]:
                    role = form["RoleArn"][0]
                    fake.assumed.append(role)
                    key = "ROLEKEY" + role.split(":")[4]
                    fake.secrets[key] = (f"role-secret-{role.split(':')[4]}", f"session-token-{role.split(':')[4]}")
                    xml = (f"<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>{key}</AccessKeyId>"
                           f"<SecretAccessKey>{fake.secrets[key][0]}</SecretAccessKey>"
                           f"<SessionToken>{fake.secrets[key][1]}</SessionToken>"
                           f"<Expiration>2026-09-10T11:00:00Z</Expiration></Credentials></AssumeRoleResult>"
                           f"</AssumeRoleResponse>")
                    return self.answer(200, xml.encode(), "text/xml")
                self.answer(400, {"__type": "UnknownOperationException", "message": "unknown"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def verify(self, headers, body):
        """The access key when the Authorization header is the right signature of this exact request."""
        found = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=([^/]+)/\d{8}/([^/]+)/([^/]+)/aws4_request, "
                             r"SignedHeaders=([^,]+), Signature=[0-9a-f]{64}", headers.get("Authorization", ""))
        if not found or found[1] not in self.secrets:
            return None
        secret, token = self.secrets[found[1]]
        if headers.get("X-Amz-Security-Token") != token:
            return None
        sent = {name: headers[name] for name in found[4].split(";")
                if name not in ("host", "x-amz-date", "x-amz-security-token")}
        when = datetime.strptime(headers["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        expected = collector.sign("POST", f"http://{headers['Host']}/", sent, body,
                                  collector.Credentials(found[1], secret, token), found[2], found[3], when)
        return found[1] if expected["Authorization"] == headers["Authorization"] else None

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class SignatureTests(unittest.TestCase):
    def test_signature_matches_the_aws_published_examples(self):
        self.assertEqual(collector.signing_key(EXAMPLE.secret_key, "20150830", "us-east-1", "iam").hex(),
                         "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")
        now = datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc)
        cases = [("GET", "https://example.amazonaws.com/", {}, b"",
                  "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
                 ("GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", {}, b"",
                  "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"),
                 ("POST", "https://example.amazonaws.com/", {"Content-Type": "application/x-www-form-urlencoded"},
                  b"Param1=value1", "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a")]
        for method, url, headers, body, signature in cases:
            with self.subTest(url=url, method=method):
                signed = collector.sign(method, url, headers, body, EXAMPLE, "us-east-1", "service", now)
                self.assertTrue(signed["Authorization"].endswith(f"Signature={signature}"), signed["Authorization"])
                self.assertEqual(signed["X-Amz-Date"], "20150830T123600Z")
        temporary = collector.sign("GET", "https://example.amazonaws.com/", {}, b"",
                                   EXAMPLE._replace(token="session"), "us-east-1", "service", now)
        self.assertEqual(temporary["X-Amz-Security-Token"], "session")
        self.assertIn("SignedHeaders=host;x-amz-date;x-amz-security-token", temporary["Authorization"])


class CollectorTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.aws = FakeAws()
        self.addCleanup(self.aws.close)
        status, token, _ = self.client("admin").post("/api/tokens", {"name": "cloudtrail"})
        self.assertEqual(status, 201)
        self.token = token["token"]
        self.state = Path(self.tmp.name) / "state" / "cloudtrail.json"
        self.sleeps = []

    def make(self, url=None, **kw):
        kw.setdefault("regions", ["us-east-1"])
        return collector.Collector(url or self.base, self.token, kw.pop("regions"), self.state, EXAMPLE,
                                   endpoint=self.aws.url, sts_endpoint=self.aws.url, sleep=self.sleeps.append,
                                   clock=lambda: NOW, **kw)

    def stored(self):
        status, data, _ = self.client("analyst").get("/api/events?source=cloudtrail&limit=100")
        self.assertEqual(status, 200)
        return sorted(data["events"], key=lambda e: e["ts"])

    def test_collects_every_page_oldest_first_and_never_twice(self):
        self.aws.events[EXAMPLE.access_key] = [   # newest first, three entries, so two pages
            record("e3", "GetObject", "s3.amazonaws.com", at=NOW - 100),
            record("e2", "CreateUser", "iam.amazonaws.com", user="svc-deploy-tmp", at=NOW - 200),
            record("e1", "DescribeInstances", at=NOW - 300),
            record("old", "DescribeInstances", at=NOW - 7200)]   # before the first run's one-hour lookback
        run = self.make()
        self.assertEqual(run.collect_once(max_retries=0), 3)
        events = self.stored()
        self.assertEqual([(e["event_type"], e["user"]) for e in events],
                         [("cloud_api_call", "ops-admin"), ("cloud_iam_change", "svc-deploy-tmp"),
                          ("cloud_data_access", "ops-admin")])
        self.assertTrue(all(e["synthetic"] == 0 and e["host"] == "111111111111" for e in events))
        self.assertEqual([q.get("NextToken") for q in self.aws.lookups], [None, "2"])
        self.assertEqual((self.aws.lookups[0]["StartTime"], self.aws.lookups[0]["EndTime"]), (NOW - 3600, NOW))
        saved = json.loads(self.state.read_text())["default|us-east-1"]
        self.assertEqual((saved["until"], sorted(saved["seen"])), (NOW, ["e1", "e2", "e3"]))

        # A new process: the next poll overlaps the last one by 15 minutes and sends only what is new.
        self.aws.events[EXAMPLE.access_key].insert(0, record("e4", "ListBuckets", "s3.amazonaws.com", at=NOW - 50))
        self.aws.lookups.clear()
        again = self.make()
        self.assertEqual(again.collect_once(max_retries=0), 1)
        self.assertEqual(self.aws.lookups[0]["StartTime"], NOW - collector.OVERLAP_SECONDS)
        self.assertEqual(len(self.stored()), 4)
        self.assertEqual(again.collect_once(max_retries=0), 0)

    def test_assumes_one_read_only_role_per_account(self):
        self.aws.events["ROLEKEY111111111111"] = [record("a1", "ConsoleLogin", "signin.amazonaws.com")]
        self.aws.events["ROLEKEY222222222222"] = [record("b1", "StopLogging", "cloudtrail.amazonaws.com",
                                                         account="222222222222")]
        run = self.make(role_arns=[ROLE_A, ROLE_B], regions=["us-east-1", "eu-west-1"])
        self.assertEqual(run.collect_once(max_retries=0), 4)  # each event shows in both regions of this fake
        self.assertEqual(self.aws.assumed, [ROLE_A, ROLE_B])  # once per role, reused for the second region
        self.assertEqual([q["access_key"] for q in self.aws.lookups], ["ROLEKEY111111111111"] * 2 + ["ROLEKEY222222222222"] * 2)
        self.assertEqual({e["host"] for e in self.stored()}, {"111111111111", "222222222222"})
        self.assertEqual(sorted(json.loads(self.state.read_text())), sorted(
            f"{role}|{region}" for role in (ROLE_A, ROLE_B) for region in ("us-east-1", "eu-west-1")))

    def test_throttling_is_retried_and_a_denied_request_gives_up(self):
        self.aws.events[EXAMPLE.access_key] = [record("e1", "DescribeInstances")]
        self.aws.failures = [(400, "ThrottlingException"), (500, "InternalFailure")]
        run = self.make()
        self.assertEqual(run.collect_once(max_retries=3), 1)
        self.assertEqual((run.stats["retries"], len(self.sleeps)), (2, 2))

        self.aws.failures = [(400, "AccessDeniedException")]
        with self.assertRaisesRegex(collector.FatalError, "AccessDeniedException"):
            self.make().collect_once(max_retries=3)
        wrong = self.make()
        wrong.base_credentials = EXAMPLE._replace(secret_key="not-the-secret")
        with self.assertRaisesRegex(collector.FatalError, "InvalidSignatureException"):
            wrong.collect_once(max_retries=3)
        self.assertEqual(json.loads(self.state.read_text())["default|us-east-1"]["until"], NOW)  # from the good run only

    def test_a_batch_that_was_sent_is_not_sent_again_after_a_failure(self):
        self.aws.events[EXAMPLE.access_key] = [record(f"e{n}", "DescribeInstances", at=NOW - 100 * n) for n in (1, 2, 3)]
        answers = [201, 503]
        real_post = collector.Collector.post

        def flaky_post(run, records):
            return real_post(run, records) if answers.pop(0) == 201 else 503

        with mock.patch.object(collector, "POST_BATCH", 2), mock.patch.object(collector.Collector, "post", flaky_post):
            with self.assertRaisesRegex(collector.FatalError, "HTTP 503"):
                self.make().collect_once(max_retries=0)
        self.assertEqual(len(self.stored()), 2)
        self.assertNotIn("until", json.loads(self.state.read_text())["default|us-east-1"])
        self.assertEqual(self.make().collect_once(max_retries=0), 1)  # only the event that never arrived
        self.assertEqual(len(self.stored()), 3)

    def test_cli_runs_once_and_keeps_secrets_out_of_its_log(self):
        self.aws.events[EXAMPLE.access_key] = [record("e1", "CreateAccessKey", "iam.amazonaws.com", at=time.time() - 600)]
        env = {"AWS_ACCESS_KEY_ID": EXAMPLE.access_key, "AWS_SECRET_ACCESS_KEY": EXAMPLE.secret_key,
               "WATCHPOST_TOKEN": self.token, "AWS_REGION": "us-east-1"}
        args = ["--url", self.base, "--state", str(self.state), "--endpoint-url", self.aws.url, "--once"]
        output = io.StringIO()
        with mock.patch.dict(os.environ, env), contextlib.redirect_stderr(output):  # the real clock here
            os.environ.pop("AWS_SESSION_TOKEN", None)
            self.assertEqual(collector.main(args), 0)
            self.assertEqual(collector.main(args + ["--role-arn", "arn:aws:iam::333333333333:role/Missing",
                                                    "--sts-endpoint-url", "http://127.0.0.1:1", "--max-retries", "0"]), 2)
        self.assertEqual([e["event_type"] for e in self.stored()], ["cloud_iam_change"])
        self.assertIn("1 new event(s)", output.getvalue())
        for secret in (EXAMPLE.secret_key, self.token):
            self.assertNotIn(secret, output.getvalue())


class CollectorSafetyTests(unittest.TestCase):
    def test_refuses_missing_credentials_and_plain_http(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()) as output:
            base = ["--state", os.path.join(tmp, "s.json"), "--once", "--region", "us-east-1"]
            with mock.patch.dict(os.environ, {"WATCHPOST_TOKEN": "wp_test-token-value-0123456789"}):
                for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
                    os.environ.pop(name, None)
                self.assertEqual(collector.main(["--url", "http://127.0.0.1:1", *base]), 2)
                self.assertIn("no AWS credentials", output.getvalue())
                os.environ.update(AWS_ACCESS_KEY_ID="AKIDEXAMPLE", AWS_SECRET_ACCESS_KEY="x")
                self.assertEqual(collector.main(["--url", "http://siem.example.com", *base]), 2)
                self.assertEqual(collector.main(["--url", "http://127.0.0.1:1", "--endpoint-url",
                                                 "http://cloudtrail.example.com", *base]), 2)
                self.assertEqual(output.getvalue().count("plain HTTP"), 2)
        with self.assertRaises(collector.FatalError):
            collector.check_url("file:///etc/passwd", "--url")


if __name__ == "__main__":
    unittest.main()
