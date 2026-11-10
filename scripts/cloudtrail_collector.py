#!/usr/bin/env python3
"""Watchpost CloudTrail collector: read AWS CloudTrail with a read-only identity and post it to Watchpost.

Standard library only (Python 3.10+). It calls one AWS API, CloudTrail `LookupEvents`, which needs
no more than `cloudtrail:LookupEvents`. The AWS managed policies `SecurityAudit` and `ReadOnlyAccess`
both grant it, so an auditor identity is enough. Nothing in AWS is ever changed.

    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # the read-only identity
    export WATCHPOST_TOKEN=wp_...                            # an ingest-only token created by an admin
    python3 cloudtrail_collector.py --url https://siem.example.internal --region us-east-1 \\
        --role-arn arn:aws:iam::111111111111:role/WatchpostReadOnly \\
        --state /var/lib/watchpost-cloudtrail/state.json

`LookupEvents` answers for one account and one region at a time. Give `--region` once per region and
`--role-arn` once per account: the collector assumes each role (STS AssumeRole) with the identity it
was started with, and reads every account in every region. Without `--role-arn` it reads the
identity's own account.

Each poll asks for the events since the last one, minus an overlap (CloudTrail can deliver an event
up to 15 minutes late), and remembers the event IDs it has sent, so the overlap is not sent twice.
The state file holds the time reached and those IDs per account and region; a restart resumes there.
Events are posted oldest first to `POST /api/ingest` as CloudTrail records, unchanged.

Network errors, throttling and 5xx answers retry with exponential backoff. A batch Watchpost refuses
as invalid (400, 413, 422) is logged and skipped. AWS keys and the Watchpost token come from the
environment or a file, never from the command line, and are never logged.

Limits: `LookupEvents` returns management events of the last 90 days only. Data events (S3 object
reads, Lambda invocations) are delivered only to a trail's S3 bucket, which this collector does not read.
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_STATE = "watchpost-cloudtrail-state.json"
LOOKUP_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
PAGE_SIZE = 50                 # the most LookupEvents returns per call
PAGE_PAUSE = 0.6               # LookupEvents allows two calls a second per account and region
OVERLAP_SECONDS = 15 * 60      # CloudTrail's stated worst-case delivery delay
POST_BATCH = 200               # events per request to Watchpost
SKIP_STATUSES = {400, 413, 422}
MAX_BACKOFF = 60.0
ROLE_REFRESH_SECONDS = 300     # renew assumed-role credentials this long before they expire

Credentials = namedtuple("Credentials", "access_key secret_key token expires", defaults=(None, None))


def log(message):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} cloudtrail-collector: {message}", file=sys.stderr, flush=True)


class FatalError(Exception):
    pass


class AwsError(Exception):
    """An AWS API answered with an error. `retryable` is False for a request AWS will never accept."""

    def __init__(self, status, code, message):
        super().__init__(f"{code or 'error'} (HTTP {status}): {message}"[:300])
        self.status, self.code = status, code or ""
        self.retryable = status >= 500 or status == 429 or "Throttl" in self.code or "Expired" in self.code


# --- AWS Signature Version 4 ----------------------------------------------------------

def _hmac(key, text):
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


def signing_key(secret_key, date, region, service):
    key = _hmac(("AWS4" + secret_key).encode(), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    return key


def sign(method, url, headers, body, credentials, region, service, now):
    """The request headers plus X-Amz-Date, the session token if there is one, and Authorization."""
    parsed = urllib.parse.urlsplit(url)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    out = dict(headers)
    out["X-Amz-Date"] = stamp
    if credentials.token:
        out["X-Amz-Security-Token"] = credentials.token
    signed = {name.lower(): " ".join(str(value).split()) for name, value in out.items()}
    signed["host"] = parsed.netloc
    names = ";".join(sorted(signed))
    query = "&".join(sorted(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                            for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    canonical = "\n".join([method, urllib.parse.quote(parsed.path or "/", safe="/-_.~"), query,
                           "".join(f"{name}:{signed[name]}\n" for name in sorted(signed)), names,
                           hashlib.sha256(body).hexdigest()])
    scope = f"{stamp[:8]}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = signing_key(credentials.secret_key, stamp[:8], region, service)
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{scope}, "
                            f"SignedHeaders={names}, Signature={signature}")
    return out


# --- collector ------------------------------------------------------------------------

def _is_loopback(hostname):
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return hostname == "localhost"


def check_url(url, what, allow_insecure=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FatalError(f"{what} must be an http(s) URL, got {url!r}")
    if parsed.scheme == "http" and not allow_insecure and not _is_loopback(parsed.hostname):
        raise FatalError(f"refusing to send credentials over plain HTTP to {parsed.hostname}; use https://")
    return url.rstrip("/")


class Collector:
    def __init__(self, url, token, regions, state_path, credentials, role_arns=(), source="cloudtrail",
                 lookback=3600, cafile=None, endpoint=None, sts_endpoint=None, timeout=30,
                 sleep=time.sleep, clock=time.time):
        self.url, self.token, self.source = url.rstrip("/"), token, source
        self.regions, self.accounts = list(regions), list(role_arns) or [None]
        self.state_path = Path(state_path)
        self.base_credentials, self.lookback = credentials, lookback
        self.endpoint, self.sts_endpoint = endpoint, sts_endpoint
        self.timeout, self.sleep, self.clock = timeout, sleep, clock
        self.context = ssl.create_default_context(cafile=cafile)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.aws_context = ssl.create_default_context()
        self.aws_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.role_credentials = {}
        self.state = self._load_state()
        self.stats = {"events": 0, "batches": 0, "skipped_batches": 0, "retries": 0, "lookups": 0}

    # --- state ----------------------------------------------------------------------

    def _load_state(self):
        try:
            state = json.loads(self.state_path.read_text())
            return state if isinstance(state, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log(f"ignoring unreadable state file {self.state_path}: {type(exc).__name__}")
            return {}

    def save_state(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True))
        os.replace(tmp, self.state_path)

    # --- AWS ------------------------------------------------------------------------

    def _open(self, request, context):
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read()

    def _aws(self, url, service, region, headers, body, credentials):
        now = datetime.fromtimestamp(self.clock(), timezone.utc)
        request = urllib.request.Request(url, data=body, method="POST",
                                         headers=sign("POST", url, headers, body, credentials, region, service, now))
        status, payload = self._open(request, self.aws_context if url.startswith("https:") else None)
        if status != 200:
            text = payload.decode("utf-8", "replace")
            try:
                error = json.loads(text)
                code, message = str(error.get("__type", "")).rsplit("#", 1)[-1], error.get("message") or error.get("Message")
            except ValueError:  # STS answers in XML
                code = (re.search(r"<Code>([^<]*)</Code>", text) or [None, ""])[1]
                message = (re.search(r"<Message>([^<]*)</Message>", text) or [None, ""])[1]
            raise AwsError(status, code, message or "no message")
        return payload

    def credentials_for(self, role_arn, region):
        if role_arn is None:
            return self.base_credentials
        cached = self.role_credentials.get(role_arn)
        if cached and cached.expires - ROLE_REFRESH_SECONDS > self.clock():
            return cached
        url = self.sts_endpoint or f"https://sts.{region}.amazonaws.com"
        body = urllib.parse.urlencode({"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": role_arn,
                                       "RoleSessionName": "watchpost-cloudtrail-collector",
                                       "DurationSeconds": "3600"}).encode()
        text = self._aws(url + "/", "sts", region, {"Content-Type": "application/x-www-form-urlencoded"},
                         body, self.base_credentials).decode("utf-8", "replace")
        fields = {name: re.search(rf"<{name}>([^<]+)</{name}>", text)
                  for name in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")}
        if not all(fields.values()):
            raise AwsError(200, "MalformedResponse", "AssumeRole answered without credentials")
        expires = datetime.fromisoformat(fields["Expiration"][1].replace("Z", "+00:00")).timestamp()
        credentials = Credentials(fields["AccessKeyId"][1], fields["SecretAccessKey"][1], fields["SessionToken"][1],
                                  expires)
        self.role_credentials[role_arn] = credentials
        return credentials

    def lookup(self, role_arn, region, start, end):
        """Every management event recorded between the two epoch seconds, as (id, time, record)."""
        url = (self.endpoint or f"https://cloudtrail.{region}.amazonaws.com") + "/"
        headers = {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": LOOKUP_TARGET}
        found, token = [], None
        while True:
            query = {"StartTime": start, "EndTime": end, "MaxResults": PAGE_SIZE}
            if token:
                query["NextToken"] = token
            page = json.loads(self._aws(url, "cloudtrail", region, headers, json.dumps(query).encode(),
                                        self.credentials_for(role_arn, region)))
            self.stats["lookups"] += 1
            for item in page.get("Events") or []:
                try:
                    record = json.loads(item["CloudTrailEvent"])
                    found.append((str(item["EventId"]), float(item["EventTime"]), record))
                except (KeyError, TypeError, ValueError):
                    continue  # an entry without a readable record has nothing to ingest
            token = page.get("NextToken")
            if not token:
                return found
            self.sleep(PAGE_PAUSE)

    # --- Watchpost ------------------------------------------------------------------

    def post(self, records):
        """Send one batch of CloudTrail records. Returns the HTTP status; raises OSError on network failure."""
        body = json.dumps({"source": self.source, "events": records}).encode()
        request = urllib.request.Request(f"{self.url}/api/ingest", data=body, method="POST", headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        status, payload = self._open(request, self.context if self.url.startswith("https:") else None)
        try:
            answer = json.loads(payload or b"null")
        except ValueError:
            answer = None
        if status in (201, 207):
            log(f"sent {len(records)} event(s), accepted {answer.get('accepted')}, rejected {answer.get('rejected')}")
        elif status in SKIP_STATUSES:
            reason = answer.get("error") if isinstance(answer, dict) and answer.get("error") else "records rejected"
            log(f"Watchpost refused a batch of {len(records)} event(s) ({status}: {reason}); skipping it")
        return status

    def _with_backoff(self, what, action, max_retries):
        """Run action() until it returns. It raises FatalError to give up, anything else to retry."""
        delay, attempt = 1.0, 0
        while True:
            try:
                return action()
            except FatalError:
                raise
            except AwsError as exc:
                if not exc.retryable and max_retries is not None:
                    raise FatalError(f"{what}: {exc}") from None
                problem = str(exc)
            except (OSError, ValueError) as exc:  # URLError, timeouts, resets, bad JSON from a proxy
                problem = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            attempt += 1
            if max_retries is not None and attempt > max_retries:
                raise FatalError(f"{what}: giving up after {max_retries} retries ({problem})")
            self.stats["retries"] += 1
            wait = min(delay, MAX_BACKOFF) * (0.5 + random.random() / 2)
            log(f"{what}: {problem}; retrying in {wait:.1f}s")
            self.sleep(wait)
            delay *= 2

    def _send(self, records, max_retries):
        def attempt():
            status = self.post(records)
            if status in (201, 207):
                self.stats["batches"] += 1
                self.stats["events"] += len(records)
            elif status in SKIP_STATUSES:
                self.stats["skipped_batches"] += 1
            else:
                hint = " (check the ingest token; it may be revoked)" if status in (401, 403) else ""
                raise OSError(f"HTTP {status}{hint}")
        self._with_backoff("Watchpost", attempt, max_retries)

    # --- one pass -------------------------------------------------------------------

    def collect_once(self, max_retries=None):
        """Read every account and region once. Returns the number of events sent or skipped."""
        total = 0
        for role_arn in self.accounts:
            for region in self.regions:
                total += self._collect(role_arn, region, max_retries)
        return total

    def _collect(self, role_arn, region, max_retries):
        name = f"{role_arn or 'own account'} {region}"
        entry = self.state.setdefault(f"{role_arn or 'default'}|{region}", {})
        end = int(self.clock())
        start = int(entry["until"]) - OVERLAP_SECONDS if "until" in entry else end - self.lookback
        seen = entry.setdefault("seen", {})
        found = self._with_backoff(name, lambda: self.lookup(role_arn, region, start, end), max_retries)
        fresh = sorted((item for item in found if item[0] not in seen), key=lambda item: item[1])
        for index in range(0, len(fresh), POST_BATCH):
            batch = fresh[index:index + POST_BATCH]
            self._send([record for _, _, record in batch], max_retries)
            seen.update({event_id: when for event_id, when, _ in batch})
            self.save_state()  # a batch that was sent is never sent again, even if the next one fails
        # Only IDs that the next poll's overlap can still return need remembering.
        entry["seen"] = {event_id: when for event_id, when in seen.items() if when >= end - 2 * OVERLAP_SECONDS}
        entry["until"] = end
        self.save_state()
        if fresh:
            log(f"{name}: {len(fresh)} new event(s)")
        return len(fresh)

    def run(self, interval=60.0):
        while True:
            self.collect_once()
            self.sleep(interval)


def read_token(args):
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    else:
        token = os.environ.get(args.token_env, "").strip()
    if not token.startswith("wp_"):
        raise FatalError(f"no ingest token: set ${args.token_env} or pass --token-file (tokens start with wp_)")
    return token


def read_credentials(environ=os.environ):
    access, secret = environ.get("AWS_ACCESS_KEY_ID", "").strip(), environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if not access or not secret:
        raise FatalError("no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY "
                         "(and AWS_SESSION_TOKEN for temporary credentials) for the read-only identity")
    return Credentials(access, secret, environ.get("AWS_SESSION_TOKEN", "").strip() or None)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read AWS CloudTrail with a read-only identity and send it to Watchpost.")
    parser.add_argument("--url", required=True, help="Watchpost base URL, e.g. https://siem.example.internal")
    parser.add_argument("--region", action="append", default=[], metavar="REGION",
                        help="AWS region to read; repeatable (default: $AWS_REGION or $AWS_DEFAULT_REGION)")
    parser.add_argument("--role-arn", action="append", default=[], metavar="ARN",
                        help="read-only role to assume, one per account; repeatable (default: the identity's own account)")
    parser.add_argument("--state", default=DEFAULT_STATE, help=f"state file (default ./{DEFAULT_STATE})")
    parser.add_argument("--source", default="cloudtrail", help="source name for the events (default cloudtrail)")
    parser.add_argument("--token-env", default="WATCHPOST_TOKEN", help="environment variable holding the ingest token")
    parser.add_argument("--token-file", help="file holding the ingest token (instead of the environment variable)")
    parser.add_argument("--lookback", type=int, default=60, metavar="MINUTES",
                        help="on the first run, how far back to read (default 60; CloudTrail keeps 90 days)")
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between polls (default 60)")
    parser.add_argument("--once", action="store_true", help="read once and exit")
    parser.add_argument("--max-retries", type=int, help="give up after N retries (default: retry forever)")
    parser.add_argument("--cafile", help="CA bundle for a self-signed Watchpost HTTPS certificate")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="allow sending the Watchpost token over plain HTTP to a non-loopback host")
    parser.add_argument("--endpoint-url", help="CloudTrail endpoint, for a VPC endpoint (default: the regional one)")
    parser.add_argument("--sts-endpoint-url", help="STS endpoint, for a VPC endpoint (default: the regional one)")
    args = parser.parse_args(argv)
    try:
        regions = args.region or [r for r in [os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")] if r]
        if not regions:
            raise FatalError("no region: pass --region or set AWS_REGION")
        collector = Collector(
            check_url(args.url, "--url", args.allow_insecure_http), read_token(args), regions, args.state,
            read_credentials(), role_arns=args.role_arn, source=args.source, lookback=args.lookback * 60,
            cafile=args.cafile,
            endpoint=args.endpoint_url and check_url(args.endpoint_url, "--endpoint-url"),
            sts_endpoint=args.sts_endpoint_url and check_url(args.sts_endpoint_url, "--sts-endpoint-url"))
        if args.once:
            collector.collect_once(max_retries=args.max_retries if args.max_retries is not None else 5)
            return 0
        collector.run(args.interval)
    except FatalError as exc:
        log(f"fatal: {exc}")
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
