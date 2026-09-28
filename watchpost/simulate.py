"""Synthetic, clearly labeled demo data and reproducible attack simulations.

Every generated event has source "demo:<scenario>" and is stored with synthetic=1.
External-looking IPs come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so they never refer to real hosts.

Each scenario carries ground-truth labels (which rules *should* fire), which the
evaluation harness uses to measure rule accuracy.

CLI (only sends to loopback unless --allow-remote is given):
    python3 -m watchpost.simulate --list
    python3 -m watchpost.simulate --scenario brute_force --token wp_... [--url http://127.0.0.1:8080]
    python3 -m watchpost.simulate --scenario all --out demo.jsonl
"""

import argparse
import json
import random
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, time, timedelta, timezone

from .db import iso, utcnow

EMPLOYEES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]


def demo_day(now=None):
    """Most recent weekday strictly before today (UTC), so 'business hours' is well defined."""
    day = (now or utcnow()).date() - timedelta(days=1)
    while day.weekday() >= 5:
        day -= timedelta(days=1)
    return day


def _at(day, hh, mm, ss=0):
    return datetime.combine(day, time(hh, mm, ss), tzinfo=timezone.utc)


def _event(ts, scenario, event_type, user, ip, host="web01", message=None):
    return {
        "ts": iso(ts), "source": f"demo:{scenario}", "host": host, "event_type": event_type,
        "user": user, "src_ip": ip, "dest_ip": "10.0.0.10",
        "message": message or f"[SYNTHETIC] {event_type} for {user} from {ip}",
    }


def baseline(day, rng):
    events = []
    for i, user in enumerate(EMPLOYEES):
        ip = f"10.0.1.{20 + i}"
        start = _at(day, 8, 30) + timedelta(minutes=rng.randint(0, 60))
        if rng.random() < 0.4:  # the occasional typo
            events.append(_event(start - timedelta(seconds=20), "baseline", "auth_failure", user, ip))
        events.append(_event(start, "baseline", "auth_success", user, ip))
        events.append(_event(start + timedelta(hours=rng.randint(3, 7)), "baseline", "auth_success", user, ip,
                             host="files01"))
    return events


def brute_force(day, rng):
    ip, start = "203.0.113.45", _at(day, 14, 5)
    return [_event(start + timedelta(seconds=i * 4 + rng.randint(0, 2)), "brute_force", "auth_failure",
                   "admin", ip, message="[SYNTHETIC] Failed password for admin (brute-force simulation)")
            for i in range(40)]


def password_spray(day, rng):
    ip, start = "198.51.100.23", _at(day, 15, 20)
    targets = EMPLOYEES + ["hr_admin", "payroll", "backup", "helpdesk"]
    return [_event(start + timedelta(seconds=i * 35 + rng.randint(0, 5)), "password_spray", "auth_failure",
                   user, ip, message="[SYNTHETIC] Failed password (spray simulation: 'Spring2026!')")
            for i, user in enumerate(targets)]


def compromise(day, rng):
    ip, start = "192.0.2.77", _at(day, 16, 40)
    events = [_event(start + timedelta(seconds=i * 20), "compromise", "auth_failure", "dave", ip)
              for i in range(7)]
    events.append(_event(start + timedelta(seconds=160), "compromise", "auth_success", "dave", ip,
                         message="[SYNTHETIC] Accepted password for dave after repeated failures"))
    return events


def off_hours_admin(day, rng):
    return [_event(_at(day, 3, 12), "off_hours_admin", "auth_success", "root", "10.0.9.9", host="db01",
                   message="[SYNTHETIC] Accepted publickey for root at 03:12 UTC")]


def noisy_scanner(day, rng):
    """Benign but noisy: an internal vulnerability scanner. A deliberate false-positive source."""
    ip, start = "10.0.50.5", _at(day, 11, 0)
    return [_event(start + timedelta(seconds=i * 15), "noisy_scanner", "auth_failure", "svc_scan", ip,
                   message="[SYNTHETIC] Authorized internal scanner credential check")
            for i in range(12)]


def noisy_scanner_repeat(day, rng):
    """The same scanner on its afternoon pass; gives the feedback loop a second false positive."""
    ip, start = "10.0.50.5", _at(day, 13, 0)
    return [_event(start + timedelta(seconds=i * 15), "noisy_scanner", "auth_failure", "svc_scan", ip,
                   message="[SYNTHETIC] Authorized internal scanner credential check")
            for i in range(12)]


# expected: rule_id -> group_key the alert should be keyed on. Anything else firing is a false positive.
SCENARIOS = {
    "baseline": {"build": baseline, "malicious": False, "expected": {},
                 "description": "Normal office logins with occasional typos."},
    "brute_force": {"build": brute_force, "malicious": True,
                    "expected": {"brute_force_ip": "203.0.113.45", "account_repeated_failures": "admin"},
                    "description": "40 failed logins for 'admin' from one IP in under 3 minutes."},
    "password_spray": {"build": password_spray, "malicious": True,
                       "expected": {"password_spray": "198.51.100.23"},
                       "description": "One IP tries one password against 12 accounts over 7 minutes."},
    "compromise": {"build": compromise, "malicious": True,
                   "expected": {"success_after_failures": "dave|192.0.2.77"},
                   "description": "7 failures for 'dave', then a successful login from the same IP."},
    "off_hours_admin": {"build": off_hours_admin, "malicious": True,
                        "expected": {"off_hours_privileged_login": None},
                        "description": "root logs in at 03:12 UTC."},
    "noisy_scanner": {"build": noisy_scanner, "malicious": False, "expected": {},
                      "description": "Authorized internal scanner (10.0.50.5) - benign, but trips brute-force."},
    "noisy_scanner_repeat": {"build": noisy_scanner_repeat, "malicious": False, "expected": {},
                             "description": "The scanner's second pass later the same day."},
}


def build(scenario_names=None, seed=7, now=None):
    """Return {scenario: [events]} for the requested scenarios (default: all)."""
    rng = random.Random(seed)
    day = demo_day(now)
    names = scenario_names or list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        raise ValueError(f"unknown scenario(s): {', '.join(unknown)}")
    return {name: SCENARIOS[name]["build"](day, rng) for name in names}


# --- CLI ---------------------------------------------------------------------------

def _is_loopback(url):
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Send labeled synthetic attack scenarios to a local Watchpost.")
    parser.add_argument("--scenario", default="all", help="scenario name or 'all'")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", help="ingest API token (or set SIEM_INGEST_TOKEN)")
    parser.add_argument("--out", help="write JSONL to this file instead of sending")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--allow-remote", action="store_true",
                        help="permit a non-loopback URL (only for a Watchpost instance you own)")
    args = parser.parse_args(argv)

    if args.list:
        for name, spec in SCENARIOS.items():
            print(f"{name:22} {'malicious' if spec['malicious'] else 'benign':9}  {spec['description']}")
        return 0

    names = None if args.scenario == "all" else [args.scenario]
    batches = build(names, seed=args.seed)

    if args.out:
        with open(args.out, "w") as handle:
            for events in batches.values():
                for event in events:
                    handle.write(json.dumps(event) + "\n")
        print(f"wrote {sum(map(len, batches.values()))} synthetic events to {args.out}")
        return 0

    import os
    token = args.token or os.environ.get("SIEM_INGEST_TOKEN")
    if not token:
        parser.error("an ingest token is required (--token or SIEM_INGEST_TOKEN)")
    if not _is_loopback(args.url) and not args.allow_remote:
        parser.error("refusing to send to a non-loopback URL without --allow-remote")

    for name, events in batches.items():
        body = json.dumps({"source": f"demo:{name}", "synthetic": True, "events": events}).encode()
        request = urllib.request.Request(
            args.url.rstrip("/") + "/api/ingest", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            print(f"{name}: HTTP {exc.code} {exc.read().decode()[:200]}", file=sys.stderr)
            return 1
        det = result["detection"]
        print(f"{name:22} accepted={result['accepted']:3} rejected={result['rejected']} "
              f"detection={det['status']} alerts_created={det.get('alerts_created', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
