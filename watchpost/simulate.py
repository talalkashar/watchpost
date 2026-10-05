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


def _event(ts, scenario, event_type, user, ip, host="web01", message=None, **extra):
    return {
        "ts": iso(ts), "source": f"demo:{scenario}", "host": host, "event_type": event_type,
        "user": user, "src_ip": ip, "dest_ip": "10.0.0.10",
        "message": message or f"[SYNTHETIC] {event_type} for {user} from {ip}",
        **extra,
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


SCAN_PROBES = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/",
               "/.aws/credentials", "/server-status", "/cgi-bin/test.cgi", "/actuator/env",
               "/index.php?id=1%27%20or%20%271%27=%271", "/search?q=1%20union%20select%20password"]


def web_scan(day, rng):
    ip, start = "203.0.113.80", _at(day, 10, 10)
    events = [_event(start + timedelta(seconds=i * 5 + rng.randint(0, 3)), "web_scan", "web_scan", None, ip,
                     message=f"GET {path} -> 404 [SYNTHETIC scanner probe]", bytes=162)
              for i, path in enumerate(SCAN_PROBES)]
    events += [_event(start + timedelta(seconds=30 * i), "web_scan", "web_request", None, f"10.0.1.{20 + i}",
                      message=f"GET /app/dashboard -> 200 [SYNTHETIC]", bytes=5120) for i in range(4)]
    return events


def port_sweep(day, rng):
    ip, start = "198.51.100.140", _at(day, 12, 15)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080]
    events = [_event(start + timedelta(seconds=i * 2), "port_sweep", "fw_deny", None, ip, host="fw01",
                     message=f"[SYNTHETIC] firewall deny {ip} -> 10.0.0.10:{port}/tcp", dest_port=port)
              for i, port in enumerate(ports)]
    events.append(_event(start + timedelta(seconds=90), "port_sweep", "fw_allow", None, "10.0.1.20", host="fw01",
                         message="[SYNTHETIC] firewall allow 10.0.1.20 -> 10.0.0.10:443/tcp", dest_port=443,
                         bytes=48_000))
    return events


def impossible_travel(day, rng):
    return [
        _event(_at(day, 9, 0), "impossible_travel", "auth_success", "erin", "10.0.1.24", host="mail01",
               message="[SYNTHETIC] Accepted password for erin (office, Riverton HQ)"),
        _event(_at(day, 9, 25), "impossible_travel", "vpn_login", "erin", "203.0.113.150", host="vpn01",
               message="[SYNTHETIC] VPN session for erin from Emberfield 25 minutes later"),
    ]


def privilege_escalation(day, rng):
    ip, start = "192.0.2.140", _at(day, 17, 30)
    events = [_event(start + timedelta(seconds=i * 20), "privilege_escalation", "auth_failure", "frank", ip)
              for i in range(3)]
    events.append(_event(start + timedelta(seconds=60), "privilege_escalation", "auth_success", "frank", ip,
                         message="[SYNTHETIC] Accepted password for frank after 3 failures"))
    events.append(_event(start + timedelta(minutes=6), "privilege_escalation", "privilege_escalation", "frank", ip,
                         message="[SYNTHETIC] frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash"))
    # A normal admin session: login without failures, then sudo. Must not alert.
    events.append(_event(_at(day, 16, 0), "privilege_escalation", "auth_success", "grace", "10.0.1.26"))
    events.append(_event(_at(day, 16, 5), "privilege_escalation", "privilege_escalation", "grace", "10.0.1.26",
                         message="[SYNTHETIC] grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; "
                                 "COMMAND=/usr/bin/systemctl restart nginx"))
    return events


def cloud_new_principal(day, rng):
    events = [_event(_at(day, 9, i * 5), "cloud_new_principal", "cloud_api_call", "ops-admin", "10.0.1.30",
                     host=None, message=f"[SYNTHETIC] {action} on {service}")
              for i, (action, service) in enumerate([("DescribeInstances", "ec2.amazonaws.com"),
                                                     ("ListBuckets", "s3.amazonaws.com"),
                                                     ("ListUsers", "iam.amazonaws.com")])]
    # A known principal changing IAM is routine.
    events.append(_event(_at(day, 9, 40), "cloud_new_principal", "cloud_iam_change", "ops-admin", "10.0.1.30",
                         host=None, message="[SYNTHETIC] AttachUserPolicy on iam.amazonaws.com"))
    # A principal never seen before creates a user and an access key.
    ip = "203.0.113.150"
    for i, action in enumerate(["CreateUser", "CreateAccessKey", "AttachUserPolicy"]):
        events.append(_event(_at(day, 17, 45) + timedelta(seconds=i * 30), "cloud_new_principal", "cloud_iam_change", "svc-deploy-tmp",
                             ip, host=None, message=f"[SYNTHETIC] {action} on iam.amazonaws.com"))
    return events


def exfiltration(day, rng):
    ip, start = "203.0.113.150", _at(day, 18, 0)
    events = [_event(start + timedelta(seconds=i * 15), "exfiltration", "cloud_data_access", "svc-deploy-tmp", ip,
                     host=None, message="[SYNTHETIC] GetObject on s3.amazonaws.com (customer-exports)",
                     bytes=50_000_000 + rng.randint(0, 1_000_000))
              for i in range(40)]
    events += [_event(_at(day, 11, i * 5), "exfiltration", "cloud_data_access", "analytics", "10.0.1.31",
                      host=None, message="[SYNTHETIC] GetObject on s3.amazonaws.com (reports)", bytes=1_000_000)
               for i in range(10)]
    return events


def shadow_it(day, rng):
    """judy uploads customer exports to a personal file-sharing service nobody approved."""
    ip, start = "10.0.1.40", _at(day, 13, 30)
    events = [_event(start + timedelta(seconds=i * 40 + rng.randint(0, 5)), "shadow_it", "cloud_data_access",
                     "judy", ip, host="proxy01", bytes=4_000_000,
                     message="[SYNTHETIC] UploadFile on personal-drive.example (customer-exports)")
              for i in range(6)]
    # The sanctioned corporate drive alongside. Must not alert.
    events += [_event(_at(day, 10, i * 7), "shadow_it", "cloud_data_access", "judy", ip, host="proxy01",
                      bytes=2_000_000, message="[SYNTHETIC] UploadFile on corp-drive.example (team-share)")
               for i in range(3)]
    return events


# --- Benign look-alikes (noise lab) ------------------------------------------------------
# Each one is ordinary activity that resembles what one rule looks for. Whether the rule
# fires on it is measured, not assumed: several of these do trip their rule.

def password_typo(day, rng):
    ip, start = "10.0.1.22", _at(day, 8, 50)
    events = [_event(start + timedelta(seconds=i * 9), "password_typo", "auth_failure", "carol", ip,
                     message="[SYNTHETIC] Failed password for carol (mistyped)") for i in range(3)]
    events.append(_event(start + timedelta(seconds=40), "password_typo", "auth_success", "carol", ip))
    return events


def stale_password_device(day, rng):
    """A phone mail client keeps retrying an old password until its owner fixes it."""
    ip, start = "10.0.1.27", _at(day, 9, 30)
    events = [_event(start + timedelta(seconds=i * 60), "stale_password_device", "auth_failure", "heidi", ip,
                     host="mail01", message="[SYNTHETIC] Failed password for heidi (phone retrying an old password)")
              for i in range(10)]
    events.append(_event(start + timedelta(seconds=630), "stale_password_device", "auth_success", "heidi", ip,
                         host="mail01", message="[SYNTHETIC] Accepted password for heidi (password updated on phone)"))
    return events


def password_expiry_nat(day, rng):
    """The morning after a password-expiry day: a whole branch office behind one NAT address."""
    ip, start = "172.16.4.1", _at(day, 8, 50)
    events = []
    for i, user in enumerate(EMPLOYEES):
        t = start + timedelta(seconds=i * 110)
        for attempt in range(2 if i % 3 == 0 else 1):
            events.append(_event(t + timedelta(seconds=attempt * 12), "password_expiry_nat", "auth_failure", user,
                                 ip, message=f"[SYNTHETIC] Failed password for {user} (expired password)"))
        events.append(_event(t + timedelta(seconds=75), "password_expiry_nat", "auth_success", user, ip,
                             message=f"[SYNTHETIC] Accepted password for {user} (after reset)"))
    return events


def oncall_admin(day, rng):
    return [_event(_at(day, 3, 0), "oncall_admin", "auth_success", "admin", "10.0.1.26", host="db01",
                   message="[SYNTHETIC] Accepted publickey for admin at 03:00 UTC (on-call, paged for a disk alert)")]


MONITOR_PATHS = ["/", "/health", "/login", "/app/dashboard", "/api/v1/status", "/static/app.css",
                 "/robots.txt", "/server-status"]


def uptime_monitor(day, rng):
    """An uptime monitor walks eight paths every five minutes for an hour.

    /server-status is on the scanner path list, so that request is a web_scan event just as
    the web log parser would classify it. At this pace the rule stays quiet; a monitor
    polling every minute would trip it.
    """
    ip, start = "10.0.60.7", _at(day, 10, 0)
    events = []
    for walk in range(12):
        for i, path in enumerate(MONITOR_PATHS):
            kind = "web_scan" if path == "/server-status" else "web_request"
            events.append(_event(start + timedelta(seconds=walk * 300 + i), "uptime_monitor", kind, None, ip,
                                 message=f"GET {path} -> 200 [SYNTHETIC uptime monitor]", bytes=512))
    return events


def authorized_port_scan(day, rng):
    """The authorized internal scanner's weekly port sweep, denied by the firewall like any other."""
    ip, start = "10.0.50.5", _at(day, 2, 0)
    ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080]
    return [_event(start + timedelta(seconds=i * 3), "authorized_port_scan", "fw_deny", None, ip, host="fw01",
                   message=f"[SYNTHETIC] firewall deny {ip} -> 10.0.0.10:{port}/tcp (authorized scan)",
                   dest_port=port) for i, port in enumerate(ports)]


def vpn_traveler(day, rng):
    """grace logs in at HQ, flies to the remote site, and connects over VPN four and a half hours later."""
    return [
        _event(_at(day, 8, 0), "vpn_traveler", "auth_success", "grace", "10.0.1.26", host="mail01",
               message="[SYNTHETIC] Accepted password for grace (office, Riverton HQ)"),
        _event(_at(day, 12, 30), "vpn_traveler", "vpn_login", "grace", "192.168.40.12", host="vpn01",
               message="[SYNTHETIC] VPN session for grace from Hillcrest remote site after a morning flight"),
    ]


def typo_then_sudo(day, rng):
    """An administrator mistypes a password three times, logs in, and restarts a service."""
    ip, start = "10.0.1.26", _at(day, 14, 30)
    events = [_event(start + timedelta(seconds=i * 8), "typo_then_sudo", "auth_failure", "grace", ip,
                     message="[SYNTHETIC] Failed password for grace (mistyped)") for i in range(3)]
    events.append(_event(start + timedelta(seconds=35), "typo_then_sudo", "auth_success", "grace", ip))
    events.append(_event(start + timedelta(minutes=2), "typo_then_sudo", "privilege_escalation", "grace", ip,
                         message="[SYNTHETIC] grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; "
                                 "COMMAND=/usr/bin/systemctl restart nginx"))
    return events


def ci_key_rotation(day, rng):
    """The CI role deploys every night, then rotates its own access key in the morning."""
    events = [_event(_at(day, 2, i * 3), "ci_key_rotation", "cloud_api_call", "ci-deploy", "10.0.7.20", host=None,
                     message=f"[SYNTHETIC] {action} on {service}")
              for i, (action, service) in enumerate([("DescribeInstances", "ec2.amazonaws.com"),
                                                     ("UpdateFunctionCode", "lambda.amazonaws.com"),
                                                     ("ListBuckets", "s3.amazonaws.com")])]
    for i, action in enumerate(["CreateAccessKey", "DeleteAccessKey"]):
        events.append(_event(_at(day, 10, 0) + timedelta(seconds=i * 20), "ci_key_rotation", "cloud_iam_change",
                             "ci-deploy", "10.0.7.20", host=None,
                             message=f"[SYNTHETIC] {action} on iam.amazonaws.com (scheduled key rotation)"))
    return events


def nightly_backup(day, rng):
    """The backup server ships about 5 GB off site at 01:00, as it did on each of the three nights before."""
    ip, events = "10.0.5.10", []
    for back in (3, 2, 1, 0):
        start = _at(day - timedelta(days=back), 1, 0)
        events += [_event(start + timedelta(seconds=i * 150), "nightly_backup", "fw_allow", None, ip, host="fw01",
                          message=f"[SYNTHETIC] firewall allow {ip} -> 198.51.100.200:443/tcp (nightly backup)",
                          dest_ip="198.51.100.200", dest_port=443, bytes=400_000_000 + rng.randint(0, 40_000_000))
                   for i in range(12)]
    return events


def sanctioned_saas(day, rng):
    """A team uses the sanctioned corporate drive through its regional endpoint."""
    return [_event(_at(day, 11, i * 6), "sanctioned_saas", "cloud_data_access", "bob", "10.0.1.21", host="proxy01",
                   bytes=3_000_000, message="[SYNTHETIC] UploadFile on eu.corp-drive.example (team-share)")
            for i in range(6)]


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
    "web_scan": {"build": web_scan, "malicious": True, "expected": {"web_scanner": "203.0.113.80"},
                 "description": "One IP probes /.env, /wp-login.php, .git and injection strings in a minute."},
    "port_sweep": {"build": port_sweep, "malicious": True, "expected": {"firewall_port_sweep": "198.51.100.140"},
                   "description": "The firewall blocks one IP on 20 different ports in 40 seconds."},
    "impossible_travel": {"build": impossible_travel, "malicious": True,
                          "expected": {"impossible_geo_login": "erin|10.0.1.24|203.0.113.150"},
                          "description": "erin logs in at HQ, then over VPN from another continent 25 minutes later."},
    "privilege_escalation": {"build": privilege_escalation, "malicious": True,
                             "expected": {"privilege_escalation_after_login": "frank|web01"},
                             "description": "3 failures, a login, then sudo to root; a normal admin sudo alongside."},
    "cloud_new_principal": {"build": cloud_new_principal, "malicious": True,
                            "expected": {"cloud_iam_change_by_new_principal": "svc-deploy-tmp"},
                            "description": "A never-seen principal creates a user and access key; a known admin's "
                                           "IAM change does not alert."},
    "exfiltration": {"build": exfiltration, "malicious": True,
                     "expected": {"data_exfil_volume": "svc-deploy-tmp"},
                     "description": "About 2 GB read from cloud storage in 10 minutes; normal report reads alongside."},
    "shadow_it": {"build": shadow_it, "malicious": True,
                  "expected": {"unsanctioned_cloud_service": "judy|personal-drive.example"},
                  "description": "judy uploads customer exports to a file-sharing service that is not sanctioned; "
                                 "her uploads to the corporate drive do not alert."},
}

# What "Load demo data" and `--scenario all` send. The look-alikes below are kept out of the demo
# dataset: the noise lab evaluates them, and any one can be replayed by name.
DEMO_SCENARIOS = list(SCENARIOS)

# Benign look-alikes: `lookalike_of` names the rule each one is written to test.
for _name in ("noisy_scanner", "noisy_scanner_repeat"):
    SCENARIOS[_name]["lookalike_of"] = "brute_force_ip"

SCENARIOS.update({
    "password_typo": {
        "build": password_typo, "malicious": False, "expected": {}, "lookalike_of": "success_after_failures",
        "description": "carol mistypes her password three times, then logs in."},
    "stale_password_device": {
        "build": stale_password_device, "malicious": False, "expected": {},
        "lookalike_of": "account_repeated_failures",
        "description": "heidi's phone retries an old password ten times in ten minutes until she updates it."},
    "password_expiry_nat": {
        "build": password_expiry_nat, "malicious": False, "expected": {}, "lookalike_of": "password_spray",
        "description": "The morning after a password-expiry day: eight users behind one branch NAT address "
                       "each fail once or twice, then log in."},
    "oncall_admin": {
        "build": oncall_admin, "malicious": False, "expected": {}, "lookalike_of": "off_hours_privileged_login",
        "description": "The on-call administrator answers a page and logs in as admin at 03:00 UTC."},
    "uptime_monitor": {
        "build": uptime_monitor, "malicious": False, "expected": {}, "lookalike_of": "web_scanner",
        "description": "An uptime monitor walks eight paths, /server-status among them, every five minutes."},
    "authorized_port_scan": {
        "build": authorized_port_scan, "malicious": False, "expected": {}, "lookalike_of": "firewall_port_sweep",
        "description": "The authorized internal scanner (10.0.50.5) sweeps 15 ports and the firewall denies them."},
    "vpn_traveler": {
        "build": vpn_traveler, "malicious": False, "expected": {}, "lookalike_of": "impossible_geo_login",
        "description": "grace logs in at HQ, takes a morning flight, and connects over VPN from the remote site "
                       "four and a half hours later."},
    "typo_then_sudo": {
        "build": typo_then_sudo, "malicious": False, "expected": {},
        "lookalike_of": "privilege_escalation_after_login",
        "description": "An administrator mistypes a password three times, logs in, and restarts a service with sudo."},
    "ci_key_rotation": {
        "build": ci_key_rotation, "malicious": False, "expected": {},
        "lookalike_of": "cloud_iam_change_by_new_principal",
        "description": "The CI role, active every night, rotates its own access key."},
    "nightly_backup": {
        "build": nightly_backup, "malicious": False, "expected": {}, "lookalike_of": "data_exfil_volume",
        "description": "The backup server ships about 5 GB off site at 01:00, as on each of the three nights before. "
                       "The lab scores this steady state; the first-ever transfer of a new job alerts until an "
                       "analyst closes it as benign."},
    "sanctioned_saas": {
        "build": sanctioned_saas, "malicious": False, "expected": {}, "lookalike_of": "unsanctioned_cloud_service",
        "description": "A team uploads to the sanctioned corporate drive through its regional endpoint."},
})


def build(scenario_names=None, seed=7, now=None):
    """Return {scenario: [events]} for the requested scenarios (default: the demo dataset)."""
    rng = random.Random(seed)
    day = demo_day(now)
    names = scenario_names or DEMO_SCENARIOS
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
