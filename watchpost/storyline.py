"""Attack storyline mode: a scripted, clearly synthetic six-stage intrusion replayed over wall-clock time.

This is demo data, like `simulate.py`, but paced so a viewer can watch the dashboard react.
`build(seed, speed)` returns a deterministic timeline of (offset_seconds, event, stage) tuples.
`Runner` replays that timeline on a background thread, feeding batches through the same
in-process ingest path the demo loader uses (parse -> engine.ingest -> detection -> correlation),
so alerts, incidents, and the SSE stream all light up as the story unfolds.

Every record is stored with synthetic=1, tagged source "demo:storyline", and uses RFC 5737
documentation IPs and fictional hosts and users. Nothing leaves the process.
"""

import json
import random
import threading
import time
from datetime import timedelta

from . import engine, health
from .db import audit, iso, now_iso, utcnow
from .diagnostics import describe_exception, record_error
from .normalize import parse_payload
from .simulate import EMPLOYEES, SCAN_PROBES

SOURCE = "demo:storyline"
ATTACKER_IP = "203.0.113.80"          # RFC 5737 TEST-NET-3
ATTACKER_VPN_IP = "198.51.100.140"    # RFC 5737 TEST-NET-2
VICTIM_USER = "dave"
ROGUE_PRINCIPAL = "svc-deploy-tmp"
STORY_SECONDS = 120                   # story length at speed 1
BATCH_SECONDS = 4                     # story seconds per ingest batch

STAGES = [
    ("recon", 0, "Reconnaissance: web probes and a port sweep from one external address"),
    ("credential_attack", 20, "Credential attack: password spray, then brute force on one account"),
    ("foothold", 48, "Foothold: the brute-forced account logs in over VPN"),
    ("escalation", 62, "Escalation: sudo to root on web01, a new service account is created"),
    ("lateral_cloud", 80, "Lateral movement: login to db01, cloud IAM key created by the new principal"),
    ("exfiltration", 96, "Exfiltration: bulk cloud storage reads and large outbound transfers"),
]


def _rec(offset, stage, event_type, user, ip, host="web01", message=None, **extra):
    return offset, {
        "source": SOURCE, "host": host, "event_type": event_type, "user": user, "src_ip": ip,
        "dest_ip": "10.0.0.10", "message": message or f"[SYNTHETIC] {event_type} for {user} from {ip}",
        **extra,
    }, stage


def _baseline(rng):
    """Normal activity spread across the whole story so the attack stands out against a living system."""
    out = []
    for i in range(24):
        t = i * 5 + rng.randint(0, 2)
        who = EMPLOYEES[i % len(EMPLOYEES)]
        ip = f"10.0.1.{20 + (i % 8)}"
        out.append(_rec(t, "baseline", "auth_success", who, ip, message=f"[SYNTHETIC] Accepted password for {who} from {ip}"))
        out.append(_rec(t + 1, "baseline", "web_request", who, ip,
                        message="GET /app/dashboard -> 200 [SYNTHETIC]", bytes=rng.randint(2000, 9000)))
        if i % 3 == 0:
            out.append(_rec(t + 2, "baseline", "fw_allow", None, ip, host="fw01",
                            message=f"[SYNTHETIC] firewall allow {ip} -> 10.0.0.10:443/tcp", dest_port=443, bytes=rng.randint(10_000, 90_000)))
    out.append(_rec(30, "baseline", "auth_failure", "carol", "10.0.1.22", message="[SYNTHETIC] Failed password for carol from 10.0.1.22 (typo)"))
    return out


def _recon(rng):
    out = [_rec(i * 1.2, "recon", "web_scan", None, ATTACKER_IP,
                message=f"GET {path} -> 404 [SYNTHETIC scanner probe]", bytes=162)
           for i, path in enumerate(SCAN_PROBES)]
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080]
    out += [_rec(6 + i * 0.6, "recon", "fw_deny", None, ATTACKER_IP, host="fw01",
                 message=f"[SYNTHETIC] firewall deny {ATTACKER_IP} -> 10.0.0.10:{port}/tcp", dest_port=port)
            for i, port in enumerate(ports)]
    return out


def _credential_attack(rng):
    base = 20
    out = [_rec(base + i * 0.8, "credential_attack", "auth_failure", EMPLOYEES[i % len(EMPLOYEES)], ATTACKER_IP,
                message=f"[SYNTHETIC] Failed password for {EMPLOYEES[i % len(EMPLOYEES)]} from {ATTACKER_IP}")
           for i in range(8)]
    out += [_rec(base + 8 + i * 1.0, "credential_attack", "auth_failure", VICTIM_USER, ATTACKER_IP,
                 message=f"[SYNTHETIC] Failed password for {VICTIM_USER} from {ATTACKER_IP}")
            for i in range(18)]
    return out


def _foothold(rng):
    return [
        _rec(48, "foothold", "vpn_login", VICTIM_USER, ATTACKER_IP, host="vpn01",
             message=f"[SYNTHETIC] VPN session established for {VICTIM_USER} from {ATTACKER_IP}"),
        _rec(50, "foothold", "auth_success", VICTIM_USER, ATTACKER_IP,
             message=f"[SYNTHETIC] Accepted password for {VICTIM_USER} from {ATTACKER_IP}"),
        _rec(55, "foothold", "process_start", VICTIM_USER, ATTACKER_IP,
             message="[SYNTHETIC] process start: /usr/bin/id"),
    ]


def _escalation(rng):
    return [
        _rec(62, "escalation", "privilege_escalation", VICTIM_USER, ATTACKER_IP,
             message=f"[SYNTHETIC] {VICTIM_USER} : TTY=pts/0 ; COMMAND=/bin/bash (sudo to root)"),
        _rec(68, "escalation", "user_created", VICTIM_USER, ATTACKER_IP,
             message=f"[SYNTHETIC] new user: name={ROGUE_PRINCIPAL}, UID=1099, groups=sudo"),
        _rec(72, "escalation", "file_access", "root", ATTACKER_IP,
             message="[SYNTHETIC] read /etc/shadow"),
    ]


def _lateral_cloud(rng):
    return [
        _rec(80, "lateral_cloud", "auth_success", VICTIM_USER, "10.0.0.10", host="db01",
             message=f"[SYNTHETIC] Accepted publickey for {VICTIM_USER} from 10.0.0.10 (web01)"),
        _rec(87, "lateral_cloud", "cloud_iam_change", ROGUE_PRINCIPAL, ATTACKER_VPN_IP, host=None,
             message="[SYNTHETIC] iam:CreateAccessKey for svc-deploy-tmp"),
        _rec(90, "lateral_cloud", "cloud_iam_change", ROGUE_PRINCIPAL, ATTACKER_VPN_IP, host=None,
             message="[SYNTHETIC] iam:AttachUserPolicy AdministratorAccess"),
    ]


def _exfiltration(rng):
    out = [_rec(96 + i * 0.5, "exfiltration", "cloud_data_access", ROGUE_PRINCIPAL, ATTACKER_VPN_IP, host=None,
                message="[SYNTHETIC] GetObject on s3.amazonaws.com (customer-exports)",
                bytes=50_000_000 + rng.randint(0, 1_000_000))
           for i in range(40)]
    out += [_rec(100 + i * 4, "exfiltration", "fw_allow", None, "10.0.0.10", host="fw01",
                 message=f"[SYNTHETIC] firewall allow 10.0.0.10 -> {ATTACKER_VPN_IP}:443/tcp", dest_port=443,
                 bytes=400_000_000)
            for i in range(4)]
    return out


def build(seed=7, speed=1.0):
    """Ordered timeline of (offset_seconds, event, stage). Deterministic for a seed; `speed` only validates."""
    if not (0.1 <= float(speed) <= 10_000):
        raise ValueError("speed must be between 0.1 and 10000")
    rng = random.Random(seed)
    timeline = []
    for part in (_baseline, _recon, _credential_attack, _foothold, _escalation, _lateral_cloud, _exfiltration):
        timeline.extend(part(rng))
    timeline.sort(key=lambda item: item[0])
    return timeline


def stage_at(offset):
    """Name of the attack stage active at a story offset."""
    current = STAGES[0][0]
    for name, start, _ in STAGES:
        if offset >= start:
            current = name
    return current


# --- Runner ---------------------------------------------------------------------------

class Runner:
    """Replays one storyline on a background thread. One runner per App; start() refuses while alive."""

    def __init__(self, open_conn):
        self._open_conn = open_conn
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self.status = {"running": False, "stage": None, "progress": 0.0, "events_sent": 0,
                       "alerts_created": 0, "started_at": None, "finished_at": None, "error": None,
                       "speed": None, "seed": None, "started_by": None}
        health.register_check("storyline", self.health_check)

    def start(self, speed=1.0, seed=7, started_by="system"):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self._stop.clear()
            self.status.update({"running": True, "stage": STAGES[0][0], "progress": 0.0, "events_sent": 0,
                                "alerts_created": 0, "started_at": now_iso(), "finished_at": None,
                                "error": None, "speed": float(speed), "seed": int(seed), "started_by": started_by})
            self._thread = threading.Thread(target=self._run, args=(float(speed), int(seed), started_by),
                                            name="storyline", daemon=True)
            self._thread.start()
            return True

    def stop(self):
        self._stop.set()

    def join(self, timeout=None):
        if self._thread:
            self._thread.join(timeout)

    def snapshot(self):
        return dict(self.status)

    def health_check(self):
        s = self.status
        if s["error"]:
            return ("degraded", f"last storyline run failed: {s['error']}",
                    "Check the error log; storyline runs only touch synthetic data.", {"started_at": s["started_at"]})
        detail = {"running": s["running"], "stage": s["stage"], "events_sent": s["events_sent"]}
        return "ok", ("storyline running" if s["running"] else "storyline idle"), None, detail

    def _run(self, speed, seed, started_by):
        conn = None
        try:
            conn = self._open_conn()
            timeline = build(seed, speed)
            start = utcnow()
            wall_start = time.monotonic()
            index, total = 0, len(timeline)
            while index < total and not self._stop.is_set():
                # Ship every record whose story offset has been reached, in fixed story-time buckets.
                bucket_end = timeline[index][0] + BATCH_SECONDS
                batch = []
                while index < total and timeline[index][0] < bucket_end:
                    offset, event, stage = timeline[index]
                    batch.append(dict(event, ts=iso(start + timedelta(seconds=offset))))
                    index += 1
                last_offset = timeline[index - 1][0]
                target_wall = wall_start + last_offset / speed
                while not self._stop.is_set():
                    remaining = target_wall - time.monotonic()
                    if remaining <= 0:
                        break
                    self._stop.wait(min(remaining, 0.25))
                if self._stop.is_set():
                    break
                normalized, rejections = parse_payload(json.dumps(batch), "json", SOURCE)
                result = engine.ingest(conn, normalized, rejections, SOURCE, "json", f"storyline:{started_by}",
                                       synthetic=True)
                self.status["events_sent"] += result.get("accepted", 0)
                self.status["alerts_created"] += (result.get("detection") or {}).get("alerts_created", 0) or 0
                self.status["stage"] = stage_at(last_offset)
                self.status["progress"] = round(min(1.0, index / total), 3)
            stopped = self._stop.is_set()
            self.status["progress"] = self.status["progress"] if stopped else 1.0
            audit(conn, started_by, "storyline_stopped" if stopped else "storyline_finished", None,
                  {"seed": seed, "speed": speed, "events_sent": self.status["events_sent"],
                   "alerts_created": self.status["alerts_created"]})
        except Exception as exc:  # never take the server down for a demo
            self.status["error"] = describe_exception(exc)
            try:
                if conn is not None:
                    record_error(conn, "storyline", exc)
            except Exception:
                pass
        finally:
            self.status["running"] = False
            self.status["finished_at"] = now_iso()
            if conn is not None:
                conn.close()


def run_once_fast(open_conn, seed=7, speed=1000.0, started_by="test"):
    """Convenience for tests and the smoke check: replay the whole storyline and wait for it."""
    runner = Runner(open_conn)
    runner.start(speed=speed, seed=seed, started_by=started_by)
    runner.join(timeout=120)
    health.unregister_check("storyline", runner.health_check)
    return runner.snapshot()


class DemoLoop:
    """Restarts the storyline every N minutes for unattended public demos (SIEM_DEMO_LOOP=<minutes>)."""

    def __init__(self, runner, minutes, speed=1.0):
        self.runner, self.minutes, self.speed = runner, minutes, speed
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="storyline-loop", daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self.runner.stop()

    def _run(self):
        while not self._stop.is_set():
            self.runner.start(speed=self.speed, seed=7, started_by="demo-loop")
            self._stop.wait(self.minutes * 60)


def start_if_enabled(app):
    """Called from main.py. Returns the running loop, or None when SIEM_DEMO_LOOP is 0."""
    minutes = getattr(app.config, "demo_loop_minutes", 0)
    if minutes <= 0:
        return None
    return DemoLoop(app.storyline, minutes, getattr(app.config, "demo_loop_speed", 1.0)).start()
