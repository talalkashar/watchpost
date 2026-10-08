#!/usr/bin/env python3
"""Reproducible load test: ingest N synthetic events, run detection once, time the hot read paths.

    python3 scripts/loadtest.py                      # 100,000 events into a throwaway DB under /tmp
    python3 scripts/loadtest.py --events 250000 --json
    python3 scripts/loadtest.py --url http://127.0.0.1:8090 --token wp_... --db /path/to/server.db

Everything is seeded (--seed), so two runs on the same UTC day build the same events (timestamps are relative
to the demo day, as in watchpost/simulate.py). The mix is a week of background activity (2,000 users, 200
hosts, about 3,800 IPs, 18 event types, a few very busy accounts) plus the labeled demo scenarios, so
detection has real attacks to find. Every event is stored synthetic=1.

Ingest goes through the /api/ingest route's own code path (JSON parse, normalization, storage, detection on
the batch's time range), in time-ordered batches like a live feed. With --url it goes over HTTP instead, to a
server you started yourself (loopback only, never port 8080); reads are then timed in-process against --db,
which must be that server's database file. Reads call the route handlers with a fake request, so the numbers
include the handler and JSON encoding but no HTTP. These are one machine's numbers, not a benchmark.
"""

import argparse
import json
import os
import platform
import random
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SIEM_PBKDF2_ITERATIONS", "1000")  # throwaway accounts; hashing cost is not measured

from watchpost import engine, server, simulate  # noqa: E402
from watchpost.config import Config  # noqa: E402
from watchpost.db import iso  # noqa: E402

PASSWORD = "loadtest-password-1"

# (event_type, weight, source). Weights are rough shares of a small office's log volume.
MIX = [
    ("web_request", 22, "nginx"), ("auth_success", 16, "sshd"), ("fw_allow", 12, "fw01"),
    ("network_connection", 9, "zeek"), ("auth_failure", 7, "sshd"), ("fw_deny", 7, "fw01"),
    ("process_start", 6, "sysmon"), ("file_access", 4, "sysmon"), ("cloud_api_call", 4, "cloudtrail"),
    ("web_error", 3, "nginx"), ("syslog", 3, "syslog"), ("privilege_use", 2, "sudo"),
    ("vpn_login", 2, "vpn01"), ("cloud_data_access", 1, "cloudtrail"), ("other", 1, "misc"),
    ("account_lockout", 0.3, "ad"), ("web_scan", 0.3, "nginx"), ("user_created", 0.1, "ad"),
]
PORTS = [22, 53, 80, 123, 443, 445, 3306, 3389, 5432, 8080, 8443]
PATHS = ["/", "/login", "/app/dashboard", "/api/v1/items", "/static/app.js", "/reports", "/search"]
PROCESSES = ["bash", "python3", "curl", "systemd", "cron", "sshd", "nginx", "postgres", "java"]


def generate(n, seed, days=7, users=2000, hosts=200, internal_ips=3000, now=None):
    """N events, time-ordered: background activity over `days` ending at the demo day, plus the demo scenarios."""
    rng = random.Random(seed)
    day = simulate.demo_day(now)
    end = datetime.combine(day, dtime(23, 59), tzinfo=timezone.utc)
    span = days * 86400
    scenarios = [e for events in simulate.build(seed=seed, now=now).values() for e in events]
    user_names = [f"user{i:04d}" for i in range(users)]
    host_names = [f"{kind}{i:03d}" for i in range(hosts) for kind in ("web", "app", "db", "wks")][:hosts]
    internal = [f"10.{(i >> 8) % 4}.{i & 255}.{(i * 7) % 250 + 2}" for i in range(internal_ips)]
    external = [f"{net}.{h}" for net in ("192.0.2", "198.51.100", "203.0.113") for h in range(1, 255)]
    types, weights, sources = zip(*MIX)
    events = []
    for _ in range(max(0, n - len(scenarios))):
        kind = rng.choices(range(len(types)), weights)[0]
        event_type, source = types[kind], sources[kind]
        # A few busy accounts and a long tail. Failed logins spread evenly (a typo here and there), and
        # privileged actions come from a small admin team at its usual addresses, as in a real office.
        user = user_names[min(int(rng.paretovariate(1.2)) - 1, users - 1) if rng.random() < 0.5
                          and event_type != "auth_failure" else rng.randrange(users)]
        src = rng.choice(external) if event_type in ("fw_deny", "web_scan", "web_request") and rng.random() < 0.6 \
            else rng.choice(internal)
        if event_type == "privilege_use":
            admin = rng.randrange(20)
            user, src = f"admin{admin:02d}", internal[admin * 2 + rng.randrange(2)]
        host = rng.choice(host_names)
        ts = end - timedelta(seconds=rng.random() * span)
        event = {"ts": iso(ts), "source": source, "host": host, "event_type": event_type, "user": user,
                 "src_ip": src, "dest_ip": rng.choice(internal)}
        if event_type.startswith("fw_") or event_type == "network_connection":
            event["dest_port"] = rng.choice(PORTS)
            event["bytes"] = rng.randint(64, 200_000)
            event["message"] = f"[SYNTHETIC] {event_type} {src} -> {event['dest_ip']}:{event['dest_port']}"
        elif event_type.startswith("web_"):
            event["message"] = f"[SYNTHETIC] GET {rng.choice(PATHS)} {404 if event_type == 'web_error' else 200}"
        elif event_type == "process_start":
            event["message"] = f"[SYNTHETIC] process {rng.choice(PROCESSES)} started by {user}"
        else:
            event["message"] = f"[SYNTHETIC] {event_type} for {user} from {src} on {host}"
        events.append(event)
    events = (events + scenarios)[:n] if n < len(scenarios) else events + scenarios
    events.sort(key=lambda e: e["ts"])
    return events


def fake_request(app, query=None, body=b""):
    return SimpleNamespace(app=app, conn=app.conn(), query=query or {}, body=body, status=200,
                           user={"username": "admin", "role": "admin"})


def ingest_in_process(app, events, batch):
    """Each batch through the /api/ingest handler; returns (seconds, seconds spent in detection, alerts made)."""
    detection = {"seconds": 0.0, "alerts": 0}
    real = engine.run_detection

    def timed(*args, **kwargs):
        started = time.perf_counter()
        result = real(*args, **kwargs)
        detection["seconds"] += time.perf_counter() - started
        detection["alerts"] += result.get("alerts_created", 0)
        return result

    engine.run_detection = timed
    try:
        started = time.perf_counter()
        for i in range(0, len(events), batch):
            body = json.dumps({"source": "loadtest", "synthetic": True, "events": events[i:i + batch]}).encode()
            req = fake_request(app, body=body)
            try:
                result = server.ingest_json(req)
            finally:
                req.conn.close()
            if result["rejected"]:
                raise SystemExit(f"batch {i // batch}: {result['rejected']} rejected: {result['rejections'][:3]}")
        return time.perf_counter() - started, detection["seconds"], detection["alerts"]
    finally:
        engine.run_detection = real


def ingest_http(url, token, events, batch):
    started = time.perf_counter()
    for i in range(0, len(events), batch):
        body = json.dumps({"source": "loadtest", "synthetic": True, "events": events[i:i + batch]}).encode()
        request = urllib.request.Request(url.rstrip("/") + "/api/ingest", data=body, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(request, timeout=600) as response:
                json.load(response)
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"batch {i // batch}: HTTP {exc.code} {exc.read().decode()[:200]}")
    return time.perf_counter() - started


def call(app, path):
    """GET a route in-process: the same handler lookup as server.Handler._handle, then JSON-encode the result."""
    parsed = urllib.parse.urlparse(path)
    query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    for method, pattern, fn, _, _ in server.ROUTES:
        match = pattern.match(parsed.path)
        if match and method == "GET":
            break
    else:
        raise SystemExit(f"no GET route for {parsed.path}")
    req = fake_request(app, query)
    try:
        return json.dumps(fn(req, *match.groups()))
    finally:
        req.conn.close()


def read_paths(app, events):
    """(label, path) for each hot read. Filter values are picked from the generated data with a fixed rule."""
    conn = app.conn()
    try:
        user = conn.execute("SELECT user FROM events WHERE user LIKE 'user%' GROUP BY user"
                            " ORDER BY COUNT(*) DESC, user LIMIT 1").fetchone()[0]
        ip = conn.execute("SELECT src_ip FROM events WHERE src_ip LIKE '10.%' GROUP BY src_ip"
                          " ORDER BY COUNT(*) DESC, src_ip LIMIT 1").fetchone()[0]
        host = conn.execute("SELECT host FROM events GROUP BY host ORDER BY COUNT(*) DESC, host LIMIT 1").fetchone()[0]
        alert = conn.execute("SELECT MIN(id) FROM alerts").fetchone()[0]
    finally:
        conn.close()
    newest = events[-1]["ts"]
    day_before = iso(datetime.fromisoformat(newest.replace("Z", "+00:00")) - timedelta(days=1))
    q = urllib.parse.quote
    paths = [
        ("events: no filter", "/api/events"),
        ("events: user", f"/api/events?user={q(user.upper())}"),
        ("events: user prefix", "/api/events?user=user01*"),
        ("events: ip (src or dest)", f"/api/events?ip={ip}"),
        ("events: host", f"/api/events?host={host}"),
        ("events: type + last day", f"/api/events?event_type=auth_failure&start={q(day_before)}"),
        ("events: severity >= high", "/api/events?severity=high&severity_mode=min"),
        ("events: message text", "/api/events?q=dashboard"),
        ("events: page 50", "/api/events?offset=5000&limit=100"),
        ("hunt: user + type", f"/api/hunt?q={q(f'user:{user} event_type:auth_failure')}"),
        ("hunt: ip", f"/api/hunt?q={q(f'ip:{ip}')}"),
        ("hunt: host prefix + NOT", f"/api/hunt?q={q('host:db* NOT event_type:fw_allow')}"),
        ("hunt: message", f"/api/hunt?q={q(chr(34) + 'GET /reports' + chr(34))}"),
        ("alerts: list", "/api/alerts"),
        ("alerts: open", "/api/alerts?status=open"),
        ("dashboard", "/api/dashboard"),
        ("metrics", "/api/metrics"),
        ("entities: list", "/api/entities"),
        ("entity: user", f"/api/entities/user/{q(user)}"),
        ("entity: src_ip", f"/api/entities/src_ip/{q(ip)}"),
        ("entity: host", f"/api/entities/host/{q(host)}"),
        ("attack coverage", "/api/attack/coverage"),
        ("noise lab", "/api/noise-lab"),
    ]
    if alert:
        paths.insert(15, ("alert detail", f"/api/alerts/{alert}"))
    return paths


def percentile(samples, pct):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1)))]


def time_reads(app, paths, repeat):
    rows = []
    for label, path in paths:
        call(app, path)  # warm the page cache and any in-process cache once; not counted
        samples = []
        for _ in range(repeat):
            started = time.perf_counter()
            call(app, path)
            samples.append((time.perf_counter() - started) * 1000)
        rows.append({"path": label, "request": path, "p50_ms": round(percentile(samples, 50), 1),
                     "p95_ms": round(percentile(samples, 95), 1)})
    return rows


def db_size(path):
    return sum(os.path.getsize(p) for p in (path, path + "-wal") if os.path.exists(p))


def machine():
    return {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
            "cpus": os.cpu_count()}


def run(args):
    if args.url:
        parsed = urllib.parse.urlparse(args.url)
        if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit("--url must be a loopback address")
        if parsed.port == 8080 or parsed.port is None:
            raise SystemExit("--url must name a port other than 8080 (e.g. 8090)")
        if not (args.token and args.db):
            raise SystemExit("--url needs --token (an ingest token) and --db (that server's database file)")
    tmp = None
    if not args.db:
        tmp = tempfile.mkdtemp(prefix="watchpost-load-", dir="/tmp")
        args.db = os.path.join(tmp, "load.db")
    config = Config.from_env(db_path=args.db, admin_password=PASSWORD, analyst_password=PASSWORD,
                             max_batch_events=max(args.batch, 20000), rate_limit_enabled=False)
    app = server.App(config)

    started = time.perf_counter()
    events = generate(args.events, args.seed)
    generate_s = time.perf_counter() - started

    detection_s, alerts = None, None
    if args.url:
        ingest_s = ingest_http(args.url, args.token, events, args.batch)
    else:
        ingest_s, detection_s, alerts = ingest_in_process(app, events, args.batch)

    req = fake_request(app)
    try:
        started = time.perf_counter()
        full = engine.run_detection(req.conn, trigger="loadtest")
        full_s = time.perf_counter() - started
        stored = req.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_count = req.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        incidents = req.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        req.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        req.conn.close()

    report = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "command": "python3 scripts/loadtest.py " + " ".join(args.argv),
        "machine": machine(),
        "seed": args.seed, "events": len(events), "events_stored": stored, "batch": args.batch,
        "mode": "http" if args.url else "in-process",
        "generate_s": round(generate_s, 2),
        "ingest_s": round(ingest_s, 2),
        "ingest_events_per_s": round(len(events) / ingest_s),
        "ingest_detection_s": round(detection_s, 2) if detection_s is not None else None,
        "full_detection_s": round(full_s, 2), "full_detection_status": full["status"],
        "full_detection_events_scanned": full["events_scanned"],
        "alerts": alert_count, "incidents": incidents, "alerts_created_on_ingest": alerts,
        "db_bytes": db_size(args.db),
        "reads": time_reads(app, read_paths(app, events), args.repeat),
        "repeat": args.repeat,
    }
    if tmp and not args.keep:
        for name in os.listdir(tmp):
            os.remove(os.path.join(tmp, name))
        os.rmdir(tmp)
    return report


def markdown(report):
    m = report["machine"]
    lines = [
        f"Watchpost load test, {report['date']}: {report['events']:,} synthetic events (seed {report['seed']}, "
        f"batches of {report['batch']}, {report['mode']})",
        f"Machine: Python {m['python']}, {m['platform']}, {m['cpus']} CPUs. "
        f"DB on disk: {report['db_bytes'] / 1e6:.1f} MB.",
        "",
        "| Step | Result |",
        "|---|---|",
        f"| Ingest (parse, normalize, store, detect per batch) | {report['ingest_s']} s, "
        f"{report['ingest_events_per_s']:,} events/s |",
    ]
    if report["ingest_detection_s"] is not None:
        lines.append(f"| of which per-batch detection | {report['ingest_detection_s']} s |")
    lines += [
        f"| Full detection run ({report['full_detection_events_scanned']:,} events) | "
        f"{report['full_detection_s']} s ({report['full_detection_status']}) |",
        f"| Alerts / incidents after the run | {report['alerts']} / {report['incidents']} |",
        "",
        f"| Read path (route handler + JSON, {report['repeat']} runs) | p50 ms | p95 ms |",
        "|---|---:|---:|",
    ]
    lines += [f"| {r['path']} | {r['p50_ms']} | {r['p95_ms']} |" for r in report["reads"]]
    return "\n".join(lines)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description="Watchpost load test (synthetic data, one machine).")
    parser.add_argument("--events", type=int, default=100_000)
    parser.add_argument("--batch", type=int, default=1000, help="events per ingest request")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--repeat", type=int, default=20, help="timed runs per read path")
    parser.add_argument("--db", help="database file (default: a throwaway one under /tmp)")
    parser.add_argument("--keep", action="store_true", help="keep the throwaway database")
    parser.add_argument("--url", help="ingest over HTTP to this loopback server (not port 8080), e.g. :8090")
    parser.add_argument("--token", help="ingest API token for --url")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a markdown table")
    args = parser.parse_args(argv)
    if args.events < 1 or args.batch < 1 or args.repeat < 1:
        parser.error("--events, --batch and --repeat must be positive")
    args.argv = argv
    report = run(args)
    print(json.dumps(report, indent=2) if args.json else markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
