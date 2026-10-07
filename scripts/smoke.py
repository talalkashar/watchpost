#!/usr/bin/env python3
"""End-to-end smoke check against a real server process with a throwaway database.

Flow: start server -> health -> login -> create ingest token -> upload sample files
-> run the attack simulation CLI with the token -> search -> investigate and resolve
an alert -> feedback suggestion -> second-person approval -> verify health -> stop.

Exits non-zero on the first failed step. Never touches data/ or any external host.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
ADMIN_PW, ANALYST_PW, VIEWER_PW = "smoke-admin-password", "smoke-analyst-password", "smoke-viewer-password"
STEP = 0


def step(message):
    global STEP
    STEP += 1
    print(f"[{STEP:02d}] {message}")


def check(condition, message):
    if not condition:
        print(f"      FAIL: {message}")
        raise SystemExit(1)


class Session:
    def __init__(self, base):
        self.base, self.csrf = base, None
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def call(self, method, path, body=None, raw=None, ctype="application/json", headers=None):
        headers = dict(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            headers["Content-Type"] = ctype
        if method == "POST" and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"null")

    def download(self, path):
        req = urllib.request.Request(self.base + path)
        try:
            with self.opener.open(req, timeout=60) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read(), exc.headers

    def login(self, user, password):
        status, data = self.call("POST", "/api/auth/login", {"username": user, "password": password})
        check(status == 200, f"login as {user} returned {status}: {data}")
        self.csrf = data["csrf_token"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    tmp = tempfile.TemporaryDirectory()
    port, syslog_port = free_port(), free_port()
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "SIEM_DB": os.path.join(tmp.name, "smoke.db"), "SIEM_HOST": "127.0.0.1",
           "SIEM_PORT": str(port), "SIEM_ADMIN_PASSWORD": ADMIN_PW, "SIEM_ANALYST_PASSWORD": ANALYST_PW,
           "SIEM_VIEWER_PASSWORD": VIEWER_PW,
           "SIEM_SYSLOG": "1", "SIEM_SYSLOG_PORT": str(syslog_port)}
    log_path = os.path.join(tmp.name, "server.log")
    log_file = open(log_path, "w")
    proc = subprocess.Popen([sys.executable, "main.py"], cwd=ROOT, env=env, stdout=log_file, stderr=log_file)
    try:
        step("server starts and reports healthy")
        for _ in range(50):
            try:
                with urllib.request.urlopen(base + "/api/health", timeout=2) as r:
                    health = json.load(r)
                break
            except OSError:
                time.sleep(0.2)
        else:
            check(False, "server did not start; see log:\n" + Path(log_path).read_text())
        check(health["status"] == "ok", f"health: {health}")
        with urllib.request.urlopen(base + "/", timeout=5) as r:
            check(b"Watchpost" in r.read(), "UI index not served")

        admin, analyst = Session(base), Session(base)
        step("unauthenticated API access is refused")
        check(Session(base).call("GET", "/api/alerts")[0] == 401, "alerts readable without login")
        admin.login("admin", ADMIN_PW)
        analyst.login("analyst", ANALYST_PW)

        step("admin creates an ingest-only API token")
        status, tok = admin.call("POST", "/api/tokens", {"name": "smoke"})
        check(status == 201 and tok["token"].startswith("wp_"), f"token: {status}")

        step("sample files upload through the API")
        for name, fmt in [("auth.log", "authlog"), ("windows_security.jsonl", "jsonl"), ("vpn_events.csv", "csv"),
                          ("nginx_access.log", "weblog"), ("firewall.csv", "csv"), ("cloudtrail.json", "json"),
                          ("linux_host.log", "authlog")]:
            text = (ROOT / "samples" / name).read_bytes()
            status, res = analyst.call("POST", f"/api/ingest/upload?format={fmt}&source=sample-{fmt}&synthetic=1&year=2026",
                                       raw=text, ctype="text/plain")
            check(status in (201, 207) and res["accepted"] > 0, f"{name}: {status} {res}")
            check(res["detection"]["status"] == "ok", f"{name}: detection {res['detection']}")
            print(f"      {name}: accepted={res['accepted']} rejected={res['rejected']} "
                  f"alerts_created={res['detection']['alerts_created']}")

        step("attack simulation CLI sends labeled scenarios with the token")
        out = subprocess.run([sys.executable, "-m", "watchpost.simulate", "--url", base, "--token", tok["token"]],
                             cwd=ROOT, capture_output=True, text=True, timeout=120)
        check(out.returncode == 0, out.stderr)
        print("      " + out.stdout.strip().replace("\n", "\n      "))
        refused = subprocess.run([sys.executable, "-m", "watchpost.simulate", "--url", "http://example.com",
                                  "--token", "wp_x"], cwd=ROOT, capture_output=True, text=True)
        check(refused.returncode != 0 and "non-loopback" in refused.stderr, "simulator accepted a remote URL")

        step("token cannot read data")
        check(Session(base).call("GET", "/api/events", headers={"Authorization": f"Bearer {tok['token']}"})[0] == 403,
              "token could read events")

        step("search filters return the attack traffic")
        status, res = analyst.call("GET", "/api/events?ip=203.0.113.45&event_type=auth_failure")
        check(status == 200 and res["total"] >= 40, f"search: {res.get('total')}")
        status, res = analyst.call("GET", "/api/events?source=demo:sample-authlog")
        check(res["total"] > 0, "sample auth.log events not searchable")

        step("expected alerts exist")
        status, alerts = analyst.call("GET", "/api/alerts")
        rules_fired = {a["rule_id"] for a in alerts}
        expected = {"brute_force_ip", "password_spray", "account_repeated_failures",
                    "success_after_failures", "off_hours_privileged_login", "web_scanner", "firewall_port_sweep",
                    "impossible_geo_login", "privilege_escalation_after_login", "cloud_iam_change_by_new_principal",
                    "data_exfil_volume", "unsanctioned_cloud_service"}
        check(expected <= rules_fired, f"missing rules: {expected - rules_fired}")
        print(f"      {len(alerts)} alerts across {len(rules_fired)} rules")

        step("alerts are correlated into incidents with ATT&CK stages")
        status, incidents = analyst.call("GET", "/api/incidents")
        check(status == 200 and incidents, f"incidents: {status} {incidents}")
        multi = [i for i in incidents if len(i["stages"]) >= 2]
        check(multi, f"no multi-stage incident: {[i['title'] for i in incidents]}")
        status, detail = analyst.call("GET", f"/api/incidents/{multi[0]['id']}")
        check(status == 200 and detail["alerts"] and detail["timeline"] and detail["techniques"], "incident detail")
        print(f"      {len(incidents)} incidents; e.g. #{detail['id']} {detail['title']} ({detail['severity']})")

        step("attack storyline replays end to end at high speed (admin only)")
        check(analyst.call("POST", "/api/storyline/start", {"speed": 1000})[0] == 403, "analyst could start the storyline")
        status, story = admin.call("POST", "/api/storyline/start", {"speed": 1000})
        check(status == 202 and story["running"], f"storyline start: {status} {story}")
        for _ in range(300):
            status, story = analyst.call("GET", "/api/storyline/status")
            if not story["running"]:
                break
            time.sleep(0.1)
        check(not story["running"] and story["error"] is None and story["progress"] == 1.0, f"storyline: {story}")
        check(story["events_sent"] > 100 and story["alerts_created"] > 0, f"storyline output: {story}")
        print(f"      {story['events_sent']} synthetic events, {story['alerts_created']} alerts, last stage {story['stage']}")

        step("ATT&CK coverage lists every catalog technique")
        status, coverage = analyst.call("GET", "/api/attack/coverage")
        hit = [t["id"] for t in coverage["techniques"] if t["hits"]]
        check(status == 200 and coverage["summary"]["covered"] == coverage["summary"]["techniques"] and hit,
              f"coverage: {coverage.get('summary')}")
        print(f"      {coverage['summary']['techniques']} techniques covered, {len(hit)} with alerts")

        step("analyst investigates and resolves the compromise alert")
        target = next(a for a in alerts if a["rule_id"] == "success_after_failures" and "dave" in a["group_key"])
        status, detail = analyst.call("GET", f"/api/alerts/{target['id']}")
        check(detail["evidence"] and detail["timeline"] and detail["explanation"], "alert detail incomplete")
        analyst.call("POST", f"/api/alerts/{target['id']}/status", {"status": "investigating"})
        analyst.call("POST", f"/api/alerts/{target['id']}/notes", {"body": "Smoke test note"})
        status, res = analyst.call("POST", f"/api/alerts/{target['id']}/status",
                                   {"status": "resolved", "disposition": "true_positive"})
        check(status == 200 and res["status"] == "resolved", f"resolve: {status} {res}")

        step("incident report downloads as PDF and Markdown")
        status, pdf, headers = analyst.download(f"/api/alerts/{target['id']}/report.pdf")
        check(status == 200 and pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"),
              f"alert report.pdf: {status} {pdf[:80]!r}")
        check("attachment" in headers.get("Content-Disposition", ""), "report.pdf is not an attachment")
        status, md, _ = analyst.download(f"/api/alerts/{target['id']}/report.md")
        check(status == 200 and target["title"] in md.decode() and "SYNTHETIC DATA" in md.decode(),
              f"alert report.md: {status}")
        print(f"      alert #{target['id']} report: {len(pdf)} bytes PDF, {len(md)} bytes Markdown")
        incident = multi[0]
        status, ipdf, headers = analyst.download(f"/api/incidents/{incident['id']}/report.pdf")
        check(status == 200 and ipdf.startswith(b"%PDF-1.4") and "attachment" in headers.get("Content-Disposition", ""),
              f"incident report.pdf: {status}")
        status, imd, _ = analyst.download(f"/api/incidents/{incident['id']}/report.md")
        text = imd.decode()
        check(status == 200 and text.startswith("# Incident report: ") and "SYNTHETIC DATA" in text
              and all(f"**{stage}:**" in text for stage in incident["stages"]),
              f"incident report.md lacks ATT&CK tactics {incident['stages']}: {status}")
        print(f"      incident #{incident['id']} report: {len(ipdf)} bytes PDF, {len(imd)} bytes Markdown,"
              f" tactics {', '.join(incident['stages'])}")

        step("false-positive feedback produces a reviewed rule change")
        for a in alerts:
            if a["rule_id"] == "brute_force_ip":
                verdict = "false_positive" if a["group_key"] == "10.0.50.5" else "true_positive"
                analyst.call("POST", f"/api/alerts/{a['id']}/status", {"status": "resolved", "disposition": verdict})
        status, sug = analyst.call("POST", "/api/rules/suggestions")
        change = next((c for c in sug["created"] if c["target"] == "brute_force_ip"), None)
        check(change is not None, f"no suggestion: {sug}")
        print(f"      proposal #{change['id']}: {change['payload']} "
              f"(scenario FP {change['evaluation']['before']['fp']} -> {change['evaluation']['after']['fp']})")
        status, res = admin.call("POST", f"/api/changes/{change['id']}/review", {"decision": "approve", "note": "smoke", "evidence_digest": change["evidence_digest"]})
        check(status == 200 and res["status"] == "approved", f"approve: {status} {res}")

        step("noise lab scores every rule against benign look-alikes")
        status, lab = analyst.call("GET", "/api/noise-lab")
        rows = {r["rule_id"]: r for r in lab["rules"]}
        check(status == 200 and len(rows) == lab["summary"]["rules"] and all(r["lookalikes_tested"] for r in rows.values()),
              f"noise lab: {status} {lab.get('summary')}")
        check(rows["data_exfil_volume"]["lookalikes_fired"] == ["nightly_backup"]
              and rows["data_exfil_volume"]["recall"] == 1.0, f"flat exfil without an exception: {rows['data_exfil_volume']}")
        check(rows["firewall_port_sweep"]["lookalikes_fired"] == ["authorized_port_scan"],
              f"port sweep look-alike: {rows['firewall_port_sweep']}")
        for r in rows.values():
            fired = r["lookalikes_fired"] + r["other_benign_fired"]
            print(f"      {r['rule_id']:34} recall {r['recall']} precision {r['precision']} {r['verdict']:6}"
                  f" fired on: {', '.join(fired) or 'none'}")

        step("tuning exception: proposed by an analyst, approved by an admin, counted by the engine")
        status, change = analyst.call("POST", "/api/rules/firewall_port_sweep/suppressions",
                                      {"group_key": "10.0.50.5", "days": 30,
                                       "reason": "Authorized internal scanner (smoke test)."})
        check(status == 201 and change["status"] == "pending" and change["evaluation"]["after"]["fp"] == 0
              and not change["evaluation"]["after"]["missed"], f"exception proposal: {status} {change}")
        check(analyst.call("GET", "/api/suppressions")[1] == [], "exception applied before review")
        status, res = admin.call("POST", f"/api/changes/{change['id']}/review", {"decision": "approve", "note": "smoke", "evidence_digest": change["evidence_digest"]})
        check(status == 200 and res["status"] == "approved", f"exception approve: {status} {res}")
        status, listed = analyst.call("GET", "/api/suppressions")
        check(status == 200 and [(s["rule_id"], s["group_key"], s["active"]) for s in listed]
              == [("firewall_port_sweep", "10.0.50.5", True)], f"suppressions: {listed}")
        status, sim = analyst.call("POST", "/api/demo/simulate", {"scenario": "authorized_port_scan"})
        status2, sweeps = analyst.call("GET", "/api/alerts?rule_id=firewall_port_sweep")
        check(status == 201 and sim["detection"]["alerts_suppressed"] >= 1
              and "10.0.50.5" not in [a["group_key"] for a in sweeps], f"exception not applied: {sim['detection']}")
        status, lab = analyst.call("GET", "/api/noise-lab")
        row = {r["rule_id"]: r for r in lab["rules"]}["firewall_port_sweep"]
        check(row["verdict"] == "quiet" and row["suppressed"] == 1, f"lab after exception: {row}")
        print(f"      exception #{listed[0]['id']} until {listed[0]['expires_at']}: "
              f"{sim['detection']['alerts_suppressed']} finding(s) suppressed")

        step("live ingestion: syslog listener and file shipper")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(b"<11>1 2026-09-28T10:00:00Z smoke-host smokeapp 1 - - live syslog frame",
                       ("127.0.0.1", syslog_port))
        for _ in range(50):
            status, res = analyst.call("GET", "/api/events?source=syslog&host=smoke-host")
            if res["total"]:
                break
            time.sleep(0.2)
        check(res["total"] == 1 and res["events"][0]["event_type"] == "syslog", f"syslog event: {res}")
        shipped = Path(tmp.name) / "shipped.log"
        shipped.write_text("Sep 28 12:00:00 smoke-box sshd[1]: Accepted publickey for smokeuser "
                           "from 198.51.100.99 port 22 ssh2\n")
        out = subprocess.run([sys.executable, "scripts/shipper.py", "--url", base, "--once", "--from-start",
                              "--max-retries", "0", "--file", f"{shipped}:authlog:smoke-shipper",
                              "--state", os.path.join(tmp.name, "pos.json"), "--year", "2026"],
                             cwd=ROOT, capture_output=True, text=True, timeout=60,
                             env={**os.environ, "WATCHPOST_TOKEN": tok["token"]})
        check(out.returncode == 0, out.stderr)
        status, res = analyst.call("GET", "/api/events?source=smoke-shipper")
        check(res["total"] == 1 and res["events"][0]["user"] == "smokeuser", f"shipped event: {res}")
        check(tok["token"] not in out.stderr, "shipper logged its token")
        print("      syslog frame and shipped auth.log line both searchable")

        step("metrics and health are consistent")
        status, m = analyst.call("GET", "/api/metrics")
        check(m["alerts_resolved"] >= 2 and m["events_total"] > 0, f"metrics: {m}")
        status, h = admin.call("GET", "/api/health/details")
        check(h["status"] == "ok", f"health after flow: {[(c['name'], c['status'], c['message']) for c in h['checks']]}")
        check(any(c["name"] == "syslog" and c["status"] == "ok" for c in h["checks"]), "syslog health missing")
        check(m["time_to_resolve_by_severity"] and m["false_positive_rate_by_rule"]
              and len(m["open_alert_aging"]["buckets"]) == 5 and m["omitted_metrics"], f"SOC metrics: {m}")
        print(f"      time to resolve for {len(m['time_to_resolve_by_severity'])} severities, false-positive rate for "
              f"{len(m['false_positive_rate_by_rule'])} rules, {sum(b['count'] for b in m['open_alert_aging']['buckets'])} "
              f"open alerts aged")

        step("entity risk: ranked list and an explainable entity page")
        status, top = analyst.call("GET", "/api/entities?limit=5")
        check(status == 200 and top["entities"], f"entities: {status} {top}")
        first = top["entities"][0]
        check(first["score"] == round(sum(c["weight"] for c in first["contributions"]), 2), f"score not explained: {first}")
        status, ent = analyst.call("GET", f"/api/entities/{first['kind']}/{quote(first['value'], safe='')}")
        check(status == 200 and ent["score"] == first["score"] and ent["recent_events"] and ent["first_seen"],
              f"entity page: {status} {ent}")
        check(analyst.call("GET", "/api/entities/src_ip/2001%3Adb8%3A%3A1")[1]["score"] == 0, "unknown entity")
        check(analyst.call("GET", "/api/entities?kind=planet")[0] == 400, "bad entity kind accepted")
        print(f"      riskiest: {first['kind']} {first['value']} scores {first['score']} from {first['alerts']} alerts")

        step("SOC dashboard: aggregates, synthetic geo, and the live SSE stream")
        status, dash = analyst.call("GET", "/api/dashboard")
        check(status == 200 and dash["attackers"] and dash["alert_timeline"]["bins"] and dash["risky_entities"],
              f"dashboard: {status}")
        status, located = analyst.call("GET", "/api/geo?ips=203.0.113.45,8.8.8.8")
        check(located["ips"]["203.0.113.45"]["synthetic"] and located["ips"]["8.8.8.8"] is None, f"geo: {located}")
        cookie = "; ".join(f"{c.name}={c.value}" for h in analyst.opener.handlers
                           for c in getattr(h, "cookiejar", []))
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(f"GET /api/stream HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\n\r\n".encode())
            buf = b""
            while buf.count(b"\n\n") < 2:  # the hello and health frames (headers end in CRLF CRLF)
                chunk = sock.recv(65536)
                check(chunk, "stream closed early")
                buf += chunk
        check(b"text/event-stream" in buf and b"event: hello" in buf and b"event: health" in buf, "stream frames")
        print(f"      {len(dash['attackers'])} attacker IPs, stream sent hello + health")

        step("viewer account is read-only; login is rate limited")
        viewer = Session(base)
        viewer.login("viewer", VIEWER_PW)
        incident_id = viewer.call("GET", "/api/incidents")[1][0]["id"]
        check(viewer.call("GET", f"/api/incidents/{incident_id}")[0] == 200, "viewer cannot read an incident")
        check(viewer.download(f"/api/incidents/{incident_id}/report.pdf")[0] == 200, "viewer cannot download a report")
        for path, body in [("/api/ingest", []), (f"/api/incidents/{incident_id}/status", {"status": "resolved"}),
                           ("/api/demo/load", {}), ("/api/tokens", {"name": "x"})]:
            status, _ = viewer.call("POST", path, body)
            check(status == 403, f"viewer POST {path} returned {status}")
        statuses = [Session(base).call("POST", "/api/auth/login", {"username": "nobody", "password": "x" * 12})[0]
                    for _ in range(12)]
        check(statuses[-1] == 429, f"login attempts were not rate limited: {statuses}")
        print(f"      login answered 429 after {statuses.index(429)} attempts")

        step("server log contains no secrets")
        log_text = Path(log_path).read_text()
        for secret in (ADMIN_PW, ANALYST_PW, VIEWER_PW, tok["token"]):
            check(secret not in log_text, "a secret appeared in the server log")
        print("\nSMOKE OK")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log_file.close()
        tmp.cleanup()


if __name__ == "__main__":
    main()
