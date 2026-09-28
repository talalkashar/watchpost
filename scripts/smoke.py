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

ROOT = Path(__file__).resolve().parent.parent
ADMIN_PW, ANALYST_PW = "smoke-admin-password", "smoke-analyst-password"
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
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "SIEM_DB": os.path.join(tmp.name, "smoke.db"), "SIEM_HOST": "127.0.0.1",
           "SIEM_PORT": str(port), "SIEM_ADMIN_PASSWORD": ADMIN_PW, "SIEM_ANALYST_PASSWORD": ANALYST_PW}
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
                    "data_exfil_volume"}
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
        status, res = admin.call("POST", f"/api/changes/{change['id']}/review", {"decision": "approve", "note": "smoke"})
        check(status == 200 and res["status"] == "approved", f"approve: {status} {res}")

        step("metrics and health are consistent")
        status, m = analyst.call("GET", "/api/metrics")
        check(m["alerts_resolved"] >= 2 and m["events_total"] > 0, f"metrics: {m}")
        status, h = admin.call("GET", "/api/health/details")
        check(h["status"] == "ok", f"health after flow: {[(c['name'], c['status'], c['message']) for c in h['checks']]}")

        step("server log contains no secrets")
        log_text = Path(log_path).read_text()
        for secret in (ADMIN_PW, ANALYST_PW, tok["token"]):
            check(secret not in log_text, "a secret appeared in the server log")
        print("\nSMOKE OK")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log_file.close()
        tmp.cleanup()


if __name__ == "__main__":
    main()
