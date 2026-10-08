"""HTTP API and static UI server (standard library only)."""

import hmac
import ipaddress
import json
import queue
import mimetypes
import re
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import (__version__, assets, attack, auth, ecs, engine, entities, geo, hunt, improve, incidents, portability,
               queries, report, sigma, simulate, storyline, stream, triage)
from . import backtest as backtest_mod
from .ratelimit import TokenBucketLimiter
from .config import Config
from .db import audit, connect, init_schema, now_iso, row_to_dict, utcnow, verify_chain
from .diagnostics import configure_logging, log, record_error
from .health import STATIC_DIR, run_health_checks
from .normalize import EventError, parse_payload, validate_source

SESSION_COOKIE = "wp_session"


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Download:
    """A non-JSON response body sent as a file attachment."""

    def __init__(self, body, content_type, filename):
        self.body, self.content_type, self.filename = body, content_type, filename


class App:
    def __init__(self, config: Config):
        self.config = config
        conn = connect(config.db_path, config.audit_key)
        try:
            init_schema(conn)
            engine.seed_rules(conn)
            improve.seed_settings(conn)
            self.credentials_file = auth.bootstrap_users(conn, config, Path(config.db_path).parent)
        finally:
            conn.close()
        self.login_limiter = self.request_limiter = self.backtest_limiter = self.change_backtest_limiter = None
        if config.rate_limit_enabled:
            self.login_limiter = TokenBucketLimiter(config.login_rate_burst, config.login_rate_per_minute)
            self.request_limiter = TokenBucketLimiter(config.rate_burst, config.rate_per_minute)
            # Per account: each backtest replays up to backtest.MAX_EVENTS stored events twice. Previews are the
            # cheap thing to repeat and get the tight bucket; rule proposals and approvals get their own.
            self.backtest_limiter = TokenBucketLimiter(BACKTEST_BURST, BACKTEST_PER_MINUTE)
            self.change_backtest_limiter = TokenBucketLimiter(CHANGE_BACKTEST_BURST, BACKTEST_PER_MINUTE)
        self.storyline = storyline.Runner(self.conn)

    def conn(self):
        return connect(self.config.db_path, self.config.audit_key)


# --- Routing ---------------------------------------------------------------------------

ROUTES = []


def route(method, pattern, role="viewer", csrf=True):
    """role: minimum role, 'public' for no auth, or 'ingest' to also accept API tokens.

    `viewer` accounts are read-only: whatever a route declares, a viewer may only send GETs
    (plus logout). See Handler._authorize.
    """
    def decorator(fn):
        ROUTES.append((method, re.compile(f"^{pattern}$"), fn, role, csrf))
        return fn
    return decorator


def body_json(req):
    try:
        data = json.loads(req.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ApiError(400, "request body must be valid JSON")
    if not isinstance(data, dict):
        raise ApiError(400, "request body must be a JSON object")
    return data


@route("POST", "/api/auth/login", role="public", csrf=False)
def login(req):
    data = body_json(req)
    result = auth.login(req.conn, data.get("username", ""), data.get("password", ""),
                        req.app.config.session_ttl_seconds)
    if isinstance(result, auth.MfaChallenge):
        # Not a session: a short-lived, single-use token for POST /api/auth/mfa.
        return {"mfa_required": True, "mfa_token": result.mfa_token,
                "expires_in": auth.MFA_TOKEN_TTL_SECONDS}
    token, csrf, user = result
    req.set_cookie = token
    return {"user": user, "csrf_token": csrf}


@route("POST", "/api/auth/mfa", role="public", csrf=False)
def login_mfa(req):
    data = body_json(req)
    token, csrf, user = auth.complete_mfa(req.conn, data.get("mfa_token"), data.get("code"),
                                          req.app.config.session_ttl_seconds)
    req.set_cookie = token
    return {"user": user, "csrf_token": csrf}


@route("POST", "/api/auth/logout")
def logout(req):
    auth.logout(req.conn, req.session_token)
    req.set_cookie = ""
    return {"ok": True}


@route("GET", "/api/auth/me")
def me(req):
    return {"user": {"username": req.user["username"], "role": req.user["role"]},
            "csrf_token": req.user["csrf"]}


# Account security: TOTP enrollment and sessions. The viewer can read its own status and sessions only.

@route("GET", "/api/auth/mfa/status")
def mfa_status(req):
    return auth.mfa_status(req.conn, req.user["username"])


@route("POST", "/api/auth/mfa/enroll", role="analyst")
def mfa_enroll(req):
    return auth.mfa_enroll(req.conn, req.user["username"])


@route("POST", "/api/auth/mfa/confirm", role="analyst")
def mfa_confirm(req):
    return auth.mfa_confirm(req.conn, req.user["username"], body_json(req).get("code"))


@route("POST", "/api/auth/mfa/disable", role="analyst")
def mfa_disable(req):
    return auth.mfa_disable(req.conn, req.user["username"], body_json(req).get("code"))


@route("GET", "/api/auth/sessions")
def my_sessions(req):
    return auth.list_sessions(req.conn, req.user["username"], req.user.get("sid"))


@route("POST", r"/api/auth/sessions/([0-9a-f]{16})/revoke", role="analyst")
def my_session_revoke(req, sid):
    return auth.revoke_session(req.conn, sid, req.user["username"], owner=req.user["username"])


@route("GET", "/api/health", role="public")
def health_summary(req):
    report = run_health_checks(lambda: connect(req.app.config.db_path), req.app.config.db_path)
    req.status = 503 if report["status"] == "failing" else 200
    # Public view: statuses only, no internal details.
    return {"status": report["status"], "version": __version__, "checked_at": report["checked_at"],
            "checks": {c["name"]: c["status"] for c in report["checks"]}}


@route("GET", "/api/health/details")
def health_details(req):
    report = run_health_checks(lambda: connect(req.app.config.db_path), req.app.config.db_path)
    report["recent_errors"] = [dict(r) for r in req.conn.execute(
        "SELECT created_at, component, message, guidance FROM error_log ORDER BY id DESC LIMIT 20")]
    report["recent_detection_runs"] = [dict(r) for r in req.conn.execute(
        "SELECT * FROM detection_runs ORDER BY id DESC LIMIT 10")]
    return report


@route("POST", "/api/detection/run", role="analyst")
def detection_run(req):
    result = engine.run_detection(req.conn, trigger=f"full:{req.user['username']}")
    audit(req.conn, req.user["username"], "detection_run", None, result)
    return result


# Ingestion ---------------------------------------------------------------------------

def _ingest(req, text, fmt, source, synthetic, year=None):
    try:
        source = validate_source(source)
        events, rejections = parse_payload(text, fmt, source, year=year,
                                           max_events=req.app.config.max_batch_events)
    except EventError as exc:
        raise ApiError(400, str(exc))
    if synthetic:
        for event in events:
            if not event["source"].startswith("demo:"):
                event["source"] = "demo:" + event["source"][:59]
    try:
        result = engine.ingest(req.conn, events, rejections, source, fmt, req.user["username"], synthetic)
    except Exception as exc:
        record_error(req.conn, "ingestion", exc,
                     guidance="The batch was not stored. Check storage health, then resubmit the batch.")
        raise ApiError(500, "ingestion failed; the batch was not stored (see Health for details)")
    req.status = 207 if result["rejected"] and result["accepted"] else (422 if not result["accepted"] else 201)
    return result


@route("POST", "/api/ingest", role="ingest", csrf=True)
def ingest_json(req):
    """Body: a single event object, an array, or {"source": ..., "synthetic": bool, "events": [...]}."""
    try:
        data = json.loads(req.body or b"null")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ApiError(400, "request body must be valid JSON")
    source, synthetic = "api", False
    if isinstance(data, dict) and "events" in data:
        source = data.get("source") or source
        synthetic = data.get("synthetic") is True
        data = data["events"]
    return _ingest(req, json.dumps(data), "json", source, synthetic)


@route("POST", "/api/ingest/upload", role="ingest", csrf=True)
def ingest_upload(req):
    """Raw file body. Query: format=auto|json|jsonl|csv|authlog, source=name, synthetic=1, year=YYYY."""
    try:
        text = req.body.decode("utf-8")
    except UnicodeDecodeError:
        raise ApiError(400, "upload must be UTF-8 text")
    if not text.strip():
        raise ApiError(400, "upload is empty")
    year = req.query.get("year")
    if year is not None and not (year.isdigit() and 2000 <= int(year) <= 2100):
        raise ApiError(400, "year must be between 2000 and 2100")
    return _ingest(req, text, req.query.get("format", "auto"), req.query.get("source", "upload"),
                   req.query.get("synthetic") == "1", int(year) if year else None)


@route("GET", "/api/ingest/batches")
def batches(req):
    rows = req.conn.execute("SELECT * FROM ingest_batches ORDER BY created_at DESC LIMIT 50")
    return [row_to_dict(r, ["errors"]) for r in rows]


@route("POST", "/api/demo/load", role="admin")
def demo_load(req):
    data = body_json(req)
    existing = req.conn.execute("SELECT COUNT(*) FROM events WHERE synthetic = 1").fetchone()[0]
    if existing and not data.get("force"):
        raise ApiError(409, f"{existing} synthetic events already loaded; send force=true to add another copy")
    seed = data.get("seed", 7)
    if not isinstance(seed, int):
        raise ApiError(400, "seed must be an integer")
    results = {}
    demo_assets = assets.seed_demo_assets(req.conn, req.user["username"])
    for name, events in simulate.build(seed=seed).items():
        normalized, rejections = parse_payload(json.dumps(events), "json", f"demo:{name}")
        results[name] = engine.ingest(req.conn, normalized, rejections, f"demo:{name}", "json",
                                      req.user["username"], synthetic=True)
    audit(req.conn, req.user["username"], "demo_loaded", None, {"seed": seed, "assets_created": demo_assets})
    return {name: {k: r[k] for k in ("accepted", "rejected", "detection")} for name, r in results.items()}


@route("GET", "/api/demo/scenarios", role="viewer")
def demo_scenarios(req):
    return [{"name": n, "malicious": s["malicious"], "description": s["description"],
             "expected_rules": list(s["expected"])} for n, s in simulate.SCENARIOS.items()]


@route("POST", "/api/demo/simulate", role="analyst")
def demo_simulate(req):
    """Replay one labeled attack scenario into the local store (synthetic, loopback only by design)."""
    data = body_json(req)
    name, seed = data.get("scenario"), data.get("seed", 7)
    if name not in simulate.SCENARIOS:
        raise ApiError(400, f"scenario must be one of {', '.join(simulate.SCENARIOS)}")
    if not isinstance(seed, int):
        raise ApiError(400, "seed must be an integer")
    events = simulate.build([name], seed=seed)[name]
    normalized, rejections = parse_payload(json.dumps(events), "json", f"demo:{name}")
    req.status = 201
    return engine.ingest(req.conn, normalized, rejections, f"demo:{name}", "json",
                         req.user["username"], synthetic=True)


@route("POST", "/api/storyline/start", role="admin")
def storyline_start(req):
    """Replay the scripted six-stage synthetic intrusion over wall-clock time (one run at a time)."""
    data = body_json(req)
    speed, seed = data.get("speed", 1.0), data.get("seed", 7)
    if not isinstance(speed, (int, float)) or isinstance(speed, bool) or not (0.1 <= speed <= 10000):
        raise ApiError(400, "speed must be a number between 0.1 and 10000")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ApiError(400, "seed must be an integer")
    if not req.app.storyline.start(speed=speed, seed=seed, started_by=req.user["username"]):
        raise ApiError(409, "a storyline is already running; stop it first")
    audit(req.conn, req.user["username"], "storyline_started", None, {"speed": speed, "seed": seed})
    req.status = 202
    return req.app.storyline.snapshot()


@route("POST", "/api/storyline/stop", role="admin")
def storyline_stop(req):
    req.app.storyline.stop()
    return req.app.storyline.snapshot()


@route("GET", "/api/storyline/status")
def storyline_status(req):
    status = req.app.storyline.snapshot()
    status["stages"] = [{"name": n, "starts_at": t, "description": d} for n, t, d in storyline.STAGES]
    status["synthetic"] = True
    return status


# Events and alerts ---------------------------------------------------------------------

@route("GET", "/api/events")
def events(req):
    return queries.search_events(req.conn, req.query)


@route("GET", "/api/hunt")
def hunt_run(req):
    return hunt.run(req.conn, req.query)


@route("GET", "/api/hunt/saved")
def hunt_saved(req):
    return hunt.list_saved(req.conn)


@route("POST", "/api/hunt/saved", role="analyst")
def hunt_save(req):
    req.status = 201
    return hunt.save_search(req.conn, body_json(req), req.user["username"])


@route("POST", r"/api/hunt/saved/(\d+)/delete", role="analyst")
def hunt_delete(req, search_id):
    return hunt.delete_saved(req.conn, int(search_id), req.user["username"], auth.has_role(req.user, "admin"))


@route("GET", r"/api/events/(\d+)")
def event_detail(req, event_id):
    return queries.get_event(req.conn, int(event_id))


@route("GET", r"/api/events/(\d+)/ecs")
def event_ecs(req, event_id):
    """The event as an ECS-shaped document (ecs.py). A field mapping for export, not how events are stored."""
    event = queries.get_event(req.conn, int(event_id))
    event.pop("alerts")
    return ecs.to_ecs(event)


@route("GET", "/api/alerts")
def alerts(req):
    now = utcnow()
    return [{**a, "sla_breach": triage.pending_breaches(a, now)} for a in queries.list_alerts(req.conn, req.query)]


@route("GET", r"/api/alerts/(\d+)")
def alert_detail(req, alert_id):
    return queries.get_alert(req.conn, int(alert_id))


@route("POST", r"/api/alerts/(\d+)/notes", role="analyst")
def alert_note(req, alert_id):
    req.status = 201
    return queries.add_note(req.conn, int(alert_id), req.user["username"], body_json(req).get("body"))


@route("POST", r"/api/alerts/(\d+)/status", role="analyst")
def alert_status(req, alert_id):
    data = body_json(req)
    return queries.update_status(req.conn, int(alert_id), req.user["username"], data.get("status"),
                                 data.get("disposition"), data.get("note"))


@route("POST", r"/api/alerts/(\d+)/assign", role="analyst")
def alert_assign(req, alert_id):
    return queries.assign(req.conn, int(alert_id), req.user["username"], body_json(req).get("assignee"))


# Incidents (correlated alerts) and ATT&CK coverage -------------------------------------

@route("GET", "/api/incidents")
def incident_list(req):
    return incidents.list_incidents(req.conn, req.query)


@route("GET", r"/api/incidents/(\d+)")
def incident_detail(req, incident_id):
    return incidents.get_incident(req.conn, int(incident_id))


@route("POST", r"/api/incidents/(\d+)/status", role="analyst")
def incident_status(req, incident_id):
    data = body_json(req)
    return incidents.update_status(req.conn, int(incident_id), req.user["username"], data.get("status"),
                                   data.get("note"))


@route("GET", "/api/attack/coverage")
def attack_coverage(req):
    return incidents.coverage(req.conn)


@route("GET", r"/api/attack/navigator\.json")
def attack_navigator(req):
    """The same coverage as a MITRE ATT&CK Navigator layer (open it with 'Open Existing Layer')."""
    return attack.navigator_layer(incidents.coverage(req.conn))


# Reports ---------------------------------------------------------------------------------

def _report(req, kind, ident, fmt):
    model = report.build(req.conn, ident) if kind == "incident" else report.build_from_alert(req.conn, ident)
    audit(req.conn, req.user["username"], "report_downloaded", f"{kind}:{ident}", {"format": fmt})
    name = f"watchpost-{kind}-{ident}-report.{fmt}"
    if fmt == "pdf":
        return Download(report.to_pdf_bytes(model), "application/pdf", name)
    return Download(report.to_markdown(model).encode("utf-8"), "text/markdown; charset=utf-8", name)


@route("GET", r"/api/alerts/(\d+)/report\.(md|pdf)")
def alert_report(req, alert_id, fmt):
    return _report(req, "alert", int(alert_id), fmt)


@route("GET", r"/api/incidents/(\d+)/report\.(md|pdf)")
def incident_report(req, incident_id, fmt):
    return _report(req, "incident", int(incident_id), fmt)


@route("GET", "/api/metrics")
def metrics(req):
    return queries.metrics(req.conn, req.query.get("hours"))


@route("GET", "/api/metrics/triage")
def triage_metrics(req):
    return triage.triage_metrics(req.conn, req.query.get("window"))


# SOC dashboard ---------------------------------------------------------------------------

GEO_MAX_IPS = 200
DASHBOARD_ENTITIES = 8


@route("GET", "/api/dashboard")
def dashboard(req):
    return {**queries.dashboard(req.conn),
            "risky_entities": entities.list_entities(req.conn, {"limit": DASHBOARD_ENTITIES})["entities"]}


@route("GET", "/api/entities")
def entity_list(req):
    return entities.list_entities(req.conn, req.query)


def _entity_route(kind):
    # One literal route per kind; the value is percent-encoded in the path (it may hold dots, colons, pipes).
    @route("GET", rf"/api/entities/{kind}/([^/]+)")
    def entity_detail(req, value):
        return entities.get_entity(req.conn, kind, unquote(value))


for _kind in entities.KINDS:
    _entity_route(_kind)


@route("GET", "/api/geo")
def geo_lookup(req):
    """Positions from the synthetic geo table only. Addresses outside it come back null ("unknown")."""
    ips = [ip.strip() for ip in req.query.get("ips", "").split(",") if ip.strip()]
    if len(ips) > GEO_MAX_IPS:
        raise ApiError(400, f"at most {GEO_MAX_IPS} ips per request")
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ApiError(400, "ips must be a comma-separated list of IP addresses")
    located = {ip: geo.locate(ip) for ip in ips}
    return {"label": geo.LABEL,
            "ips": {ip: ({**loc, "internal": geo.is_internal(ip)} if loc else None) for ip, loc in located.items()}}


class _StreamResponse:
    """Returned by the stream route; the handler then keeps the connection open."""


STREAM_RESPONSE = _StreamResponse()


@route("GET", "/api/stream")
def event_stream(req):
    return STREAM_RESPONSE


# Rules, feedback, and reviewed changes ----------------------------------------------------

@route("GET", "/api/rules")
def rules(req):
    perf = improve.rule_performance(req.conn)
    latest = improve.list_evaluations(req.conn, limit=1)
    evaluation = latest[0]["results"]["rules"] if latest else {}
    return [{**r, "performance": perf.get(r["id"]), "evaluation": evaluation.get(r["id"]),
             **({"sigma": _sigma_detail(req.conn, r)} if sigma.is_sigma(r["id"]) else {})}
            for r in engine.load_rules(req.conn, enabled_only=False)]


def _sigma_detail(conn, rule):
    """An imported rule's original YAML (read-only), its sha256, its compiled conditions and its sample."""
    rec = sigma.stored(conn, rule["id"])
    if rec is None:
        return None
    return {**{k: rec[k] for k in ("source", "sha256", "sigma_id", "imported_by", "approved_by", "change_request_id",
                                   "created_at", "sample")},
            "conditions": sigma.describe(rule["params"]["detection"]),
            "sample_result": sigma.sample_result(rule["params"], rec["sample"])}


@route("GET", r"/api/rules/([a-z_]+)/history")
def rule_history(req, rule_id):
    rows = req.conn.execute("SELECT * FROM rule_history WHERE rule_id = ? ORDER BY version DESC", (rule_id,))
    return [row_to_dict(r, ["params"]) for r in rows]


def _backtest_quota(req, limiter, cost=1):
    """Spend `cost` backtests, all or none, from the account's quota in `limiter` (None when rate limiting is off)."""
    if limiter is not None:
        needed = f" ({cost} needed)" if cost > 1 else ""
        if cost > limiter.burst:
            raise ApiError(429, f"too many backtests{needed}: the quota holds at most {int(limiter.burst)}")
        allowed, retry_after = limiter.allow(req.user["username"], cost)
        if not allowed:
            raise ApiError(429, f"too many backtests{needed}; retry in {retry_after} s")


@route("POST", r"/api/rules/([a-z_]+)/proposals", role="analyst")
def rule_propose(req, rule_id):
    data = body_json(req)
    _backtest_quota(req, req.app.change_backtest_limiter)  # the proposal's evidence carries a backtest
    payload = {k: data[k] for k in ("params", "enabled") if k in data}
    req.status = 201
    return improve.propose_change(req.conn, "rule_update", rule_id, payload, data.get("reason"),
                                  req.user["username"])


@route("GET", "/api/rules/export")
def rules_export(req):
    """Every rule's tuning as a versioned JSON document. Detection logic is code and is not exported."""
    body = json.dumps(portability.export_rules(req.conn), sort_keys=True, indent=2).encode()
    return Download(body, "application/json", "watchpost-rules.json")


IMPORT_LABEL_RE = re.compile(r"[^A-Za-z0-9 ._()\-]")


@route("POST", "/api/rules/import", role="analyst")
def rules_import(req):
    """Turn an exported rules document into reviewed rule_update proposals. Applies nothing by itself.

    ?dry_run=1 returns the per-rule outcomes and proposes nothing. ?label= names the file in each reason.
    """
    if len(req.body) > portability.MAX_IMPORT_BYTES:
        raise ApiError(413, f"a rules import is at most {portability.MAX_IMPORT_BYTES} bytes")
    dry_run = req.query.get("dry_run") == "1"
    label = IMPORT_LABEL_RE.sub("", req.query.get("label", ""))[:100].strip() or "upload"
    plan = portability.plan_import(req.conn, body_json(req))
    if not dry_run:
        # Each proposal runs a backtest: spend one per changed rule from the same bucket as hand-made
        # proposals, all up front, so an import is refused whole rather than half proposed.
        if portability.to_propose(plan):
            _backtest_quota(req, req.app.change_backtest_limiter, portability.to_propose(plan))
        portability.propose_import(req.conn, plan, label, req.user["username"])
    return {"dry_run": dry_run, "label": label, "summary": portability.summary(plan), "rules": plan}


SIGMA_MAX_BODY = 256 * 1024  # the YAML (at most sigma.MAX_SOURCE_BYTES) plus its labeled sample


@route("POST", "/api/rules/sigma", role="analyst")
def sigma_import(req):
    """Import a Sigma rule: {source, sample (optional), reason (optional)}. Applies nothing by itself.

    ?dry_run=1 compiles it and previews it on stored events (spends one preview backtest) and returns the
    compiled conditions or the refusal reason. Otherwise it becomes a `sigma_add` change request (spends one
    from the rule-proposal bucket, as its evidence carries the same preview); approval adds the rule disabled.
    """
    if len(req.body) > SIGMA_MAX_BODY:
        raise ApiError(413, f"a Sigma import is at most {SIGMA_MAX_BODY} bytes")
    data = body_json(req)
    if not set(data) <= {"source", "sample", "reason"}:
        raise ApiError(400, "a Sigma import is {source, sample (optional), reason (optional)}")
    dry_run = req.query.get("dry_run") == "1"
    _backtest_quota(req, req.app.backtest_limiter if dry_run else req.app.change_backtest_limiter)
    try:
        compiled = sigma.compile_rule(data.get("source"))
        sample = sigma.validate_sample(data["sample"]) if data.get("sample") is not None else None
    except sigma.SigmaError as exc:
        if not dry_run:
            raise ApiError(400, f"refused: {exc}")
        return {"dry_run": True, "ok": False, "refused": str(exc)}
    if dry_run:
        exists = req.conn.execute("SELECT 1 FROM rules WHERE id = ?", (compiled["rule_id"],)).fetchone()
        return {"dry_run": True, "ok": not exists,
                "refused": f"rule {compiled['rule_id']!r} already exists" if exists else None,
                "compiled": {k: compiled[k] for k in ("rule_id", "title", "severity", "techniques", "conditions",
                                                      "warnings", "sha256", "params", "logsource")},
                "sample": sigma.sample_result(compiled["params"], sample),
                "backtest": sigma.preview(req.conn, compiled["params"])}
    payload = {"source": data["source"], **({"sample": sample} if sample is not None else {})}
    req.status = 201
    return improve.propose_change(req.conn, "sigma_add", compiled["rule_id"], payload,
                                  data.get("reason") or f"import Sigma rule {compiled['title']}"[:2000],
                                  req.user["username"])


@route("POST", r"/api/rules/([a-z_]+)/sigma-sample", role="analyst")
def sigma_sample_propose(req, rule_id):
    """Attach or replace an imported rule's labeled sample; a change request like any other."""
    data = body_json(req)
    req.status = 201
    return improve.propose_change(req.conn, "sigma_sample", rule_id, {"sample": data.get("sample")},
                                  data.get("reason"), req.user["username"])


BACKTEST_BURST, BACKTEST_PER_MINUTE = 6, 12
CHANGE_BACKTEST_BURST = 20  # rule proposals and approvals: room for a review session


@route("GET", r"/api/rules/([a-z_]+)/backtest", role="analyst")
def rule_backtest(req, rule_id):
    """Preview a draft rule change on stored events before proposing it. Changes nothing.

    Analyst and above, like proposing; a viewer sees the backtest inside a change request's evidence.
    ?params=<JSON object of the params to change>&days=<1-30, default 7>.
    """
    try:
        params = json.loads(req.query.get("params") or "{}")
    except json.JSONDecodeError:
        raise ApiError(400, "params must be a JSON object")
    days = req.query.get("days", str(backtest_mod.DEFAULT_WINDOW_DAYS))
    if not days.isdigit() or not 1 <= int(days) <= backtest_mod.MAX_WINDOW_DAYS:
        raise ApiError(400, f"days must be an integer between 1 and {backtest_mod.MAX_WINDOW_DAYS}")
    _backtest_quota(req, req.app.backtest_limiter)
    return improve.preview_backtest(req.conn, rule_id, params, int(days))


@route("POST", r"/api/rules/([a-z_]+)/suppressions", role="analyst")
def suppression_propose(req, rule_id):
    """Propose a tuning exception; nothing is suppressed until an admin approves the change request."""
    data = body_json(req)
    req.status = 201
    return improve.propose_change(req.conn, "suppression_add", rule_id,
                                  {"group_key": data.get("group_key"), "days": data.get("days")},
                                  data.get("reason"), req.user["username"])


@route("GET", "/api/suppressions")
def suppressions(req):
    return improve.list_suppressions(req.conn)


@route("POST", r"/api/suppressions/(\d+)/revoke", role="admin")
def suppression_revoke(req, suppression_id):
    """End an approved exception before it expires; it stops applying from the next detection run."""
    return improve.revoke_suppression(req.conn, int(suppression_id), req.user["username"])


@route("GET", "/api/noise-lab")
def noise_lab(req):
    return improve.noise_lab(req.conn)


@route("POST", "/api/rules/suggestions", role="analyst")
def rule_suggestions(req):
    created = improve.generate_suggestions(req.conn)
    return {"created": created,
            "message": f"{len(created)} new proposal(s) from analyst feedback" if created
            else "no new suggestions: each rule needs at least 2 false-positive verdicts with a common cause"}


@route("GET", "/api/settings")
def settings(req):
    return improve.list_settings(req.conn)


@route("POST", r"/api/settings/([a-z_]+)/proposals", role="admin")
def setting_propose(req, key):
    data = body_json(req)
    req.status = 201
    return improve.propose_change(req.conn, "setting_update", key, {"value": data.get("value")},
                                  data.get("reason"), req.user["username"])


@route("GET", "/api/changes")
def changes(req):
    return improve.list_changes(req.conn, req.query.get("status"))


@route("POST", r"/api/changes/(\d+)/review", role="admin")
def change_review(req, change_id):
    data = body_json(req)
    if data.get("decision") == "approve":
        row = req.conn.execute("SELECT kind FROM change_requests WHERE id = ?", (int(change_id),)).fetchone()
        if row is not None and row["kind"] in ("rule_update", "sigma_add"):
            _backtest_quota(req, req.app.change_backtest_limiter)  # approval recomputes the evidence, backtest included
    return improve.review_change(req.conn, int(change_id), data.get("decision"), req.user["username"],
                                 data.get("note", ""), data.get("evidence_digest"),
                                 data.get("acknowledge_detection_loss"))


@route("GET", "/api/evaluations")
def evaluations(req):
    return improve.list_evaluations(req.conn)


@route("POST", "/api/evaluations", role="analyst")
def evaluation_run(req):
    req.status = 201
    return improve.run_evaluation(req.conn, req.user["username"])


# Asset inventory ------------------------------------------------------------------------

@route("GET", "/api/assets")
def asset_list(req):
    pending = [c for c in improve.list_changes(req.conn, "pending") if c["kind"] in improve.ASSET_KINDS]
    return {"assets": assets.list_assets(req.conn), "criticalities": list(assets.CRITICALITIES),
            "kinds": list(assets.KINDS), "data_tags": assets.DATA_TAGS, "pending": pending}


def _asset_saved(req, asset):
    """After an inventory change, re-weigh open alerts and refresh incident severities."""
    changed = assets.rescore_open_alerts(req.conn)
    if changed:
        engine.correlate_alerts(req.conn)
    return {"asset": asset, "alerts_rescored": changed}


def _review_required(req, exc, proposal_route):
    """409 for a direct edit that could lower alert severity, pointing at the route that proposes it."""
    req.status = 409
    return {"error": f"{exc}; propose it with POST {proposal_route}", "review_required": True,
            "reasons": exc.reasons, "proposal_route": proposal_route}


# Edits that can only keep or raise alert severity apply here at once; the rest are refused with 409 and go
# through /proposals and a second admin's review (assets.review_reasons decides which is which).
@route("POST", "/api/assets", role="admin")
def asset_create(req):
    try:
        asset = assets.save_asset(req.conn, body_json(req), req.user["username"], gated=True)
    except assets.ReviewRequired as exc:
        return _review_required(req, exc, "/api/assets/proposals")
    req.status = 201
    return _asset_saved(req, asset)


@route("POST", r"/api/assets/(\d+)", role="admin")
def asset_update(req, asset_id):
    try:
        asset = assets.save_asset(req.conn, body_json(req), req.user["username"], int(asset_id), gated=True)
    except assets.ReviewRequired as exc:
        return _review_required(req, exc, f"/api/assets/{asset_id}/proposals")
    return _asset_saved(req, asset)


@route("POST", r"/api/assets/(\d+)/delete", role="admin")
def asset_delete(req, asset_id):
    """A delete always needs a second admin. Kept as a route so older clients get a pointer, not a 404."""
    assets.get_asset(req.conn, int(asset_id))  # an unknown asset is still a 404
    return _review_required(req, assets.ReviewRequired(assets.review_reasons(None, None)),
                            f"/api/assets/{asset_id}/proposals")


@route("POST", "/api/assets/proposals", role="admin")
def asset_propose_add(req):
    data = body_json(req)
    asset = assets.validate({k: v for k, v in data.items() if k != "reason"})  # stored as validated, nothing else
    req.status = 201
    return improve.propose_change(req.conn, "asset_add", asset["name"], asset, data.get("reason"),
                                  req.user["username"])


@route("POST", r"/api/assets/(\d+)/proposals", role="admin")
def asset_propose(req, asset_id):
    """Propose an edit (the full asset, as for a direct edit) or, with {"delete": true}, a delete."""
    data = body_json(req)
    if data.get("delete") is True:
        assets.get_asset(req.conn, int(asset_id))
        kind, payload = "asset_delete", {}
    else:
        kind, payload = "asset_update", assets.edit_payload(req.conn, int(asset_id),
                                                            {k: v for k, v in data.items() if k != "reason"})
    req.status = 201
    return improve.propose_change(req.conn, kind, asset_id, payload, data.get("reason"), req.user["username"])


# Administration ------------------------------------------------------------------------

@route("GET", "/api/tokens", role="admin")
def tokens(req):
    return [dict(r) for r in req.conn.execute(
        "SELECT id, name, prefix, created_by, created_at, last_used_at, revoked_at FROM api_tokens ORDER BY id")]


@route("POST", "/api/tokens", role="admin")
def token_create(req):
    token = auth.create_api_token(req.conn, body_json(req).get("name"), req.user["username"])
    req.status = 201
    return {"token": token, "note": "Shown once. Only a hash is stored."}


@route("POST", r"/api/tokens/(\d+)/revoke", role="admin")
def token_revoke(req, token_id):
    cur = req.conn.execute("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                           (now_iso(), int(token_id)))
    if not cur.rowcount:
        raise ApiError(404, "token not found or already revoked")
    audit(req.conn, req.user["username"], "api_token_revoked", token_id)
    return {"ok": True}


@route("GET", "/api/sessions", role="admin")
def sessions(req):
    return auth.list_sessions(req.conn, req.query.get("user") or None, req.user.get("sid"))


@route("POST", r"/api/sessions/([0-9a-f]{16})/revoke", role="admin")
def session_revoke(req, sid):
    return auth.revoke_session(req.conn, sid, req.user["username"])


@route("POST", r"/api/users/(\w{3,32})/mfa/reset", role="admin")
def user_mfa_reset(req, username):
    return auth.mfa_admin_reset(req.conn, username, req.user["username"])


@route("GET", "/api/audit", role="admin")
def audit_log(req):
    return [dict(r) for r in req.conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")]


@route("GET", "/api/audit/verify", role="admin")
def audit_verify(req):
    return verify_chain(req.conn)


# The only non-GET routes a read-only viewer may call.
VIEWER_WRITES = (logout,)


# --- Request handling --------------------------------------------------------------------

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Watchpost"
    sys_version = ""
    app: App = None

    def log_message(self, fmt, *args):
        # Path only (no query string, which may carry search terms).
        log.info("%s %s %s", self.command, urlparse(self.path).path, args[1] if len(args) > 1 else "")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _send(self, status, payload, content_type="application/json", extra_headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return b""
        try:
            length = int(length)
        except ValueError:
            raise ApiError(400, "invalid Content-Length")
        if length < 0 or length > self.app.config.max_upload_bytes:
            raise ApiError(413, f"request body exceeds {self.app.config.max_upload_bytes} bytes")
        return self.rfile.read(length)

    def _session_token(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _client_ip(self):
        """The peer address, or with SIEM_TRUST_PROXY=1 and a loopback peer, the last X-Forwarded-For entry.

        The last entry is the one the local proxy wrote itself; earlier entries are client-supplied.
        """
        ip = self.client_address[0]
        if self.app.config.trust_proxy and ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            forwarded = self.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        return ip

    def _rate_limited(self, path):
        """Spend a token from the login or general bucket; on an empty bucket send 429 and return True."""
        is_login = self.command == "POST" and path in ("/api/auth/login", "/api/auth/mfa")
        limiter = self.app.login_limiter if is_login else self.app.request_limiter
        if limiter is None:
            return False
        allowed, retry_after = limiter.allow(self._client_ip())
        if allowed:
            return False
        what = "login attempts" if is_login else "requests"
        self.close_connection = True  # the unread body (if any) must not be parsed as the next request
        self._send(429, {"error": f"too many {what}; retry in {retry_after} s", "retry_after": retry_after},
                   extra_headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
        return True

    def _handle(self):
        parsed = urlparse(self.path)
        if self._rate_limited(parsed.path):
            return
        if not parsed.path.startswith("/api/"):
            return self._static(parsed.path)
        self.query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        self.status = 200
        self.set_cookie = None
        self.conn = None
        try:
            for method, pattern, fn, role, csrf in ROUTES:
                match = pattern.match(parsed.path)
                if match and method == self.command:
                    break
            else:
                allowed = any(p.match(parsed.path) for _, p, _, _, _ in ROUTES)
                raise ApiError(405 if allowed else 404, "method not allowed" if allowed else "not found")

            self.body = self._read_body() if self.command == "POST" else b""
            if self.command == "POST" and self.body and \
                    fn not in (ingest_upload,) and "json" not in self.headers.get("Content-Type", ""):
                raise ApiError(415, "Content-Type must be application/json")
            self.conn = self.app.conn()
            self._authorize(role, csrf, fn)
            result = fn(self, *match.groups())
            if result is STREAM_RESPONSE:
                return self._stream()
            headers = {"Cache-Control": "no-store"}
            if self.set_cookie is not None:
                headers["Set-Cookie"] = self._cookie_header(self.set_cookie)
            if isinstance(result, Download):
                headers["Content-Disposition"] = f'attachment; filename="{result.filename}"'
                return self._send(self.status, result.body, result.content_type, headers)
            self._send(self.status, result, extra_headers=headers)
        except ApiError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (auth.AuthError, queries.QueryError, improve.ChangeError, assets.AssetError) as exc:
            self._send(getattr(exc, "status", 400), {"error": str(exc)})
        except Exception as exc:
            record_error(self.conn, "api", exc, guidance=f"Unhandled error on {self.command} {parsed.path}")
            self._send(500, {"error": "internal error; it has been recorded on the Health page"})
        finally:
            if self.conn is not None:
                self.conn.close()

    def _authorize(self, role, csrf, fn=None):
        self.session_token = self._session_token()
        self.user = None
        if role == "public":
            return
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            if role != "ingest":
                raise ApiError(403, "API tokens can only be used for ingestion endpoints")
            self.user = auth.token_user(self.conn, header[7:].strip())
            if self.user is None:
                raise ApiError(401, "invalid or revoked API token")
            return  # bearer tokens are not sent automatically by browsers, so no CSRF risk
        self.user = auth.session_user(self.conn, self.session_token)
        if self.user is None:
            raise ApiError(401, "authentication required")
        minimum = "analyst" if role == "ingest" else role
        if not auth.has_role(self.user, minimum):
            raise ApiError(403, f"requires the {minimum} role")
        if self.user["role"] == "viewer" and self.command != "GET" and fn not in VIEWER_WRITES:
            raise ApiError(403, "viewer accounts are read-only")
        if self.command == "POST" and csrf:
            sent = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(sent, self.user["csrf"]):
                raise ApiError(403, "missing or invalid CSRF token")

    def _stream(self):
        """Server-Sent Events: hello and a health snapshot, then published messages and heartbeats.

        Runs on this connection's own thread (ThreadingHTTPServer) until the client goes away.
        """
        self.conn.close()
        self.conn = None  # hold no database connection while streaming
        try:
            sub = stream.BROKER.subscribe()
        except stream.TooManySubscribers:
            return self._send(503, {"error": "too many live stream connections; retry later"})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            self.close_connection = True
            report = run_health_checks(lambda: connect(self.app.config.db_path), self.app.config.db_path)
            self._frame("hello", {"version": __version__, "user": self.user["username"],
                                  "heartbeat_seconds": stream.HEARTBEAT_SECONDS}, retry=3000)
            self._frame("health", {"partial": False, "status": report["status"], "checked_at": report["checked_at"],
                                   "checks": {c["name"]: c["status"] for c in report["checks"]}})
            while True:
                try:
                    kind, data = sub.get(timeout=stream.HEARTBEAT_SECONDS)
                except queue.Empty:
                    kind, data = "heartbeat", {"ts": now_iso(), "subscribers": stream.BROKER.active()}
                self._frame(kind, data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError, OSError):
            pass  # client went away
        finally:
            stream.BROKER.unsubscribe(sub)

    def _frame(self, kind, data, retry=None):
        payload = (f"retry: {retry}\n".encode() if retry else b"") + \
            stream.frame(kind, data, stream.BROKER.next_id())
        self.wfile.write(payload)
        self.wfile.flush()

    def _cookie_header(self, token):
        parts = [f"{SESSION_COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if self.app.config.secure_cookies:
            parts.append("Secure")
        if token:
            parts.append(f"Max-Age={self.app.config.session_ttl_seconds}")
        else:
            parts.append("Max-Age=0")
        return "; ".join(parts)

    def _static(self, path):
        if self.command != "GET":
            return self._send(405, {"error": "method not allowed"})
        name = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC_DIR / name).resolve()
        if STATIC_DIR.resolve() not in target.parents or not target.is_file():
            return self._send(404, b"not found", "text/plain")
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype, {"Cache-Control": "no-cache"})


def make_server(config=None):
    config = config or Config.from_env()
    app = App(config)
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer((config.host, config.port), handler)
    server.daemon_threads = True
    return server, app


def main(before_serve=None):
    """`before_serve(app)` may start extra services; it returns an object with stop(), or None."""
    configure_logging()
    server, app = make_server()
    host, port = server.server_address[:2]
    log.info("Watchpost %s listening on http://%s:%s", __version__, host, port)
    if app.credentials_file:
        log.info("Initial admin/analyst passwords were generated and saved to %s", app.credentials_file)
    if host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Bound to %s: reachable beyond this machine. Set SIEM_SECURE_COOKIES=1 behind HTTPS.", host)
    service = before_serve(app) if before_serve else None
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if service is not None:
            service.stop()
        app.storyline.stop()
        server.server_close()


if __name__ == "__main__":
    main()
