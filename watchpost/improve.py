"""Continuous improvement: evaluation, rule performance, suggestions, and reviewed changes.

Nothing here learns on its own. Suggestions are deterministic heuristics over analyst
feedback, and no rule or security setting changes until a second person approves it.
"""

import copy
import json
from collections import Counter
from datetime import datetime, time, timedelta, timezone

from . import rules as rules_mod
from . import simulate
from .db import audit, iso, now_iso, row_to_dict, transaction, utcnow
from .engine import active_suppressions, apply_rule_change, load_rules

SECURITY_SETTINGS = {
    "login_lockout_threshold": (3, 20, 5, "Failed logins before an account is temporarily locked"),
    "login_lockout_minutes": (1, 1440, 15, "Minutes an account stays locked"),
}
MIN_FEEDBACK_FOR_SUGGESTION = 2
MAX_SUPPRESSION_DAYS = 90  # tuning exceptions always expire


class ChangeError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def seed_settings(conn):
    for key, (_, _, default, _) in SECURITY_SETTINGS.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value, updated_at, updated_by) VALUES (?,?,?,?)",
            (key, str(default), now_iso(), "system"),
        )


def list_settings(conn):
    rows = {r["key"]: dict(r) for r in conn.execute("SELECT * FROM settings")}
    return [
        {**rows.get(key, {"key": key, "value": str(default)}), "min": low, "max": high, "description": desc}
        for key, (low, high, default, desc) in SECURITY_SETTINGS.items()
    ]


# --- Evaluation against labeled synthetic scenarios -----------------------------------

def evaluate(rule_params, seed=7, suppressions=()):
    """Run each labeled scenario in isolation against the given {rule_id: params}.

    Returns per-rule true positives, false negatives, and false positives, plus which benign
    look-alikes written for the rule were tested and which of them fired. `suppressions` is a set
    of (rule_id, group_key) tuning exceptions: matching findings are dropped and counted, as the
    engine does.
    """
    now = utcnow()
    scenarios = simulate.build(list(simulate.SCENARIOS), seed=seed, now=now)
    # Events dated before the scenario day are history context, as in the engine's rescan.
    day_start = iso(datetime.combine(simulate.demo_day(now), time.min, tzinfo=timezone.utc))
    results = {rid: {"tp": 0, "fn": 0, "fp": 0, "detected": [], "missed": [], "false_positives": [],
                     "lookalikes": [], "lookalikes_fired": [], "suppressed": 0}
               for rid in rule_params}
    next_id = 1
    for name, raw_events in scenarios.items():
        events = []
        for e in raw_events:
            events.append({"id": next_id, **e})
            next_id += 1
        expected = simulate.SCENARIOS[name]["expected"]
        lookalike_of = simulate.SCENARIOS[name].get("lookalike_of")
        for rule_id, params in rule_params.items():
            findings = [f for f in rules_mod.RULE_FUNCTIONS[rule_id](copy.deepcopy(events), params)
                        if f["last_seen"] >= day_start]
            r = results[rule_id]
            kept = [f for f in findings if (rule_id, f["group_key"]) not in suppressions]
            r["suppressed"] += len(findings) - len(kept)
            findings = kept
            if lookalike_of == rule_id:
                r["lookalikes"].append(name)
                if findings:
                    r["lookalikes_fired"].append(name)
            if rule_id in expected:
                want = expected[rule_id]
                hit = [f for f in findings if want is None or f["group_key"] == want]
                if hit:
                    r["tp"] += 1
                    r["detected"].append(name)
                else:
                    r["fn"] += 1
                    r["missed"].append(name)
                extra = len(findings) - len(hit)
            else:
                extra = len(findings)
            if extra:
                r["fp"] += extra
                r["false_positives"].append(name)
    for r in results.values():
        r["recall"] = round(r["tp"] / (r["tp"] + r["fn"]), 3) if r["tp"] + r["fn"] else None
        r["precision"] = round(r["tp"] / (r["tp"] + r["fp"]), 3) if r["tp"] + r["fp"] else None
    return {"seed": seed, "scenarios": list(scenarios), "rules": results}


def current_params(conn, include_disabled=False):
    return {r["id"]: rules_mod.validate_params(r["id"], r["params"])
            for r in load_rules(conn, enabled_only=not include_disabled)}


def record_evaluation(conn, results, trigger, actor, change_request_id=None):
    return conn.execute(
        "INSERT INTO evaluation_runs(created_at, trigger, created_by, change_request_id, results)"
        " VALUES (?,?,?,?,?)",
        (now_iso(), trigger, actor, change_request_id, json.dumps(results)),
    ).lastrowid


def run_evaluation(conn, actor):
    results = evaluate(current_params(conn))
    run_id = record_evaluation(conn, results, "manual", actor)
    return {"id": run_id, **results}


def list_evaluations(conn, limit=20):
    rows = conn.execute("SELECT * FROM evaluation_runs ORDER BY id DESC LIMIT ?", (limit,))
    return [row_to_dict(r, ["results"]) for r in rows]


# --- Analyst feedback -> rule performance ---------------------------------------------

def rule_performance(conn):
    perf = {}
    for rule in load_rules(conn, enabled_only=False):
        row = conn.execute(
            "SELECT COUNT(*) AS total,"
            " SUM(status = 'open') AS open, SUM(status = 'investigating') AS investigating,"
            " SUM(status = 'resolved') AS resolved,"
            " SUM(disposition = 'true_positive') AS tp, SUM(disposition = 'false_positive') AS fp,"
            " SUM(disposition = 'benign') AS benign"
            " FROM alerts WHERE rule_id = ?", (rule["id"],)
        ).fetchone()
        stats = {k: row[k] or 0 for k in row.keys()}
        labeled = stats["tp"] + stats["fp"]
        stats["precision"] = round(stats["tp"] / labeled, 3) if labeled else None
        perf[rule["id"]] = stats
    return perf


def _feedback_evidence(conn, rule_id, disposition):
    """Per alert: the set of IPs and users involved, for alerts with the given disposition."""
    alerts = conn.execute("SELECT id, event_count FROM alerts WHERE rule_id = ? AND disposition = ?",
                          (rule_id, disposition)).fetchall()
    out = []
    for alert in alerts:
        rows = conn.execute(
            "SELECT DISTINCT e.src_ip, e.user FROM events e JOIN alert_events ae ON ae.event_id = e.id"
            " WHERE ae.alert_id = ?", (alert["id"],)
        ).fetchall()
        out.append({
            "alert_id": alert["id"], "event_count": alert["event_count"],
            "ips": {r["src_ip"] for r in rows if r["src_ip"]},
            "users": {r["user"] for r in rows if r["user"]},
        })
    return out


def suggest_for_rule(conn, rule):
    """Return a proposed params change with its justification, or None."""
    fps = _feedback_evidence(conn, rule["id"], "false_positive")
    if len(fps) < MIN_FEEDBACK_FOR_SUGGESTION:
        return None
    tps = _feedback_evidence(conn, rule["id"], "true_positive")
    params = rule["params"]
    tp_ips = set().union(*[t["ips"] for t in tps]) if tps else set()
    tp_users = set().union(*[t["users"] for t in tps]) if tps else set()

    ip_counts = Counter(ip for f in fps for ip in f["ips"])
    ips = sorted(ip for ip, n in ip_counts.items()
                 if n >= MIN_FEEDBACK_FOR_SUGGESTION and ip not in tp_ips and ip not in params["ignore_ips"])
    if ips:
        return {
            "params": {"ignore_ips": params["ignore_ips"] + ips},
            "reason": f"{len(fps)} alerts from this rule were marked false positive by analysts; "
                      f"{', '.join(ips)} appeared in {max(ip_counts[i] for i in ips)} of them and in no "
                      f"true-positive alert. Proposed: exclude these IP(s) from this rule.",
        }

    user_counts = Counter(u for f in fps for u in f["users"])
    users = sorted(u for u, n in user_counts.items()
                   if n >= MIN_FEEDBACK_FOR_SUGGESTION and u not in tp_users and u not in params["ignore_users"])
    if users:
        return {
            "params": {"ignore_users": params["ignore_users"] + users},
            "reason": f"{len(fps)} false-positive alerts involved the account(s) {', '.join(users)}, "
                      f"which never appeared in a true-positive alert. Proposed: exclude them from this rule.",
        }

    key = "threshold" if "threshold" in params else None
    if key and tps:
        max_fp = max(f["event_count"] for f in fps)
        min_tp = min(t["event_count"] for t in tps)
        if params[key] <= max_fp < min_tp:
            return {
                "params": {key: max_fp + 1},
                "reason": f"False-positive alerts had up to {max_fp} events; confirmed true positives had at "
                          f"least {min_tp}. Raising {key} from {params[key]} to {max_fp + 1} would have "
                          f"suppressed the labeled false positives without losing labeled true positives.",
            }
    return None


def generate_suggestions(conn, actor="system:feedback"):
    created = []
    for rule in load_rules(conn, enabled_only=False):
        rule["params"] = rules_mod.validate_params(rule["id"], rule["params"])
        suggestion = suggest_for_rule(conn, rule)
        if not suggestion:
            continue
        payload = {"params": suggestion["params"]}
        duplicate = conn.execute(
            "SELECT 1 FROM change_requests WHERE kind = 'rule_update' AND target = ? AND payload = ?"
            " AND status = 'pending'", (rule["id"], json.dumps(payload, sort_keys=True))
        ).fetchone()
        if duplicate:
            continue
        created.append(propose_change(conn, "rule_update", rule["id"], payload, suggestion["reason"], actor))
    return created


# --- Change requests (two-person review) ------------------------------------------------

def _validate_change(conn, kind, target, payload):
    if not isinstance(payload, dict):
        raise ChangeError("payload must be an object")
    if kind == "rule_update":
        rule = conn.execute("SELECT params FROM rules WHERE id = ?", (target,)).fetchone()
        if rule is None:
            raise ChangeError(f"unknown rule {target!r}", 404)
        if not set(payload) <= {"params", "enabled"} or not payload:
            raise ChangeError("rule changes may only contain 'params' and/or 'enabled'")
        if "enabled" in payload and not isinstance(payload["enabled"], bool):
            raise ChangeError("enabled must be true or false")
        if "params" in payload:
            try:
                merged = rules_mod.validate_params(target, {**json.loads(rule["params"]), **payload["params"]})
            except rules_mod.RuleConfigError as exc:
                raise ChangeError(str(exc))
            return merged
        return None
    if kind == "setting_update":
        if target not in SECURITY_SETTINGS:
            raise ChangeError(f"unknown setting {target!r}", 404)
        low, high, _, _ = SECURITY_SETTINGS[target]
        value = payload.get("value")
        if set(payload) != {"value"} or not isinstance(value, int) or isinstance(value, bool) \
                or not low <= value <= high:
            raise ChangeError(f"{target} must be an integer between {low} and {high}")
        return None
    if kind == "suppression_add":
        if conn.execute("SELECT 1 FROM rules WHERE id = ?", (target,)).fetchone() is None:
            raise ChangeError(f"unknown rule {target!r}", 404)
        key, days = payload.get("group_key"), payload.get("days")
        if set(payload) != {"group_key", "days"} or not isinstance(key, str) or not 0 < len(key) <= 256:
            raise ChangeError("group_key must be the alert group key to suppress (1-256 characters)")
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_SUPPRESSION_DAYS:
            raise ChangeError(f"days must be an integer between 1 and {MAX_SUPPRESSION_DAYS}")
        return None
    raise ChangeError("kind must be rule_update, setting_update or suppression_add")


def propose_change(conn, kind, target, payload, reason, actor):
    if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 2000:
        raise ChangeError("a reason of 5-2000 characters is required")
    merged = _validate_change(conn, kind, target, payload)
    evaluation = None
    if kind == "rule_update":
        before = current_params(conn, include_disabled=True)
        after = dict(before)
        if merged is not None:
            after[target] = merged
        base = evaluate({target: before[target]})["rules"][target]
        new = evaluate({target: after[target]})["rules"][target]
        evaluation = {"rule": target, "before": base, "after": new}
    elif kind == "suppression_add":
        params = {target: current_params(conn, include_disabled=True)[target]}
        active = active_suppressions(conn)
        evaluation = {"rule": target, "before": evaluate(params, suppressions=active)["rules"][target],
                      "after": evaluate(params, suppressions=active | {(target, payload["group_key"])})
                      ["rules"][target]}
    cur = conn.execute(
        "INSERT INTO change_requests(kind, target, payload, reason, proposed_by, evaluation, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (kind, target, json.dumps(payload, sort_keys=True), reason.strip(), actor,
         json.dumps(evaluation) if evaluation else None, now_iso()),
    )
    audit(conn, actor, "change_proposed", f"{kind}:{target}", {"id": cur.lastrowid})
    return get_change(conn, cur.lastrowid)


def get_change(conn, change_id):
    return row_to_dict(conn.execute("SELECT * FROM change_requests WHERE id = ?", (change_id,)).fetchone(),
                       ["payload", "evaluation"])


def list_changes(conn, status=None, limit=100):
    sql, args = "SELECT * FROM change_requests", []
    if status:
        sql += " WHERE status = ?"
        args.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [row_to_dict(r, ["payload", "evaluation"]) for r in conn.execute(sql, args)]


def review_change(conn, change_id, decision, reviewer, note=""):
    if decision not in ("approve", "reject"):
        raise ChangeError("decision must be approve or reject")
    with transaction(conn):
        change = get_change(conn, change_id)
        if change is None:
            raise ChangeError("change request not found", 404)
        if change["status"] != "pending":
            raise ChangeError(f"change request is already {change['status']}", 409)
        if change["proposed_by"] == reviewer:
            raise ChangeError("you cannot review your own change request; a second person must approve it", 403)
        note = (note or "").strip()[:2000]
        if decision == "approve":
            _validate_change(conn, change["kind"], change["target"], change["payload"])  # re-check at apply time
            if change["kind"] == "rule_update":
                apply_rule_change(conn, change["target"], change["payload"], change["proposed_by"], reviewer,
                                  change_id, change["reason"][:500])
            elif change["kind"] == "suppression_add":
                expires = iso(utcnow() + timedelta(days=change["payload"]["days"]))
                conn.execute(
                    "INSERT INTO suppressions(rule_id, group_key, reason, expires_at, proposed_by, approved_by,"
                    " change_request_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (change["target"], change["payload"]["group_key"], change["reason"], expires,
                     change["proposed_by"], reviewer, change_id, now_iso()))
                audit(conn, reviewer, "suppression_added", change["target"],
                      {"group_key": change["payload"]["group_key"], "expires_at": expires,
                       "change_request": change_id})
            else:
                conn.execute("UPDATE settings SET value = ?, updated_at = ?, updated_by = ? WHERE key = ?",
                             (str(change["payload"]["value"]), now_iso(), reviewer, change["target"]))
                audit(conn, reviewer, "setting_changed", change["target"],
                      {"value": change["payload"]["value"], "change_request": change_id})
        status = "approved" if decision == "approve" else "rejected"
        conn.execute(
            "UPDATE change_requests SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE id = ?",
            (status, reviewer, now_iso(), note, change_id),
        )
        audit(conn, reviewer, f"change_{status}", f"{change['kind']}:{change['target']}", {"id": change_id})
        if decision == "approve" and change["kind"] == "rule_update":
            record_evaluation(conn, evaluate(current_params(conn)), "post_change", reviewer, change_id)
    return get_change(conn, change_id)


# --- Tuning exceptions and the noise lab ------------------------------------------------

def list_suppressions(conn):
    """Every approved tuning exception, newest first; `active` is false once it has expired."""
    now = now_iso()
    return [{**dict(r), "active": r["expires_at"] > now}
            for r in conn.execute("SELECT * FROM suppressions ORDER BY id DESC")]


def _verdict(rule, r, other):
    """A plain-language reading of one rule's evaluation. Noise is reported, never hidden."""
    if not rule["enabled"]:
        return "disabled", "Disabled: this rule is not running, so it detects nothing."
    if r["missed"]:
        return "blind", f"Misses a labeled attack ({', '.join(r['missed'])})."
    fired = r["lookalikes_fired"] + other
    excepted = f" {r['suppressed']} finding(s) are covered by a reviewed exception." if r["suppressed"] else ""
    if fired:
        return "noisy", (f"Noisy: catches its attack but also fires on benign activity ({', '.join(fired)}). "
                         f"An analyst has to tell them apart.{excepted}")
    if not r["lookalikes"]:
        return "untested", "No benign look-alike has been written for this rule yet."
    return "quiet", (f"Quiet: catches its attack and stays silent on {len(r['lookalikes'])} look-alike(s) "
                     f"({', '.join(r['lookalikes'])}).{excepted}")


def noise_lab(conn):
    """Each rule against the benign look-alikes, with the current params and active exceptions."""
    results = evaluate(current_params(conn, include_disabled=True), suppressions=active_suppressions(conn))
    benign = {n for n, s in simulate.SCENARIOS.items() if not s["malicious"]}
    rows = []
    for rule in load_rules(conn, enabled_only=False):
        r = results["rules"][rule["id"]]
        other = [n for n in r["false_positives"] if n in benign and n not in r["lookalikes_fired"]]
        verdict, summary = _verdict(rule, r, other)
        rows.append({
            "rule_id": rule["id"], "name": rule["name"], "severity": rule["severity"],
            "enabled": bool(rule["enabled"]), "recall": r["recall"], "precision": r["precision"],
            "tp": r["tp"], "fn": r["fn"], "fp": r["fp"], "detected": r["detected"], "missed": r["missed"],
            "lookalikes_tested": r["lookalikes"], "lookalikes_fired": r["lookalikes_fired"],
            "other_benign_fired": other, "suppressed": r["suppressed"], "verdict": verdict, "summary": summary,
        })
    return {
        "seed": results["seed"],
        "rules": rows,
        "scenarios": [{"name": n, "malicious": s["malicious"], "description": s["description"],
                       "lookalike_of": s.get("lookalike_of"), "expected_rules": list(s["expected"])}
                      for n, s in simulate.SCENARIOS.items()],
        "summary": {"rules": len(rows), "noisy": sum(r["verdict"] == "noisy" for r in rows),
                    "lookalikes": sum("lookalike_of" in s for s in simulate.SCENARIOS.values())},
    }
