"""Continuous improvement: evaluation, rule performance, suggestions, and reviewed changes.

Nothing here learns on its own. Suggestions are deterministic heuristics over analyst
feedback, and no rule, security setting, or severity-lowering asset edit changes until a second
person approves it.
"""

import copy
import hashlib
import json
from collections import Counter
from datetime import datetime, time, timedelta, timezone

from . import assets as assets_mod
from . import backtest as backtest_mod
from . import grouping
from . import rules as rules_mod
from . import search_rules
from . import sigma
from . import simulate
from . import sources as sources_mod
from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction, utcnow
from .engine import active_suppressions, apply_rule_change, correlate_alerts, load_rules

SECURITY_SETTINGS = {
    "login_lockout_threshold": (3, 20, 5, "Failed logins before an account is temporarily locked"),
    "login_lockout_minutes": (1, 1440, 15, "Minutes an account stays locked"),
    "viewer_masking": (0, 1, 0, "1: viewer accounts see pseudonyms for usernames and internal IPs (masking.py)"),
}
MIN_FEEDBACK_FOR_SUGGESTION = 2
MAX_SUPPRESSION_DAYS = 90  # tuning exceptions always expire
MAX_RULE_SUPPRESSION_DAYS = 30
ASSET_KINDS = ("asset_add", "asset_update", "asset_delete")  # inventory edits; see assets.review_reasons
SIGMA_KINDS = ("sigma_add", "sigma_sample")  # import a Sigma rule (added disabled); attach its labeled sample
SEARCH_KINDS = ("search_add", "search_sample")  # promote a saved search to a rule (added disabled); its sample


def sampled_family(rule_id):
    """The module of a rule family proved by its own labeled sample (sigma, search_rules), or None for a
    built-in rule. Each has RULE_PREFIX, SAMPLE_PREFIX, stored_result and sample_scenarios."""
    return next((m for m in (sigma, search_rules) if rule_id.startswith(m.RULE_PREFIX)), None)


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
    engine does. For data_exfil_volume an exception drops nothing; it turns on that principal's baseline.
    """
    now = utcnow()
    scenarios = simulate.build(list(simulate.SCENARIOS), seed=seed, now=now)
    # Events dated before the scenario day are history context, as in the engine's rescan.
    day_start = iso(datetime.combine(simulate.demo_day(now), time.min, tzinfo=timezone.utc))
    # The silence rule judges each scenario as of the end of its day: events arrive at their timestamps there.
    day_end = iso(datetime.combine(simulate.demo_day(now) + timedelta(days=1), time.min, tzinfo=timezone.utc))
    results = {rid: {"tp": 0, "fn": 0, "fp": 0, "detected": [], "missed": [], "false_positives": [],
                     "lookalikes": [], "lookalikes_fired": [], "suppressed": 0, "group_keys": set()}
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
            run_params = rules_mod.exception_params(rule_id, params, suppressions)
            if rule_id == sources_mod.RULE_ID:
                run_params = {**run_params, "now": day_end}
            findings = [f for f in rules_mod.rule_function(rule_id)(copy.deepcopy(events), run_params)
                        if f["last_seen"] >= day_start]
            r = results[rule_id]
            r["group_keys"].update(f["group_key"] for f in findings)  # every key the scenarios exercise
            skips = rule_id not in rules_mod.EXCEPTION_ENABLES_BASELINE  # exfil: baseline, not a skip
            kept = [f for f in findings if not (skips and (rule_id, f["group_key"]) in suppressions)]
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
            elif sampled_family(rule_id) and simulate.SCENARIOS[name]["malicious"]:
                extra = 0  # the built-in labels say nothing about an imported or promoted rule firing on an attack
            else:
                extra = len(findings)
            if extra:
                r["fp"] += extra
                r["false_positives"].append(name)
    for r in results.values():
        r["group_keys"] = sorted(r["group_keys"])
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
        if sampled_family(rule["id"]):
            continue  # a Sigma rule has no tunable params; a search rule has no ignore lists to suggest
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
        if not set(payload) <= {"params", "enabled", "grouping"} or not payload:
            raise ChangeError("rule changes may only contain params, enabled and/or grouping")
        if "grouping" in payload:
            try:
                grouping.validate(payload["grouping"])
            except ValueError as exc:
                raise ChangeError(str(exc))
        if "enabled" in payload and not isinstance(payload["enabled"], bool):
            raise ChangeError("enabled must be true or false")
        if sigma.is_sigma(target):
            # Imported logic is not tuned in place, and it runs only once its labeled sample passes.
            if "params" in payload and payload["params"] != {} and \
                    {**json.loads(rule["params"]), **payload["params"]} != json.loads(rule["params"]):
                raise ChangeError("a Sigma rule has no tunable params: change its YAML and import it again")
            if payload.get("enabled") is True:
                _require_passing_sample(conn, sigma, target, "Sigma rule")
            return json.loads(rule["params"]) if "params" in payload else None
        if search_rules.is_search(target):
            # The threshold and window tune like any rule; the query, group-by and title are the rule itself.
            if "params" in payload:
                if not isinstance(payload["params"], dict):
                    raise ChangeError("params must be an object")
                current = json.loads(rule["params"])
                fixed = sorted(k for k, v in payload["params"].items()
                               if k not in search_rules.TUNABLE and current.get(k, v) != v or k not in current)
                if fixed:
                    raise ChangeError(f"only threshold and window_seconds of a search rule are tunable "
                                      f"({', '.join(fixed)} cannot change): promote a saved search again for a "
                                      "different query")
            if payload.get("enabled") is True:
                _require_passing_sample(conn, search_rules, target, "search rule")
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
    if kind == "rule_suppression_add":
        if conn.execute("SELECT 1 FROM rules WHERE id = ?", (target,)).fetchone() is None:
            raise ChangeError(f"unknown rule {target!r}", 404)
        if set(payload) != {"starts_at", "expires_at"}:
            raise ChangeError("a rule suppression window requires starts_at and expires_at")
        try:
            starts, expires = parse_iso(payload["starts_at"]), parse_iso(payload["expires_at"])
        except (AttributeError, TypeError, ValueError):
            raise ChangeError("starts_at and expires_at must be ISO-8601 timestamps")
        if starts.tzinfo is None or expires.tzinfo is None:
            raise ChangeError("starts_at and expires_at must include a timezone")
        if expires <= starts:
            raise ChangeError("expires_at must be after starts_at")
        if expires - starts > timedelta(days=MAX_RULE_SUPPRESSION_DAYS):
            raise ChangeError(f"a rule suppression window may last at most {MAX_RULE_SUPPRESSION_DAYS} days")
        # Store UTC in the same canonical form used by now_iso(), so indexed text comparisons remain temporal.
        payload["starts_at"], payload["expires_at"] = iso(starts), iso(expires)
        return None
    if kind == "maintenance_add":
        try:
            sources_mod.validate_window(target, payload)
        except sources_mod.WindowError as exc:
            raise ChangeError(str(exc), exc.status)
        return None
    if kind in ASSET_KINDS:
        try:
            return assets_mod.plan_change(conn, kind, target, payload)  # (before, after)
        except assets_mod.AssetError as exc:
            raise ChangeError(str(exc), exc.status)
    if kind in SIGMA_KINDS:
        return _validate_sigma(conn, kind, target, payload)
    if kind in SEARCH_KINDS:
        return _validate_search(conn, kind, target, payload)
    raise ChangeError(f"kind must be rule_update, setting_update, suppression_add, rule_suppression_add, "
                      f"maintenance_add or one of "
                      f"{', '.join(ASSET_KINDS + SIGMA_KINDS + SEARCH_KINDS)}")


def _require_passing_sample(conn, family, target, label):
    """Refuse enabling a sampled rule (Sigma, search) until its labeled sample passes."""
    result = family.stored_result(conn, target)
    if result is None or not result["passes"]:
        raise ChangeError(f"this {label} cannot be enabled until it has a labeled sample that passes ("
                          + ("no sample attached" if result is None else result["summary"]) + ")")


def _validate_sigma(conn, kind, target, payload):
    """sigma_add: {source, sample?} compiles to a new rule `target`; sigma_sample: {sample} for a Sigma rule.

    Returns (compiled rule or None, validated sample or None).
    """
    try:
        if kind == "sigma_add":
            if not set(payload) <= {"source", "sample"} or "source" not in payload:
                raise ChangeError("a Sigma import is {source, sample (optional)}")
            compiled = sigma.compile_rule(payload["source"])
            if compiled["rule_id"] != target:
                raise ChangeError(f"the rule id for this title is {compiled['rule_id']!r}, not {target!r}")
            if conn.execute("SELECT 1 FROM rules WHERE id = ?", (target,)).fetchone():
                raise ChangeError(f"rule {target!r} already exists; give the Sigma rule a different title", 409)
            sample = payload.get("sample")
            return compiled, sigma.validate_sample(sample) if sample is not None else None
        if not sigma.is_sigma(target) or sigma.stored(conn, target) is None:
            raise ChangeError(f"unknown Sigma rule {target!r}", 404)
        if set(payload) != {"sample"}:
            raise ChangeError("a sample change is {sample}")
        return None, sigma.validate_sample(payload["sample"])
    except sigma.SigmaError as exc:
        raise ChangeError(str(exc))


def _validate_search(conn, kind, target, payload):
    """search_add: {saved_search_id, query, definition, sample?} compiles to a new rule `target` (the query is
    the one copied from the saved search when it was promoted); search_sample: {sample} for a search rule.

    Returns (compiled rule or None, validated sample or None).
    """
    try:
        if kind == "search_add":
            if not set(payload) <= {"saved_search_id", "query", "definition", "sample"} or \
                    not {"query", "definition"} <= set(payload):
                raise ChangeError("a promoted search is {saved_search_id, query, definition, sample (optional)}")
            sid = payload.get("saved_search_id")
            if sid is not None and (not isinstance(sid, int) or isinstance(sid, bool)):
                raise ChangeError("saved_search_id must be an integer")
            compiled = search_rules.compile_rule(None, payload["query"], payload["definition"])
            if compiled["rule_id"] != target:
                raise ChangeError(f"the rule id for this name is {compiled['rule_id']!r}, not {target!r}")
            if conn.execute("SELECT 1 FROM rules WHERE id = ?", (target,)).fetchone():
                raise ChangeError(f"rule {target!r} already exists; give the search rule a different name", 409)
            sample = payload.get("sample")
            return compiled, search_rules.validate_sample(sample) if sample is not None else None
        if not search_rules.is_search(target) or search_rules.stored(conn, target) is None:
            raise ChangeError(f"unknown search rule {target!r}", 404)
        if set(payload) != {"sample"}:
            raise ChangeError("a sample change is {sample}")
        return None, search_rules.validate_sample(payload["sample"])
    except search_rules.SearchRuleError as exc:
        raise ChangeError(str(exc))


LIVE_IMPACT_RECENT = 5  # newest matching alerts listed in an exception's evidence
BACKTEST_EVIDENCE_LIMIT = 10  # kept/new/lost findings listed in a rule change's evidence; counts are complete


# Every verdict is in alert_activity as "<from> -> resolved (<disposition>)" (queries.update_status), and
# that log is append-only: re-opening or re-closing an alert adds a row, it never rewrites one.
def _rule_alerts(conn, rule_id):
    """A rule's alerts, newest first, and their status-change history. Matching is then done in Python."""
    alerts = [dict(r) for r in conn.execute(
        "SELECT id, title, status, disposition, group_key FROM alerts WHERE rule_id = ? ORDER BY id DESC",
        (rule_id,))]
    history = [dict(r) for r in conn.execute(
        "SELECT act.alert_id, act.actor, act.detail, act.created_at FROM alert_activity act"
        " JOIN alerts a ON a.id = act.alert_id WHERE a.rule_id = ? AND act.action = 'status_changed'"
        " ORDER BY act.id DESC", (rule_id,))]
    return alerts, history


def _alert_impact(alerts, history, ids, proposer):
    """Counts and history of the alerts in `ids`, out of `_rule_alerts`."""
    rows = [{k: a[k] for k in ("id", "title", "status", "disposition")} for a in alerts if a["id"] in ids]
    history = [h for h in history if h["alert_id"] in ids]
    # History, not the current verdict: whoever proposes the change can also re-close the alert.
    ever_true_positive = {h["alert_id"] for h in history if h["detail"].endswith("(true_positive)")}
    ever_true_positive |= {row["id"] for row in rows if row["disposition"] == "true_positive"}
    own = [{k: h[k] for k in ("alert_id", "detail", "created_at")} for h in history if h["actor"] == proposer]
    by_status, by_disposition = {}, {}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        if row["disposition"]:
            by_disposition[row["disposition"]] = by_disposition.get(row["disposition"], 0) + 1
    return {
        "alerts": len(rows), "by_status": by_status, "by_disposition": by_disposition,
        "recent": rows[:LIVE_IMPACT_RECENT],
        "ever_true_positive": len(ever_true_positive),
        # Status and verdict changes the proposer made on these alerts, so the reviewer sees them.
        "proposer_verdict_changes": {"count": len(own), "recent": own[:LIVE_IMPACT_RECENT]},
    }


def _ignore_additions(conn, rule_id, before, after, proposer):
    """Live impact of every list edit in a rule change that makes the rule skip events.

    That is a value added to an ignore list, or removed from privileged_users (rules.HIDING_EDITS): a
    permanent exception with no expiry. Entries are compared the way the rules compare them, so a
    respelling of an existing entry is no edit and two spellings of a new one are listed once. An alert
    is touched when rules.covers says the rule would skip (or no longer watch) one of its evidence events.
    """
    edits = []
    for param, change in rules_mod.HIDING_EDITS.items():
        old, new = before.get(param, []), after.get(param, [])
        source, other = (new, old) if change == "added" else (old, new)
        seen = {rules_mod.list_entry(param, v) for v in other}
        for value in source:
            entry = rules_mod.list_entry(param, value)
            if entry not in seen:
                seen.add(entry)
                edits.append((param, change, value, entry))
    if not edits:
        return []
    alerts, history = _rule_alerts(conn, rule_id)
    evidence = {}
    for row in conn.execute(
            "SELECT ae.alert_id, e.src_ip, e.user, e.message FROM alert_events ae"
            " JOIN alerts a ON a.id = ae.alert_id JOIN events e ON e.id = ae.event_id WHERE a.rule_id = ?",
            (rule_id,)):
        evidence.setdefault(row["alert_id"], []).append(dict(row))
    return [{"param": param, "change": change, "value": value, "live_impact": _alert_impact(
                alerts, history,
                {i for i, events in evidence.items() if any(rules_mod.covers(param, {entry}, e) for e in events)},
                proposer)}
            for param, change, value, entry in edits]


def _live_impact(conn, rule_id, group_key, scenario_keys, proposer):
    """What an exception would touch in this database, which the labeled scenarios cannot show."""
    baseline = rule_id in rules_mod.EXCEPTION_ENABLES_BASELINE
    alerts, history = _rule_alerts(conn, rule_id)
    return {
        # The engine skips a finding whose group key equals the exception's exactly; so does this.
        **_alert_impact(alerts, history, {a["id"] for a in alerts if a["group_key"] == group_key}, proposer),
        # False means before/after below say nothing about this key: no labeled scenario contains it.
        "in_labeled_scenario": group_key in scenario_keys,
        "effect": "baseline" if baseline else "skip",
        "effect_note": ("Nothing is hidden: the exception enables baseline mode for this principal, which then "
                        "alerts only on a burst several times its own recent normal." if baseline else
                        "Every finding of this rule for this group key is hidden until the exception expires "
                        "or is revoked."),
    }


def _not_running(result):
    """A rule's evaluation when it is disabled: it fires on nothing, so every labeled attack is missed."""
    labeled = sorted(result["detected"] + result["missed"])
    return {**result, "tp": 0, "fn": len(labeled), "fp": 0, "detected": [], "missed": labeled,
            "false_positives": [], "lookalikes_fired": [], "suppressed": 0, "group_keys": [],
            "recall": 0.0 if labeled else None, "precision": None}


def _evidence(conn, kind, target, payload, proposer):
    """Validate a change and compute what a reviewer is shown for it, from the current state.

    Used at proposal time and again at approval, so an approval can be refused when the two differ.
    """
    merged = _validate_change(conn, kind, target, payload)
    evaluation = None
    if kind == "rule_update":
        before = current_params(conn, include_disabled=True)
        after = dict(before)
        if merged is not None:
            after[target] = merged
        base = evaluate({target: before[target]})["rules"][target]
        new = evaluate({target: after[target]})["rules"][target]
        enabled = bool(conn.execute("SELECT enabled FROM rules WHERE id = ?", (target,)).fetchone()["enabled"])
        if not enabled:
            base = _not_running(base)
        if not payload.get("enabled", enabled):
            new = _not_running(new)
        evaluation = {"rule": target, "before": base, "after": new,
                      "ignore_additions": _ignore_additions(conn, target, before[target], after[target], proposer),
                      # Replayed over stored events. Events are only appended, so one arriving between viewing
                      # and approving changes this (and the digest): the reviewer re-confirms, as for assets.
                      "backtest": backtest_mod.backtest(conn, target, after[target],
                                                        running=(enabled, payload.get("enabled", enabled)),
                                                        limit=BACKTEST_EVIDENCE_LIMIT)}
        if "grouping" in payload:
            evaluation["grouping_preview"] = grouping.preview(conn, target, payload["grouping"])
    elif kind == "suppression_add":
        params = {target: current_params(conn, include_disabled=True)[target]}
        active = active_suppressions(conn)
        base = evaluate(params, suppressions=active)["rules"][target]
        evaluation = {"rule": target, "before": base,
                      "after": evaluate(params, suppressions=active | {(target, payload["group_key"])})
                      ["rules"][target],
                      "live_impact": _live_impact(conn, target, payload["group_key"], base["group_keys"],
                                                  proposer)}
    elif kind == "rule_suppression_add":
        params = current_params(conn, include_disabled=True)[target]
        base = evaluate({target: params})["rules"][target]
        family = sampled_family(target)
        sample = family.stored_result(conn, target) if family else None
        if sample:
            name = family.SAMPLE_PREFIX + target
            base = {**base,
                    "detected": base["detected"] + [name] * sample["passes"],
                    "missed": base["missed"] + [name] * bool(sample["missed"]),
                    "lookalikes": base["lookalikes"] + [name],
                    "lookalikes_fired": base["lookalikes_fired"] + [name] * bool(sample["fired"])}
        enabled = bool(conn.execute("SELECT enabled FROM rules WHERE id = ?", (target,)).fetchone()["enabled"])
        if not enabled:
            base = _not_running(base)
        evaluation = {"rule": target, "before": base, "after": _not_running(base),
                      # A window temporarily stops this rule, so replay current params as running -> paused.
                      "backtest": backtest_mod.backtest(conn, target, params,
                                                          running=(enabled, False),
                                                          limit=BACKTEST_EVIDENCE_LIMIT)}
    elif kind in ASSET_KINDS:
        evaluation = assets_mod.change_evidence(conn, *merged)
    elif kind == "sigma_add":
        compiled, sample = merged
        evaluation = {"rule": target, "title": compiled["title"], "sha256": compiled["sha256"],
                      "severity": compiled["severity"], "techniques": [t["id"] for t in compiled["techniques"]],
                      "conditions": compiled["conditions"], "warnings": compiled["warnings"],
                      "sample": sigma.sample_result(compiled["params"], sample),
                      # What it would match among stored events. Added disabled either way.
                      "backtest": sigma.preview(conn, compiled["params"])}
    elif kind == "search_add":
        compiled, sample = merged
        params = compiled["params"]
        evaluation = {"rule": target, "title": compiled["title"], "query": compiled["query"],
                      "severity": compiled["severity"], "techniques": [t["id"] for t in compiled["techniques"]],
                      "conditions": compiled["conditions"],
                      **{k: params[k] for k in ("group_by", "threshold", "window_seconds")},
                      "sample": search_rules.sample_result(params, sample),
                      # Its findings among stored events. Added disabled either way.
                      "backtest": search_rules.preview(conn, params)}
    elif kind in ("sigma_sample", "search_sample"):
        family = sigma if kind == "sigma_sample" else search_rules
        row = conn.execute("SELECT params, enabled FROM rules WHERE id = ?", (target,)).fetchone()
        evaluation = {"rule": target, "enabled": bool(row["enabled"]),
                      "before": family.stored_result(conn, target),
                      "sample": family.sample_result(json.loads(row["params"]), merged[1])}
    return json.loads(json.dumps(evaluation))  # as it reads back from storage, so the two compare equal


BACKTEST_CONTEXT = ("window", "max_event_id", "events_scanned", "synthetic_events")


def evidence_digest(evaluation):
    """A stable hash of a change's evidence. An approval names the evidence it was given by this digest."""
    if evaluation is None:
        return None
    if isinstance(evaluation.get("backtest"), dict):
        # The backtest's scan context moves with every ingested event (the window ends at the newest one);
        # the digest covers what the reviewer decides on: the kept / new / lost findings and open alerts lost.
        evaluation = {**evaluation, "backtest": {k: v for k, v in evaluation["backtest"].items()
                                                 if k not in BACKTEST_CONTEXT}}
    canonical = json.dumps(evaluation, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Two gates stand between a change and a labeled attack going undetected, and they differ on purpose.
# An exception hides one group key for good reason or bad, and nothing legitimate needs it for
# confirmed-malicious activity: `_refusal` is a hard no, at propose and at approve. A value added to an
# ignore list (or removed from privileged_users) is the same thing without an expiry, so true-positive
# history refuses it too. Any other rule change
# (a looser threshold, or disabling the rule) can be a legitimate trade, so it is not refused: the
# reviewer must explicitly acknowledge the scenarios in `_detection_loss`, and the audit log names them.
# Neither reads anything the proposer can edit: the scenario check uses the built-in labeled scenarios
# and the rule parameters, and the true-positive check uses the append-only alert history.

def _detection_loss(evaluation):
    """Labeled attacks the rule detects before the change and misses after it."""
    return sorted(set(evaluation["before"]["detected"]) & set(evaluation["after"]["missed"]))


def _open_alerts_lost(evaluation):
    """Open alerts the backtest reproduces with today's params and not with the proposed ones.

    The same trade as a lost labeled attack, from real stored events: approval needs the same explicit
    acknowledgement. Change requests from before backtesting carry no backtest until refreshed.
    """
    bt = (evaluation or {}).get("backtest")
    return [a["id"] for a in bt["open_alerts_lost"]] if bt else []


def validate_rule_update(conn, rule_id, payload):
    """Validate a rule_update payload exactly as a proposal is. Returns the merged params, or None."""
    return _validate_change(conn, "rule_update", rule_id, payload)


def preview_backtest(conn, rule_id, params, window_days=backtest_mod.DEFAULT_WINDOW_DAYS):
    """Backtest a draft rule change before it is proposed. Validated exactly as a rule_update proposal."""
    if not isinstance(params, dict):
        raise ChangeError("params must be a JSON object")
    merged = _validate_change(conn, "rule_update", rule_id, {"params": params})
    enabled = bool(conn.execute("SELECT enabled FROM rules WHERE id = ?", (rule_id,)).fetchone()["enabled"])
    return backtest_mod.backtest(conn, rule_id, merged, window_days=window_days, running=(enabled, enabled))


def _refusal(kind, evaluation):
    """Why a change may not be approved at all, or None. Confirmed-malicious activity is never excepted."""
    if kind == "rule_update":
        blocked = [f"{x['param']} {x['value']}" for x in evaluation["ignore_additions"]
                   if x["live_impact"]["ever_true_positive"]]
        if blocked:
            return (f"an alert of this rule involving {', '.join(blocked)} has been closed as a true positive; "
                    "a rule change may not make the rule skip confirmed-malicious activity")
    if kind != "suppression_add":
        return None
    lost = _detection_loss(evaluation)
    if lost:
        return (f"this exception would make the rule miss a labeled attack it detects today ({', '.join(lost)}); "
                f"confirmed-malicious activity cannot be excepted")
    if evaluation["live_impact"]["ever_true_positive"]:
        return ("an alert of this rule with this group key has been closed as a true positive; "
                "confirmed-malicious activity cannot be excepted")
    return None


def propose_change(conn, kind, target, payload, reason, actor):
    if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 2000:
        raise ChangeError("a reason of 5-2000 characters is required")
    evaluation = _evidence(conn, kind, target, payload, actor)
    refusal = _refusal(kind, evaluation)
    if refusal:
        raise ChangeError(refusal)
    cur = conn.execute(
        "INSERT INTO change_requests(kind, target, payload, reason, proposed_by, evaluation, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (kind, target, json.dumps(payload, sort_keys=True), reason.strip(), actor,
         json.dumps(evaluation) if evaluation else None, now_iso()),
    )
    audit(conn, actor, "change_proposed", f"{kind}:{target}", {"id": cur.lastrowid})
    return get_change(conn, cur.lastrowid)


def _change(row):
    change = row_to_dict(row, ["payload", "evaluation"])
    if change is not None:
        change["evidence_digest"] = evidence_digest(change["evaluation"])
    return change


def get_change(conn, change_id):
    return _change(conn.execute("SELECT * FROM change_requests WHERE id = ?", (change_id,)).fetchone())


def list_changes(conn, status=None, limit=100):
    sql, args = "SELECT * FROM change_requests", []
    if status:
        sql += " WHERE status = ?"
        args.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [_change(r) for r in conn.execute(sql, args)]


def review_change(conn, change_id, decision, reviewer, note="", digest=None, acknowledge_detection_loss=False):
    """Approve or reject a pending change. An approval applies only to the evidence named by `digest`."""
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
        problem, lost, lost_alerts = None, [], []
        if decision == "approve":
            # Recomputed, compared and applied in this one transaction: approval acts on the evidence the
            # reviewer was shown (named by its digest), or not at all.
            fresh = _evidence(conn, change["kind"], change["target"], change["payload"], change["proposed_by"])
            if fresh is not None and (not isinstance(digest, str) or not digest):
                raise ChangeError("evidence_digest is required to approve: send the digest of the evidence "
                                  "you reviewed")
            if fresh != change["evaluation"]:
                conn.execute("UPDATE change_requests SET evaluation = ? WHERE id = ?",
                             (json.dumps(fresh), change_id))
                audit(conn, reviewer, "change_evidence_refreshed", f"{change['kind']}:{change['target']}",
                      {"id": change_id})
            refusal = _refusal(change["kind"], fresh)
            if change["kind"] in ("rule_update", "rule_suppression_add"):
                lost, lost_alerts = _detection_loss(fresh), _open_alerts_lost(fresh)
            if refusal:
                problem = ChangeError(refusal)
            elif fresh is not None and digest != evidence_digest(fresh):
                problem = ChangeError("the evidence changed since this request was last shown; nothing was "
                                      "applied. Review the updated evidence and approve again", 409)
            elif (lost or lost_alerts) and acknowledge_detection_loss is not True:
                what = [f"labeled attacks it detects today ({', '.join(lost)})"] if lost else []
                if lost_alerts:
                    what.append(f"{fresh['backtest']['counts']['open_alerts_lost']} open alert(s) on stored "
                                f"events (#{', #'.join(map(str, lost_alerts))})")
                problem = ChangeError(f"this change makes the rule miss {' and '.join(what)}; approve with "
                                      "acknowledge_detection_loss: true to accept that")
        if problem is not None:
            pass  # left pending; raised once the refreshed evidence is committed
        elif decision == "approve":
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
            elif change["kind"] == "rule_suppression_add":
                conn.execute(
                    "INSERT INTO rule_suppression_windows(rule_id, starts_at, expires_at, reason, proposed_by,"
                    " approved_by, change_request_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (change["target"], change["payload"]["starts_at"], change["payload"]["expires_at"],
                     change["reason"], change["proposed_by"], reviewer, change_id, now_iso()))
                audit(conn, reviewer, "rule_suppression_window_added", change["target"],
                      {**change["payload"], "change_request": change_id})
            elif change["kind"] == "maintenance_add":
                sources_mod.add_window(conn, change["target"], change["payload"], change["reason"],
                                       change["proposed_by"], reviewer, change_id)
            elif change["kind"] == "sigma_add":
                compiled, sample = _validate_sigma(conn, "sigma_add", change["target"], change["payload"])
                sigma.add_rule(conn, compiled, change["payload"]["source"], sample, change["proposed_by"],
                               reviewer, change_id, now_iso())
                audit(conn, reviewer, "sigma_rule_added", change["target"],
                      {"sha256": compiled["sha256"], "enabled": False, "sample": sample is not None,
                       "change_request": change_id})
            elif change["kind"] == "sigma_sample":
                _, sample = _validate_sigma(conn, "sigma_sample", change["target"], change["payload"])
                version = sigma.set_sample(conn, change["target"], sample, change["proposed_by"], reviewer, change_id,
                                           now_iso())
                audit(conn, reviewer, "sigma_sample_set", change["target"],
                      {"version": version, "passes": fresh["sample"]["passes"], "change_request": change_id})
            elif change["kind"] == "search_add":
                compiled, sample = _validate_search(conn, "search_add", change["target"], change["payload"])
                search_rules.add_rule(conn, compiled, change["payload"].get("saved_search_id"), sample,
                                      change["proposed_by"], reviewer, change_id, now_iso())
                audit(conn, reviewer, "search_rule_added", change["target"],
                      {"query": compiled["query"], "enabled": False, "sample": sample is not None,
                       "change_request": change_id})
            elif change["kind"] == "search_sample":
                _, sample = _validate_search(conn, "search_sample", change["target"], change["payload"])
                version = search_rules.set_sample(conn, change["target"], sample, change["proposed_by"], reviewer,
                                                  change_id, now_iso())
                audit(conn, reviewer, "search_sample_set", change["target"],
                      {"version": version, "passes": fresh["sample"]["passes"], "change_request": change_id})
            elif change["kind"] in ASSET_KINDS:
                # Checked again by _evidence above in this transaction, so a conflict has already refused it.
                assets_mod.apply_change(conn, change["kind"], change["target"], change["payload"], reviewer,
                                        {"change_request": change_id, "proposed_by": change["proposed_by"]})
            else:
                conn.execute("UPDATE settings SET value = ?, updated_at = ?, updated_by = ? WHERE key = ?",
                             (str(change["payload"]["value"]), now_iso(), reviewer, change["target"]))
                audit(conn, reviewer, "setting_changed", change["target"],
                      {"value": change["payload"]["value"], "change_request": change_id})
        if problem is None:
            status = "approved" if decision == "approve" else "rejected"
            conn.execute(
                "UPDATE change_requests SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE id = ?",
                (status, reviewer, now_iso(), note, change_id),
            )
            audit(conn, reviewer, f"change_{status}", f"{change['kind']}:{change['target']}",
                  {"id": change_id, **({"acknowledged_detection_loss": lost} if lost else {}),
                   **({"acknowledged_open_alerts_lost": lost_alerts} if lost_alerts else {})})
            if decision == "approve" and change["kind"] == "rule_update":
                record_evaluation(conn, evaluate(current_params(conn)), "post_change", reviewer, change_id)
    if problem is not None:
        raise problem
    result = get_change(conn, change_id)
    if decision == "approve" and change["kind"] in ASSET_KINDS:
        # Same follow-up as a direct inventory edit: re-weigh open alerts, then refresh incident severities.
        result["alerts_rescored"] = assets_mod.rescore_open_alerts(conn)
        if result["alerts_rescored"]:
            correlate_alerts(conn)
    return result


# --- Tuning exceptions and the noise lab ------------------------------------------------

def list_suppressions(conn):
    """Every approved tuning exception, newest first; `active` is false once it has expired or been revoked."""
    now = now_iso()
    return [{**dict(r), "active": r["expires_at"] > now and r["revoked_at"] is None}
            for r in conn.execute("SELECT * FROM suppressions ORDER BY id DESC")]


def revoke_suppression(conn, suppression_id, actor):
    """End a tuning exception early. The row stays as history; detection ignores it from the next run."""
    with transaction(conn):
        row = conn.execute("SELECT * FROM suppressions WHERE id = ?", (suppression_id,)).fetchone()
        if row is None:
            raise ChangeError("tuning exception not found", 404)
        if row["revoked_at"] is not None:
            raise ChangeError("tuning exception is already revoked", 409)
        if row["expires_at"] <= now_iso():
            raise ChangeError("tuning exception has already expired", 409)
        conn.execute("UPDATE suppressions SET revoked_at = ?, revoked_by = ? WHERE id = ?",
                     (now_iso(), actor, suppression_id))
        audit(conn, actor, "suppression_revoked", row["rule_id"],
              {"id": suppression_id, "group_key": row["group_key"], "change_request": row["change_request_id"]})
    return next(s for s in list_suppressions(conn) if s["id"] == suppression_id)


def list_rule_suppression_windows(conn):
    """Every approved rule-wide window, including upcoming, expired and ended history."""
    now = now_iso()
    result = []
    for row in conn.execute("SELECT * FROM rule_suppression_windows ORDER BY id DESC"):
        item = dict(row)
        if item["ended_at"] is not None:
            state = "ended"
        elif item["starts_at"] > now:
            state = "upcoming"
        elif item["expires_at"] <= now:
            state = "expired"
        else:
            state = "active"
        result.append({**item, "state": state, "active": state == "active"})
    return result


def end_rule_suppression_window(conn, window_id, actor):
    """End an active or upcoming window early while retaining its approved interval as history."""
    with transaction(conn):
        row = conn.execute("SELECT * FROM rule_suppression_windows WHERE id = ?", (window_id,)).fetchone()
        if row is None:
            raise ChangeError("rule suppression window not found", 404)
        if row["ended_at"] is not None:
            raise ChangeError("rule suppression window is already ended", 409)
        if row["expires_at"] <= now_iso():
            raise ChangeError("rule suppression window has already expired", 409)
        ended = now_iso()
        conn.execute("UPDATE rule_suppression_windows SET ended_at = ?, ended_by = ? WHERE id = ?",
                     (ended, actor, window_id))
        audit(conn, actor, "rule_suppression_window_ended", row["rule_id"],
              {"id": window_id, "change_request": row["change_request_id"]})
    return next(w for w in list_rule_suppression_windows(conn) if w["id"] == window_id)


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
        sample = None
        family = sampled_family(rule["id"])
        if family:
            # The rule's own labeled sample stands in for a scenario: detected when it passes.
            sample = family.stored_result(conn, rule["id"])
            name = family.SAMPLE_PREFIX + rule["id"]
            if sample:
                r = {**r, "detected": r["detected"] + [name] * sample["passes"],
                     "missed": r["missed"] + [name] * bool(sample["missed"]),
                     "lookalikes": r["lookalikes"] + [name],
                     "lookalikes_fired": r["lookalikes_fired"] + [name] * bool(sample["fired"])}
        verdict, summary = _verdict(rule, r, other)
        if family and sample is None and rule["enabled"]:
            verdict, summary = "untested", (f"{'Imported Sigma rule' if family is sigma else 'Promoted saved search'}"
                                            " without a labeled sample: nothing proves it detects.")
        rows.append({
            "rule_id": rule["id"], "name": rule["name"], "severity": rule["severity"],
            "enabled": bool(rule["enabled"]), "recall": r["recall"], "precision": r["precision"],
            "tp": r["tp"], "fn": r["fn"], "fp": r["fp"], "detected": r["detected"], "missed": r["missed"],
            "lookalikes_tested": r["lookalikes"], "lookalikes_fired": r["lookalikes_fired"],
            "other_benign_fired": other, "suppressed": r["suppressed"], "verdict": verdict, "summary": summary,
            **({"sample": sample} if family else {}),
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


_NOISE_LAB_CACHE = {}  # {key: result}; one entry, replaced when rules, exceptions, or the demo day change


def cached_noise_lab(conn):
    """noise_lab(), reused while the inputs that decide it stay the same.

    The evaluation is a pure function of the rule params and enabled flags, the active tuning
    exceptions, and the scenario day, so those form the key. Callers must not modify the result.
    """
    key = (tuple((r["id"], r["version"], bool(r["enabled"]), json.dumps(r["params"], sort_keys=True))
                 for r in load_rules(conn, enabled_only=False)),
           tuple(sorted(active_suppressions(conn))), simulate.demo_day(utcnow()))
    if key not in _NOISE_LAB_CACHE:
        result = noise_lab(conn)
        _NOISE_LAB_CACHE.clear()
        _NOISE_LAB_CACHE[key] = result
    return _NOISE_LAB_CACHE[key]
