"""Rule export and import: move rule tuning between Watchpost instances.

What moves is tuning: `params`, `enabled`, and reviewed alert `grouping` of rules this code already has. Detection logic is Python
code in rules.py and is not exported, so an import cannot add a rule or change how one detects.

An import applies nothing. Each rule whose tuning differs from today's becomes an ordinary `rule_update`
change request through improve.propose_change, with the same validation, backtest evidence, detection-loss
gate and two-person review as a proposal made by hand.
"""

from . import __version__
from . import improve
from . import rules as rules_mod
from .db import audit, now_iso, transaction
from .engine import load_rules

# A validated param key the stored row does not have yet. Distinct from any real value, including None.
_MISSING = object()

FORMAT, FORMAT_VERSION = "watchpost-rules", 1
NOTE = ("Rule tuning only (params, enabled, grouping). Detection logic is Python code in watchpost/rules.py and is not "
        "exported: an import can retune rules the importing instance already has, never add or change logic.")
MAX_IMPORT_BYTES = 256 * 1024
MAX_IMPORT_RULES = 200
DOCUMENT_KEYS = {"format", "format_version", "watchpost_version", "exported_at", "note", "rules"}
# Keys an exported rule carries. Only params and enabled are imported; the rest describe the rule as it was.
RULE_KEYS = {"id", "name", "version", "enabled", "severity", "params", "grouping", "techniques", "description"}


def _technique_ids(techniques):
    """Technique ids from catalog dicts or plain strings. One bad entry must not fail the export."""
    if not isinstance(techniques, list):
        return []
    ids = []
    for item in techniques:
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.append(item["id"])
    return ids


def _export_params(rule):
    """Validated params, or the stored value when it no longer validates. One row must not fail the export."""
    try:
        return rules_mod.validate_params(rule["id"], rule["params"])
    except rules_mod.RuleConfigError:
        return rule["params"]


def _copy_tuning(value):
    """A plan must not share list objects with the document the caller still holds."""
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return {key: list(item) if isinstance(item, list) else item for key, item in value.items()}
    return value


def _tuning_payload(entry, rule):
    """Only tuning that differs. An export always carries params, enabled and grouping.

    Passing `enabled: true` through for an already-enabled Sigma or search rule re-runs the sample
    gate, so a round trip (and a grouping-only change) is refused even though nothing was turned on.
    """
    payload = {}
    if "params" in entry:
        incoming, stored = entry["params"], rule["params"]
        if not isinstance(incoming, dict):
            if incoming != stored:
                raise improve.ChangeError("params must be an object")
        elif not isinstance(stored, dict):
            raise improve.ChangeError("stored params are not an object and cannot be merged")
        elif {**stored, **incoming} != stored:
            payload["params"] = incoming
    if "enabled" in entry:
        enabled = entry["enabled"]
        # 1 == True, but only a real boolean is a tuning value. A non-boolean is refused, not ignored.
        if not isinstance(enabled, bool) or enabled != bool(rule["enabled"]):
            payload["enabled"] = enabled
    if "grouping" in entry and entry["grouping"] != rule["grouping"]:
        payload["grouping"] = entry["grouping"]
    return payload


def _changed_params(rule_id, rule, merged):
    """Param keys whose validated value differs. A stored row that no longer validates is a repair."""
    try:
        today = rules_mod.validate_params(rule_id, rule["params"])
    except rules_mod.RuleConfigError:
        today = {}
    changed = {}
    for key, value in (merged or {}).items():
        if today.get(key, _MISSING) != value:
            changed[key] = list(value) if isinstance(value, list) else value
    return changed


def _refused_reasons(plan):
    """One reason per refused row. Colliding ids (and every id-less row) keep the earlier reasons."""
    refused, seen = {}, {}
    for item in plan:
        if item["outcome"] != "refused":
            continue
        base = str(item["id"])
        seen[base] = seen.get(base, 0) + 1
        key = base if seen[base] == 1 else f"{base}#{seen[base]}"
        refused[key] = item["reason"]
    return refused


def export_rules(conn):
    """Every rule's tuning and description, sorted by id. Callers serialize with sorted keys."""
    rules = [{"id": r["id"], "name": r["name"], "version": r["version"], "enabled": bool(r["enabled"]),
              "severity": r["severity"], "params": _export_params(r), "grouping": r["grouping"],
              "techniques": _technique_ids(r["techniques"]), "description": r["description"]}
             for r in load_rules(conn, enabled_only=False)]
    return {"format": FORMAT, "format_version": FORMAT_VERSION, "watchpost_version": __version__,
            "exported_at": now_iso(), "note": NOTE, "rules": sorted(rules, key=lambda r: r["id"])}


def _check_document(doc):
    if not isinstance(doc, dict):
        raise improve.ChangeError("the import must be a JSON object")
    unknown = set(doc) - DOCUMENT_KEYS
    if unknown:
        raise improve.ChangeError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
    if doc.get("format") != FORMAT:
        raise improve.ChangeError(f"format must be {FORMAT!r}")
    version = doc.get("format_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != FORMAT_VERSION:
        raise improve.ChangeError(f"format_version must be {FORMAT_VERSION}")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise improve.ChangeError("rules must be a list")
    if len(rules) > MAX_IMPORT_RULES:
        raise improve.ChangeError(f"at most {MAX_IMPORT_RULES} rules per import")
    return rules


def plan_import(conn, doc):
    """Per-rule outcomes without changing anything: would_propose (with the changes), unchanged, or refused.

    The document as a whole is refused (ChangeError) when its format is wrong; a bad rule is refused alone.
    """
    entries = _check_document(doc)
    current = {r["id"]: r for r in load_rules(conn, enabled_only=False)}
    plan, seen = [], set()
    for n, entry in enumerate(entries):
        rule_id = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(rule_id, str) or not rule_id.strip():
            plan.append({"id": None, "outcome": "refused",
                         "reason": f"rule entry {n} must be an object with a non-empty string id"})
            continue
        item = {"id": rule_id}
        unknown = set(entry) - RULE_KEYS
        if rule_id in seen:
            item.update(outcome="refused", reason="duplicate entry for this rule")
        elif unknown:
            item.update(outcome="refused", reason=f"unknown key(s): {', '.join(sorted(unknown))}")
        elif rule_id not in current:
            item.update(outcome="refused", reason=f"unknown rule {rule_id!r}; an import cannot add detection logic")
        else:
            try:
                payload = _tuning_payload(entry, current[rule_id])
                merged = improve.validate_rule_update(conn, rule_id, payload) if payload else None
            except improve.ChangeError as exc:
                item.update(outcome="refused", reason=str(exc))
            else:
                changes = {}
                if payload and "params" in payload:
                    params = _changed_params(rule_id, current[rule_id], merged)
                    if params:
                        changes["params"] = params
                if payload and "enabled" in payload:
                    changes["enabled"] = payload["enabled"]
                if payload and "grouping" in payload:
                    changes["grouping"] = _copy_tuning(payload["grouping"])
                if changes:
                    item.update(outcome="would_propose", changes=changes)
                else:
                    item.update(outcome="unchanged")
        seen.add(rule_id)
        plan.append(item)
    return plan


def to_propose(plan):
    return sum(1 for item in plan if item["outcome"] == "would_propose")


def summary(plan):
    counts = {}
    for item in plan:
        counts[item["outcome"]] = counts.get(item["outcome"], 0) + 1
    first = "would_propose" if "would_propose" in counts else "proposed"
    return {key: counts.get(key, 0) for key in (first, "unchanged", "refused")}


def _staged_plan(plan, staged):
    """The plan as it will read after commit. `staged` is not applied to `plan` yet."""
    return [{**item, **staged[index]} if index in staged else item for index, item in enumerate(plan)]


def propose_import(conn, plan, label, actor):
    """Turn each would_propose outcome into a pending rule_update change request, and audit the import.

    Proposals, the per-rule change audits, and the import audit are one transaction. The plan object
    records those results only after that transaction commits, so a failure leaves the same object reusable.
    A ChangeError (the true-positive gate) refuses that rule and still commits the others with this audit.
    """
    staged = {}
    with transaction(conn):
        for index, item in enumerate(plan):
            if item["outcome"] != "would_propose":
                continue
            try:
                change = improve.propose_change(conn, "rule_update", item["id"], item["changes"],
                                                f"imported from {label}", actor)
            except improve.ChangeError as exc:
                staged[index] = {"outcome": "refused", "reason": str(exc)}
            else:
                staged[index] = {"outcome": "proposed", "change_id": change["id"]}
        view = _staged_plan(plan, staged)
        audit(conn, actor, "rules_imported", label, {
            "proposed": [item["change_id"] for item in view if item["outcome"] == "proposed"],
            "unchanged": sum(1 for item in view if item["outcome"] == "unchanged"),
            "refused": _refused_reasons(view),
        })
    for index, fields in staged.items():
        plan[index].update(fields)
    return plan
