"""Rule export and import: move rule tuning between Watchpost instances.

What moves is tuning, the `params` and `enabled` of rules this code already has. Detection logic is Python
code in rules.py and is not exported, so an import cannot add a rule or change how one detects.

An import applies nothing. Each rule whose tuning differs from today's becomes an ordinary `rule_update`
change request through improve.propose_change, with the same validation, backtest evidence, detection-loss
gate and two-person review as a proposal made by hand.
"""

from . import __version__
from . import improve
from . import rules as rules_mod
from .db import audit, now_iso
from .engine import load_rules

FORMAT, FORMAT_VERSION = "watchpost-rules", 1
NOTE = ("Rule tuning only (params, enabled). Detection logic is Python code in watchpost/rules.py and is not "
        "exported: an import can retune rules the importing instance already has, never add or change logic.")
MAX_IMPORT_BYTES = 256 * 1024
MAX_IMPORT_RULES = 200
DOCUMENT_KEYS = {"format", "format_version", "watchpost_version", "exported_at", "note", "rules"}
# Keys an exported rule carries. Only params and enabled are imported; the rest describe the rule as it was.
RULE_KEYS = {"id", "name", "version", "enabled", "severity", "params", "techniques", "description"}


def export_rules(conn):
    """Every rule's tuning and description, sorted by id. Callers serialize with sorted keys."""
    rules = [{"id": r["id"], "name": r["name"], "version": r["version"], "enabled": bool(r["enabled"]),
              "severity": r["severity"], "params": rules_mod.validate_params(r["id"], r["params"]),
              "techniques": [t["id"] for t in r["techniques"]], "description": r["description"]}
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
        if not isinstance(rule_id, str):
            plan.append({"id": None, "outcome": "refused", "reason": f"rule entry {n} must be an object with a string id"})
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
            payload = {k: entry[k] for k in ("params", "enabled") if k in entry}
            try:
                merged = improve.validate_rule_update(conn, rule_id, payload)
            except improve.ChangeError as exc:
                item.update(outcome="refused", reason=str(exc))
            else:
                changes = {}
                today = rules_mod.validate_params(rule_id, current[rule_id]["params"])
                params = {k: v for k, v in (merged or {}).items() if v != today[k]}
                if params:
                    changes["params"] = params
                if "enabled" in payload and payload["enabled"] != bool(current[rule_id]["enabled"]):
                    changes["enabled"] = payload["enabled"]
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


def propose_import(conn, plan, label, actor):
    """Turn each would_propose outcome into a pending rule_update change request, and audit the import."""
    for item in plan:
        if item["outcome"] != "would_propose":
            continue
        try:
            change = improve.propose_change(conn, "rule_update", item["id"], item["changes"],
                                            f"imported from {label}", actor)
        except improve.ChangeError as exc:  # e.g. the true-positive gate on an ignore-list addition
            item.update(outcome="refused", reason=str(exc))
        else:
            item.update(outcome="proposed", change_id=change["id"])
    audit(conn, actor, "rules_imported", label, {
        "proposed": [item["change_id"] for item in plan if item["outcome"] == "proposed"],
        "unchanged": sum(1 for item in plan if item["outcome"] == "unchanged"),
        "refused": {str(item["id"]): item["reason"] for item in plan if item["outcome"] == "refused"},
    })
    return plan
