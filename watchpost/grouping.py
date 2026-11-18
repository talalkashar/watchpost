"""Reviewed per-rule alert deduplication keys (separate from incident correlation)."""

import hashlib

FIELDS = ("src_ip", "dest_ip", "user", "host", "event_type", "source")

# Newest events by id. The rest are events_omitted. An exact cap is not a drop.
SCAN_LIMIT = 10000
# First sorted keys on before and after. The rest are group_keys_omitted.
KEY_LIMIT = 20

# SQLite COLLATE NOCASE folds these letters only. User and host keys use the same fold.
# src_ip and dest_ip stay the stored address. event_type and source stay the stored spelling.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_FOLDED = frozenset({"user", "host"})


def validate(fields):
    if not isinstance(fields, list) or any(not isinstance(value, str) for value in fields):
        raise ValueError("grouping must be a list of field names")
    if len(fields) > 3 or len(set(fields)) != len(fields) or any(value not in FIELDS for value in fields):
        raise ValueError(f"grouping may contain up to 3 unique fields from {', '.join(FIELDS)}")
    return fields


def _key_part(field, value):
    text = str(value)
    if field in _FOLDED:
        return text.translate(_ASCII_FOLD)
    return text


def apply(findings, events, fields):
    """Replace keys deterministically without changing a finding's attached evidence ids."""
    if not fields:
        return findings
    by_id = {event["id"]: event for event in events}
    out = []
    for finding in findings:
        evidence = [by_id[event_id] for event_id in finding["event_ids"] if event_id in by_id]
        parts = []
        for field in fields:
            present = (event[field] for event in evidence if event.get(field) not in (None, ""))
            values = sorted({_key_part(field, value) for value in present})
            parts.append(",".join(values) if values else "(none)")
        key = "|".join(parts)
        if len(key) > 256:
            key = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
        out.append({**finding, "group_key": key})
    return out


def _side(found):
    keys = sorted({item["group_key"] for item in found})
    return {"findings": len(found), "group_keys": keys[:KEY_LIMIT],
            "group_keys_omitted": len(keys) - len(keys[:KEY_LIMIT])}


def preview(conn, rule_id, fields):
    from . import engine
    rule = next((r for r in engine.load_rules(conn, enabled_only=False) if r["id"] == rule_id), None)
    if rule is None:
        raise ValueError("unknown rule")
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    events = [dict(row) for row in conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (SCAN_LIMIT,))]
    events.reverse()
    omitted = total - SCAN_LIMIT if total > SCAN_LIMIT else 0
    before = engine.rule_findings({**rule, "grouping": []}, events, [], None, set())[0]
    after = engine.rule_findings({**rule, "grouping": fields}, events, [], None, set())[0]
    ids = lambda found: sorted(i for item in found for i in item["event_ids"])
    return {"rule": rule_id, "fields": fields, "events_scanned": len(events),
            "events_omitted": omitted, "capped": omitted != 0,
            "before": _side(before), "after": _side(after),
            "evidence_ids_preserved": ids(before) == ids(after)}
