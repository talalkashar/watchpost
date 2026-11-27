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
# One field joins values with a comma. Fields join with a pipe. A missing value is this marker.
_MISSING = "(none)"


def validate(fields):
    if not isinstance(fields, list) or any(not isinstance(value, str) for value in fields):
        raise ValueError("grouping must be a list of field names")
    if len(fields) > 3 or len(set(fields)) != len(fields) or any(value not in FIELDS for value in fields):
        raise ValueError(f"grouping may contain up to 3 unique fields from {', '.join(FIELDS)}")
    return fields


def _folded(field, value):
    text = str(value)
    if field in _FOLDED:
        return text.translate(_ASCII_FOLD)
    return text


def _escape(text):
    """Make one value safe to join. A stored comma, pipe, backslash, or "(none)" stays distinct."""
    escaped = text.replace("\\", "\\\\").replace(",", "\\,").replace("|", "\\|")
    if escaped == _MISSING:
        return "\\" + escaped
    return escaped


def _index_events(events):
    """Every row for an id. A repeated id must not depend on which copy was last in the list."""
    by_id = {}
    for event in events:
        by_id.setdefault(event["id"], []).append(event)
    return by_id


def _key(values, escape):
    parts = []
    for group in values:
        ordered = sorted(group)
        parts.append(",".join(_escape(v) for v in ordered) if escape else ",".join(ordered))
    text = "|".join(part or _MISSING for part in parts)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest() if len(text) > 256 else text


def _field_values(rows, fields):
    values = [set() for _ in fields]
    count = 0
    for row in rows:
        count += 1
        for field, group in zip(fields, values):
            value = row[field] if field in row.keys() else None
            if value not in (None, ""):
                group.add(_folded(field, value))
    return count, values


def retained_key(stored, fields, rows, expected_count):
    """Prove the key using the entire original membership, including retention gaps."""
    count, values = _field_values(rows, fields)
    if not count or count != expected_count:
        return None
    current = _key(values, True)
    if stored == current or stored == _key(values, False):
        return current
    return None


def ordinary_key(key, fields):
    parts = key.split("|")
    return (len(parts) == len(fields) and not key.startswith("sha256:")
            and "," not in key and "\\" not in key and all(p and p != _MISSING for p in parts))


def apply(findings, events, fields):
    """Replace keys deterministically without changing a finding's attached evidence ids.

    Values are folded, sorted, then escaped, so event order and id order do not change the key.
    A comma, pipe, or backslash inside a value cannot alias a different group.
    """
    if not fields:
        return findings
    fields = validate(fields)
    by_id = _index_events(events)
    out = []
    for finding in findings:
        evidence = [event for event_id in finding["event_ids"] if event_id in by_id
                    for event in by_id[event_id]]
        _, values = _field_values(evidence, fields)
        out.append({**finding, "group_key": _key(values, True)})
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
