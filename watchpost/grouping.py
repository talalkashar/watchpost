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


def _bound(key):
    if len(key) > 256:
        return "sha256:" + hashlib.sha256(key.encode()).hexdigest()
    return key


def _values(rows, field):
    present = (row.get(field) for row in rows if row.get(field) not in (None, ""))
    return sorted({_folded(field, value) for value in present})


def _join(values, escape):
    if not values:
        return _MISSING
    if escape:
        return ",".join(_escape(value) for value in values)
    return ",".join(values)


def _legacy_rows(rows):
    """Pre-#111 kept one row per id, and the last copy in the list won."""
    by_id = {}
    for row in rows:
        by_id[row["id"]] = row
    return list(by_id.values())


def _key_from_rows(rows, fields, escape):
    return _bound("|".join(_join(_values(rows, field), escape) for field in fields))


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
        out.append({**finding, "group_key": _key_from_rows(evidence, fields, True)})
    return out


def keys_for(rows, fields):
    """The pre-#111 key and the current key for the same rows and saved fields."""
    fields = validate(fields)
    return (_key_from_rows(_legacy_rows(rows), fields, False), _key_from_rows(rows, fields, True))


def resolve_stored(stored, evidence_rows, fields):
    """Whether `stored` is the current key or the pre-#111 key for this evidence.

    Returns ("current" or "legacy", current_key), or ("unresolved", None) when the
    evidence matches neither. Callers must not treat an unmatched string as either key.
    """
    fields = validate(fields)
    current = _key_from_rows(evidence_rows, fields, True)
    if stored == current:
        return ("current", current)
    legacy = _key_from_rows(_legacy_rows(evidence_rows), fields, False)
    if stored == legacy:
        return ("legacy", current)
    return ("unresolved", None)


def ordinary_key(key, field_count):
    """True when this string has one encoding for a rule with `field_count` saved fields.

    A comma, backslash, sha256 prefix, "(none)" part, or a different field count can name
    two entities. Those keys are not identified from the string alone.
    """
    if not isinstance(key, str) or field_count < 1 or key.startswith("sha256:"):
        return False
    if "\\" in key or "," in key:
        return False
    parts = key.split("|")
    if len(parts) != field_count:
        return False
    return all(part and part != _MISSING for part in parts)


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
