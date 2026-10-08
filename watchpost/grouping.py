"""Reviewed per-rule alert deduplication keys (separate from incident correlation)."""

import hashlib

FIELDS = ("src_ip", "dest_ip", "user", "host", "event_type", "source")


def validate(fields):
    if not isinstance(fields, list) or any(not isinstance(value, str) for value in fields):
        raise ValueError("grouping must be a list of field names")
    if len(fields) > 3 or len(set(fields)) != len(fields) or any(value not in FIELDS for value in fields):
        raise ValueError(f"grouping may contain up to 3 unique fields from {', '.join(FIELDS)}")
    return fields


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
            values = sorted({str(event[field]).casefold() for event in evidence if event.get(field) not in (None, "")})
            parts.append(",".join(values) if values else "(none)")
        key = "|".join(parts)
        if len(key) > 256:
            key = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
        out.append({**finding, "group_key": key})
    return out


def preview(conn, rule_id, fields):
    from . import engine
    rule = next((r for r in engine.load_rules(conn, enabled_only=False) if r["id"] == rule_id), None)
    if rule is None:
        raise ValueError("unknown rule")
    events = [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10000")]
    events.reverse()
    before = engine.rule_findings({**rule, "grouping": []}, events, [], None, set())[0]
    after = engine.rule_findings({**rule, "grouping": fields}, events, [], None, set())[0]
    ids = lambda found: sorted(i for item in found for i in item["event_ids"])
    return {"rule": rule_id, "fields": fields, "events_scanned": len(events), "capped": len(events) == 10000,
            "before": {"findings": len(before), "group_keys": sorted({f["group_key"] for f in before})[:20]},
            "after": {"findings": len(after), "group_keys": sorted({f["group_key"] for f in after})[:20]},
            "evidence_ids_preserved": ids(before) == ids(after)}
