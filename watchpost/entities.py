"""Entity risk: which users, source IPs, and hosts carry the most alert weight right now.

Risk score = sum over the entity's alerts of SEVERITY_WEIGHTS[severity] * 0.5 ** (age_hours / HALF_LIFE_HOURS),
leaving out alerts an analyst closed as false positive or benign. Every score comes back with the
alerts behind it and each one's weight, so it can be checked by hand. Asset criticality counts through
the alert's severity (assets.weigh raises it before the alert is stored); each contribution names the rule's
base severity and the asset note, so the raise is visible in the breakdown.

An alert belongs to an entity when one of its evidence events (alert_events -> events) carries that
user, src_ip, or host. This is the same mapping the correlation engine uses. `group_key` is not used:
its shape differs per rule ("ip", "user|ip", "user|ip|date", "user|service"), so it cannot be parsed
reliably.

Age is measured from the newest event in the database, not from the wall clock: demo data is
replayed with older timestamps and would otherwise decay to nothing.
"""

from .db import parse_iso
from .queries import EVENT_FIELDS, QueryError, _int

KINDS = ("user", "src_ip", "host")
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}
HALF_LIFE_HOURS = 24
EXCLUDED_DISPOSITIONS = ("false_positive", "benign")
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ALERT_FIELDS = "id, rule_id, severity, base_severity, severity_note, title, status, disposition, first_seen, last_seen, event_count, synthetic"


def _anchor(conn):
    return conn.execute("SELECT MAX(ts) FROM (SELECT MAX(ts) AS ts FROM events"
                        " UNION ALL SELECT MAX(last_seen) FROM alerts)").fetchone()[0]


def _contribution(alert, anchor):
    """One alert's share of a score. Not counted (weight 0) when closed as false positive or benign."""
    base = SEVERITY_WEIGHTS.get(alert["severity"], 0)
    age_hours = max(0.0, (parse_iso(anchor) - parse_iso(alert["last_seen"])).total_seconds() / 3600)
    decay = 0.5 ** (age_hours / HALF_LIFE_HOURS)
    counted = alert["disposition"] not in EXCLUDED_DISPOSITIONS
    return {"alert_id": alert["id"], "rule_id": alert["rule_id"], "title": alert["title"],
            "severity": alert["severity"],
            # Asset weight enters through severity: an alert on a critical or sensitive asset was raised before scoring.
            "base_severity": alert["base_severity"] or alert["severity"], "asset_note": alert["severity_note"],
            "status": alert["status"], "disposition": alert["disposition"],
            "last_seen": alert["last_seen"], "base_weight": base, "age_hours": round(age_hours, 1),
            "decay": round(decay, 3), "weight": round(base * decay, 2) if counted else 0.0, "counted": counted}


def _score(contributions):
    return round(sum(c["weight"] for c in contributions), 2)


def _entity_alerts(conn, where="", args=()):
    """{(kind, value): {alert_id, ...}} from evidence events. Accounts are lowercased."""
    found = {}
    for row in conn.execute("SELECT DISTINCT ae.alert_id, e.user, e.src_ip, e.host FROM alert_events ae"
                            f" JOIN events e ON e.id = ae.event_id{where}", args):
        for kind in KINDS:
            if row[kind]:
                value = row[kind].lower() if kind == "user" else row[kind]
                found.setdefault((kind, value), set()).add(row["alert_id"])
    return found


def list_entities(conn, params):
    """Top entities by risk score. Only alerts that count toward a score are listed here."""
    kind = params.get("kind")
    if kind and kind not in KINDS:
        raise QueryError(f"kind must be one of {', '.join(KINDS)}")
    limit = _int(params.get("limit"), "limit", 10, 1, 100)
    anchor = _anchor(conn)
    alerts = {r["id"]: dict(r) for r in conn.execute(f"SELECT {_ALERT_FIELDS} FROM alerts")}
    rows = []
    for (entity_kind, value), alert_ids in _entity_alerts(conn).items():
        if kind and entity_kind != kind:
            continue
        parts = [c for c in (_contribution(alerts[i], anchor) for i in alert_ids if i in alerts) if c["counted"]]
        if not parts:
            continue
        parts.sort(key=lambda c: (-c["weight"], c["alert_id"]))
        rows.append({
            "kind": entity_kind, "value": value, "score": _score(parts), "alerts": len(parts),
            "open_alerts": sum(c["status"] != "resolved" for c in parts),
            "max_severity": max((c["severity"] for c in parts), key=lambda s: _SEVERITY_RANK.get(s, 0)),
            "last_seen": max(c["last_seen"] for c in parts), "contributions": parts,
        })
    rows.sort(key=lambda r: (-r["score"], r["kind"], r["value"]))
    return {"anchor": anchor, "half_life_hours": HALF_LIFE_HOURS, "severity_weights": SEVERITY_WEIGHTS,
            "excluded_dispositions": list(EXCLUDED_DISPOSITIONS), "entities": rows[:limit]}


def get_entity(conn, kind, value):
    """Score breakdown, alerts, incidents, and recent events for one entity.

    An entity nothing has been seen for is not an error: it has a score of 0 and empty lists.
    """
    if kind not in KINDS:
        raise QueryError("entity kind not found", 404)
    match = f"e.{kind} = ?" + (" COLLATE NOCASE" if kind == "user" else "")
    if kind == "user":
        value = value.lower()
    anchor = _anchor(conn)
    alert_ids = sorted(_entity_alerts(conn, f" WHERE {match}", (value,)).get((kind, value), ()))
    marks = ",".join("?" for _ in alert_ids)
    alerts = [dict(r) for r in conn.execute(
        f"SELECT {_ALERT_FIELDS} FROM alerts WHERE id IN ({marks}) ORDER BY last_seen DESC, id DESC", alert_ids)]
    contributions = sorted((_contribution(a, anchor) for a in alerts), key=lambda c: (-c["weight"], c["alert_id"]))
    incidents = [dict(r) for r in conn.execute(
        "SELECT DISTINCT i.id, i.title, i.severity, i.status, i.first_seen, i.last_seen, i.alert_count, i.synthetic"
        f" FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id WHERE ia.alert_id IN ({marks})"
        " ORDER BY i.last_seen DESC, i.id DESC", alert_ids)]
    seen = conn.execute(f"SELECT MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen, COUNT(*) AS event_count,"
                        f" MAX(e.synthetic) AS synthetic FROM events e WHERE {match}", (value,)).fetchone()
    fields = ", ".join("e." + c.strip() for c in EVENT_FIELDS.split(","))
    recent = [dict(r) for r in conn.execute(
        f"SELECT {fields} FROM events e WHERE {match} ORDER BY e.ts DESC, e.id DESC LIMIT 50", (value,))]
    return {
        "kind": kind, "value": value, "score": _score(contributions), "anchor": anchor,
        "half_life_hours": HALF_LIFE_HOURS, "severity_weights": SEVERITY_WEIGHTS,
        "excluded_dispositions": list(EXCLUDED_DISPOSITIONS), "contributions": contributions,
        "alerts": alerts, "incidents": incidents, "recent_events": recent,
        "first_seen": seen["first_seen"], "last_seen": seen["last_seen"], "event_count": seen["event_count"],
        "synthetic": bool(seen["synthetic"]),
    }
