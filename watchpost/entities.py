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

from datetime import date, timedelta

from .db import parse_iso
from .queries import EVENT_FIELDS, QueryError, _int, canonical_ip, catalog_name

KINDS = ("user", "src_ip", "host")
# SQLite COLLATE NOCASE folds these letters only. User and host keys use the same fold.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}
HALF_LIFE_HOURS = 24
EXCLUDED_DISPOSITIONS = ("false_positive", "benign")
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ALERT_FIELDS = "id, rule_id, severity, base_severity, severity_note, title, status, disposition, first_seen, last_seen, event_count, synthetic"
# The entity page draws one bar per UTC day. A longer stored history keeps the newest month.
_DAY_BARS = 31
# Entity detail returns this many events, newest by ts, then id. The rest are recent_events_omitted.
RECENT_EVENTS_LIMIT = 50
# Alerts and incidents on that page, newest by last_seen, then id. The rest are alerts_omitted
# and incidents_omitted. Incidents are read with SQL LIMIT and a distinct count.
# The score and contributions still use every alert. That alert read is not limited.
RELATED_LIMIT = 50


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


def _utc_day(ts):
    return date.fromisoformat(ts[:10])


def _entity_value(kind, value):
    """The value an entity is keyed and returned as.

    Accounts and hosts fold ASCII letters only, the same fold as COLLATE NOCASE
    and event search. Erin, ERIN, and erin are one account whose value is erin,
    and WEB01 and web01 are one host. str.lower would also fold É, so ÉRIN and
    érin would share the key érin while the lookup would miss the ÉRIN rows.
    Those two stay apart. A source IP stays as stored. `get_entity` canonicalizes
    an IP path before this, so that key is the form ingest stores.
    """
    if kind in ("user", "host"):
        return value.translate(_ASCII_FOLD)
    return value


def _entity_match(kind):
    """SQL comparing one bound value to e.<kind>. User and host ignore ASCII case."""
    collate = " COLLATE NOCASE" if kind in ("user", "host") else ""
    return f"e.{kind} = ?{collate}"


def _alerts_by_day(conn, kind, value):
    """Count this entity's alerts on each UTC day of its stored events.

    An alert is placed on the day of its newest evidence event that names the entity.
    That timestamp is the event's `ts`, so replayed demo data stays on the day it
    depicts. Days from the first stored event to the last are filled, including zeros.
    A span longer than `_DAY_BARS` keeps the newest days. `omitted` is how many alerts
    sit on a day older than that window.
    """
    match = _entity_match(kind)
    span = conn.execute(
        f"SELECT MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen FROM events e WHERE {match}", (value,)).fetchone()
    if not span["first_seen"]:
        return {"start": None, "end": None, "days": [], "omitted": 0}
    counts = {}
    for row in conn.execute(
            "SELECT ae.alert_id AS alert_id, MAX(e.ts) AS ts FROM alert_events ae"
            f" JOIN events e ON e.id = ae.event_id WHERE {match} GROUP BY ae.alert_id", (value,)):
        key = _utc_day(row["ts"]).isoformat()
        counts[key] = counts.get(key, 0) + 1
    start, end = _utc_day(span["first_seen"]), _utc_day(span["last_seen"])
    if (end - start).days + 1 > _DAY_BARS:
        start = end - timedelta(days=_DAY_BARS - 1)
    days = []
    cursor = start
    while cursor <= end:
        key = cursor.isoformat()
        days.append({"day": key, "count": counts.get(key, 0)})
        cursor += timedelta(days=1)
    # Alerts whose newest evidence day is older than the drawn window stay counted here.
    omitted = sum(n for day_key, n in counts.items() if day_key < start.isoformat())
    return {"start": start.isoformat(), "end": end.isoformat(), "days": days, "omitted": omitted}


def _entity_alerts(conn, where="", args=()):
    """{(kind, value): {alert_id, ...}} from evidence events.

    Accounts and hosts fold ASCII case, so Erin and erin share one score, and so do WEB01 and web01.
    """
    found = {}
    for row in conn.execute("SELECT DISTINCT ae.alert_id, e.user, e.src_ip, e.host FROM alert_events ae"
                            f" JOIN events e ON e.id = ae.event_id{where}", args):
        for kind in KINDS:
            if row[kind]:
                found.setdefault((kind, _entity_value(kind, row[kind])), set()).add(row["alert_id"])
    return found


def _scoreable_disposition(column="disposition"):
    """SQL and binds for an alert that can add to a risk score.

    `EXCLUDED_DISPOSITIONS` is the only list. A null disposition (still open, or closed
    without one of those labels) counts. A false positive or benign close does not.
    """
    marks = ", ".join("?" * len(EXCLUDED_DISPOSITIONS))
    return f"({column} IS NULL OR {column} NOT IN ({marks}))", EXCLUDED_DISPOSITIONS


def list_entities(conn, params):
    """Top entities by risk score.

    The alert read and the evidence walk both keep only alerts that can score, using
    `EXCLUDED_DISPOSITIONS` in SQL. A false positive still scores 0 on the entity page
    and is absent here.

    `kind` folds ASCII case onto `user`, `src_ip`, or `host` (`User` is `user`).
    An unknown kind is 400. An empty kind lists every kind. The entity path stays
    those three lowercase spellings.

    `entities` is the highest scores, at most `limit` (default 10, max 100).
    Ties keep `kind`, then `value`. `entities_omitted` is how many scored
    entities were past that cap. A list that fits returns 0. A false positive
    or benign close is not scored, so it is not part of that count.
    """
    kind = params.get("kind")
    if kind:
        # ASCII case folds onto the catalog spelling (`User` is `user`). A non-ASCII lookalike stays 400.
        kind = catalog_name(kind, KINDS)
        if kind is None:
            raise QueryError(f"kind must be one of {', '.join(KINDS)}")
    limit = _int(params.get("limit"), "limit", 10, 1, 100)
    anchor = _anchor(conn)
    clause, bound = _scoreable_disposition()
    alerts = {r["id"]: dict(r) for r in conn.execute(
        f"SELECT {_ALERT_FIELDS} FROM alerts WHERE {clause}", bound)}
    walk, walk_bound = _scoreable_disposition("a.disposition")
    rows = []
    for (entity_kind, value), alert_ids in _entity_alerts(
            conn, f" JOIN alerts a ON a.id = ae.alert_id WHERE {walk}", walk_bound).items():
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
    shown = rows[:limit]
    return {"anchor": anchor, "half_life_hours": HALF_LIFE_HOURS, "severity_weights": SEVERITY_WEIGHTS,
            "excluded_dispositions": list(EXCLUDED_DISPOSITIONS), "entities": shown,
            "entities_omitted": len(rows) - len(shown)}


def _entity_incidents(conn, alert_ids):
    """Newest RELATED_LIMIT incidents on these alerts, and how many were left out.

    Order is last_seen descending, then id descending. One incident linked from
    two of these alerts is one row. No alerts means no incidents and omitted 0,
    and this query is not run. The score still reads every alert.
    """
    if not alert_ids:
        return [], 0
    marks = ",".join("?" * len(alert_ids))
    where = f" WHERE ia.alert_id IN ({marks})"
    page = [dict(r) for r in conn.execute(
        "SELECT DISTINCT i.id, i.title, i.severity, i.status, i.first_seen, i.last_seen,"
        " i.alert_count, i.synthetic FROM incidents i"
        " JOIN incident_alerts ia ON ia.incident_id = i.id"
        + where + " ORDER BY i.last_seen DESC, i.id DESC LIMIT ?",
        list(alert_ids) + [RELATED_LIMIT])]
    total = conn.execute(
        "SELECT COUNT(DISTINCT i.id) AS n FROM incidents i"
        " JOIN incident_alerts ia ON ia.incident_id = i.id" + where,
        list(alert_ids)).fetchone()["n"]
    return page, total - len(page)


def get_entity(conn, kind, value):
    """Score breakdown, alerts, incidents, recent events, and alerts by day for one entity.

    An entity nothing has been seen for is not an error: it has a score of 0 and empty lists.
    A source IP is the form ingest stores (`2001:DB8::1` is `2001:db8::1`). Anything
    that is not one address is 400. A user or host path is the ASCII-folded key.
    `recent_events` is the newest RECENT_EVENTS_LIMIT matching events. `recent_events_omitted`
    is how many matching events were past that cap. `event_count` stays the full count.
    `alerts` and `incidents` are the newest RELATED_LIMIT by last_seen, then id.
    `alerts_omitted` and `incidents_omitted` are how many were past that cap.
    Incidents are that page from SQL (`ORDER BY i.last_seen DESC, i.id DESC LIMIT`)
    and `COUNT(DISTINCT i.id)` minus the page. The alert read that feeds the score
    has no LIMIT. A false positive or benign close stays weight 0.
    """
    if kind not in KINDS:
        raise QueryError("entity kind not found", 404)
    if kind == "src_ip":
        value = canonical_ip(value, "src_ip")
    match = _entity_match(kind)
    value = _entity_value(kind, value)
    anchor = _anchor(conn)
    alert_ids = sorted(_entity_alerts(conn, f" WHERE {match}", (value,)).get((kind, value), ()))
    marks = ",".join("?" for _ in alert_ids)
    alerts = [dict(r) for r in conn.execute(
        f"SELECT {_ALERT_FIELDS} FROM alerts WHERE id IN ({marks}) ORDER BY last_seen DESC, id DESC", alert_ids)]
    contributions = sorted((_contribution(a, anchor) for a in alerts), key=lambda c: (-c["weight"], c["alert_id"]))
    alerts_omitted = max(0, len(alerts) - RELATED_LIMIT)
    alerts = alerts[:RELATED_LIMIT]
    incidents, incidents_omitted = _entity_incidents(conn, alert_ids)
    seen = conn.execute(f"SELECT MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen, COUNT(*) AS event_count,"
                        f" MAX(e.synthetic) AS synthetic FROM events e WHERE {match}", (value,)).fetchone()
    fields = ", ".join("e." + c.strip() for c in EVENT_FIELDS.split(","))
    recent = [dict(r) for r in conn.execute(
        f"SELECT {fields} FROM events e WHERE {match}"
        f" ORDER BY e.ts DESC, e.id DESC LIMIT {RECENT_EVENTS_LIMIT}", (value,))]
    return {
        "kind": kind, "value": value, "score": _score(contributions), "anchor": anchor,
        "half_life_hours": HALF_LIFE_HOURS, "severity_weights": SEVERITY_WEIGHTS,
        "excluded_dispositions": list(EXCLUDED_DISPOSITIONS), "contributions": contributions,
        "alerts": alerts, "alerts_omitted": alerts_omitted, "incidents": incidents,
        "incidents_omitted": incidents_omitted, "recent_events": recent,
        "recent_events_omitted": seen["event_count"] - len(recent),
        "alerts_by_day": _alerts_by_day(conn, kind, value),
        "first_seen": seen["first_seen"], "last_seen": seen["last_seen"], "event_count": seen["event_count"],
        "synthetic": bool(seen["synthetic"]),
    }
