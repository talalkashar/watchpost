"""Alert correlation: group related alerts into incidents.

Two alerts are related when events of both carry the same entity (source IP, account, or
host) no more than `window_seconds` apart. Times come from each alert's evidence events
("sightings"), not from the alert's overall span, so a long-running alert does not swallow
everything that happened on a busy host in between. Relations chain: if A relates to B and B
to C, all three land in one group. Pure functions only; engine.correlate_alerts persists.

Rules of the grouping, so reruns are idempotent:
- an alert belongs to at most one incident;
- alerts already in an open incident stay together, and new related alerts join it;
- two existing incidents are never merged; a new alert that relates to both joins the older one.
"""

from collections import defaultdict

from . import attack
from .db import parse_iso

DEFAULT_WINDOW_SECONDS = 1800
ENTITY_TYPES = ("src_ip", "user", "host")
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
ESCALATION_TACTICS = 3


def _epoch(ts):
    return parse_iso(ts).timestamp()


def correlate(alerts, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Group alerts that share an entity within the window.

    `alerts`: [{"id", "first_seen", "last_seen", "entities": {"src_ip": [...], "user": [...], "host": [...]},
               "incident_id": int or None, "sightings": [(kind, value, ts), ...] (optional)}]
    Without sightings, every entity of an alert counts as seen across the alert's whole span.
    Returns [{"incident_id", "alert_ids", "new_alert_ids"}], one per group, in a stable order.
    """
    alerts = sorted(alerts, key=lambda a: (a["first_seen"], a["id"]))
    parent = {a["id"]: a["id"] for a in alerts}
    incident = {a["id"]: a.get("incident_id") for a in alerts}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        ia, ib = incident[ra], incident[rb]
        if ia and ib and ia != ib:
            return  # never merge two existing incidents
        if ib and not ia:
            keep, drop = rb, ra
        elif ia and not ib:
            keep, drop = ra, rb
        else:
            keep, drop = min(ra, rb), max(ra, rb)
        parent[drop] = keep
        incident[keep] = ia or ib

    # Members of the same existing incident always stay together.
    members = defaultdict(list)
    for a in alerts:
        if a.get("incident_id"):
            members[a["incident_id"]].append(a["id"])
    for ids in members.values():
        for other in ids[1:]:
            union(ids[0], other)

    # Link alerts whose events carry the same entity close in time. Edges touching the oldest
    # incident are applied first, so an alert that could join two incidents joins the older one.
    by_entity = defaultdict(list)
    for a in alerts:
        if a.get("sightings"):
            for kind, value, ts in a["sightings"]:
                t = _epoch(ts)
                by_entity[(kind, str(value).lower())].append((t, t, a))
        else:
            start, end = _epoch(a["first_seen"]), _epoch(a["last_seen"])
            for kind in ENTITY_TYPES:
                for value in (a.get("entities") or {}).get(kind) or []:
                    by_entity[(kind, str(value).lower())].append((start, end, a))
    never = float("inf")
    edges = set()
    for points in by_entity.values():
        points.sort(key=lambda p: (p[0], p[2]["id"]))
        active = {}  # alert id -> (latest end seen, alert)
        for start, end, a in points:
            for other_id, (other_end, other) in list(active.items()):
                if start - other_end > window_seconds:
                    del active[other_id]
                elif other_id != a["id"]:
                    rank = min(a.get("incident_id") or never, other.get("incident_id") or never)
                    edges.add((rank, min(a["id"], other_id), max(a["id"], other_id)))
            previous = active.get(a["id"], (end, a))[0]
            active[a["id"]] = (max(previous, end), a)
    for _, a, b in sorted(edges):
        union(a, b)

    groups = defaultdict(list)
    for a in alerts:
        groups[find(a["id"])].append(a)
    out = []
    for root, group in groups.items():
        out.append({
            "incident_id": incident[root],
            "alert_ids": sorted(a["id"] for a in group),
            "new_alert_ids": sorted(a["id"] for a in group if not a.get("incident_id")),
        })
    out.sort(key=lambda g: (g["incident_id"] is None, g["incident_id"] or 0, g["alert_ids"][0]))
    return out


def should_open(alerts):
    """A new incident needs at least two related alerts, or one critical alert."""
    return len(alerts) >= 2 or any(a["severity"] == "critical" for a in alerts)


def _bump(severity):
    index = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[min(index + 1, len(SEVERITY_ORDER) - 1)]


def summarize(alerts):
    """Incident fields from its alerts: [{"severity", "first_seen", "last_seen", "entities", "tactics",
    "synthetic"}]. Severity is the highest alert severity, raised one level when the alerts span
    three or more ATT&CK tactics."""
    severity = max((a["severity"] for a in alerts), key=lambda s: SEVERITY_ORDER.index(s)
                   if s in SEVERITY_ORDER else 0)
    stages = attack.tactic_order(t for a in alerts for t in a.get("tactics") or [])
    escalated = len(stages) >= ESCALATION_TACTICS
    if escalated:
        severity = _bump(severity)
    entities = {kind: sorted({str(v) if kind != "user" else str(v).lower()
                              for a in alerts for v in (a.get("entities") or {}).get(kind) or []})
                for kind in ENTITY_TYPES}
    who = (entities["src_ip"] + entities["user"] + entities["host"])[:3]
    if not stages:
        path = "Related alerts"
    elif len(stages) <= 3:
        path = " → ".join(stages)
    else:
        path = f"{stages[0]} → … → {stages[-1]} ({len(stages)} tactics)"
    return {
        "title": f"{path}: {', '.join(who)}" if who else path,
        "severity": severity,
        "escalated": escalated,
        "first_seen": min(a["first_seen"] for a in alerts),
        "last_seen": max(a["last_seen"] for a in alerts),
        "entities": entities,
        "stages": stages,
        "alert_count": len(alerts),
        "synthetic": int(all(a.get("synthetic") for a in alerts)),
    }
