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

Correlation rules (PATTERNS) sit on top of that. Each names a shape that matters more than its parts: a
scan followed by an attack from the same source, a suspicious login followed by data leaving, logging
switched off around other activity. A rule is written over ATT&CK tactics, so it also applies to imported
Sigma rules and promoted searches, and over a longer window than the grouping above, because the stages
of an intrusion are often hours apart. Alerts that complete a rule are linked into one incident even when
the plain window would keep them apart, and the incident's severity is raised to at least the rule's.
An alert counts for a rule by the tactics of the rule that raised it; alerts without tactics never match.
"""

from collections import defaultdict

from . import attack
from .db import parse_iso

DEFAULT_WINDOW_SECONDS = 1800
ENTITY_TYPES = ("src_ip", "user", "host")
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
ESCALATION_TACTICS = 3
PATTERN_WINDOW_SECONDS = 24 * 3600
HUB_VALUES = 3   # an alert naming more accounts (or sources) than this ties none of them to a later stage

# kind "sequence": one alert per step, each starting no earlier than the one before, first to last within
#   the window. kind "together": the same without the order; the step ("other",) is any tactic not named in
#   the first step. A step is a set of tactics; an alert fits it when the rule that raised it maps to any.
# `shared` is what must be the same across the steps, and it is always an actor: the source address or the
# account. Never the host: a host is a place, and unrelated things happen on one host all day.
PATTERNS = [
    {"id": "scan_then_attack", "kind": "sequence", "severity": "high", "shared": ("src_ip",),
     "name": "Scan, then attack, from one source",
     "description": "A source that scanned was later behind a password attack or a suspicious login.",
     "steps": (("Reconnaissance", "Discovery"), ("Credential Access", "Initial Access"))},
    {"id": "attack_then_access", "kind": "sequence", "severity": "critical", "shared": ("src_ip", "user"),
     "name": "Password attack, then a suspicious login",
     "description": "A password attack was followed by a suspicious login for the same account or from the same source.",
     "steps": (("Credential Access",), ("Initial Access",))},
    {"id": "access_then_escalation", "kind": "sequence", "severity": "high", "shared": ("user",),
     "name": "Suspicious login, then privilege escalation",
     "description": "An account with a suspicious login later gained or used higher privileges, or made itself persistent.",
     "steps": (("Initial Access",), ("Privilege Escalation", "Persistence"))},
    {"id": "access_then_exfiltration", "kind": "sequence", "severity": "critical", "shared": ("user",),
     "name": "Suspicious login, then data leaving",
     "description": "An account with a suspicious login was later seen collecting or sending out data.",
     "steps": (("Initial Access", "Privilege Escalation"), ("Collection", "Exfiltration"))},
    {"id": "defenses_impaired", "kind": "together", "severity": "critical", "shared": ("user",),
     "name": "Logging impaired around other activity",
     "description": "An account that switched off or tampered with logging also raised another kind of alert.",
     "steps": (("Defense Evasion",), ("other",))},
]
PATTERN_INFO = {p["id"]: p for p in PATTERNS}


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
    # Alerts that complete a correlation rule belong together, however far apart the plain window puts them.
    for pattern in PATTERNS:
        for ids in _pattern_matches(pattern, alerts):
            rank = min((incident[i] or never for i in ids), default=never)
            edges.update((rank, a, b) for a, b in zip(ids, ids[1:]))
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


def _fits(alert, step, first):
    tactics = set(alert.get("tactics") or [])
    return bool(tactics - set(first)) if step == ("other",) else bool(tactics & set(step))


def _pattern_matches(pattern, alerts, window_seconds=PATTERN_WINDOW_SECONDS):
    """Every set of alerts that completes `pattern`, as sorted tuples of alert ids."""
    by_value = defaultdict(list)
    for a in alerts:
        if not a.get("tactics"):
            continue
        for kind in pattern["shared"]:
            values = {str(value).lower() for value in (a.get("entities") or {}).get(kind) or []}
            if len(values) <= HUB_VALUES:
                for value in values:
                    by_value[(kind, value)].append((_epoch(a["first_seen"]), a["id"], a))
    steps, ordered, found = pattern["steps"], pattern["kind"] == "sequence", set()
    for sharing in by_value.values():
        sharing.sort(key=lambda entry: entry[:2])
        for n, (start, _, first) in enumerate(sharing):
            if not _fits(first, steps[0], steps[0]):
                continue
            # "together" may find its other alerts before the first one; a sequence only after it.
            pool = sharing[n + 1:] if ordered else sharing[:n] + sharing[n + 1:]
            chosen, after = [first["id"]], start
            for step in steps[1:]:
                fitting = next(((t, a) for t, _, a in pool if a["id"] not in chosen and _fits(a, step, steps[0])
                                and abs(t - start) <= window_seconds and (not ordered or t >= after)), None)
                if fitting is None:
                    break
                chosen.append(fitting[1]["id"])
                after = fitting[0]
            else:
                found.add(tuple(sorted(chosen)))
    return sorted(found)


def match_patterns(alerts):
    """The correlation rules these alerts complete: [{"id", "alert_ids"}], in PATTERNS order."""
    out = []
    for pattern in PATTERNS:
        ids = sorted({i for match in _pattern_matches(pattern, alerts) for i in match})
        if ids:
            out.append({"id": pattern["id"], "alert_ids": ids})
    return out


def should_open(alerts):
    """A new incident needs at least two related alerts, or one critical alert."""
    return len(alerts) >= 2 or any(a["severity"] == "critical" for a in alerts)


def _bump(severity):
    index = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[min(index + 1, len(SEVERITY_ORDER) - 1)]


def summarize(alerts):
    """Incident fields from its alerts: [{"id", "severity", "first_seen", "last_seen", "entities", "tactics",
    "synthetic"}]. Severity is the highest alert severity, raised one level when the alerts span
    three or more ATT&CK tactics, and to at least the severity of any correlation rule they complete."""
    def rank(s):
        return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0

    severity = max((a["severity"] for a in alerts), key=rank)
    stages = attack.tactic_order(t for a in alerts for t in a.get("tactics") or [])
    escalated = len(stages) >= ESCALATION_TACTICS
    if escalated:
        severity = _bump(severity)
    patterns = match_patterns(alerts) if all("id" in a for a in alerts) else []
    severity = max([severity] + [PATTERN_INFO[p["id"]]["severity"] for p in patterns], key=rank)
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
        "patterns": patterns,
        "alert_count": len(alerts),
        "synthetic": int(all(a.get("synthetic") for a in alerts)),
    }
