"""A bounded investigation graph built from stored alert evidence and incident membership."""

from collections import defaultdict

from . import correlate, incidents

ALERT_LIMIT = 180
NODE_LIMIT = 500
EVIDENCE_LIMIT = 64
EVIDENCE_EDGE_LIMIT = 2000


def snapshot(conn):
    rows = conn.execute(
        "SELECT a.id, a.title, a.severity, a.rule_id, r.name, r.techniques,"
        " i.id AS incident_id, i.title AS incident_title, i.severity AS incident_severity"
        " FROM alerts a LEFT JOIN rules r ON r.id=a.rule_id"
        " LEFT JOIN incident_alerts ia ON ia.alert_id=a.id LEFT JOIN incidents i ON i.id=ia.incident_id"
        " ORDER BY a.id DESC LIMIT ?", (ALERT_LIMIT + 1,)).fetchall()
    limited = len(rows) > ALERT_LIMIT
    rows = rows[:ALERT_LIMIT]
    nodes, edges = [], []
    alerts, cases, entities = {}, {}, {}
    sightings = defaultdict(list)

    def node(kind, label, **fields):
        idx = len(nodes)
        nodes.append({"id": idx, "type": kind, "label": label, **fields})
        return idx

    def edge(source, target, kind):
        edges.append({"source": source, "target": target, "type": kind})

    # Reserve space for alert and incident pivots before admitting evidence entities.
    for row in rows:
        alert = alerts[row["id"]] = node(
            "alert", row["name"] or row["rule_id"], ref=row["id"], title=row["title"],
            severity=row["severity"], rule=row["rule_id"],
            techniques=[t["id"] for t in incidents.technique_objects(row["techniques"], include_unlisted=True)])
        case = row["incident_id"]
        if case is not None:
            if case not in cases:
                cases[case] = node("incident", row["incident_title"], ref=case, severity=row["incident_severity"])
            edge(alert, cases[case], "membership")

    evidence_edges = 0
    for row in rows:
        alert = alerts[row["id"]]
        case = row["incident_id"]
        # Indexed by (alert_id, event_id). A very large alert cannot dominate a read.
        evidence = conn.execute(
            "SELECT e.ts, e.host, e.user, e.src_ip FROM"
            " (SELECT event_id FROM alert_events WHERE alert_id=? ORDER BY event_id DESC LIMIT ?) ae"
            " JOIN events e ON e.id=ae.event_id ORDER BY ae.event_id DESC",
            (row["id"], EVIDENCE_LIMIT + 1)).fetchall()
        limited |= len(evidence) > EVIDENCE_LIMIT
        linked = set()
        for event in evidence[:EVIDENCE_LIMIT]:
            seen_at = correlate.epoch_seconds(event["ts"]) if case is not None else None
            for kind in correlate.ENTITY_TYPES:
                value = event[kind]
                if not value:
                    continue
                key = (kind, correlate.entity_key(kind, value))
                target = entities.get(key)
                if target not in linked:
                    if evidence_edges >= EVIDENCE_EDGE_LIMIT or (target is None and len(nodes) >= NODE_LIMIT):
                        limited = True
                        continue
                    if target is None:
                        target = entities[key] = node(kind, value)
                    linked.add(target)
                    edge(alert, target, "evidence")
                    evidence_edges += 1
                if case is not None:
                    sightings[case, target].append((seen_at, alert))

    # Within each incident/entity, adjacent evidence sightings prove a real link.
    # Show one nearest-in-time witness per higher alert id to avoid drawing cliques.
    witnesses = {}
    for group in sightings.values():
        ordered = sorted(set(group))
        for (before, a), (after, b) in zip(ordered, ordered[1:]):
            if a == b:
                continue
            gap = after - before
            if gap <= correlate.DEFAULT_WINDOW_SECONDS:
                newer, older = sorted((a, b))  # node indices run newest alert id first
                candidate = (gap, older)
                if newer not in witnesses or candidate < witnesses[newer]:
                    witnesses[newer] = candidate
    for newer, (_, older) in sorted(witnesses.items()):
        edge(older, newer, "correlation")
    return {"nodes": nodes, "edges": edges, "limited": limited}


def mask_snapshot(data, masker):
    # Schema words ("host", "user", "source", etc.) can themselves be event usernames.
    # Only data-bearing strings need masking. Edges refer to opaque numeric indices.
    for node in data["nodes"]:
        node["label"] = masker.mask(node["label"], node["type"])
        for field in ("title", "rule", "techniques"):
            if field in node:
                node[field] = masker.mask(node[field])
    return data
