"""Read-side incident queries, incident status changes, and ATT&CK coverage."""

import json

from . import assets, attack, correlate, improve, search_rules, sigma, simulate
from .db import audit, now_iso, row_to_dict, transaction
from .engine import load_rules
from .normalize import SEVERITIES
from .queries import EVENT_FIELDS, QueryError, _int, alert_row, catalog_pieces

INCIDENT_STATUSES = ("open", "investigating", "resolved")
# Incident detail returns this many distinct evidence events, earliest first. The rest are events_omitted.
INCIDENT_EVENT_LIMIT = 1000
# Incident detail returns this many linked alerts, earliest first_seen then id. The rest are alerts_omitted.
# The timeline uses that same page. Techniques, stages, and severity still cover every linked alert.
INCIDENT_ALERT_LIMIT = 200
_SEVERITY_ORDER = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                   "WHEN 'low' THEN 3 ELSE 4 END")


def _incident(row):
    return row_to_dict(row, ["entities", "stages"])


def _technique_objects(raw):
    """Technique dicts stored on a rule. Missing or non-list JSON contributes nothing."""
    if not raw:
        return []
    parsed = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(parsed, list):
        return []
    return [t for t in parsed if isinstance(t, dict) and t.get("id")]


def top_techniques(conn, incident_ids):
    """Earliest kill-chain technique on each incident, matching the matrix column order.

    Ties inside a tactic break on technique id. An incident with no mapped technique is absent.
    """
    if not incident_ids:
        return {}
    placeholders = ",".join("?" * len(incident_ids))
    rows = conn.execute(
        "SELECT ia.incident_id, r.techniques FROM incident_alerts ia"
        " JOIN alerts a ON a.id = ia.alert_id"
        " LEFT JOIN rules r ON r.id = a.rule_id"
        f" WHERE ia.incident_id IN ({placeholders})", incident_ids)
    best = {}
    for row in rows:
        for technique in _technique_objects(row["techniques"]):
            candidate = {"id": technique["id"], "name": technique.get("name") or "",
                         "tactic": technique.get("tactic") or ""}
            key = (attack.tactic_rank(candidate["tactic"]), candidate["id"])
            current = best.get(row["incident_id"])
            if current is None or key < current[0]:
                best[row["incident_id"]] = (key, candidate)
    return {incident_id: pair[1] for incident_id, pair in best.items()}


def list_incidents(conn, params):
    """Matching incidents, and how many the limit left out.

    Rows stay not-resolved first, then severity, then last_seen, then id
    descending (the newer id stays). The second value is 0 when every match
    fits. Callers that return the bare array send that count as
    X-Watchpost-Omitted.
    """
    where, args = [], []
    if params.get("status"):
        # One status or a comma list. Spaces around a name are ignored.
        # ASCII case folds onto the catalog spelling (`Open` binds `open`). A blank piece is invalid.
        statuses = catalog_pieces(
            params["status"], INCIDENT_STATUSES,
            f"status must be from {', '.join(INCIDENT_STATUSES)}")
        where.append(f"status IN ({','.join('?' for _ in statuses)})")
        args += statuses
    if params.get("severity"):
        # One level or a comma list (critical,high), the same rule as the alert queue.
        # Same fold (`High` binds `high`). A blank piece is invalid, same as an unknown name.
        levels = catalog_pieces(params["severity"], SEVERITIES, "invalid severity")
        where.append(f"severity IN ({','.join('?' for _ in levels)})")
        args += levels
    limit = _int(params.get("limit"), "limit", 100, 1, 500)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM incidents{clause}", args).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM incidents{clause} ORDER BY status = 'resolved', {_SEVERITY_ORDER},"
                        f" last_seen DESC, id DESC LIMIT ?", args + [limit])
    items = [_incident(r) for r in rows]
    tops = top_techniques(conn, [item["id"] for item in items])
    # Same sentence as the incident detail. The window is the correlator default, not per row.
    sentence = correlate.rule_summary()
    for item in items:
        item["top_technique"] = tops.get(item["id"])
        item["correlation_rule"] = sentence
    return items, total - len(items)


def linked_alerts(conn, incident_id):
    """Every alert on the incident, earliest first_seen then id, with its rule name and techniques.

    Case export and the incident report use this full list. Incident detail pages the same order.
    """
    rules = {r["id"]: r for r in load_rules(conn, enabled_only=False)}
    alerts = [alert_row(r) for r in conn.execute(
        "SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = ?"
        " ORDER BY a.first_seen, a.id", (incident_id,))]
    for alert in alerts:
        rule = rules.get(alert["rule_id"]) or {}
        alert["rule_name"] = rule.get("name", alert["rule_id"])
        alert["techniques"] = rule.get("techniques", [])
    return alerts


def evidence_dest_ips(conn, incident_id):
    """Destinations on this incident's evidence, including events past the detail page.

    A blank destination is not an address. A destination on another incident is not included.
    """
    rows = conn.execute(
        "SELECT DISTINCT e.dest_ip AS dest_ip FROM events e"
        " JOIN alert_events ae ON ae.event_id = e.id"
        " JOIN incident_alerts ia ON ia.alert_id = ae.alert_id"
        " WHERE ia.incident_id = ? AND e.dest_ip IS NOT NULL AND e.dest_ip != ''",
        (incident_id,))
    return {row["dest_ip"] for row in rows}


def get_incident(conn, incident_id):
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise QueryError("incident not found", 404)
    incident = _incident(row)

    alerts = linked_alerts(conn, incident_id)
    techniques = {}
    for alert in alerts:
        for t in alert["techniques"]:
            techniques.setdefault(t["id"], {**t, "alert_ids": []})["alert_ids"].append(alert["id"])
    shown = alerts[:INCIDENT_ALERT_LIMIT]

    event_alerts = {}
    for r in conn.execute("SELECT ae.event_id, ae.alert_id FROM alert_events ae JOIN incident_alerts ia"
                          " ON ia.alert_id = ae.alert_id WHERE ia.incident_id = ?", (incident_id,)):
        event_alerts.setdefault(r["event_id"], []).append(r["alert_id"])
    fields = ", ".join("e." + c.strip() for c in EVENT_FIELDS.split(","))
    events = [{**dict(r), "alert_ids": sorted(event_alerts.get(r["id"], []))} for r in conn.execute(
        f"SELECT DISTINCT {fields} FROM events e JOIN alert_events ae ON ae.event_id = e.id"
        " JOIN incident_alerts ia ON ia.alert_id = ae.alert_id WHERE ia.incident_id = ?"
        " ORDER BY e.ts, e.id LIMIT ?", (incident_id, INCIDENT_EVENT_LIMIT))]
    # Same join as the page. A second alert link is still one event. A link whose event is gone is not a row.
    event_total = conn.execute(
        "SELECT COUNT(DISTINCT e.id) AS n FROM events e"
        " JOIN alert_events ae ON ae.event_id = e.id"
        " JOIN incident_alerts ia ON ia.alert_id = ae.alert_id WHERE ia.incident_id = ?",
        (incident_id,)).fetchone()["n"]

    ordered = sorted(techniques.values(), key=lambda t: (attack.tactic_rank(t["tactic"]), t["id"]))
    incident["alerts"] = shown
    incident["alerts_omitted"] = len(alerts) - len(shown)
    incident["events"] = events
    incident["events_omitted"] = event_total - len(events)
    incident["timeline"] = [{
        "ts": a["first_seen"], "last_seen": a["last_seen"], "alert_id": a["id"], "rule_id": a["rule_id"],
        "title": a["title"], "severity": a["severity"], "status": a["status"],
        "tactics": attack.tactic_order(t["tactic"] for t in a["techniques"]),
        "techniques": [t["id"] for t in a["techniques"]],
    } for a in shown]
    incident["techniques"] = ordered
    incident["techniques_by_tactic"] = [
        {"tactic": tactic, "techniques": [t for t in ordered if t["tactic"] == tactic]}
        for tactic in incident["stages"]
    ]
    incident["escalated"] = len(incident["stages"]) >= 3
    incident["correlation_rule"] = correlate.rule_summary()
    # Hosts and source addresses stay the incident entity lists. Destinations include
    # evidence left out of the events page. Those events are not added to `events`.
    addresses = set(incident["entities"].get("src_ip") or [])
    addresses.update(evidence_dest_ips(conn, incident_id))
    incident["assets"] = assets.for_entities(
        conn, incident["entities"].get("host"), sorted(addresses))
    return incident


def update_status(conn, incident_id, actor, status, note=None):
    if status not in INCIDENT_STATUSES:
        raise QueryError(f"status must be one of {', '.join(INCIDENT_STATUSES)}")
    if note is not None and (not isinstance(note, str) or len(note) > 5000):
        raise QueryError("note must be a string of 5000 characters or fewer")
    with transaction(conn):
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            raise QueryError("incident not found", 404)
        now = now_iso()
        if status == "resolved":
            conn.execute("UPDATE incidents SET status = ?, resolved_at = ?, updated_at = ? WHERE id = ?",
                         (status, now, now, incident_id))
        else:
            conn.execute("UPDATE incidents SET status = ?, resolved_at = NULL,"
                         " assignee = CASE WHEN ? = 'investigating' THEN ? ELSE assignee END, updated_at = ?"
                         " WHERE id = ?", (status, status, actor, now, incident_id))
        audit(conn, actor, "incident_status_changed", str(incident_id),
              {"from": row["status"], "to": status, "note": note.strip() if note else None})
    return _incident(conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())


def coverage(conn):
    hits = {r["rule_id"]: r["count"] for r in conn.execute(
        "SELECT rule_id, COUNT(*) AS count FROM alerts GROUP BY rule_id")}
    cov = attack.coverage(load_rules(conn, enabled_only=False), hits)
    # Imported Sigma rules and promoted searches are proved by their own labeled sample, never by the built-in
    # scenarios.
    return attack.evidence(cov, improve.cached_noise_lab(conn)["rules"],
                           {**simulate.SCENARIOS, **sigma.sample_scenarios(conn),
                            **search_rules.sample_scenarios(conn)})
