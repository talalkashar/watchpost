"""Read-side incident queries, incident status changes, and ATT&CK coverage."""

from . import assets, attack, improve, simulate
from .db import audit, now_iso, row_to_dict, transaction
from .engine import load_rules
from .normalize import SEVERITIES
from .queries import EVENT_FIELDS, QueryError, _int, alert_row

INCIDENT_STATUSES = ("open", "investigating", "resolved")
_SEVERITY_ORDER = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                   "WHEN 'low' THEN 3 ELSE 4 END")


def _incident(row):
    return row_to_dict(row, ["entities", "stages"])


def list_incidents(conn, params):
    where, args = [], []
    if params.get("status"):
        statuses = params["status"].split(",")
        if not set(statuses) <= set(INCIDENT_STATUSES):
            raise QueryError(f"status must be from {', '.join(INCIDENT_STATUSES)}")
        where.append(f"status IN ({','.join('?' for _ in statuses)})")
        args += statuses
    if params.get("severity"):
        if params["severity"] not in SEVERITIES:
            raise QueryError("invalid severity")
        where.append("severity = ?")
        args.append(params["severity"])
    limit = _int(params.get("limit"), "limit", 100, 1, 500)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(f"SELECT * FROM incidents{clause} ORDER BY status = 'resolved', {_SEVERITY_ORDER},"
                        f" last_seen DESC LIMIT ?", args + [limit])
    return [_incident(r) for r in rows]


def get_incident(conn, incident_id):
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise QueryError("incident not found", 404)
    incident = _incident(row)
    rules = {r["id"]: r for r in load_rules(conn, enabled_only=False)}

    alerts = [alert_row(r) for r in conn.execute(
        "SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = ?"
        " ORDER BY a.first_seen, a.id", (incident_id,))]
    techniques = {}
    for alert in alerts:
        rule = rules.get(alert["rule_id"]) or {}
        alert["rule_name"] = rule.get("name", alert["rule_id"])
        alert["techniques"] = rule.get("techniques", [])
        for t in alert["techniques"]:
            techniques.setdefault(t["id"], {**t, "alert_ids": []})["alert_ids"].append(alert["id"])

    event_alerts = {}
    for r in conn.execute("SELECT ae.event_id, ae.alert_id FROM alert_events ae JOIN incident_alerts ia"
                          " ON ia.alert_id = ae.alert_id WHERE ia.incident_id = ?", (incident_id,)):
        event_alerts.setdefault(r["event_id"], []).append(r["alert_id"])
    fields = ", ".join("e." + c.strip() for c in EVENT_FIELDS.split(","))
    events = [{**dict(r), "alert_ids": sorted(event_alerts.get(r["id"], []))} for r in conn.execute(
        f"SELECT DISTINCT {fields} FROM events e JOIN alert_events ae ON ae.event_id = e.id"
        " JOIN incident_alerts ia ON ia.alert_id = ae.alert_id WHERE ia.incident_id = ?"
        " ORDER BY e.ts, e.id LIMIT 1000", (incident_id,))]

    ordered = sorted(techniques.values(), key=lambda t: (attack.tactic_rank(t["tactic"]), t["id"]))
    incident["alerts"] = alerts
    incident["events"] = events
    incident["timeline"] = [{
        "ts": a["first_seen"], "last_seen": a["last_seen"], "alert_id": a["id"], "rule_id": a["rule_id"],
        "title": a["title"], "severity": a["severity"], "status": a["status"],
        "tactics": attack.tactic_order(t["tactic"] for t in a["techniques"]),
        "techniques": [t["id"] for t in a["techniques"]],
    } for a in alerts]
    incident["techniques"] = ordered
    incident["techniques_by_tactic"] = [
        {"tactic": tactic, "techniques": [t for t in ordered if t["tactic"] == tactic]}
        for tactic in incident["stages"]
    ]
    incident["escalated"] = len(incident["stages"]) >= 3
    # Assets behind the incident: by host name and by the addresses its evidence reached.
    incident["assets"] = assets.for_entities(
        conn, incident["entities"].get("host"),
        sorted({e["dest_ip"] for e in events if e.get("dest_ip")} | set(incident["entities"].get("src_ip") or [])))
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
    return attack.evidence(cov, improve.cached_noise_lab(conn)["rules"], simulate.SCENARIOS)
