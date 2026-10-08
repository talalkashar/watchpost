"""Chronological incident case records and JSON/Markdown rendering."""

import json

from . import __version__, incidents
from .db import now_iso
from .report import md as _md


def _audit_detail(value):
    try:
        detail = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return detail if isinstance(detail, dict) else {}


def build(conn, incident_id):
    """Combine an incident's evidence and analyst workflow into one ordered record."""
    incident = incidents.get_incident(conn, incident_id)
    alert_ids = [alert["id"] for alert in incident["alerts"]]
    alerts = {alert["id"]: alert for alert in incident["alerts"]}
    timeline = [{"ts": incident["created_at"], "type": "incident_created",
                 "detail": f"Incident #{incident_id} created"}]

    for row in conn.execute(
            "SELECT ia.alert_id, ia.added_at FROM incident_alerts ia WHERE ia.incident_id = ?",
            (incident_id,)):
        alert = alerts[row["alert_id"]]
        timeline.append({"ts": row["added_at"], "type": "alert_added", "alert_id": row["alert_id"],
                         "rule_id": alert["rule_id"], "severity": alert["severity"], "title": alert["title"]})

    for event in incident["events"]:
        timeline.append({"ts": event["ts"], "type": "evidence", "alert_ids": event["alert_ids"],
                         "event": {key: value for key, value in event.items() if key != "alert_ids"}})

    if alert_ids:
        marks = ",".join("?" for _ in alert_ids)
        for row in conn.execute(
                f"SELECT * FROM alert_activity WHERE alert_id IN ({marks}) AND action != 'note_added'", alert_ids):
            timeline.append({"ts": row["created_at"], "type": row["action"], "alert_id": row["alert_id"],
                             "actor": row["actor"], "detail": row["detail"]})
        for row in conn.execute(f"SELECT * FROM alert_notes WHERE alert_id IN ({marks})", alert_ids):
            timeline.append({"ts": row["created_at"], "type": "analyst_note", "alert_id": row["alert_id"],
                             "author": row["author"], "body": row["body"]})

    for row in conn.execute("SELECT created_at, actor, detail FROM audit_log WHERE action = 'incident_status_changed'"
                            " AND target = ?", (str(incident_id),)):
        detail = _audit_detail(row["detail"])
        timeline.append({"ts": row["created_at"], "type": "incident_status_changed", "actor": row["actor"],
                         "from": detail.get("from"), "to": detail.get("to"), "note": detail.get("note")})

    order = {"evidence": 0, "incident_created": 1, "alert_added": 2, "assigned": 3,
             "status_changed": 4, "analyst_note": 5, "incident_status_changed": 6}
    timeline.sort(key=lambda item: (item["ts"], order.get(item["type"], 99),
                                    item.get("alert_id", 0), item.get("event", {}).get("id", 0)))
    for sequence, item in enumerate(timeline, 1):
        item["sequence"] = sequence

    return {
        "format": "watchpost-incident-case", "format_version": 1, "generator": f"Watchpost {__version__}",
        "generated_at": now_iso(), "id": incident["id"], "title": incident["title"],
        "severity": incident["severity"], "status": incident["status"], "assignee": incident["assignee"],
        "synthetic": bool(incident["synthetic"]), "first_seen": incident["first_seen"],
        "last_seen": incident["last_seen"], "entities": incident["entities"], "stages": incident["stages"],
        "alerts": [{key: alert.get(key) for key in
                    ("id", "rule_id", "title", "severity", "status", "disposition", "assignee", "first_seen",
                     "last_seen", "event_count")} for alert in incident["alerts"]],
        "timeline": timeline,
    }


def to_json_bytes(case):
    return json.dumps(case, sort_keys=True, indent=2).encode("utf-8")


def _timeline_detail(item):
    kind = item["type"]
    if kind == "evidence":
        event = item["event"]
        return ("Evidence", f"Alert(s) {', '.join('#' + str(i) for i in item['alert_ids'])}: "
                f"{event.get('event_type')} — {event.get('message') or ''}")
    if kind == "incident_created":
        return "Incident created", item["detail"]
    if kind == "alert_added":
        return "Alert added", f"Alert #{item['alert_id']} ({item['rule_id']}): {item['title']}"
    if kind == "assigned":
        return "Alert assigned", f"Alert #{item['alert_id']} by {item['actor']}: {item['detail']}"
    if kind == "status_changed":
        return "Alert status changed", f"Alert #{item['alert_id']} by {item['actor']}: {item['detail']}"
    if kind == "analyst_note":
        return "Analyst note", f"Alert #{item['alert_id']} by {item['author']}: {item['body']}"
    if kind == "incident_status_changed":
        note = f" — {item['note']}" if item.get("note") else ""
        return "Incident status changed", f"{item['actor']}: {item.get('from')} → {item.get('to')}{note}"
    return "Alert activity", f"Alert #{item['alert_id']} by {item['actor']}: {kind} — {item.get('detail') or ''}"


def to_markdown_bytes(case):
    lines = [f"# Incident case #{case['id']}: {_md(case['title'])}", "",
             "SYNTHETIC DATA" if case["synthetic"] else "", "",
             f"- **Status:** {_md(case['status'])}", f"- **Severity:** {_md(case['severity'])}",
             f"- **Assignee:** {_md(case['assignee'])}", f"- **First seen:** {_md(case['first_seen'])}",
             f"- **Last seen:** {_md(case['last_seen'])}", f"- **Generated:** {_md(case['generated_at'])}", "",
             "## Chronological timeline", "", "| # | Time | Activity | Detail |", "|---:|---|---|---|"]
    for item in case["timeline"]:
        label, detail = _timeline_detail(item)
        lines.append(f"| {item['sequence']} | {_md(item['ts'])} | {_md(label)} | {_md(detail)} |")
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")
