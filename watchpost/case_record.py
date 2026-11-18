"""Chronological incident case records and JSON/Markdown rendering."""

import json

from . import __version__, attack, incidents
from .db import now_iso
from .report import LEVEL_NOTE as _LEVEL_NOTE
from .report import md as _md

# Newest notes, activity rows (except note_added), and incident status changes, by id.
# The rest are notes_omitted, activity_omitted, and status_changes_omitted. An exact cap is not a drop.
CASE_ROW_LIMIT = 100


def _audit_detail(value):
    try:
        detail = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return detail if isinstance(detail, dict) else {}


def _newest(conn, table_where, args):
    """Newest CASE_ROW_LIMIT rows matching a fixed FROM/WHERE, and how many were left out.

    `table_where` is a constant in this module, never a request value. The rows come back in id
    order. The timeline sort is still by time.
    """
    total = conn.execute(f"SELECT COUNT(*) AS n FROM {table_where}", args).fetchone()["n"]
    rows = [dict(row) for row in conn.execute(
        f"SELECT * FROM (SELECT * FROM {table_where} ORDER BY id DESC LIMIT ?) ORDER BY id",
        (*args, CASE_ROW_LIMIT))]
    return rows, total - len(rows)


def build(conn, incident_id):
    """Combine an incident's evidence and analyst workflow into one ordered record."""
    incident = incidents.get_incident(conn, incident_id)
    # Every linked alert, not only the ones whose evidence made the event cap.
    linked = [row["alert_id"] for row in conn.execute(
        "SELECT alert_id FROM incident_alerts WHERE incident_id = ?", (incident_id,))]
    alerts = {alert["id"]: alert for alert in incident["alerts"]}
    timeline = [{"ts": incident["created_at"], "type": "incident_created",
                 "detail": f"Incident #{incident_id} created"}]

    for row in conn.execute(
            "SELECT ia.alert_id, ia.added_at FROM incident_alerts ia WHERE ia.incident_id = ?",
            (incident_id,)):
        alert = alerts[row["alert_id"]]
        timeline.append({"ts": row["added_at"], "type": "alert_added", "alert_id": row["alert_id"],
                         "rule_id": alert["rule_id"], "severity": alert["severity"], "title": alert["title"]})

    # Evidence is already capped on the incident. Copy that count; do not cap it again.
    for event in incident["events"]:
        timeline.append({"ts": event["ts"], "type": "evidence", "alert_ids": event["alert_ids"],
                         "event": {key: value for key, value in event.items() if key != "alert_ids"}})

    notes, notes_omitted = [], 0
    activity, activity_omitted = [], 0
    if linked:
        marks = ",".join("?" * len(linked))
        notes, notes_omitted = _newest(conn, f"alert_notes WHERE alert_id IN ({marks})", linked)
        activity, activity_omitted = _newest(
            conn, f"alert_activity WHERE alert_id IN ({marks}) AND action != 'note_added'", linked)
    for row in notes:
        timeline.append({"ts": row["created_at"], "type": "analyst_note", "alert_id": row["alert_id"],
                         "author": row["author"], "body": row["body"]})
    for row in activity:
        timeline.append({"ts": row["created_at"], "type": row["action"], "alert_id": row["alert_id"],
                         "actor": row["actor"], "detail": row["detail"]})

    status_rows, status_omitted = _newest(
        conn, "audit_log WHERE action = 'incident_status_changed' AND target = ?", (str(incident_id),))
    for row in status_rows:
        detail = _audit_detail(row["detail"])
        timeline.append({"ts": row["created_at"], "type": "incident_status_changed", "actor": row["actor"],
                         "from": detail.get("from"), "to": detail.get("to"), "note": detail.get("note")})

    order = {"evidence": 0, "incident_created": 1, "alert_added": 2, "assigned": 3,
             "status_changed": 4, "analyst_note": 5, "incident_status_changed": 6}
    timeline.sort(key=lambda item: (item["ts"], order.get(item["type"], 99),
                                    item.get("alert_id", 0), item.get("event", {}).get("id", 0)))
    for sequence, item in enumerate(timeline, 1):
        item["sequence"] = sequence

    graded = {row["id"]: row["level"] for row in incidents.coverage(conn)["techniques"]}
    techniques = []
    for technique in incident["techniques"]:
        # A technique the catalog does not grade is still only a name on a rule, so it stays mapped.
        level = graded.get(technique["id"], "mapped")
        if level not in attack.LEVELS:
            level = "mapped"
        techniques.append({
            "id": technique["id"], "name": technique.get("name") or "",
            "tactic": technique.get("tactic") or "", "level": level,
            "alert_ids": list(technique.get("alert_ids") or []),
        })

    return {
        "format": "watchpost-incident-case", "format_version": 1, "generator": f"Watchpost {__version__}",
        "generated_at": now_iso(), "id": incident["id"], "title": incident["title"],
        "severity": incident["severity"], "status": incident["status"], "assignee": incident["assignee"],
        "synthetic": bool(incident["synthetic"]), "first_seen": incident["first_seen"],
        "last_seen": incident["last_seen"], "entities": incident["entities"], "stages": incident["stages"],
        "techniques": techniques,
        "events_omitted": incident["events_omitted"],
        "notes_omitted": notes_omitted,
        "activity_omitted": activity_omitted,
        "status_changes_omitted": status_omitted,
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


def _left_out(case):
    """Name a dropped count only when it is not 0. A list that fits adds no line."""
    named = (
        ("events_omitted", "evidence event", "evidence events"),
        ("notes_omitted", "note", "notes"),
        ("activity_omitted", "activity row", "activity rows"),
        ("status_changes_omitted", "status change", "status changes"),
    )
    lines = []
    for key, singular, plural in named:
        count = case.get(key) or 0
        if count:
            lines.append(f"_{count} {singular if count == 1 else plural} left out._")
    return lines


def to_markdown_bytes(case):
    lines = [f"# Incident case #{case['id']}: {_md(case['title'])}", "",
             "SYNTHETIC DATA" if case["synthetic"] else "", "",
             f"- **Status:** {_md(case['status'])}", f"- **Severity:** {_md(case['severity'])}",
             f"- **Assignee:** {_md(case['assignee'])}", f"- **First seen:** {_md(case['first_seen'])}",
             f"- **Last seen:** {_md(case['last_seen'])}", f"- **Generated:** {_md(case['generated_at'])}", "",
             "## ATT&CK techniques", "", _LEVEL_NOTE, ""]
    techniques = case.get("techniques") or []
    if techniques:
        lines += ["| Technique | Name | Tactic | Evidence level | Alerts |", "|---|---|---|---|---|"]
        for technique in techniques:
            alerts = ", ".join(f"#{alert_id}" for alert_id in technique.get("alert_ids") or []) or "-"
            lines.append("| " + " | ".join(_md(value) for value in (
                technique.get("id"), technique.get("name"), technique.get("tactic"),
                technique.get("level"), alerts)) + " |")
    else:
        lines.append("No ATT&CK technique is recorded for the rules on this incident.")
    lines += ["", "## Chronological timeline", "", "| # | Time | Activity | Detail |", "|---:|---|---|---|"]
    for item in case["timeline"]:
        label, detail = _timeline_detail(item)
        lines.append(f"| {item['sequence']} | {_md(item['ts'])} | {_md(label)} | {_md(detail)} |")
    extra = _left_out(case)
    if extra:
        lines.append("")
        lines.extend(extra)
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")
