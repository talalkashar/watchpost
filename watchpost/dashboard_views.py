"""Saved SOC dashboard filters and panel layouts."""

import json
import sqlite3

from .db import audit, now_iso, transaction
from .queries import QueryError

ViewError = QueryError

SEVERITIES = ("critical", "high", "medium", "low")
PANELS = ("p-map", "p-feed", "p-timeline", "p-attackers", "p-attack",
          "p-board", "p-rules", "p-health", "p-entities")
VISIBILITIES = ("private", "shared")


def _payload(data):
    if not isinstance(data, dict):
        raise ViewError("view must be an object")
    name = data.get("name")
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= 80):
        raise ViewError("name must be 1-80 characters")
    visibility = data.get("visibility")
    if visibility not in VISIBILITIES:
        raise ViewError("visibility must be private or shared")
    filters = data.get("filters")
    if not isinstance(filters, dict) or set(filters) != {"severities"}:
        raise ViewError("filters must contain only severities")
    severities = filters["severities"]
    if not isinstance(severities, list) or not severities \
            or any(value not in SEVERITIES for value in severities) \
            or len(set(severities)) != len(severities):
        raise ViewError("severities must be a non-empty list of unique known severities")
    layout = data.get("layout")
    if not isinstance(layout, list) or not layout or any(value not in PANELS for value in layout) \
            or len(set(layout)) != len(layout):
        raise ViewError("layout must be a non-empty list of unique dashboard panels")
    return name.strip(), visibility, {"severities": severities}, layout


def _row(row):
    result = dict(row)
    result["filters"] = json.loads(result["filters"])
    result["layout"] = json.loads(result["layout"])
    return result


def list_views(conn, actor):
    rows = conn.execute(
        "SELECT id, name, filters, layout, visibility, owner, created_at, updated_at"
        " FROM dashboard_views WHERE owner = ? OR visibility = 'shared'"
        " ORDER BY name COLLATE NOCASE, id", (actor,)).fetchall()
    return [_row(row) for row in rows]


def save(conn, data, actor, view_id=None):
    name, visibility, filters, layout = _payload(data)
    timestamp = now_iso()
    try:
        with transaction(conn):
            if view_id is None:
                cur = conn.execute(
                    "INSERT INTO dashboard_views(name, filters, layout, visibility, owner, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (name, json.dumps(filters), json.dumps(layout), visibility, actor, timestamp, timestamp))
                view_id = cur.lastrowid
                action = "dashboard_view_created"
            else:
                cur = conn.execute(
                    "UPDATE dashboard_views SET name = ?, filters = ?, layout = ?, visibility = ?, updated_at = ?"
                    " WHERE id = ? AND owner = ?",
                    (name, json.dumps(filters), json.dumps(layout), visibility, timestamp, int(view_id), actor))
                if not cur.rowcount:
                    raise ViewError("dashboard view not found", 404)
                action = "dashboard_view_updated"
            audit(conn, actor, action, name, {"id": view_id, "visibility": visibility})
    except sqlite3.IntegrityError as exc:
        raise ViewError(f"you already have a dashboard view named {name!r}", 409) from exc
    row = conn.execute("SELECT id, name, filters, layout, visibility, owner, created_at, updated_at"
                       " FROM dashboard_views WHERE id = ?", (view_id,)).fetchone()
    return _row(row)


def delete(conn, view_id, actor):
    with transaction(conn):
        row = conn.execute("SELECT name FROM dashboard_views WHERE id = ? AND owner = ?",
                           (int(view_id), actor)).fetchone()
        if row is None:
            raise ViewError("dashboard view not found", 404)
        conn.execute("DELETE FROM dashboard_views WHERE id = ?", (int(view_id),))
        audit(conn, actor, "dashboard_view_deleted", row["name"], {"id": int(view_id)})
    return {"ok": True}
