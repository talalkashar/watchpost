"""Saved SOC dashboard filters and panel layouts."""

import json
import sqlite3

from .db import audit, now_iso, transaction
from .queries import QueryError, catalog_name

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
    # ASCII case folds onto the catalog spelling (`Private` stores `private`, `High` stores `high`).
    # `info` is not a dashboard severity. `High` with `high` is still a duplicate. Panel ids stay exact.
    visibility = catalog_name(data.get("visibility"), VISIBILITIES)
    if visibility is None:
        raise ViewError("visibility must be private or shared")
    filters = data.get("filters")
    if not isinstance(filters, dict) or set(filters) != {"severities"}:
        raise ViewError("filters must contain only severities")
    severities = filters["severities"]
    folded = []
    if isinstance(severities, list):
        for value in severities:
            level = catalog_name(value, SEVERITIES)
            if level is None or level in folded:
                folded = []
                break
            folded.append(level)
    if not folded:
        raise ViewError("severities must be a non-empty list of unique known severities")
    layout = data.get("layout")
    if not isinstance(layout, list) or not layout or any(value not in PANELS for value in layout) \
            or len(set(layout)) != len(layout):
        raise ViewError("layout must be a non-empty list of unique dashboard panels")
    return name.strip(), visibility, {"severities": folded}, layout


def _row(row):
    result = dict(row)
    result["filters"] = json.loads(result["filters"])
    result["layout"] = json.loads(result["layout"])
    return result


# Views this account can see. The rest of that set is X-Watchpost-Omitted.
VIEW_LIST_LIMIT = 100
_VISIBLE = "owner = ? OR visibility = 'shared'"
# SQLite row ids and LIMIT values are signed 64-bit. A wider int raises OverflowError at bind time.
_SQLITE_INT_MAX = 2**63 - 1


def _view_id(view_id):
    """The row id, or 404 when this value cannot be that row.

    A float used to be truncated with int(): the UPDATE committed for that
    truncated id, then the read used the raw float and raised TypeError.
    A bool is not id 1. An int SQLite cannot store used to be a 500.
    """
    if isinstance(view_id, bool):
        raise ViewError("dashboard view not found", 404)
    if isinstance(view_id, int):
        number = view_id
    elif isinstance(view_id, str) and view_id.isdecimal():
        number = int(view_id)
    else:
        raise ViewError("dashboard view not found", 404)
    if number < 1 or number > _SQLITE_INT_MAX:
        raise ViewError("dashboard view not found", 404)
    return number


def _list_limit(limit):
    """A LIMIT SQLite will cap. Negative LIMIT means no limit at all."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ViewError("limit must be a non-negative integer")
    if limit < 0 or limit > _SQLITE_INT_MAX:
        raise ViewError("limit must be a non-negative integer")
    return limit


def list_views(conn, actor, limit=VIEW_LIST_LIMIT):
    """Views this account can see, and how many the limit left out.

    Own views and shared views, ordered by name COLLATE NOCASE, then id.
    A private view owned by someone else is not a row and is not counted.
    The second value is 0 when the visible list fits. Callers that return
    the bare array send that count as X-Watchpost-Omitted.
    The count and the page are one snapshot, so the leftover is not negative.
    `limit` is a non-negative integer. A negative limit is not "everything".
    """
    limit = _list_limit(limit)
    # Two autocommit statements can see different commits, and the leftover goes negative.
    own = not conn.in_transaction
    if own:
        conn.execute("BEGIN")
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM dashboard_views WHERE {_VISIBLE}", (actor,)).fetchone()[0]
        fetched = conn.execute(
            "SELECT id, name, filters, layout, visibility, owner, created_at, updated_at"
            f" FROM dashboard_views WHERE {_VISIBLE}"
            " ORDER BY name COLLATE NOCASE, id LIMIT ?", (actor, limit)).fetchall()
        rows = [_row(row) for row in fetched]
    finally:
        if own:
            conn.execute("ROLLBACK")
    return rows, total - len(rows)


def _stored_view_name(conn, owner, name, view_id=None):
    """The saved spelling of `name` for this owner.

    Unique is (owner, name COLLATE NOCASE), so `Dup` and `dup` are one row for that owner.
    Another owner's view of the same name is a different row. `view_id` is this row, so a
    rename to its own other spelling is not a clash.
    """
    sql = "SELECT name FROM dashboard_views WHERE owner = ? AND name = ? COLLATE NOCASE"
    params = [owner, name]
    if view_id is not None:
        sql += " AND id != ?"
        params.append(int(view_id))
    row = conn.execute(sql, params).fetchone()
    return None if row is None else row["name"]


def _name_taken(stored):
    raise ViewError(f"you already have a dashboard view named {stored!r}", 409)


def save(conn, data, actor, view_id=None):
    name, visibility, filters, layout = _payload(data)
    if view_id is not None:
        view_id = _view_id(view_id)
    timestamp = now_iso()
    with transaction(conn):
        stored = _stored_view_name(conn, actor, name, view_id)
        if stored is not None:
            _name_taken(stored)
        try:
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
                    (name, json.dumps(filters), json.dumps(layout), visibility, timestamp, view_id, actor))
                if not cur.rowcount:
                    raise ViewError("dashboard view not found", 404)
                action = "dashboard_view_updated"
        except sqlite3.IntegrityError:
            # A concurrent insert can pass the lookup and still hit UNIQUE (owner, name COLLATE NOCASE).
            stored = _stored_view_name(conn, actor, name, view_id)
            _name_taken(stored if stored is not None else name)
        audit(conn, actor, action, name, {"id": view_id, "visibility": visibility})
        # Read before commit. A delete that lands after commit must not turn this into TypeError,
        # and a missing row must not commit an update the caller never receives.
        row = conn.execute("SELECT id, name, filters, layout, visibility, owner, created_at, updated_at"
                           " FROM dashboard_views WHERE id = ?", (view_id,)).fetchone()
        if row is None:
            raise ViewError("dashboard view not found", 404)
        saved = _row(row)
    return saved


def delete(conn, view_id, actor):
    view_id = _view_id(view_id)
    with transaction(conn):
        row = conn.execute("SELECT name FROM dashboard_views WHERE id = ? AND owner = ?",
                           (view_id, actor)).fetchone()
        if row is None:
            raise ViewError("dashboard view not found", 404)
        cur = conn.execute("DELETE FROM dashboard_views WHERE id = ? AND owner = ?",
                           (view_id, actor))
        if not cur.rowcount:
            raise ViewError("dashboard view not found", 404)
        audit(conn, actor, "dashboard_view_deleted", row["name"], {"id": view_id})
    return {"ok": True}
