"""Read-side queries and analyst workflow operations."""

from datetime import timedelta

from .db import iso, now_iso, parse_iso, row_to_dict, transaction, utcnow
from .normalize import EVENT_TYPES, SEVERITIES, EventError, parse_timestamp

ALERT_STATUSES = ("open", "investigating", "resolved")
DISPOSITIONS = ("true_positive", "false_positive", "benign")
EVENT_FIELDS = "id, ts, ingested_at, source, host, event_type, outcome, severity, user, src_ip, dest_ip, dest_port, " \
               "bytes, message, synthetic, batch_id"


class QueryError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _int(value, name, default, low, high):
    if value in (None, ""):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise QueryError(f"{name} must be an integer")
    if not low <= number <= high:
        raise QueryError(f"{name} must be between {low} and {high}")
    return number


def _ts(value, name):
    try:
        return parse_timestamp(value)
    except EventError as exc:
        raise QueryError(f"{name}: {exc}")


def search_events(conn, params):
    where, args = [], []
    if params.get("start"):
        where.append("ts >= ?")
        args.append(_ts(params["start"], "start"))
    if params.get("end"):
        where.append("ts <= ?")
        args.append(_ts(params["end"], "end"))
    if params.get("severity"):
        levels = params["severity"].split(",")
        if not set(levels) <= set(SEVERITIES):
            raise QueryError(f"severity must be from {', '.join(SEVERITIES)}")
        if params.get("severity_mode") == "min" and len(levels) == 1:
            levels = SEVERITIES[SEVERITIES.index(levels[0]):]
        where.append(f"severity IN ({','.join('?' for _ in levels)})")
        args += levels
    if params.get("event_type"):
        if params["event_type"] not in EVENT_TYPES:
            raise QueryError(f"event_type must be one of {', '.join(sorted(EVENT_TYPES))}")
        where.append("event_type = ?")
        args.append(params["event_type"])
    for field, column in (("source", "source"), ("host", "host"), ("user", "user"), ("batch_id", "batch_id")):
        if params.get(field):
            if params[field].endswith("*"):
                where.append(f"{column} LIKE ? ESCAPE '\\'")
                args.append(_escape_like(params[field][:-1]) + "%")
            else:
                where.append(f"{column} = ? COLLATE NOCASE" if field == "user" else f"{column} = ?")
                args.append(params[field])
    if params.get("ip"):
        where.append("(src_ip = ? OR dest_ip = ?)")
        args += [params["ip"], params["ip"]]
    if params.get("q"):
        where.append("message LIKE ? ESCAPE '\\'")
        args.append("%" + _escape_like(params["q"][:200]) + "%")
    if params.get("synthetic") in ("0", "1"):
        where.append("synthetic = ?")
        args.append(int(params["synthetic"]))

    limit = _int(params.get("limit"), "limit", 100, 1, 1000)
    offset = _int(params.get("offset"), "offset", 0, 0, 10_000_000)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM events{clause}", args).fetchone()[0]
    rows = conn.execute(
        f"SELECT {EVENT_FIELDS} FROM events{clause} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
        args + [limit, offset],
    )
    return {"total": total, "limit": limit, "offset": offset, "events": [dict(r) for r in rows]}


def _escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_event(conn, event_id):
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise QueryError("event not found", 404)
    event = dict(row)
    event["alerts"] = [dict(r) for r in conn.execute(
        "SELECT a.id, a.title, a.status FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id"
        " WHERE ae.event_id = ?", (event_id,))]
    return event


def list_alerts(conn, params):
    where, args = [], []
    if params.get("status"):
        statuses = params["status"].split(",")
        if not set(statuses) <= set(ALERT_STATUSES):
            raise QueryError(f"status must be from {', '.join(ALERT_STATUSES)}")
        where.append(f"status IN ({','.join('?' for _ in statuses)})")
        args += statuses
    if params.get("severity"):
        if params["severity"] not in SEVERITIES:
            raise QueryError("invalid severity")
        where.append("severity = ?")
        args.append(params["severity"])
    if params.get("rule_id"):
        where.append("rule_id = ?")
        args.append(params["rule_id"])
    limit = _int(params.get("limit"), "limit", 100, 1, 500)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
             "WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC")
    rows = conn.execute(f"SELECT * FROM alerts{clause} ORDER BY status = 'resolved', {order} LIMIT ?",
                        args + [limit])
    return [dict(r) for r in rows]


def get_alert(conn, alert_id):
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        raise QueryError("alert not found", 404)
    alert = dict(alert)
    alert["rule"] = row_to_dict(conn.execute("SELECT id, name, description, version, techniques FROM rules"
                                             " WHERE id = ?", (alert["rule_id"],)).fetchone(), ["techniques"])
    alert["evidence"] = [dict(r) for r in conn.execute(
        f"SELECT {', '.join('e.' + c.strip() for c in EVENT_FIELDS.split(','))} FROM events e"
        " JOIN alert_events ae ON ae.event_id = e.id WHERE ae.alert_id = ? ORDER BY e.ts, e.id LIMIT 500",
        (alert_id,))]
    alert["notes"] = [dict(r) for r in conn.execute(
        "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY id", (alert_id,))]
    alert["activity"] = [dict(r) for r in conn.execute(
        "SELECT * FROM alert_activity WHERE alert_id = ? ORDER BY id", (alert_id,))]
    alert["timeline"] = related_timeline(conn, alert)
    return alert


def related_timeline(conn, alert, pad_minutes=30):
    """All events touching the alert's IPs or users, from 30 minutes before to 30 after.

    Shows context the rule did not use: e.g. what the attacking IP did after a successful login.
    """
    ips = {e["src_ip"] for e in alert["evidence"] if e["src_ip"]}
    users = {e["user"] for e in alert["evidence"] if e["user"]}
    if not ips and not users:
        return []
    start = iso(parse_iso(alert["first_seen"]) - timedelta(minutes=pad_minutes))
    end = iso(parse_iso(alert["last_seen"]) + timedelta(minutes=pad_minutes))
    clauses, args = [], []
    if ips:
        clauses.append(f"src_ip IN ({','.join('?' for _ in ips)})")
        args += sorted(ips)
    if users:
        clauses.append(f"user IN ({','.join('?' for _ in users)})")
        args += sorted(users)
    evidence_ids = {e["id"] for e in alert["evidence"]}
    rows = conn.execute(
        f"SELECT id, ts, source, host, event_type, severity, user, src_ip, message FROM events"
        f" WHERE ts BETWEEN ? AND ? AND ({' OR '.join(clauses)}) ORDER BY ts, id LIMIT 300",
        [start, end] + args,
    )
    return [{**dict(r), "is_evidence": r["id"] in evidence_ids} for r in rows]


def add_note(conn, alert_id, author, body):
    if not isinstance(body, str) or not body.strip():
        raise QueryError("note body is required")
    if len(body) > 5000:
        raise QueryError("note must be 5000 characters or fewer")
    with transaction(conn):
        if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            raise QueryError("alert not found", 404)
        now = now_iso()
        note_id = conn.execute(
            "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
            (alert_id, author, body.strip(), now)).lastrowid
        conn.execute("INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                     (alert_id, author, "note_added", None, now))
        conn.execute("UPDATE alerts SET updated_at = ? WHERE id = ?", (now, alert_id))
    return dict(conn.execute("SELECT * FROM alert_notes WHERE id = ?", (note_id,)).fetchone())


def update_status(conn, alert_id, actor, status, disposition=None, note=None):
    if status not in ALERT_STATUSES:
        raise QueryError(f"status must be one of {', '.join(ALERT_STATUSES)}")
    if status == "resolved" and disposition not in DISPOSITIONS:
        raise QueryError(f"resolving requires a disposition: {', '.join(DISPOSITIONS)}")
    if status != "resolved" and disposition is not None:
        raise QueryError("disposition can only be set when resolving")
    with transaction(conn):
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if alert is None:
            raise QueryError("alert not found", 404)
        now = now_iso()
        if status == "resolved":
            conn.execute("UPDATE alerts SET status = ?, disposition = ?, resolved_at = ?, updated_at = ?"
                         " WHERE id = ?", (status, disposition, now, now, alert_id))
        else:
            # Reopening clears the previous verdict so feedback metrics stay accurate.
            conn.execute("UPDATE alerts SET status = ?, disposition = NULL, resolved_at = NULL,"
                         " assignee = CASE WHEN ? = 'investigating' THEN ? ELSE assignee END, updated_at = ?"
                         " WHERE id = ?", (status, status, actor, now, alert_id))
        detail = f"{alert['status']} -> {status}" + (f" ({disposition})" if disposition else "")
        conn.execute("INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                     (alert_id, actor, "status_changed", detail, now))
    if note:
        add_note(conn, alert_id, actor, note)
    return dict(conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())


def metrics(conn, hours=24):
    hours = _int(hours, "hours", 24, 1, 24 * 90)
    since = iso(utcnow() - timedelta(hours=hours))
    one = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    by = lambda sql, *a: [dict(r) for r in conn.execute(sql, a)]

    # Anchor the activity histogram to the newest event so demo data (dated yesterday) is visible.
    latest = one("SELECT MAX(ts) FROM events")
    histogram = []
    if latest:
        end = parse_iso(latest).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        start = end - timedelta(hours=24)
        rows = conn.execute(
            "SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS events,"
            " SUM(event_type = 'auth_failure') AS failures FROM events WHERE ts >= ? AND ts < ?"
            " GROUP BY hour", (iso(start), iso(end))).fetchall()
        counts = {r["hour"]: r for r in rows}
        for i in range(24):
            key = iso(start + timedelta(hours=i))[:13]
            row = counts.get(key)
            histogram.append({"hour": key + ":00Z", "events": row["events"] if row else 0,
                              "failures": row["failures"] if row else 0})

    mttr = one("SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 1440) FROM alerts"
               " WHERE resolved_at IS NOT NULL")
    return {
        "window_hours": hours,
        "events_total": one("SELECT COUNT(*) FROM events"),
        "events_ingested_window": one("SELECT COUNT(*) FROM events WHERE ingested_at >= ?", since),
        "synthetic_events": one("SELECT COUNT(*) FROM events WHERE synthetic = 1"),
        "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE status = 'open'"),
        "alerts_investigating": one("SELECT COUNT(*) FROM alerts WHERE status = 'investigating'"),
        "alerts_resolved": one("SELECT COUNT(*) FROM alerts WHERE status = 'resolved'"),
        "alerts_by_severity": by("SELECT severity, COUNT(*) AS count FROM alerts WHERE status != 'resolved'"
                                 " GROUP BY severity"),
        "alerts_by_rule": by("SELECT rule_id, COUNT(*) AS count FROM alerts GROUP BY rule_id ORDER BY count DESC"),
        "dispositions": by("SELECT disposition, COUNT(*) AS count FROM alerts WHERE disposition IS NOT NULL"
                           " GROUP BY disposition"),
        "mean_time_to_resolve_minutes": round(mttr, 1) if mttr is not None else None,
        "top_failure_ips": by("SELECT src_ip, COUNT(*) AS count FROM events WHERE event_type = 'auth_failure'"
                              " AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 5"),
        "top_failure_users": by("SELECT user, COUNT(*) AS count FROM events WHERE event_type = 'auth_failure'"
                                " AND user IS NOT NULL GROUP BY user ORDER BY count DESC LIMIT 5"),
        "events_by_type": by("SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
                             " ORDER BY count DESC"),
        "activity_last_24h_of_data": histogram,
    }
