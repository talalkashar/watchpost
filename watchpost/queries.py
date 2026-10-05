"""Read-side queries and analyst workflow operations."""

from datetime import timedelta

import json

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
    # since_id: only events stored after that id, newest stored first (the dashboard's polling fallback).
    since_id = _int(params.get("since_id"), "since_id", None, 0, 2**63 - 1)
    if since_id is not None:
        where.append("id > ?")
        args.append(since_id)

    limit = _int(params.get("limit"), "limit", 100, 1, 1000)
    offset = _int(params.get("offset"), "offset", 0, 0, 10_000_000)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM events{clause}", args).fetchone()[0]
    rows = conn.execute(
        f"SELECT {EVENT_FIELDS} FROM events{clause} ORDER BY "
        f"{'id DESC' if since_id is not None else 'ts DESC, id DESC'} LIMIT ? OFFSET ?",
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
    return [alert_row(r) for r in rows]


def alert_row(row):
    """An alert with its matched assets decoded (alerts created before asset modeling have none)."""
    alert = dict(row)
    alert["assets"] = json.loads(alert["assets"]) if alert.get("assets") else []
    return alert


def get_alert(conn, alert_id):
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        raise QueryError("alert not found", 404)
    alert = alert_row(alert)
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


# Open-alert age buckets in minutes since the alert was created: (label, from, up to).
AGING_BUCKETS = (("under 1h", 0, 60), ("1-4h", 60, 240), ("4-24h", 240, 1440), ("1-7d", 1440, 10080),
                 ("over 7d", 10080, float("inf")))
# Left out on purpose: they compare an event's own timestamp with this instance's clock, and demo
# and simulated events are replayed with timestamps from the previous business day.
OMITTED_METRICS = [
    {"metric": "time_to_detect", "reason": "Event time to alert creation. Replayed synthetic events carry older"
                                           " timestamps, so this would measure the replay offset, not detection."},
    {"metric": "dwell_time", "reason": "First malicious event to resolution. It starts from the same replayed"
                                       " event timestamps, so it would be inflated by the replay offset."},
]


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
    # SOC metrics (3.0). All three use created_at/resolved_at, which are wall-clock times of this
    # instance, so they stay honest when the events themselves are replayed with older timestamps.
    minutes = "(julianday(resolved_at) - julianday(created_at)) * 1440"
    resolve_by_severity = [
        {"severity": r["severity"], "resolved": r["resolved"], "mean_minutes": round(r["mean"], 1),
         "max_minutes": round(r["longest"], 1)} for r in conn.execute(
            f"SELECT severity, COUNT(*) AS resolved, AVG({minutes}) AS mean, MAX({minutes}) AS longest FROM alerts"
            f" WHERE resolved_at IS NOT NULL GROUP BY severity ORDER BY {SEVERITY_RANK_SQL.format(col='severity')}"
            " DESC")]
    fp_by_rule = [
        {**dict(r), "false_positive_rate": round(r["false_positive"] / r["reviewed"], 3)} for r in conn.execute(
            "SELECT rule_id, COUNT(*) AS reviewed, SUM(disposition = 'false_positive') AS false_positive,"
            " SUM(disposition = 'benign') AS benign FROM alerts WHERE disposition IS NOT NULL GROUP BY rule_id"
            " ORDER BY SUM(disposition = 'false_positive') * 1.0 / COUNT(*) DESC, rule_id")]
    now = utcnow()
    ages = [(now - parse_iso(r["created_at"])).total_seconds() / 60 for r in conn.execute(
        "SELECT created_at FROM alerts WHERE status != 'resolved'")]
    aging = {"buckets": [{"label": label, "count": sum(low <= a < high for a in ages)}
                         for label, low, high in AGING_BUCKETS],
             "oldest_minutes": round(max(ages), 1) if ages else None}
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
        "time_to_resolve_by_severity": resolve_by_severity,
        "false_positive_rate_by_rule": fp_by_rule,
        "open_alert_aging": aging,
        "omitted_metrics": OMITTED_METRICS,
    }


SEVERITY_RANK_SQL = ("CASE {col} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2"
                     " WHEN 'low' THEN 1 ELSE 0 END")
RANK_SEVERITY = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def _alert_timeline(conn):
    """Alerts per bucket by event time (last_seen), stacked by severity, plus event volume.

    The window ends at the newest alert so demo data dated yesterday still shows. When
    every recent alert falls inside the last two hours (a live storyline run), it zooms
    in to 5-minute buckets; otherwise it shows 24 hourly buckets.
    """
    newest = conn.execute("SELECT MAX(last_seen) FROM alerts").fetchone()[0] or \
        conn.execute("SELECT MAX(ts) FROM events").fetchone()[0]
    if not newest:
        return {"bucket_minutes": 60, "bins": []}
    end_dt = parse_iso(newest)
    oldest_recent = conn.execute("SELECT MIN(last_seen) FROM alerts WHERE last_seen >= ?",
                                 (iso(end_dt - timedelta(hours=24)),)).fetchone()[0]
    zoom = oldest_recent is not None and parse_iso(oldest_recent) >= end_dt - timedelta(hours=2)
    minutes, count = (5, 24) if zoom else (60, 24)
    end = end_dt.replace(second=0, microsecond=0)
    end = end.replace(minute=end.minute - end.minute % minutes) + timedelta(minutes=minutes)
    start = end - timedelta(minutes=minutes * count)
    bins = [{"start": iso(start + timedelta(minutes=minutes * i)), "critical": 0, "high": 0, "medium": 0,
             "low": 0, "events": 0} for i in range(count)]

    def index(ts):
        i = int((parse_iso(ts) - start).total_seconds() // (minutes * 60))
        return i if 0 <= i < count else None

    for row in conn.execute("SELECT last_seen, severity FROM alerts WHERE last_seen >= ? AND last_seen < ?",
                            (iso(start), iso(end))):
        i = index(row["last_seen"])
        if i is not None and row["severity"] in bins[i]:
            bins[i][row["severity"]] += 1
    for row in conn.execute("SELECT substr(ts, 1, 16) AS minute, COUNT(*) AS n FROM events"
                            " WHERE ts >= ? AND ts < ? GROUP BY minute", (iso(start), iso(end))):
        i = index(row["minute"] + ":00Z")
        if i is not None:
            bins[i]["events"] += row["n"]
    return {"bucket_minutes": minutes, "bins": bins}


def dashboard(conn):
    """Everything the SOC dashboard needs in one read. Live changes then arrive over /api/stream."""
    one = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    now = utcnow().replace(second=0, microsecond=0)
    since = now - timedelta(minutes=59)
    per_minute = {r["minute"]: r["n"] for r in conn.execute(
        "SELECT substr(ingested_at, 1, 16) AS minute, COUNT(*) AS n FROM events WHERE ingested_at >= ?"
        " GROUP BY minute", (iso(since),))}
    epm = []
    for i in range(60):
        key = iso(since + timedelta(minutes=i))[:16]
        epm.append({"minute": key + ":00Z", "count": per_minute.get(key, 0)})

    sev_events = SEVERITY_RANK_SQL.format(col="e.severity")
    sev_alerts = SEVERITY_RANK_SQL.format(col="a.severity")
    attackers = [{**dict(r), "max_severity": RANK_SEVERITY[r["sev_rank"]]} for r in conn.execute(
        f"SELECT e.src_ip AS ip, COUNT(DISTINCT e.id) AS events, COUNT(DISTINCT a.id) AS alerts,"
        f" MAX(MAX({sev_events}), MAX({sev_alerts})) AS sev_rank, MAX(e.ts) AS last_seen,"
        f" SUM(a.status != 'resolved') AS open_alerts"
        f" FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id JOIN events e ON e.id = ae.event_id"
        f" WHERE e.src_ip IS NOT NULL GROUP BY e.src_ip ORDER BY alerts DESC, events DESC LIMIT 40")]
    for a in attackers:
        del a["sev_rank"]

    top_rules = [dict(r) for r in conn.execute(
        "SELECT a.rule_id, r.name, r.severity, COUNT(*) AS alerts, SUM(a.status != 'resolved') AS open"
        " FROM alerts a LEFT JOIN rules r ON r.id = a.rule_id GROUP BY a.rule_id ORDER BY alerts DESC LIMIT 10")]
    board = [dict(r) for r in conn.execute(
        "SELECT id, rule_id, severity, title, status, group_key, first_seen, last_seen, event_count, synthetic,"
        " assignee FROM alerts ORDER BY status = 'resolved', "
        + SEVERITY_RANK_SQL.format(col="severity") + " DESC, last_seen DESC LIMIT 60")]
    recent = [dict(r) for r in conn.execute(
        f"SELECT {EVENT_FIELDS} FROM events ORDER BY ts DESC, id DESC LIMIT 60")]
    return {
        "generated_at": now_iso(),
        "events_total": one("SELECT COUNT(*) FROM events"),
        "synthetic_events": one("SELECT COUNT(*) FROM events WHERE synthetic = 1"),
        "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE status = 'open'"),
        "alerts_investigating": one("SELECT COUNT(*) FROM alerts WHERE status = 'investigating'"),
        "alerts_critical_open": one("SELECT COUNT(*) FROM alerts WHERE status != 'resolved'"
                                    " AND severity = 'critical'"),
        "alerts_total": one("SELECT COUNT(*) FROM alerts"),
        "events_per_minute": epm,
        "alert_timeline": _alert_timeline(conn),
        "attackers": attackers,
        "top_rules": top_rules,
        "alerts": board,
        "recent_events": recent,
    }
