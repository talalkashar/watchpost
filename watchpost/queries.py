"""Read-side queries and analyst workflow operations."""

import ipaddress
import json
from datetime import timedelta

from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction, utcnow
from .normalize import EVENT_TYPES, SEVERITIES, EventError, parse_timestamp

# A-Z only. SQLite NOCASE folds the same letters; É and é stay apart.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

ALERT_STATUSES = ("open", "investigating", "resolved")
DISPOSITIONS = ("true_positive", "false_positive", "benign")
# OFFSET makes SQLite visit every skipped row. Past this, walk newer events with since_id.
MAX_EVENT_OFFSET = 10_000
# A longer needle used to be sliced, so it matched messages that lacked the rest.
MAX_SEARCH_Q = 200
# Alert detail returns this many evidence events, earliest first. The rest are evidence_omitted.
EVIDENCE_LIMIT = 500
# Related timeline returns this many events, earliest in the window. The rest are timeline_omitted.
TIMELINE_LIMIT = 300
# Alert detail returns this many notes and this many activity rows, newest by id.
# Each list stays in id order. The older rows are notes_omitted and activity_omitted.
NOTE_LIMIT = 100
ACTIVITY_LIMIT = 100
# Dashboard attacker list is this many source IPs, most alerts, then most events, then ip.
# attackers_omitted is how many source IPs on alerts were past that cap.
ATTACKER_LIMIT = 40
# Dashboard top rules is this many rule ids, most alerts first, then rule_id.
# rules_omitted is how many rule ids on alerts were past that cap.
# A rule with no alerts is not a row and is not omitted.
TOP_RULE_LIMIT = 10
# Dashboard alert board is this many alerts. Not resolved first, then severity,
# then last_seen, then id descending (the newer id stays).
# board_omitted is how many alerts were past that cap.
BOARD_LIMIT = 60
# Dashboard recent events are this many, newest by ts, then id.
# recent_events_omitted is how many stored events were past that cap.
RECENT_LIMIT = 60
# Metrics failure lists are this many groups, most failures first.
# top_failure_ips orders by count, then src_ip.
# top_failure_users orders by count, then the folded user.
# top_failure_ips_omitted and top_failure_users_omitted are how many groups were past that cap.
TOP_FAILURE_LIMIT = 5
# Metrics alerts_by_rule is this many rule ids, most alerts first, then rule_id.
# alerts_by_rule_omitted is how many rule ids on alerts were past that cap.
# A rule with no alerts is not a row and is not omitted.
ALERTS_BY_RULE_LIMIT = 100
# Metrics false_positive_rate_by_rule is this many rule ids that have a disposition,
# false-positive rate descending, then rule_id.
# false_positive_rate_by_rule_omitted is how many of those rule ids were past that cap.
# A rule with no disposition is not a row and is not omitted.
FP_RATE_BY_RULE_LIMIT = 100
# Metrics events_by_type is this many event types, most events first, then event_type.
# events_by_type_omitted is how many event types were past that cap.
# A type with no events is not a row and is not omitted. The field still counts every stored event.
EVENTS_BY_TYPE_LIMIT = 100
# Event detail returns this many linked alerts, newest by alert id, then id order.
# alerts_omitted is how many linked alerts were past that cap.
EVENT_ALERT_LIMIT = 50
_ATTACKER_FROM = (
    " FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id"
    " JOIN events e ON e.id = ae.event_id WHERE e.src_ip IS NOT NULL")
EVENT_FIELDS = "id, ts, ingested_at, source, host, event_type, outcome, severity, user, src_ip, dest_ip, dest_port, " \
               "bytes, message, synthetic, batch_id"


class QueryError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# Same four words as hunt.FLAGS. ASCII letters only. Not str.lower().
_SYNTHETIC_FLAGS = {"1": 1, "true": 1, "0": 0, "false": 0}


def synthetic_flag(value):
    """The bound 0 or 1 when `value` is one of the hunt flag words.

    `True` is `true` and `FALSE` is `false`. A blank, `yes`, `trüe`, or any
    other present value is QueryError naming those four words.
    """
    folded = value.translate(_ASCII_FOLD) if isinstance(value, str) else None
    if folded not in _SYNTHETIC_FLAGS:
        raise QueryError("synthetic must be 0, 1, true or false")
    return _SYNTHETIC_FLAGS[folded]


def catalog_name(value, names):
    """The catalog spelling when `value` matches one name by ASCII case, else None.

    `Auth_Failure` is `auth_failure`. A non-ASCII lookalike is not a match.
    `names` is the catalog (the stored spellings).
    """
    if not isinstance(value, str):
        return None
    folded = value.translate(_ASCII_FOLD)
    for name in names:
        if name.translate(_ASCII_FOLD) == folded:
            return name
    return None


def catalog_pieces(value, names, message):
    """Comma-separated names folded onto catalog spellings.

    `Open` is `open` and `High` is `high`. Spaces around a piece are ignored.
    A blank piece or an unknown name is QueryError(message). The returned
    spellings are what a filter binds, so a stored lookalike is not a match.
    """
    pieces = []
    for part in value.split(","):
        name = catalog_name(part.strip(), names)
        if name is None:
            raise QueryError(message)
        pieces.append(name)
    return pieces


def canonical_ip(value, field):
    """The address form ingest stores (`str(ipaddress.ip_address)`).

    A complete address binds as that form, so `2001:DB8::1` matches a row stored as `2001:db8::1`.
    A prefix is not passed here. Anything else is 400.
    """
    if isinstance(value, str):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    raise QueryError(f"{field} must be a valid IP address")


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
        # One level or a comma list. Spaces around a name are ignored, as on alerts and incidents.
        # ASCII case folds onto the catalog spelling (`High` binds `high`). A blank piece is invalid,
        # same as an unknown name.
        levels = []
        for part in params["severity"].split(","):
            name = catalog_name(part.strip(), SEVERITIES)
            if name is None:
                raise QueryError(f"severity must be from {', '.join(SEVERITIES)}")
            levels.append(name)
        # severity_mode folds ASCII onto `min`. `Min` is `min`. `minimum` is not an alias.
        if catalog_name(params.get("severity_mode"), ("min",)) == "min" and len(levels) == 1:
            levels = SEVERITIES[SEVERITIES.index(levels[0]):]
        where.append(f"severity IN ({','.join('?' for _ in levels)})")
        args += levels
    if params.get("event_type"):
        # Same fold. The bound value is the catalog spelling, so a stored `Auth_Failure` stays out.
        name = catalog_name(params["event_type"], EVENT_TYPES)
        if name is None:
            raise QueryError(f"event_type must be one of {', '.join(sorted(EVENT_TYPES))}")
        where.append("event_type = ?")
        args.append(name)
    for field, column in (("source", "source"), ("host", "host"), ("user", "user"),
                          ("outcome", "outcome"), ("batch_id", "batch_id")):
        if params.get(field):
            if params[field].endswith("*"):
                where.append(f"{column} LIKE ? ESCAPE '\\'")
                args.append(_escape_like(params[field][:-1]) + "%")
            else:
                where.append(f"{column} = ? COLLATE NOCASE"
                             if field in ("user", "host", "source", "outcome", "batch_id")
                             else f"{column} = ?")
                args.append(params[field])
    if params.get("ip"):
        # Equality only. A trailing * is a hunt prefix, not an address, so it is 400 here.
        address = canonical_ip(params["ip"], "ip")
        where.append("(src_ip = ? OR dest_ip = ?)")
        args += [address, address]
    if params.get("q"):
        needle = params["q"]
        if not isinstance(needle, str) or len(needle) > MAX_SEARCH_Q:
            raise QueryError(f"q must be at most {MAX_SEARCH_Q} characters")
        where.append("message LIKE ? ESCAPE '\\'")
        args.append("%" + _escape_like(needle) + "%")
    # A present flag is the hunt set. `true` used to be ignored, so the list looked filtered.
    # An absent key stays unfiltered. The caller passes a blank `synthetic=` as "".
    if "synthetic" in params:
        where.append("synthetic = ?")
        args.append(synthetic_flag(params["synthetic"]))
    # since_id: only events stored after that id, newest stored first (the dashboard's polling fallback).
    since_id = _int(params.get("since_id"), "since_id", None, 0, 2**63 - 1)
    if since_id is not None:
        where.append("id > ?")
        args.append(since_id)
    return page_events(conn, where, args, params, newest_stored_first=since_id is not None)


def event_offset(params):
    """Page offset for event search and hunt. Above MAX_EVENT_OFFSET is a 400 naming that maximum."""
    return _int(params.get("offset"), "offset", 0, 0, MAX_EVENT_OFFSET)


def page_events(conn, where, args, params, newest_stored_first=False):
    """One page of events matching parameterized WHERE fragments (shared by event search and hunting)."""
    limit = _int(params.get("limit"), "limit", 100, 1, 1000)
    offset = event_offset(params)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM events{clause}", args).fetchone()[0]
    rows = conn.execute(
        f"SELECT {EVENT_FIELDS} FROM events{clause} ORDER BY "
        f"{'id DESC' if newest_stored_first else 'ts DESC, id DESC'} LIMIT ? OFFSET ?",
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
    # Newest by alert id, then id order in the response. A later created_at on a lower id is still the older row.
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id"
        " WHERE ae.event_id = ?",
        (event_id,)).fetchone()["n"]
    event["alerts"] = [dict(r) for r in conn.execute(
        "SELECT id, title, status FROM ("
        " SELECT a.id, a.title, a.status FROM alerts a"
        " JOIN alert_events ae ON ae.alert_id = a.id"
        " WHERE ae.event_id = ? ORDER BY a.id DESC LIMIT ?"
        ") ORDER BY id",
        (event_id, EVENT_ALERT_LIMIT))]
    event["alerts_omitted"] = total - len(event["alerts"])
    return event


def list_alerts(conn, params):
    """Matching alerts, and how many the limit left out.

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
            params["status"], ALERT_STATUSES,
            f"status must be from {', '.join(ALERT_STATUSES)}")
        where.append(f"status IN ({','.join('?' for _ in statuses)})")
        args += statuses
    if params.get("severity"):
        # One level or a comma list (critical,high). Same fold (`High` binds `high`).
        # A blank piece is invalid, same as an unknown name.
        levels = catalog_pieces(params["severity"], SEVERITIES, "invalid severity")
        where.append(f"severity IN ({','.join('?' for _ in levels)})")
        args += levels
    if params.get("rule_id"):
        # COLLATE NOCASE folds ASCII only. Brute_Force_Ip matches brute_force_ip.
        # Érin_rule stays apart from érin_rule. An unknown name matches nothing.
        where.append("rule_id = ? COLLATE NOCASE")
        args.append(params["rule_id"])
    limit = _int(params.get("limit"), "limit", 100, 1, 500)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM alerts{clause}", args).fetchone()[0]
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
             "WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC, id DESC")
    rows = conn.execute(f"SELECT * FROM alerts{clause} ORDER BY status = 'resolved', {order} LIMIT ?",
                        args + [limit])
    shown = [alert_row(r) for r in rows]
    return shown, total - len(shown)


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
        " JOIN alert_events ae ON ae.event_id = e.id WHERE ae.alert_id = ?"
        " ORDER BY e.ts, e.id LIMIT ?",
        (alert_id, EVIDENCE_LIMIT))]
    # Count the same join the page returns. A stored event_count, or a link whose event is gone, is not a row.
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM events e"
        " JOIN alert_events ae ON ae.event_id = e.id WHERE ae.alert_id = ?",
        (alert_id,)).fetchone()["n"]
    alert["evidence_omitted"] = total - len(alert["evidence"])
    # Newest by id, then id order in the response. A later created_at on a lower id is still the older row.
    alert["notes"], alert["notes_omitted"] = _newest_by_id(conn, "alert_notes", alert_id, NOTE_LIMIT)
    alert["activity"], alert["activity_omitted"] = _newest_by_id(
        conn, "alert_activity", alert_id, ACTIVITY_LIMIT)
    alert["timeline"] = related_timeline(conn, alert)
    return alert


def _newest_by_id(conn, table, alert_id, limit):
    """The newest `limit` rows for this alert (highest id), returned in id order.

    The second value is how many older rows were left out (0 when the table fits).
    `table` is a fixed name in this module, never a request value.
    """
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM {table} WHERE alert_id = ?", (alert_id,)).fetchone()["n"]
    rows = [dict(r) for r in conn.execute(
        f"SELECT * FROM (SELECT * FROM {table} WHERE alert_id = ? ORDER BY id DESC LIMIT ?)"
        " ORDER BY id",
        (alert_id, limit))]
    return rows, total - len(rows)


def related_timeline(conn, alert, pad_minutes=30):
    """Events touching the alert's IPs, users, or hosts, from pad_minutes before to pad_minutes after.

    Returns the earliest TIMELINE_LIMIT rows in ts, id order. Sets alert["timeline_omitted"]
    to how many matching events were past that cap (0 when the window has that many or fewer).
    An event outside the window is not a row and is not omitted.

    User names and hosts match with COLLATE NOCASE (ASCII only), the same way event search does.
    Source IPs stay an exact match. Shows context the rule did not use: e.g. what else happened
    on the host, or what the attacking IP did after a successful login.
    """
    ips = {e["src_ip"] for e in alert["evidence"] if e["src_ip"]}
    users = {e["user"] for e in alert["evidence"] if e["user"]}
    hosts = {e["host"] for e in alert["evidence"] if e.get("host")}
    if not ips and not users and not hosts:
        alert["timeline_omitted"] = 0
        return []
    start = iso(parse_iso(alert["first_seen"]) - timedelta(minutes=pad_minutes))
    end = iso(parse_iso(alert["last_seen"]) + timedelta(minutes=pad_minutes))
    clauses, args = [], []
    if ips:
        clauses.append(f"src_ip IN ({','.join('?' for _ in ips)})")
        args += sorted(ips)
    if users:
        clauses.append(f"user COLLATE NOCASE IN ({','.join('?' for _ in users)})")
        args += sorted(users)
    if hosts:
        clauses.append(f"host COLLATE NOCASE IN ({','.join('?' for _ in hosts)})")
        args += sorted(hosts)
    evidence_ids = {e["id"] for e in alert["evidence"]}
    where_sql = f"ts BETWEEN ? AND ? AND ({' OR '.join(clauses)})"
    bound = [start, end] + args
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM events WHERE {where_sql}", bound).fetchone()["n"]
    rows = conn.execute(
        f"SELECT id, ts, source, host, event_type, severity, user, src_ip, message FROM events"
        f" WHERE {where_sql} ORDER BY ts, id LIMIT {TIMELINE_LIMIT}",
        bound,
    )
    result = [{**dict(r), "is_evidence": r["id"] in evidence_ids} for r in rows]
    alert["timeline_omitted"] = total - len(result)
    return result


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
    if status == "resolved":
        # False_Positive stores false_positive. A blank, a missing value, and a
        # non-ASCII lookalike stay the same error. Status is not folded.
        folded = catalog_name(disposition, DISPOSITIONS)
        if folded is None:
            raise QueryError(f"resolving requires a disposition: {', '.join(DISPOSITIONS)}")
        disposition = folded
    elif disposition is not None:
        raise QueryError("disposition can only be set when resolving")
    with transaction(conn):
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if alert is None:
            raise QueryError("alert not found", 404)
        now = now_iso()
        # Acknowledged = the first time the alert leaves `open`. COALESCE keeps the first value through reopens,
        # and an alert that left `open` before the column existed (7.0) stays NULL instead of getting a guess.
        ack = now if alert["status"] == "open" and status != "open" else None
        if status == "resolved":
            conn.execute("UPDATE alerts SET status = ?, disposition = ?, resolved_at = ?, updated_at = ?,"
                         " acknowledged_at = COALESCE(acknowledged_at, ?) WHERE id = ?",
                         (status, disposition, now, now, ack, alert_id))
        else:
            # Reopening clears the previous verdict so feedback metrics stay accurate.
            conn.execute("UPDATE alerts SET status = ?, disposition = NULL, resolved_at = NULL,"
                         " assignee = CASE WHEN ? = 'investigating' THEN ? ELSE assignee END, updated_at = ?,"
                         " acknowledged_at = COALESCE(acknowledged_at, ?) WHERE id = ?",
                         (status, status, actor, now, ack, alert_id))
        detail = f"{alert['status']} -> {status}" + (f" ({disposition})" if disposition else "")
        conn.execute("INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                     (alert_id, actor, "status_changed", detail, now))
        audit(conn, actor, "alert_status_changed", str(alert_id),
              {"from": alert["status"], "to": status, "disposition": disposition})
    if note:
        add_note(conn, alert_id, actor, note)
    return dict(conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())


def assign(conn, alert_id, actor, assignee):
    """Hand an alert to an enabled analyst or admin account. Ownership only: the status does not change.

    The name matches ASCII case, and the alert stores that account's saved spelling.
    `Admin` is `admin` when that is the only match. Two enabled analyst or admin
    accounts that share the fold are 409 and the assignee stays as it was.
    `Érin` does not match `érin`. A disabled account and a viewer do not match.
    """
    if not isinstance(assignee, str) or not assignee.strip():
        raise QueryError("assignee must be a username")
    name = assignee.strip()
    with transaction(conn):
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if alert is None:
            raise QueryError("alert not found", 404)
        # COLLATE NOCASE folds ASCII only, the same letters entity keys use.
        users = conn.execute(
            "SELECT username FROM users WHERE username = ? COLLATE NOCASE AND disabled = 0"
            " AND role IN ('analyst', 'admin')", (name,)).fetchall()
        if len(users) > 1:
            raise QueryError("assignee matches more than one enabled analyst or admin", 409)
        if not users:
            raise QueryError("assignee must be an enabled analyst or admin account")
        user = users[0]
        now = now_iso()
        conn.execute("UPDATE alerts SET assignee = ?, updated_at = ? WHERE id = ?", (user["username"], now, alert_id))
        conn.execute("INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                     (alert_id, actor, "assigned", f"{alert['assignee'] or 'nobody'} -> {user['username']}", now))
        audit(conn, actor, "alert_assigned", str(alert_id), {"from": alert["assignee"], "to": user["username"]})
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
# `window_hours` is not the scope of the whole payload. Only events_ingested_window
# filters on it. The event breakdowns count every stored row, so a client cannot
# read a 24-hour window into top_failure_ips, top_failure_users, or events_by_type.
METRICS_HONORS_HOURS = ("events_ingested_window",)
METRICS_ALL_STORED_EVENTS = ("events_total", "synthetic_events", "top_failure_ips",
                             "top_failure_users", "events_by_type")
METRICS_NEWEST_24H = ("activity_last_24h_of_data",)
METRICS_WINDOW_NOTE = (
    "hours filters events_ingested_window by ingested_at. "
    "top_failure_ips, top_failure_users, and events_by_type count every stored event. "
    "activity_last_24h_of_data is the 24 hours ending at the newest event, not this window. "
    "Alert counts are the current alerts table."
)


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
    # Rate descending, then rule_id. A rule with no disposition is not a row.
    fp_rows = conn.execute(
        "SELECT rule_id, COUNT(*) AS reviewed, SUM(disposition = 'false_positive') AS false_positive,"
        " SUM(disposition = 'benign') AS benign FROM alerts WHERE disposition IS NOT NULL GROUP BY rule_id"
        " ORDER BY SUM(disposition = 'false_positive') * 1.0 / COUNT(*) DESC, rule_id"
        f" LIMIT {FP_RATE_BY_RULE_LIMIT}").fetchall()
    fp_by_rule = [
        {**dict(r), "false_positive_rate": round(r["false_positive"] / r["reviewed"], 3)} for r in fp_rows]
    fp_by_rule_omitted = one(
        "SELECT COUNT(DISTINCT rule_id) FROM alerts WHERE disposition IS NOT NULL") - len(fp_by_rule)
    now = utcnow()
    ages = [(now - parse_iso(r["created_at"])).total_seconds() / 60 for r in conn.execute(
        "SELECT created_at FROM alerts WHERE status != 'resolved'")]
    aging = {"buckets": [{"label": label, "count": sum(low <= a < high for a in ages)}
                         for label, low, high in AGING_BUCKETS],
             "oldest_minutes": round(max(ages), 1) if ages else None}
    # Addresses stay the stored spelling. Equal counts keep the earlier src_ip.
    # Accounts fold ASCII case with SQLite lower(),
    # the same fold hunt user groups use. Alice and alice are one row named alice.
    # Érin and érin stay two rows. Equal counts keep the earlier folded name.
    # Each list is the busiest TOP_FAILURE_LIMIT groups.
    top_ips = by("SELECT src_ip, COUNT(*) AS count FROM events WHERE event_type = 'auth_failure'"
                 " AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC, src_ip"
                 f" LIMIT {TOP_FAILURE_LIMIT}")
    top_users = by("SELECT lower(user) AS user, COUNT(*) AS count FROM events WHERE event_type = 'auth_failure'"
                   " AND user IS NOT NULL GROUP BY lower(user) ORDER BY count DESC, lower(user)"
                   f" LIMIT {TOP_FAILURE_LIMIT}")
    ips_omitted = one("SELECT COUNT(DISTINCT src_ip) FROM events WHERE event_type = 'auth_failure'"
                      " AND src_ip IS NOT NULL") - len(top_ips)
    users_omitted = one("SELECT COUNT(DISTINCT lower(user)) FROM events WHERE event_type = 'auth_failure'"
                        " AND user IS NOT NULL") - len(top_users)
    # Equal counts keep the lower rule_id. A rule with no alerts is not a row.
    alerts_by_rule = by(
        "SELECT rule_id, COUNT(*) AS count FROM alerts GROUP BY rule_id"
        f" ORDER BY count DESC, rule_id LIMIT {ALERTS_BY_RULE_LIMIT}")
    alerts_by_rule_omitted = one("SELECT COUNT(DISTINCT rule_id) FROM alerts") - len(alerts_by_rule)
    # Equal counts keep the earlier event_type. A type with no events is not a row.
    # hours does not filter this list; it still counts every stored event.
    events_by_type = by(
        "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
        f" ORDER BY count DESC, event_type LIMIT {EVENTS_BY_TYPE_LIMIT}")
    events_by_type_omitted = one("SELECT COUNT(DISTINCT event_type) FROM events") - len(events_by_type)
    return {
        "window_hours": hours,
        "window_scope": {
            "honors_hours": list(METRICS_HONORS_HOURS),
            "all_stored_events": list(METRICS_ALL_STORED_EVENTS),
            "newest_event_24h": list(METRICS_NEWEST_24H),
            "note": METRICS_WINDOW_NOTE,
        },
        "events_total": one("SELECT COUNT(*) FROM events"),
        "events_ingested_window": one("SELECT COUNT(*) FROM events WHERE ingested_at >= ?", since),
        "synthetic_events": one("SELECT COUNT(*) FROM events WHERE synthetic = 1"),
        "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE status = 'open'"),
        "alerts_investigating": one("SELECT COUNT(*) FROM alerts WHERE status = 'investigating'"),
        "alerts_resolved": one("SELECT COUNT(*) FROM alerts WHERE status = 'resolved'"),
        "alerts_by_severity": by("SELECT severity, COUNT(*) AS count FROM alerts WHERE status != 'resolved'"
                                 " GROUP BY severity"),
        "alerts_by_rule": alerts_by_rule,
        "alerts_by_rule_omitted": alerts_by_rule_omitted,
        "dispositions": by("SELECT disposition, COUNT(*) AS count FROM alerts WHERE disposition IS NOT NULL"
                           " GROUP BY disposition"),
        "mean_time_to_resolve_minutes": round(mttr, 1) if mttr is not None else None,
        "top_failure_ips": top_ips,
        "top_failure_ips_omitted": ips_omitted,
        "top_failure_users": top_users,
        "top_failure_users_omitted": users_omitted,
        "events_by_type": events_by_type,
        "events_by_type_omitted": events_by_type_omitted,
        "activity_last_24h_of_data": histogram,
        "time_to_resolve_by_severity": resolve_by_severity,
        "false_positive_rate_by_rule": fp_by_rule,
        "false_positive_rate_by_rule_omitted": fp_by_rule_omitted,
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
        f"{_ATTACKER_FROM} GROUP BY e.src_ip"
        f" ORDER BY alerts DESC, events DESC, e.src_ip LIMIT {ATTACKER_LIMIT}")]
    for a in attackers:
        del a["sev_rank"]
    attackers_omitted = one(f"SELECT COUNT(DISTINCT e.src_ip){_ATTACKER_FROM}") - len(attackers)

    # Equal counts keep the lower rule_id. A rule with no alerts is not a row.
    top_rules = [dict(r) for r in conn.execute(
        "SELECT a.rule_id, r.name, r.severity, COUNT(*) AS alerts, SUM(a.status != 'resolved') AS open"
        " FROM alerts a LEFT JOIN rules r ON r.id = a.rule_id GROUP BY a.rule_id"
        f" ORDER BY alerts DESC, a.rule_id LIMIT {TOP_RULE_LIMIT}")]
    rules_omitted = one("SELECT COUNT(DISTINCT rule_id) FROM alerts") - len(top_rules)
    board = [dict(r) for r in conn.execute(
        "SELECT id, rule_id, severity, title, status, group_key, first_seen, last_seen, event_count, synthetic,"
        " assignee FROM alerts ORDER BY status = 'resolved', "
        + SEVERITY_RANK_SQL.format(col="severity")
        + f" DESC, last_seen DESC, id DESC LIMIT {BOARD_LIMIT}")]
    board_omitted = one("SELECT COUNT(*) FROM alerts") - len(board)
    recent = [dict(r) for r in conn.execute(
        f"SELECT {EVENT_FIELDS} FROM events ORDER BY ts DESC, id DESC LIMIT {RECENT_LIMIT}")]
    events_total = one("SELECT COUNT(*) FROM events")
    return {
        "generated_at": now_iso(),
        "events_total": events_total,
        "synthetic_events": one("SELECT COUNT(*) FROM events WHERE synthetic = 1"),
        "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE status = 'open'"),
        "alerts_investigating": one("SELECT COUNT(*) FROM alerts WHERE status = 'investigating'"),
        "alerts_critical_open": one("SELECT COUNT(*) FROM alerts WHERE status != 'resolved'"
                                    " AND severity = 'critical'"),
        "alerts_total": one("SELECT COUNT(*) FROM alerts"),
        "events_per_minute": epm,
        "alert_timeline": _alert_timeline(conn),
        "attackers": attackers,
        "attackers_omitted": attackers_omitted,
        "top_rules": top_rules,
        "rules_omitted": rules_omitted,
        "alerts": board,
        "board_omitted": board_omitted,
        "recent_events": recent,
        "recent_events_omitted": events_total - len(recent),
    }
