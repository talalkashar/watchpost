"""Ingestion and detection orchestration against the database."""

import json
import threading
import uuid
from datetime import timedelta

from . import assets as assets_mod
from . import correlate as correlate_mod
from . import rules as rules_mod
from . import stream
from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction
from .diagnostics import describe_exception, record_error

EVENT_COLUMNS = ["ts", "source", "host", "event_type", "outcome", "severity",
                 "user", "src_ip", "dest_ip", "dest_port", "bytes", "message", "raw"]
# Fields detection rules can read.
RULE_EVENT_FIELDS = "id, ts, event_type, user, src_ip, host, dest_ip, dest_port, bytes, message, synthetic"

# Detection runs are serialized so concurrent ingests cannot create duplicate alerts.
_detection_lock = threading.Lock()


def seed_rules(conn, actor="system"):
    now = now_iso()
    for rule in rules_mod.DEFAULT_RULES:
        techniques = json.dumps(rule["techniques"])
        exists = conn.execute("SELECT 1 FROM rules WHERE id = ?", (rule["id"],)).fetchone()
        if exists:
            # ATT&CK mappings are static metadata, not tunable: keep stored rules in step with the code.
            conn.execute("UPDATE rules SET techniques = ? WHERE id = ? AND techniques IS NOT ?",
                         (techniques, rule["id"], techniques))
            continue
        params = json.dumps(rule["params"])
        conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by,"
            " techniques) VALUES (?,?,?,?,1,?,1,?,?,?)",
            (rule["id"], rule["name"], rule["description"], rule["severity"], params, now, actor, techniques),
        )
        conn.execute(
            "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, note)"
            " VALUES (?,?,?,?,?,?,?)",
            (rule["id"], 1, 1, params, now, actor, "initial rule definition"),
        )


def load_rules(conn, enabled_only=True):
    sql = "SELECT * FROM rules" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id"
    rules = [row_to_dict(r, ["params", "techniques"]) for r in conn.execute(sql)]
    for rule in rules:
        rule["techniques"] = rule.get("techniques") or []
    return rules


# --- Ingestion ------------------------------------------------------------------

def store_batch(conn, events, rejections, source, fmt, submitted_by, synthetic=False):
    """Persist a batch atomically and return its id. Detection is run separately."""
    batch_id = uuid.uuid4().hex
    now = now_iso()
    with transaction(conn):
        conn.executemany(
            f"INSERT INTO events(ingested_at, synthetic, batch_id, {', '.join(EVENT_COLUMNS)})"
            f" VALUES (?, ?, ?, {', '.join('?' for _ in EVENT_COLUMNS)})",
            [(now, int(synthetic), batch_id, *[e.get(c) for c in EVENT_COLUMNS]) for e in events],
        )
        conn.execute(
            "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted, rejected,"
            " errors, synthetic, submitted_by, detection_status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (batch_id, now, source, fmt, len(events) + len(rejections), len(events), len(rejections),
             json.dumps(rejections[:100]), int(synthetic), submitted_by, "pending"),
        )
    return batch_id


def ingest(conn, events, rejections, source, fmt, submitted_by, synthetic=False):
    batch_id = store_batch(conn, events, rejections, source, fmt, submitted_by, synthetic)
    result = {
        "batch_id": batch_id,
        "received": len(events) + len(rejections),
        "accepted": len(events),
        "rejected": len(rejections),
        "rejections": rejections[:100],
    }
    _publish_events(conn, batch_id, len(events), synthetic)
    if not events:
        conn.execute("UPDATE ingest_batches SET detection_status = 'skipped' WHERE id = ?", (batch_id,))
        result["detection"] = {"status": "skipped", "reason": "no accepted events"}
        return result
    # Scan the time range touched by this batch, widened by the longest rule window.
    start = min(e["ts"] for e in events)
    end = max(e["ts"] for e in events)
    run = run_detection(conn, trigger=f"ingest:{batch_id[:8]}", start=start, end=end)
    conn.execute("UPDATE ingest_batches SET detection_status = ? WHERE id = ?", (run["status"], batch_id))
    result["detection"] = run
    return result


# --- Detection --------------------------------------------------------------------

def _existing_alert(conn, rule_id, group_key, first_seen, window):
    cutoff = iso(parse_iso(first_seen) - timedelta(seconds=window))
    return conn.execute(
        "SELECT * FROM alerts WHERE rule_id = ? AND group_key = ? AND status != 'resolved'"
        " AND last_seen >= ? ORDER BY id DESC LIMIT 1",
        (rule_id, group_key, cutoff),
    ).fetchone()


def _weigh(conn, rule, alert_id, assets_idx):
    """Severity after asset weighting, from every evidence event now on the alert."""
    events = [dict(r) for r in conn.execute(
        "SELECT e.host, e.src_ip, e.dest_ip FROM events e JOIN alert_events ae ON ae.event_id = e.id"
        " WHERE ae.alert_id = ?", (alert_id,))]
    weighed = assets_mod.weigh(rule["severity"], assets_mod.match(assets_idx, events))
    weighed["assets"] = json.dumps(weighed["assets"])
    return weighed


def _apply_finding(conn, rule, finding, synthetic, assets_idx):
    """Create or extend an alert. Returns 'created', 'updated', or 'unchanged'."""
    ids = finding["event_ids"]
    placeholders = ",".join("?" for _ in ids)
    already = conn.execute(
        f"SELECT COUNT(DISTINCT ae.event_id) FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id"
        f" WHERE a.rule_id = ? AND a.group_key = ? AND ae.event_id IN ({placeholders})",
        (rule["id"], finding["group_key"], *ids),
    ).fetchone()[0]
    if already == len(ids):
        return "unchanged"  # e.g. a rescan, or evidence already on a resolved alert

    now = now_iso()
    window = rule["params"].get("window_seconds", 3600)
    existing = _existing_alert(conn, rule["id"], finding["group_key"], finding["first_seen"], window)
    if existing:
        conn.executemany("INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES (?,?)",
                         [(existing["id"], i) for i in ids])
        count = conn.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?",
                             (existing["id"],)).fetchone()[0]
        weighed = _weigh(conn, rule, existing["id"], assets_idx)
        conn.execute(
            "UPDATE alerts SET last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?),"
            " event_count = ?, explanation = ?, title = ?, updated_at = ?, severity = ?, base_severity = ?,"
            " assets = ?, severity_note = ? WHERE id = ?",
            (finding["last_seen"], finding["first_seen"], count, finding["explanation"],
             finding["title"], now, weighed["severity"], weighed["base_severity"], weighed["assets"],
             weighed["severity_note"], existing["id"]),
        )
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (existing["id"], "detection", "evidence_added", f"now {count} related events", now),
        )
        if weighed["severity"] != existing["severity"]:
            conn.execute(
                "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                (existing["id"], "assets", "severity_changed",
                 f"{existing['severity']} -> {weighed['severity']} ({weighed['severity_note']})", now),
            )
        return "updated"

    cur = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,'open',?,?,?,?,?,?)",
        (rule["id"], rule["version"], finding["group_key"], rule["severity"], finding["title"],
         finding["explanation"], finding["first_seen"], finding["last_seen"], len(ids),
         int(synthetic), now, now),
    )
    alert_id = cur.lastrowid
    conn.executemany("INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES (?,?)",
                     [(alert_id, i) for i in ids])
    conn.execute(
        "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
        (alert_id, "detection", "created", f"rule {rule['id']} v{rule['version']}", now),
    )
    weighed = _weigh(conn, rule, alert_id, assets_idx)
    conn.execute("UPDATE alerts SET severity = ?, base_severity = ?, assets = ?, severity_note = ? WHERE id = ?",
                 (weighed["severity"], weighed["base_severity"], weighed["assets"], weighed["severity_note"],
                  alert_id))
    if weighed["severity"] != rule["severity"]:
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "assets", "severity_changed",
             f"{rule['severity']} -> {weighed['severity']} ({weighed['severity_note']})", now),
        )
    return "created"


def active_suppressions(conn):
    """Approved, unexpired tuning exceptions as a set of (rule_id, group_key)."""
    return {(r["rule_id"], r["group_key"]) for r in conn.execute(
        "SELECT rule_id, group_key FROM suppressions WHERE expires_at > ?", (now_iso(),))}


def run_detection(conn, trigger="manual", start=None, end=None):
    """Run all enabled rules over a time range (default: all events).

    Failures are recorded in detection_runs and error_log and returned honestly;
    the ingested events stay stored so the run can be retried.
    """
    with _detection_lock:
        started = now_iso()
        run_id = conn.execute(
            "INSERT INTO detection_runs(started_at, trigger, status) VALUES (?,?,'running')",
            (started, trigger),
        ).lastrowid
        summary = {"run_id": run_id, "status": "running", "events_scanned": 0,
                   "alerts_created": 0, "alerts_updated": 0, "alerts_suppressed": 0}
        try:
            active = load_rules(conn)
            for rule in active:
                if rule["id"] not in rules_mod.RULE_FUNCTIONS:
                    raise rules_mod.RuleConfigError(f"no implementation for rule {rule['id']}")
                rule["params"] = rules_mod.validate_params(rule["id"], rule["params"])

            max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            sql, args = f"SELECT {RULE_EVENT_FIELDS} FROM events WHERE id <= ?", [max_id]
            scan_start = None
            if start and end:
                pad = timedelta(seconds=rules_mod.lookback_seconds(active))
                history = timedelta(seconds=rules_mod.history_seconds(active))
                scan_start = iso(parse_iso(start) - pad)
                sql += " AND ts >= ? AND ts <= ?"
                args += [iso(parse_iso(start) - pad - history), iso(parse_iso(end) + pad)]
            events = [dict(r) for r in conn.execute(sql, args)]
            synthetic_ids = {e["id"] for e in events if e["synthetic"]}
            summary["events_scanned"] = len(events)
            assets_idx = assets_mod.load_index(conn)
            suppressed = active_suppressions(conn)
            # Exfil history that was already flagged and not cleared by an analyst is no baseline.
            flagged = {r[0] for r in conn.execute(
                "SELECT ae.event_id FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id"
                " WHERE a.rule_id = 'data_exfil_volume'"
                " AND (a.disposition IS NULL OR a.disposition = 'true_positive')")}
            for event in events:
                if event["id"] in flagged:
                    event["alerted"] = True

            with transaction(conn):
                for rule in active:
                    for finding in rules_mod.RULE_FUNCTIONS[rule["id"]](events, rule["params"]):
                        if scan_start and finding["last_seen"] < scan_start:
                            continue  # built only from history context; outside this scan
                        if (rule["id"], finding["group_key"]) in suppressed:
                            summary["alerts_suppressed"] += 1  # a reviewed tuning exception covers it
                            continue
                        synthetic = all(i in synthetic_ids for i in finding["event_ids"])
                        outcome = _apply_finding(conn, rule, finding, synthetic, assets_idx)
                        if outcome == "created":
                            summary["alerts_created"] += 1
                        elif outcome == "updated":
                            summary["alerts_updated"] += 1
            summary["status"] = "ok"
            conn.execute(
                "UPDATE detection_runs SET status='ok', finished_at=?, events_scanned=?, alerts_created=?,"
                " alerts_updated=?, alerts_suppressed=?, max_event_id=? WHERE id=?",
                (now_iso(), summary["events_scanned"], summary["alerts_created"],
                 summary["alerts_updated"], summary["alerts_suppressed"], max_id, run_id),
            )
            if not (start and end):
                # A full scan covers every stored event, including batches whose detection failed.
                conn.execute(
                    "UPDATE ingest_batches SET detection_status = 'recovered'"
                    " WHERE detection_status = 'failed' AND created_at <= ?", (started,))
            # Correlation runs after the alerts are safely stored; if it fails, alerts stay as they are.
            try:
                summary["correlation"] = {"status": "ok", **correlate_alerts(conn)}
            except Exception as exc:
                summary["correlation"] = {"status": "failed", "error": describe_exception(exc)}
                record_error(conn, "correlation", exc,
                             guidance="Alerts are unaffected. Fix the cause, then use 'Run detection' to "
                                      "correlate again.")
            conn.execute("UPDATE detection_runs SET correlation = ? WHERE id = ?",
                         (summary["correlation"]["status"], run_id))
        except Exception as exc:
            message = describe_exception(exc)
            summary.update(status="failed", error=message)
            record_error(conn, "detection", exc,
                         guidance="Check the rule configuration on the Rules page, fix it through a "
                                  "reviewed change request, then use 'Run detection' to process the backlog.")
            conn.execute("UPDATE detection_runs SET status='failed', finished_at=?, error=? WHERE id=?",
                         (now_iso(), message, run_id))
        _publish_detection(conn, started, summary)
        return summary


# --- Correlation into incidents -----------------------------------------------------

_CANDIDATE_FILTER = (
    " LEFT JOIN incident_alerts ia ON ia.alert_id = a.id LEFT JOIN incidents i ON i.id = ia.incident_id"
    " WHERE (ia.incident_id IS NULL AND a.status != 'resolved') OR (ia.incident_id IS NOT NULL AND i.status != 'resolved')"
)


def _candidate_alerts(conn):
    """Unassigned alerts that are not resolved, plus every alert of an incident that is not resolved."""
    alerts = {r["id"]: {**dict(r), "entities": {k: set() for k in correlate_mod.ENTITY_TYPES}, "sightings": set()}
              for r in conn.execute("SELECT a.*, ia.incident_id FROM alerts a" + _CANDIDATE_FILTER)}
    rows = conn.execute("SELECT a.id AS alert_id, e.ts, e.src_ip, e.user, e.host FROM alerts a"
                        " JOIN alert_events ae ON ae.alert_id = a.id JOIN events e ON e.id = ae.event_id"
                        + _CANDIDATE_FILTER)
    for row in rows:
        alert = alerts[row["alert_id"]]
        for kind in correlate_mod.ENTITY_TYPES:
            if row[kind]:
                value = row[kind].lower() if kind == "user" else row[kind]
                alert["entities"][kind].add(value)
                alert["sightings"].add((kind, value, row["ts"]))
    tactics = {r["id"]: [t["tactic"] for t in r["techniques"]] for r in load_rules(conn, enabled_only=False)}
    for alert in alerts.values():
        alert["entities"] = {k: sorted(v) for k, v in alert["entities"].items()}
        alert["sightings"] = sorted(alert["sightings"])
        alert["tactics"] = tactics.get(alert["rule_id"], [])
    return alerts


def _incident_values(summary):
    return (summary["title"], summary["severity"], summary["first_seen"], summary["last_seen"],
            json.dumps(summary["entities"], sort_keys=True), json.dumps(summary["stages"]),
            summary["alert_count"], summary["synthetic"])


def correlate_alerts(conn, window_seconds=correlate_mod.DEFAULT_WINDOW_SECONDS):
    """Group related alerts into incidents and persist them. Safe to rerun: nothing changes twice."""
    result = {"incidents_created": 0, "incidents_updated": 0}
    with transaction(conn):
        alerts = _candidate_alerts(conn)
        now = now_iso()
        for group in correlate_mod.correlate(list(alerts.values()), window_seconds):
            members = [alerts[i] for i in group["alert_ids"]]
            incident_id = group["incident_id"]
            if incident_id is None and not correlate_mod.should_open(members):
                continue
            values = _incident_values(correlate_mod.summarize(members))
            if incident_id is None:
                incident_id = conn.execute(
                    "INSERT INTO incidents(title, severity, first_seen, last_seen, entities, stages, alert_count,"
                    " synthetic, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,'open',?,?)",
                    (*values, now, now)).lastrowid
                result["incidents_created"] += 1
            else:
                current = conn.execute(
                    "SELECT title, severity, first_seen, last_seen, entities, stages, alert_count, synthetic"
                    " FROM incidents WHERE id = ?", (incident_id,)).fetchone()
                if tuple(current) != values:
                    conn.execute(
                        "UPDATE incidents SET title = ?, severity = ?, first_seen = ?, last_seen = ?, entities = ?,"
                        " stages = ?, alert_count = ?, synthetic = ?, updated_at = ? WHERE id = ?",
                        (*values, now, incident_id))
                    result["incidents_updated"] += 1
            new = group["alert_ids"] if group["incident_id"] is None else group["new_alert_ids"]
            conn.executemany("INSERT OR IGNORE INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
                             [(i, incident_id, now) for i in new])
    return result


# --- Live stream (SSE) ------------------------------------------------------------

STREAM_EVENT_LIMIT = 50
STREAM_EVENT_FIELDS = ("id, ts, source, host, event_type, outcome, severity, user, src_ip, dest_ip, message,"
                       " synthetic")
STREAM_ALERT_FIELDS = ("id, rule_id, severity, title, status, group_key, first_seen, last_seen, event_count,"
                       " synthetic, created_at, updated_at")


def _publish_events(conn, batch_id, count, synthetic):
    """Tell dashboards about a stored batch (newest events only). Never fails the ingest."""
    if not count or not stream.BROKER.active():
        return
    try:
        rows = conn.execute(f"SELECT {STREAM_EVENT_FIELDS} FROM events WHERE batch_id = ?"
                            " ORDER BY ts DESC, id DESC LIMIT ?", (batch_id, STREAM_EVENT_LIMIT))
        stream.BROKER.publish("event", {"batch_id": batch_id, "count": count, "synthetic": bool(synthetic),
                                        "events": [dict(r) for r in rows]})
    except Exception as exc:  # the stream is best-effort; storage already succeeded
        record_error(conn, "stream", exc, guidance="Live dashboard updates may lag; reload the dashboard.")


def _publish_detection(conn, started, summary):
    """Publish alerts (and incidents, once that table exists) touched by this run, plus detection health."""
    if not stream.BROKER.active():
        return
    try:
        failed = summary["status"] != "ok"
        stream.BROKER.publish("health", {"partial": True, "checks": {"detection": "failing" if failed else "ok"},
                                         "error": summary.get("error")})
        if failed:
            return
        for row in conn.execute(f"SELECT {STREAM_ALERT_FIELDS} FROM alerts WHERE updated_at >= ? ORDER BY id",
                                (started,)):
            alert = dict(row)
            alert["change"] = "created" if alert["created_at"] >= started else "updated"
            stream.BROKER.publish("alert", alert)
        has_incidents = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'incidents'").fetchone()
        if has_incidents:
            for row in conn.execute("SELECT * FROM incidents WHERE updated_at >= ? ORDER BY id", (started,)):
                stream.BROKER.publish("incident", dict(row))
    except Exception as exc:
        record_error(conn, "stream", exc, guidance="Live dashboard updates may lag; reload the dashboard.")


# --- Rule changes (applied only through approved change requests) ------------------

def apply_rule_change(conn, rule_id, payload, changed_by, approved_by, change_request_id, note):
    rule = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if rule is None:
        raise rules_mod.RuleConfigError(f"unknown rule {rule_id!r}")
    params = json.loads(rule["params"])
    if "params" in payload:
        params = rules_mod.validate_params(rule_id, {**params, **payload["params"]})
    enabled = int(payload.get("enabled", rule["enabled"]))
    version = rule["version"] + 1
    now = now_iso()
    conn.execute(
        "UPDATE rules SET params = ?, enabled = ?, version = ?, updated_at = ?, updated_by = ? WHERE id = ?",
        (json.dumps(params), enabled, version, now, approved_by, rule_id),
    )
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, version, enabled, json.dumps(params), now, changed_by, approved_by, change_request_id, note),
    )
    audit(conn, approved_by, "rule_changed", rule_id, {"version": version, "change_request": change_request_id})
    return version
