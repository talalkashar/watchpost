"""Ingestion and detection orchestration against the database."""

import json
import threading
import uuid
from datetime import timedelta

from . import rules as rules_mod
from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction
from .diagnostics import describe_exception, record_error

EVENT_COLUMNS = ["ts", "source", "host", "event_type", "outcome", "severity",
                 "user", "src_ip", "dest_ip", "message", "raw"]

# Detection runs are serialized so concurrent ingests cannot create duplicate alerts.
_detection_lock = threading.Lock()


def seed_rules(conn, actor="system"):
    now = now_iso()
    for rule in rules_mod.DEFAULT_RULES:
        exists = conn.execute("SELECT 1 FROM rules WHERE id = ?", (rule["id"],)).fetchone()
        if exists:
            continue
        params = json.dumps(rule["params"])
        conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by)"
            " VALUES (?,?,?,?,1,?,1,?,?)",
            (rule["id"], rule["name"], rule["description"], rule["severity"], params, now, actor),
        )
        conn.execute(
            "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, note)"
            " VALUES (?,?,?,?,?,?,?)",
            (rule["id"], 1, 1, params, now, actor, "initial rule definition"),
        )


def load_rules(conn, enabled_only=True):
    sql = "SELECT * FROM rules" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id"
    return [row_to_dict(r, ["params"]) for r in conn.execute(sql)]


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


def _apply_finding(conn, rule, finding, synthetic):
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
        conn.execute(
            "UPDATE alerts SET last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?),"
            " event_count = ?, explanation = ?, title = ?, updated_at = ? WHERE id = ?",
            (finding["last_seen"], finding["first_seen"], count, finding["explanation"],
             finding["title"], now, existing["id"]),
        )
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (existing["id"], "detection", "evidence_added", f"now {count} related events", now),
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
    return "created"


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
                   "alerts_created": 0, "alerts_updated": 0}
        try:
            active = load_rules(conn)
            for rule in active:
                if rule["id"] not in rules_mod.RULE_FUNCTIONS:
                    raise rules_mod.RuleConfigError(f"no implementation for rule {rule['id']}")
                rule["params"] = rules_mod.validate_params(rule["id"], rule["params"])

            max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            sql, args = "SELECT id, ts, event_type, user, src_ip, synthetic FROM events WHERE id <= ?", [max_id]
            if start and end:
                pad = timedelta(seconds=rules_mod.lookback_seconds(active))
                sql += " AND ts >= ? AND ts <= ?"
                args += [iso(parse_iso(start) - pad), iso(parse_iso(end) + pad)]
            events = [dict(r) for r in conn.execute(sql, args)]
            synthetic_ids = {e["id"] for e in events if e["synthetic"]}
            summary["events_scanned"] = len(events)

            with transaction(conn):
                for rule in active:
                    for finding in rules_mod.RULE_FUNCTIONS[rule["id"]](events, rule["params"]):
                        synthetic = all(i in synthetic_ids for i in finding["event_ids"])
                        outcome = _apply_finding(conn, rule, finding, synthetic)
                        if outcome == "created":
                            summary["alerts_created"] += 1
                        elif outcome == "updated":
                            summary["alerts_updated"] += 1
            summary["status"] = "ok"
            conn.execute(
                "UPDATE detection_runs SET status='ok', finished_at=?, events_scanned=?, alerts_created=?,"
                " alerts_updated=?, max_event_id=? WHERE id=?",
                (now_iso(), summary["events_scanned"], summary["alerts_created"],
                 summary["alerts_updated"], max_id, run_id),
            )
            if not (start and end):
                # A full scan covers every stored event, including batches whose detection failed.
                conn.execute(
                    "UPDATE ingest_batches SET detection_status = 'recovered'"
                    " WHERE detection_status = 'failed' AND created_at <= ?", (started,))
        except Exception as exc:
            message = describe_exception(exc)
            summary.update(status="failed", error=message)
            record_error(conn, "detection", exc,
                         guidance="Check the rule configuration on the Rules page, fix it through a "
                                  "reviewed change request, then use 'Run detection' to process the backlog.")
            conn.execute("UPDATE detection_runs SET status='failed', finished_at=?, error=? WHERE id=?",
                         (now_iso(), message, run_id))
        return summary


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
