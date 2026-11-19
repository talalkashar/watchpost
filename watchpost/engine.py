"""Ingestion and detection orchestration against the database."""

import json
import threading
import uuid
from datetime import timedelta

from . import assets as assets_mod
from . import correlate as correlate_mod
from . import grouping
from . import rules as rules_mod
from . import sources as sources_mod
from . import stream
from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction
from .diagnostics import describe_exception, record_error

EVENT_COLUMNS = ["ts", "source", "host", "event_type", "outcome", "severity",
                 "user", "src_ip", "dest_ip", "dest_port", "bytes", "message", "raw"]
# Fields detection rules can read. source and ingested_at let a backtest replay log_source_silent's gaps.
RULE_EVENT_FIELDS = ("id, ts, event_type, user, src_ip, host, dest_ip, dest_port, bytes, message, synthetic,"
                     " source, ingested_at")

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
    rules = [row_to_dict(r, ["params", "techniques", "grouping"]) for r in conn.execute(sql)]
    for rule in rules:
        rule["techniques"] = rule.get("techniques") or []
    return rules


# --- Ingestion ------------------------------------------------------------------

# The response and the stored batch errors slice keep this many rejection reasons.
REJECTION_LIMIT = 100


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
             json.dumps(rejections[:REJECTION_LIMIT]), int(synthetic), submitted_by, "pending"),
        )
    return batch_id


def ingest(conn, events, rejections, source, fmt, submitted_by, synthetic=False):
    batch_id = store_batch(conn, events, rejections, source, fmt, submitted_by, synthetic)
    shown = rejections[:REJECTION_LIMIT]
    result = {
        "batch_id": batch_id,
        "received": len(events) + len(rejections),
        "accepted": len(events),
        "rejected": len(rejections),
        "rejections": shown,
        "rejections_omitted": len(rejections) - len(shown),
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

def _group_match(alert_id, stored_key, finding_key, identity):
    """Whether this alert is the finding's group.

    `identity` is None when the rule has no saved grouping, so the native key matches exactly.
    A resolved alert matches the entity evidence produced, even when its stored text still differs.
    An unresolved alert string-matches only when that stored key is not part of a collision.
    """
    if identity is None:
        return stored_key == finding_key
    resolved, blocked = identity
    if alert_id not in resolved:
        return stored_key == finding_key
    target = resolved[alert_id]
    if target is None:
        return stored_key == finding_key and stored_key not in blocked
    return target == finding_key


def _existing_alert(conn, rule_id, group_key, first_seen, last_seen, window, identity=None):
    """Open alert for this group whose span is within `window` seconds of the finding.

    A gap of exactly `window` still matches. Rules split a cluster only when the gap is greater.
    When more than one open alert is that close, the newest one wins.
    """
    earliest = iso(parse_iso(first_seen) - timedelta(seconds=window))
    latest = iso(parse_iso(last_seen) + timedelta(seconds=window))
    if identity is None:
        return conn.execute(
            "SELECT * FROM alerts WHERE rule_id = ? AND group_key = ? AND status != 'resolved'"
            " AND last_seen >= ? AND first_seen <= ? ORDER BY id DESC LIMIT 1",
            (rule_id, group_key, earliest, latest),
        ).fetchone()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE rule_id = ? AND status != 'resolved'"
        " AND last_seen >= ? AND first_seen <= ? ORDER BY id DESC",
        (rule_id, earliest, latest),
    )
    for row in rows:
        if _group_match(row["id"], row["group_key"], group_key, identity):
            return row
    return None


def _weigh(conn, rule, alert_id, assets_idx):
    """Severity after asset weighting, from every evidence event now on the alert."""
    events = [dict(r) for r in conn.execute(
        "SELECT e.host, e.src_ip, e.dest_ip FROM events e JOIN alert_events ae ON ae.event_id = e.id"
        " WHERE ae.alert_id = ?", (alert_id,))]
    weighed = assets_mod.weigh(rule["severity"], assets_mod.match(assets_idx, events))
    weighed["assets"] = json.dumps(weighed["assets"])
    return weighed


def _apply_finding(conn, rule, finding, synthetic, assets_idx, identity=None):
    """Create or extend an alert. Returns 'created', 'updated', or 'unchanged'."""
    ids = finding["event_ids"]
    placeholders = ",".join("?" for _ in ids)
    if identity is None:
        already = conn.execute(
            f"SELECT COUNT(DISTINCT ae.event_id) FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id"
            f" WHERE a.rule_id = ? AND a.group_key = ? AND ae.event_id IN ({placeholders})",
            (rule["id"], finding["group_key"], *ids),
        ).fetchone()[0]
    else:
        rows = conn.execute(
            f"SELECT ae.event_id AS event_id, a.id AS alert_id, a.group_key AS group_key"
            f" FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id"
            f" WHERE a.rule_id = ? AND ae.event_id IN ({placeholders})",
            (rule["id"], *ids),
        )
        already = len({row["event_id"] for row in rows
                       if _group_match(row["alert_id"], row["group_key"], finding["group_key"], identity)})
    if already == len(ids):
        return "unchanged"  # e.g. a rescan, or evidence already on a resolved alert

    now = now_iso()
    window = rule["params"].get("window_seconds", 3600)
    existing = _existing_alert(conn, rule["id"], finding["group_key"], finding["first_seen"],
                               finding["last_seen"], window, identity)
    if existing:
        conn.executemany("INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES (?,?)",
                         [(existing["id"], i) for i in ids])
        count = conn.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?",
                             (existing["id"],)).fetchone()[0]
        weighed = _weigh(conn, rule, existing["id"], assets_idx)
        # Synthetic only while every attached event is synthetic. Real evidence clears the flag.
        synthetic_flag = int(bool(existing["synthetic"]) and synthetic)
        conn.execute(
            "UPDATE alerts SET last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?),"
            " event_count = ?, explanation = ?, title = ?, updated_at = ?, severity = ?, base_severity = ?,"
            " assets = ?, severity_note = ?, synthetic = ? WHERE id = ?",
            (finding["last_seen"], finding["first_seen"], count, finding["explanation"],
             finding["title"], now, weighed["severity"], weighed["base_severity"], weighed["assets"],
             weighed["severity_note"], synthetic_flag, existing["id"]),
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
    """Approved tuning exceptions that are neither expired nor revoked, as a set of (rule_id, group_key)."""
    return {(r["rule_id"], r["group_key"]) for r in conn.execute(
        "SELECT rule_id, group_key FROM suppressions WHERE expires_at > ? AND revoked_at IS NULL", (now_iso(),))}


def active_rule_suppressions(conn):
    """Rule ids whose reviewed suppression window contains the current time."""
    now = now_iso()
    return {r["rule_id"] for r in conn.execute(
        "SELECT rule_id FROM rule_suppression_windows"
        " WHERE starts_at <= ? AND expires_at > ? AND ended_at IS NULL", (now, now))}


def scan_events(conn, rules, max_id, start=None, end=None):
    """The stored events a detection run of `rules` over [start, end] reads (default: all events).

    Returns (events, history_events, scan_start). The range is widened by the longest rule window;
    rules that compare with earlier activity also get the span before it as history context.
    Shared by run_detection and the rule backtest, so a backtest reads what detection reads.
    """
    sql, args = f"SELECT {RULE_EVENT_FIELDS} FROM events WHERE id <= ?", [max_id]
    if not (start and end):
        return [dict(r) for r in conn.execute(sql, args)], [], None
    pad = timedelta(seconds=rules_mod.lookback_seconds(rules))
    scan_start = iso(parse_iso(start) - pad)
    events = [dict(r) for r in conn.execute(sql + " AND ts >= ? AND ts <= ?",
                                            args + [scan_start, iso(parse_iso(end) + pad)])]
    # Rules that compare with earlier activity also get the span before the scan window, but only
    # the event types they read: a week of every event per batch was most of the ingest time.
    history_events = []
    history = timedelta(seconds=rules_mod.history_seconds(rules))
    types = sorted({t for r in rules if r["params"].get("history_seconds")
                    for t in rules_mod.HISTORY_EVENT_TYPES[r["id"]]})
    if history and types:
        history_events = [dict(r) for r in conn.execute(
            sql + f" AND ts >= ? AND ts < ? AND event_type IN ({','.join('?' for _ in types)})",
            args + [iso(parse_iso(scan_start) - history), scan_start, *types])]
    return events, history_events, scan_start


def rule_findings(rule, events, history_events, scan_start, suppressed, suppress_rule=False):
    """One rule's findings over scanned events, as detection alerts on them.

    Returns (findings, skipped): findings built only from history context are dropped, and those a
    reviewed tuning exception covers are skipped and counted.
    """
    # For the exfil rule an exception is passed in as a baseline principal, not skipped here.
    params = rules_mod.exception_params(rule["id"], rule["params"], suppressed)
    skips = rule["id"] not in rules_mod.EXCEPTION_ENABLES_BASELINE
    rule_events = events
    if history_events and params.get("history_seconds"):
        since = iso(parse_iso(scan_start) - timedelta(seconds=params["history_seconds"]))
        wanted = rules_mod.HISTORY_EVENT_TYPES[rule["id"]]
        rule_events = [e for e in history_events
                       if e["event_type"] in wanted and e["ts"] >= since] + events
    findings, skipped = [], 0
    raw_findings = rules_mod.rule_function(rule["id"])(rule_events, params)
    for finding in grouping.apply(raw_findings, rule_events, rule.get("grouping") or []):
        if scan_start and finding["last_seen"] < scan_start:
            continue  # built only from history context; outside this scan
        if skips and (rule["id"], finding["group_key"]) in suppressed:
            skipped += 1
            continue
        findings.append(finding)
    if suppress_rule:
        return [], skipped + len(findings)
    return findings, skipped


def _rule_alert_evidence(conn, rule_id):
    rows = conn.execute(
        "SELECT a.id AS alert_id, a.group_key AS group_key, e.id AS event_id, e.src_ip, e.dest_ip,"
        " e.user, e.host, e.event_type, e.source"
        " FROM alerts a LEFT JOIN alert_events ae ON ae.alert_id = a.id"
        " LEFT JOIN events e ON e.id = ae.event_id"
        " WHERE a.rule_id = ? ORDER BY a.id, e.id",
        (rule_id,),
    )
    alerts = {}
    for row in rows:
        info = alerts.setdefault(row["alert_id"], {"group_key": row["group_key"], "evidence": []})
        if row["event_id"] is None:
            continue
        info["evidence"].append({
            "id": row["event_id"], "src_ip": row["src_ip"], "dest_ip": row["dest_ip"], "user": row["user"],
            "host": row["host"], "event_type": row["event_type"], "source": row["source"],
        })
    return alerts


def _open_review_ids(conn, rule_id):
    found = set()
    rows = conn.execute(
        "SELECT detail FROM audit_log WHERE action = 'suppression_needs_review' AND target = ?",
        (rule_id,),
    )
    for row in rows:
        if not row["detail"]:
            continue
        try:
            detail = json.loads(row["detail"])
        except json.JSONDecodeError:
            continue
        if isinstance(detail, dict) and isinstance(detail.get("suppression_id"), int):
            found.add(detail["suppression_id"])
    return found


def _rewrite_group_key(conn, rule_id, old, new, alert_ids):
    """Point one proven entity at its current key. Status and updated_at stay as stored."""
    now = now_iso()
    for alert_id in alert_ids:
        conn.execute("UPDATE alerts SET group_key = ? WHERE id = ?", (new, alert_id))
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "detection", "group_key_reconciled", f"{old} -> {new}", now),
        )
    conn.execute(
        "UPDATE suppressions SET group_key = ? WHERE rule_id = ? AND group_key = ?"
        " AND expires_at > ? AND revoked_at IS NULL",
        (new, rule_id, old, now),
    )


def _reconcile_rule(conn, rule):
    """Rename a stored key only when this rule's evidence has exactly one current key for it.

    A delimiter, a missing-value marker, or a hash is not identity by itself. When the rows
    disagree, the stored alert and suppression stay, and the suppression is not applied.
    """
    fields = grouping.validate(rule["grouping"])
    alerts = _rule_alert_evidence(conn, rule["id"])
    suppressions = [dict(row) for row in conn.execute(
        "SELECT id, group_key FROM suppressions WHERE rule_id = ? AND expires_at > ? AND revoked_at IS NULL",
        (rule["id"], now_iso()),
    )]
    by_key = {}
    for alert_id, info in alerts.items():
        by_key.setdefault(info["group_key"], []).append((alert_id, info["evidence"]))
    sup_by_key = {}
    for row in suppressions:
        sup_by_key.setdefault(row["group_key"], []).append(row)
    flagged = _open_review_ids(conn, rule["id"])
    resolved, blocked, ambiguous = {}, set(), set()
    keys = list(by_key)
    keys.extend(key for key in sup_by_key if key not in by_key)
    for key in keys:
        targets, unresolved, other = set(), False, False
        members = by_key.get(key, [])
        for alert_id, evidence in members:
            if not evidence:
                kind, target = "unresolved", None
            else:
                kind, target = grouping.resolve_stored(key, evidence, fields)
            if kind == "unresolved":
                unresolved = True
                resolved[alert_id] = None
            else:
                targets.add(target)
                resolved[alert_id] = target
                if target != key:
                    other = True
        sups = sup_by_key.get(key, [])
        reviewed = any(row["id"] in flagged for row in sups)
        proven = bool(members) and not unresolved and len(targets) == 1
        if proven and not reviewed:
            target = next(iter(targets))
            if target != key:
                _rewrite_group_key(conn, rule["id"], key, target, [alert_id for alert_id, _ in members])
            continue
        if other or len(targets) > 1:
            blocked.add(key)
        if not sups:
            continue
        # An ordinary string has one encoding. A key evidence already confirms also stays.
        # Anything else, including a previous review, is not applied and is not rewritten.
        if not reviewed and (targets == {key} or (not targets and grouping.ordinary_key(key, len(fields)))):
            continue
        ambiguous.add(key)
        for row in sups:
            if row["id"] in flagged:
                continue
            audit(conn, "detection", "suppression_needs_review", rule["id"],
                  {"suppression_id": row["id"], "group_key": key})
            flagged.add(row["id"])
    return (resolved, blocked), ambiguous


def _reconcile_grouped_rules(conn, rules):
    identities, ambiguous = {}, {}
    for rule in rules:
        if not (rule.get("grouping") or []):
            continue
        identities[rule["id"]], ambiguous[rule["id"]] = _reconcile_rule(conn, rule)
    return identities, ambiguous


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
                if rules_mod.rule_function(rule["id"]) is None:
                    raise rules_mod.RuleConfigError(f"no implementation for rule {rule['id']}")
                rule["params"] = rules_mod.validate_params(rule["id"], rule["params"])

            max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            events, history_events, scan_start = scan_events(conn, active, max_id, start, end)
            synthetic_ids = {e["id"] for e in events + history_events if e["synthetic"]}
            summary["events_scanned"] = len(events) + len(history_events)
            assets_idx = assets_mod.load_index(conn)
            suppressed_rules = active_rule_suppressions(conn)
            with transaction(conn):
                identities, ambiguous = _reconcile_grouped_rules(conn, active)
                suppressed = {(rule_id, key) for rule_id, key in active_suppressions(conn)
                              if key not in ambiguous.get(rule_id, ())}
                for rule in active:
                    if rule["id"] == sources_mod.RULE_ID:
                        # Silence is an absence: the rule reads each source's recent arrivals and the wall
                        # clock, not the events of the scanned time range.
                        arrivals = sources_mod.arrival_events(conn, max_id)
                        synthetic_ids.update(e["id"] for e in arrivals if e["synthetic"])
                        rule = {**rule, "params": sources_mod.clock_params(conn, rule["params"])}
                        findings, skipped = rule_findings(rule, arrivals, [], None, suppressed,
                                                          rule["id"] in suppressed_rules)
                    else:
                        findings, skipped = rule_findings(rule, events, history_events, scan_start, suppressed,
                                                          rule["id"] in suppressed_rules)
                    summary["alerts_suppressed"] += skipped  # a reviewed exception or rule window covers them
                    for finding in findings:
                        synthetic = all(i in synthetic_ids for i in finding["event_ids"])
                        outcome = _apply_finding(conn, rule, finding, synthetic, assets_idx,
                                                 identities.get(rule["id"]))
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
                value = correlate_mod.entity_key(kind, row[kind])
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
# Alerts and incidents published for one detection run, newest by id. The rest are omitted on health.
STREAM_DETECTION_LIMIT = 100
STREAM_EVENT_FIELDS = ("id, ts, source, host, event_type, outcome, severity, user, src_ip, dest_ip, message,"
                       " synthetic")
STREAM_ALERT_FIELDS = ("id, rule_id, severity, title, status, group_key, first_seen, last_seen, event_count,"
                       " synthetic, created_at, updated_at")


def _publish_events(conn, batch_id, count, synthetic):
    """Tell dashboards about a stored batch (newest events only). Never fails the ingest."""
    if not count or not stream.BROKER.active():
        return
    try:
        rows = [dict(r) for r in conn.execute(
            f"SELECT {STREAM_EVENT_FIELDS} FROM events WHERE batch_id = ?"
            " ORDER BY ts DESC, id DESC LIMIT ?", (batch_id, STREAM_EVENT_LIMIT))]
        stream.BROKER.publish("event", {
            "batch_id": batch_id, "count": count, "synthetic": bool(synthetic),
            "events": rows, "events_omitted": count - len(rows),
        })
    except Exception as exc:  # the stream is best-effort; storage already succeeded
        record_error(conn, "stream", exc, guidance="Live dashboard updates may lag; reload the dashboard.")


def _touched_since(conn, table, columns, started):
    """Rows of `table` with updated_at >= started: the newest limit by id, then id order.

    Returns (rows, omitted). `omitted` is 0 when that set fits in STREAM_DETECTION_LIMIT.
    """
    total = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE updated_at >= ?", (started,)).fetchone()[0]
    rows = [dict(r) for r in conn.execute(
        f"SELECT {columns} FROM {table} WHERE updated_at >= ? ORDER BY id DESC LIMIT ?",
        (started, STREAM_DETECTION_LIMIT))]
    rows.reverse()
    return rows, total - len(rows)


def _publish_detection(conn, started, summary):
    """Publish the newest alerts and incidents this run touched, plus detection health.

    At most STREAM_DETECTION_LIMIT of each, still in id order. A failing run publishes
    neither, and both omitted counts are 0. Never fails the detection run.
    """
    if not stream.BROKER.active():
        return
    try:
        failed = summary["status"] != "ok"
        if failed:
            alerts, alerts_omitted = [], 0
            incidents, incidents_omitted = [], 0
        else:
            alerts, alerts_omitted = _touched_since(conn, "alerts", STREAM_ALERT_FIELDS, started)
            for alert in alerts:
                alert["change"] = "created" if alert["created_at"] >= started else "updated"
            has_incidents = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'incidents'").fetchone()
            if has_incidents:
                incidents, incidents_omitted = _touched_since(conn, "incidents", "*", started)
            else:
                incidents, incidents_omitted = [], 0
        stream.BROKER.publish("health", {
            "partial": True, "checks": {"detection": "failing" if failed else "ok"},
            "error": summary.get("error"),
            "alerts_omitted": alerts_omitted, "incidents_omitted": incidents_omitted,
        })
        if failed:
            return
        for alert in alerts:
            stream.BROKER.publish("alert", alert)
        for incident in incidents:
            stream.BROKER.publish("incident", incident)
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
    grouping_fields = json.loads(rule["grouping"] or "[]")
    if "grouping" in payload:
        grouping_fields = grouping.validate(payload["grouping"])
    enabled = int(payload.get("enabled", rule["enabled"]))
    version = rule["version"] + 1
    now = now_iso()
    conn.execute(
        "UPDATE rules SET params = ?, grouping = ?, enabled = ?, version = ?, updated_at = ?, updated_by = ?"
        " WHERE id = ?",
        (json.dumps(params), json.dumps(grouping_fields), enabled, version, now, approved_by, rule_id),
    )
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, grouping, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rule_id, version, enabled, json.dumps(params), json.dumps(grouping_fields), now, changed_by, approved_by,
         change_request_id, note),
    )
    audit(conn, approved_by, "rule_changed", rule_id, {"version": version, "change_request": change_request_id})
    return version
