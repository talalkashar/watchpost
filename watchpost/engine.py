"""Ingestion and detection orchestration against the database."""

import json
import threading
import uuid
from datetime import timedelta

from . import assets as assets_mod
from . import correlate as correlate_mod
from . import grouping
from . import playbooks
from . import threat_intel
from . import rules as rules_mod
from . import sources as sources_mod
from . import stream
from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction
from .diagnostics import describe_exception, record_error

EVENT_COLUMNS = ["ts", "source", "host", "event_type", "outcome", "severity",
                 "user", "src_ip", "dest_ip", "dest_port", "bytes", "message", "raw", "threat"]
# Fields detection rules can read. source and ingested_at let a backtest replay log_source_silent's gaps.
RULE_EVENT_FIELDS = ("id, ts, event_type, user, src_ip, host, dest_ip, dest_port, bytes, message, synthetic,"
                     " source, ingested_at, threat")

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
    threat_intel.tag(conn, events)  # sets each event's `threat`; whatever a sender put there is overwritten
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

def _existing_alert(conn, match_sql, match_args, first_seen, last_seen, window):
    """Open alert for this group whose span is within `window` seconds of the finding.

    A gap of exactly `window` still matches. Rules split a cluster only when the gap is greater.
    When more than one open alert is that close, the newest one wins.
    """
    earliest = iso(parse_iso(first_seen) - timedelta(seconds=window))
    latest = iso(parse_iso(last_seen) + timedelta(seconds=window))
    return conn.execute(
        f"SELECT a.* FROM alerts a WHERE {match_sql} AND status != 'resolved'"
        " AND last_seen >= ? AND first_seen <= ? ORDER BY id DESC LIMIT 1",
        (*match_args, earliest, latest),
    ).fetchone()


def _weigh(conn, rule, alert_id, assets_idx):
    """Severity after asset weighting and threat intelligence, from every evidence event now on the alert."""
    events = [dict(r) for r in conn.execute(
        "SELECT e.host, e.src_ip, e.dest_ip, e.threat FROM events e JOIN alert_events ae ON ae.event_id = e.id"
        " WHERE ae.alert_id = ?", (alert_id,))]
    weighed = assets_mod.weigh(rule["severity"], assets_mod.match(assets_idx, events))
    listed = sorted({e["threat"] for e in events if e["threat"]})
    if listed:
        weighed = threat_intel.raise_severity(weighed, listed)
    weighed["assets"] = json.dumps(weighed["assets"])
    return weighed


def _apply_finding(conn, rule, finding, synthetic, assets_idx):
    """Create or extend an alert. Returns 'created', 'updated', or 'unchanged'."""
    ids = finding["event_ids"]
    placeholders = ",".join("?" for _ in ids)
    match_sql = "a.rule_id = ? AND a.group_key = ?"
    match_args = (rule["id"], finding["group_key"])
    if rule.get("grouping"):
        match_sql = ("a.id IN (SELECT alert_id FROM alert_group_keys"
                     " WHERE rule_id=? AND fields=? AND canonical=?)")
        match_args = (rule["id"], json.dumps(rule["grouping"]), finding["group_key"])
    already = conn.execute(
        f"SELECT COUNT(DISTINCT ae.event_id) FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id"
        f" WHERE {match_sql} AND ae.event_id IN ({placeholders})",
        (*match_args, *ids),
    ).fetchone()[0]
    if already == len(ids):
        return "unchanged"  # e.g. a rescan, or evidence already on a resolved alert

    now = now_iso()
    window = rule["params"].get("window_seconds", 3600)
    existing = _existing_alert(conn, match_sql, match_args, finding["first_seen"],
                               finding["last_seen"], window)
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
    if rule.get("grouping"):
        conn.execute("INSERT INTO alert_group_keys(alert_id,rule_id,fields,canonical,native) VALUES (?,?,?,?,1)",
                     (alert_id, rule["id"], json.dumps(rule["grouping"]), finding["group_key"]))
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
    playbooks.start(conn, conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())
    return "created"


def _group_tables(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS alert_group_keys (alert_id INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,"
                 "rule_id TEXT NOT NULL, fields TEXT, canonical TEXT, native INTEGER NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_group_canonical ON alert_group_keys(rule_id,fields,canonical)")
    conn.execute("CREATE TABLE IF NOT EXISTS suppression_group_state (suppression_id INTEGER PRIMARY KEY REFERENCES suppressions(id) ON DELETE CASCADE,"
                 "fields TEXT NOT NULL, cutoff INTEGER NOT NULL, review TEXT)")


def _alert_proof(conn, alert, rule):
    fields = rule["grouping"]
    if alert["rule_version"] != rule["version"]:
        history = conn.execute("SELECT grouping FROM rule_history WHERE rule_id=? AND version=? ORDER BY id DESC",
                               (rule["id"], alert["rule_version"])).fetchone()
        fields = json.loads(history[0]) if history else []
    canonical = None
    if fields:
        rows = conn.execute("SELECT e.src_ip,e.dest_ip,e.user,e.host,e.event_type,e.source"
                            " FROM alert_events ae JOIN events e ON e.id=ae.event_id WHERE ae.alert_id=?",
                            (alert["id"],))
        canonical = grouping.retained_key(alert["group_key"], fields, rows, alert["event_count"])
    return (alert["id"], rule["id"], json.dumps(fields), canonical)


def _missing_group_proofs(conn, rules):
    proofs = []
    for rule in rules:
        alerts = conn.execute("SELECT a.id,a.group_key,a.rule_version,a.event_count FROM alerts a"
                              " WHERE a.rule_id=? AND NOT EXISTS"
                              " (SELECT 1 FROM alert_group_keys g WHERE g.alert_id=a.id)", (rule["id"],))
        proofs.extend(_alert_proof(conn, a, rule) for a in alerts)
    return proofs


def _suppression_keys(conn, rules, cached, record=False):
    """Resolve a reviewed key only when all its original members agree on its identity."""
    active, reviews = set(), []
    for sup in conn.execute("SELECT id,rule_id,group_key,created_at FROM suppressions"
                            " WHERE expires_at > ? AND revoked_at IS NULL", (now_iso(),)):
        key = sup["group_key"]
        rid = sup["rule_id"]
        rule = rules.get(rid)
        if rule is None:
            if not record:
                active.add((rid, key))  # A pre-seeding database can already hold native exceptions.
            continue
        state = conn.execute("SELECT * FROM suppression_group_state WHERE suppression_id=?",
                             (sup["id"],)).fetchone() if cached else None
        fields = json.dumps(rule["grouping"])
        approved_fields = state["fields"] if state else fields
        if state is None and rule["version"] > 1:
            history = conn.execute("SELECT grouping FROM rule_history WHERE rule_id=? AND changed_at<=?"
                                   " ORDER BY version DESC,id DESC LIMIT 1", (rid, sup["created_at"])).fetchone()
            approved_fields = json.dumps(json.loads(history[0])) if history else None
        if not rule["grouping"] and approved_fields == fields and state is None:
            active.add((rid, key))
            continue
        cutoff = state["cutoff"] if state else conn.execute("SELECT COALESCE(MAX(id),0) FROM alerts").fetchone()[0]
        # Current-format alerts created after this decision cannot supply provenance for an older exception.
        targets, missing = set(), []
        if cached:
            members = conn.execute(
                "SELECT a.*,g.alert_id AS known,g.fields,g.canonical FROM alerts a LEFT JOIN alert_group_keys g ON g.alert_id=a.id"
                " WHERE a.rule_id=? AND a.group_key=? AND a.id<=? AND a.created_at<=?"
                " ORDER BY a.id", (rid, key, cutoff, sup["created_at"]))
        else:
            members = conn.execute("SELECT a.*,NULL AS known FROM alerts a WHERE rule_id=? AND group_key=?"
                                   " AND created_at<=? ORDER BY id", (rid, key, sup["created_at"]))
        for member in members:
            alert_id = member["id"]
            if member["known"] is None:
                _, _, saved, canonical = _alert_proof(conn, member, rule)
            else:
                saved, canonical = member["fields"], member["canonical"]
            if saved != fields or canonical is None:
                missing.append(alert_id)
            else:
                targets.add(canonical)
        previous = json.loads(state["review"]) if state and state["review"] else None
        effective = None
        if not previous and not missing and approved_fields == fields:
            if len(targets) == 1:
                effective = next(iter(targets))
            elif not targets and grouping.ordinary_key(key, rule["grouping"]):
                effective = key
        if effective is not None:
            active.add((rid, effective))
            detail = None
        else:
            unresolved = sorted(set(missing).union(previous["unresolved_alert_ids"] if previous else []))
            detail = {"rule_id": rid, "group_key": key, "suppression_id": sup["id"], "unresolved_alert_ids": unresolved}
            reviews.append(detail)
            if record and detail != previous:
                audit(conn, "detection", "suppression_needs_review", rid, detail)
        if record and (not state or detail != previous):
            conn.execute("INSERT INTO suppression_group_state VALUES (?,?,?,?)"
                         " ON CONFLICT(suppression_id) DO UPDATE SET review=excluded.review",
                         (sup["id"], fields, cutoff, json.dumps(detail) if detail else None))
    return active, reviews


def active_suppressions(conn):
    rules = {row["id"]: row_to_dict(row, ["grouping"])
             for row in conn.execute("SELECT id,version,grouping FROM rules")}
    cached = conn.execute("SELECT 1 FROM sqlite_master WHERE name='suppression_group_state'").fetchone()
    return _suppression_keys(conn, rules, bool(cached))[0]


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
            grouped = [r for r in active if r.get("grouping")]
            cached = conn.execute("SELECT 1 FROM sqlite_master WHERE name='suppression_group_state'").fetchone()
            if not cached and (grouped or conn.execute("SELECT 1 FROM suppressions LIMIT 1").fetchone()):
                _group_tables(conn)
                cached = True
            if grouped:
                revision = conn.execute("PRAGMA data_version").fetchone()[0]
                proofs = _missing_group_proofs(conn, grouped)
            suppressed_rules = active_rule_suppressions(conn)
            with transaction(conn):
                if grouped:
                    if revision != conn.execute("PRAGMA data_version").fetchone()[0]:
                        # A writer changed the snapshot. Prove only still-unclassified members again.
                        proofs = _missing_group_proofs(conn, grouped)
                    conn.executemany("INSERT INTO alert_group_keys VALUES (?,?,?,?,0)", proofs)
                suppressed, reviews = _suppression_keys(conn, {r["id"]: r for r in active},
                                                        bool(grouped or cached), record=bool(grouped or cached))
                summary["suppression_reviews"] = reviews
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
            summary["alert_count"], summary["synthetic"], json.dumps(summary["patterns"]))


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
                    " synthetic, patterns, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,'open',?,?)",
                    (*values, now, now)).lastrowid
                result["incidents_created"] += 1
            else:
                current = conn.execute(
                    "SELECT title, severity, first_seen, last_seen, entities, stages, alert_count, synthetic,"
                    " patterns FROM incidents WHERE id = ?", (incident_id,)).fetchone()
                if tuple(current) != values:
                    conn.execute(
                        "UPDATE incidents SET title = ?, severity = ?, first_seen = ?, last_seen = ?, entities = ?,"
                        " stages = ?, alert_count = ?, synthetic = ?, patterns = ?, updated_at = ? WHERE id = ?",
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
