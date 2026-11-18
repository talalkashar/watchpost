"""Rule backtesting: replay a proposed rule change over stored events before it is approved.

The rule runs twice over the same stored events, once with today's params and once with the proposed
ones, through the engine's own event loading (engine.scan_events) and finding filter
(engine.rule_findings), so active tuning exceptions and history context apply exactly as in detection.
Findings are compared by group key: kept, new (only the proposal fires) and lost (only today fires).

It replays what is stored, nothing else: it cannot predict traffic that has not arrived, and on the demo
the stored events are synthetic. The result names the window, the events scanned and the synthetic share.
"""

import json
from datetime import timedelta

from . import engine
from . import rules as rules_mod
from .db import iso, parse_iso

DEFAULT_WINDOW_DAYS = 7   # lookback, counted back from the newest stored event
MAX_WINDOW_DAYS = 30
MAX_EVENTS = 100_000      # cost bound: a full detection run is about 0.7 s at 100k events (README)
LIST_LIMIT = 25           # items per list (kept, new, lost); the counts are always complete
EVIDENCE_IDS = 5          # evidence event ids shown per finding
ENTITY_VALUES = 3         # values per entity kind shown per finding
ENTITY_KINDS = ("user", "src_ip", "host")


def _by_key(findings):
    """Findings grouped by group key, as {key: {"findings", "first_seen", "last_seen", "event_ids"}}."""
    out = {}
    for f in findings:
        g = out.setdefault(f["group_key"], {"findings": 0, "first_seen": f["first_seen"],
                                            "last_seen": f["last_seen"], "event_ids": set()})
        g["findings"] += 1
        g["first_seen"] = min(g["first_seen"], f["first_seen"])
        g["last_seen"] = max(g["last_seen"], f["last_seen"])
        g["event_ids"].update(f["event_ids"])
    return out


def _item(key, group, events_by_id, open_ids=()):
    entities = {k: [] for k in ENTITY_KINDS}
    for i in sorted(group["event_ids"]):
        e = events_by_id.get(i, {})
        for kind in ENTITY_KINDS:
            if e.get(kind) and e[kind] not in entities[kind] and len(entities[kind]) < ENTITY_VALUES:
                entities[kind].append(e[kind])
    return {"group_key": key, "findings": group["findings"], "first_seen": group["first_seen"],
            "last_seen": group["last_seen"], "event_count": len(group["event_ids"]),
            "evidence_event_ids": sorted(group["event_ids"])[:EVIDENCE_IDS], "entities": entities,
            "open_alert_ids": sorted(open_ids)}


def _open_alerts(conn, rule_id):
    """This rule's alerts that are not resolved, with their evidence event ids."""
    alerts = {}
    for r in conn.execute(
            "SELECT a.id, a.title, a.status, a.group_key, ae.event_id FROM alerts a"
            " JOIN alert_events ae ON ae.alert_id = a.id WHERE a.rule_id = ? AND a.status != 'resolved'",
            (rule_id,)):
        a = alerts.setdefault(r["id"], {"id": r["id"], "title": r["title"], "status": r["status"],
                                        "group_key": r["group_key"], "events": set()})
        a["events"].add(r["event_id"])
    return alerts


def _empty(rule_id, window_days, max_events, running):
    return {"rule": rule_id, "window": None, "window_days": window_days, "capped": False, "max_events": max_events,
            "max_event_id": 0, "events_scanned": 0, "synthetic": "none", "synthetic_events": 0,
            "running": running, "suppressed": {"today": 0, "proposed": 0},
            "counts": {"kept": 0, "new": 0, "lost": 0, "open_alerts_lost": 0},
            "kept": [], "new": [], "lost": [], "open_alerts_lost": [], "truncated": False}


def backtest(conn, rule_id, new_params, window_days=DEFAULT_WINDOW_DAYS, max_events=MAX_EVENTS,
             running=(True, True), limit=LIST_LIMIT):
    """Replay `rule_id` with its stored params and with `new_params` over the same stored events.

    The window is the last `window_days` (capped at MAX_WINDOW_DAYS) of stored event time, ending at the
    newest stored event. When it holds more than `max_events` events its start moves later until it
    does not (at least one rule window is always scanned) and `capped` says so. `running` is
    (enabled today, enabled after the change): a rule that is not running fires on nothing.
    Deterministic for a given database state, so its digest is stable until an event is appended or a
    rule, exception or open alert changes.
    """
    row = conn.execute("SELECT params, grouping FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise rules_mod.RuleConfigError(f"unknown rule {rule_id!r}")
    current = rules_mod.validate_params(rule_id, json.loads(row["params"]))
    proposed = rules_mod.validate_params(rule_id, new_params)
    # The same stored grouping detection applies (rules.grouping). A proposed grouping change is previewed
    # on its own; both sides of this replay use what is stored now.
    grouping = json.loads(row["grouping"] or "[]")
    window_days = max(1, min(int(window_days), MAX_WINDOW_DAYS))
    running = {"today": bool(running[0]), "proposed": bool(running[1])}

    # Pinned like a detection run: events appended while this runs are not half-read.
    max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
    end = conn.execute("SELECT MAX(ts) FROM events WHERE id <= ?", (max_id,)).fetchone()[0]
    if end is None:
        return _empty(rule_id, window_days, max_events, running)
    end_dt = parse_iso(end)
    requested = end_dt - timedelta(days=window_days)
    rules = [{"id": rule_id, "params": current, "grouping": grouping},
             {"id": rule_id, "params": proposed, "grouping": grouping}]
    pad = timedelta(seconds=rules_mod.lookback_seconds(rules))
    # The newest event past the cap, if the padded window holds more than max_events. id breaks ties.
    over = conn.execute(
        "SELECT ts FROM events WHERE id <= ? AND ts >= ? AND ts <= ?"
        " ORDER BY ts DESC, id DESC LIMIT 1 OFFSET ?",
        (max_id, iso(requested - pad), end, max_events)).fetchone()
    if over:
        candidate = parse_iso(over["ts"]) + timedelta(milliseconds=1) + pad
        if candidate <= end_dt:
            scan_from = finding_start = iso(candidate)
        else:
            # The cut sits inside one rule lookback of the newest event. scan_events subtracts `pad`
            # again, so the scan argument stays `end` and the loaded span stays [end-pad, end].
            # Count findings across that lookback (not only those ending on the newest timestamp)
            # and do not report a window wider than the one that was asked for.
            scan_from = end
            finding_start = iso(max(requested, end_dt - pad))
    else:
        scan_from = finding_start = iso(requested)

    events, history, scan_start = engine.scan_events(conn, rules, max_id, scan_from, end)
    scanned = events + history
    events_by_id = {e["id"]: e for e in scanned}
    suppressed = engine.active_suppressions(conn)

    def run(params, on):
        if not on:
            return {}, 0
        findings, skipped = engine.rule_findings(
            {"id": rule_id, "params": params, "grouping": grouping}, events, history,
            scan_start, suppressed)
        return _by_key(f for f in findings if f["last_seen"] >= finding_start), skipped  # ends inside the window

    today, skipped_today = run(current, running["today"])
    after, skipped_after = run(proposed, running["proposed"])

    # An open alert this replay reproduces today (shares evidence under its key) and the proposal does not.
    lost_alerts = {}
    for a in _open_alerts(conn, rule_id).values():
        before, later = today.get(a["group_key"]), after.get(a["group_key"])
        if before and a["events"] & before["event_ids"] and not (later and a["events"] & later["event_ids"]):
            lost_alerts[a["id"]] = a
    open_by_key = {}
    for a in lost_alerts.values():
        open_by_key.setdefault(a["group_key"], set()).add(a["id"])

    def items(keys, side, newest_first=True):
        out = [_item(k, side[k], events_by_id, open_by_key.get(k, ())) for k in keys]
        out.sort(key=lambda x: x["group_key"])
        out.sort(key=lambda x: x["last_seen"], reverse=newest_first)
        out.sort(key=lambda x: not x["open_alert_ids"])  # lost open alerts first
        return out

    kept = items(today.keys() & after.keys(), after)
    for x in kept:
        x["event_count_today"] = len(today[x["group_key"]]["event_ids"])
    new = items(after.keys() - today.keys(), after)
    lost = items(today.keys() - after.keys(), today)
    synthetic = sum(1 for e in scanned if e["synthetic"])
    open_lost = sorted(({k: a[k] for k in ("id", "title", "status", "group_key")} for a in lost_alerts.values()),
                       key=lambda a: a["id"])
    return {
        "rule": rule_id,
        "window": {"start": finding_start, "end": end},
        "window_days": window_days,
        "capped": bool(over),
        "max_events": max_events,
        "max_event_id": max_id,
        "events_scanned": len(scanned),
        "synthetic": "none" if not synthetic else "all" if synthetic == len(scanned) else "some",
        "synthetic_events": synthetic,
        "running": running,
        "suppressed": {"today": skipped_today, "proposed": skipped_after},
        "counts": {"kept": len(kept), "new": len(new), "lost": len(lost), "open_alerts_lost": len(open_lost)},
        "kept": kept[:limit], "new": new[:limit], "lost": lost[:limit],
        "open_alerts_lost": open_lost[:limit],
        "truncated": max(len(kept), len(new), len(lost), len(open_lost)) > limit,
    }


PREVIEW_GROUP_KEYS = 10  # first sorted keys on a new-rule preview; the rest are group_keys_omitted
PREVIEW_SAMPLE_FINDINGS = 5  # findings listed in a new rule's preview; the count is complete


def preview_new_rule(conn, rule_id, params, matches, window_days=DEFAULT_WINDOW_DAYS, max_events=MAX_EVENTS):
    """What a rule that does not exist yet would find among stored events (an imported Sigma rule, a promoted
    saved search). `rule_id` only picks the rule function; `matches(event)` counts the events its filter matches.

    Uses the engine's own event loading and finding filter (engine.scan_events / rule_findings), so it reads
    what detection would read, including the lookback those functions load. Findings that end before the
    window are left out. Events scanned are the ones inside the window. `window_days` is capped at
    MAX_WINDOW_DAYS, the same bound as a rule backtest.
    """
    rule = {"id": rule_id, "params": params}
    max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
    end = conn.execute("SELECT MAX(ts) FROM events WHERE id <= ?", (max_id,)).fetchone()[0]
    out = {"window": None, "max_event_id": max_id, "events_scanned": 0, "synthetic_events": 0,
           "matched_events": 0, "findings": 0, "group_keys": [], "group_keys_omitted": 0,
           "sample_findings": [], "capped": False}
    if end is None:
        return out
    window_days = max(1, min(int(window_days), MAX_WINDOW_DAYS))
    end_dt = parse_iso(end)
    start = iso(end_dt - timedelta(days=window_days))
    # id breaks ties. The row past the cap is not part of the window.
    over = conn.execute(
        "SELECT id, ts FROM events WHERE id <= ? AND ts >= ? AND ts <= ?"
        " ORDER BY ts DESC, id DESC LIMIT 1 OFFSET ?",
        (max_id, start, end, max_events)).fetchone()
    drop_id = None
    if over:
        boundary = parse_iso(over["ts"]) + timedelta(milliseconds=1)
        if boundary <= end_dt:
            start = iso(boundary)
        else:
            # Every event in the cap shares the newest timestamp. Keep the newer ids there so the
            # window is neither empty nor the whole burst.
            start = over["ts"]
            drop_id = over["id"]
    events, history, scan_start = engine.scan_events(conn, [rule], max_id, start, end)
    if drop_id is not None:
        events = [e for e in events if not (e["ts"] == start and e["id"] <= drop_id)]
    findings, _ = engine.rule_findings(rule, events, history, scan_start, set())
    findings = [f for f in findings if start <= f["last_seen"] <= end]
    window_events = [e for e in events if start <= e["ts"] <= end]
    keys = sorted({f["group_key"] for f in findings})
    shown = keys[:PREVIEW_GROUP_KEYS]
    newest = sorted(findings, key=lambda f: (f["last_seen"], f["group_key"]), reverse=True)
    out.update(window={"start": start, "end": end}, events_scanned=len(window_events),
               synthetic_events=sum(1 for e in window_events if e["synthetic"]), capped=bool(over),
               matched_events=sum(1 for e in window_events if matches(e)), findings=len(findings),
               group_keys=shown, group_keys_omitted=len(keys) - len(shown),
               sample_findings=[{"group_key": f["group_key"], "event_count": len(f["event_ids"]),
                                 "first_seen": f["first_seen"], "last_seen": f["last_seen"], "title": f["title"]}
                                for f in newest[:PREVIEW_SAMPLE_FINDINGS]])
    return out
