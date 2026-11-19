"""Rule backtesting: replay a proposed rule change over stored events before it is approved.

The rule runs twice over the same stored events, once with today's params and once with the proposed
ones, through the engine's finding filter (engine.rule_findings), so active tuning exceptions and
history context apply as in detection. The rows are the span detection would read, including padded
lookback and type-filtered history, but that read is bounded before the rows are materialized.
Findings are compared by group key: kept, new (only the proposal fires) and lost (only today fires).

It replays what is stored, nothing else: it cannot predict traffic that has not arrived, and on the demo
the stored events are synthetic. The result names the window, the events scanned and the synthetic share.
"""

import json
from datetime import datetime, timedelta, timezone

from . import engine
from . import rules as rules_mod
from .db import iso, parse_iso

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

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
    return {"rule": rule_id, "window": None, "window_days": window_days, "capped": False, "incomplete": False,
            "events_omitted": 0, "bound": None, "max_events": max_events,
            "max_event_id": 0, "events_scanned": 0, "synthetic": "none", "synthetic_events": 0,
            "running": running, "suppressed": {"today": 0, "proposed": 0},
            "counts": {"kept": 0, "new": 0, "lost": 0, "open_alerts_lost": 0},
            "kept": [], "new": [], "lost": [], "open_alerts_lost": [], "truncated": False}


def _ms(dt):
    """Whole milliseconds since the epoch. Timestamp text is millisecond UTC, so this stays exact."""
    delta = dt - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def _from_ms(ms):
    return _EPOCH + timedelta(milliseconds=ms)


def _history_spec(rules):
    """The history span and event types engine.scan_events would load, or (None, ()) when it would not."""
    history = timedelta(seconds=rules_mod.history_seconds(rules))
    types = sorted({t for r in rules if r["params"].get("history_seconds")
                    for t in rules_mod.HISTORY_EVENT_TYPES[r["id"]]})
    if history and types:
        return history, types
    return None, ()


def _count_span(conn, max_id, scan_start, event_end, history, types):
    """How many rows the event region plus its type-filtered history hold. Does not fetch them."""
    event_sql = "SELECT COUNT(*) FROM events WHERE id <= ? AND ts >= ? AND ts <= ?"
    event_args = [max_id, scan_start, event_end]
    if not (history and types):
        return conn.execute(event_sql, event_args).fetchone()[0]
    marks = ",".join("?" for _ in types)
    hist_sql = ("SELECT COUNT(*) FROM events WHERE id <= ? AND ts >= ? AND ts < ?"
                f" AND event_type IN ({marks})")
    hist_args = [max_id, iso(parse_iso(scan_start) - history), scan_start, *types]
    total = conn.execute(f"SELECT ({event_sql}) + ({hist_sql})", event_args + hist_args).fetchone()[0]
    return total


def _fetch_span(conn, max_id, scan_start, event_end, history, types, limit=None):
    """Materialize the span. `limit` is applied in SQL so a burst is never read and then sliced."""
    fields = engine.RULE_EVENT_FIELDS
    sql = f"SELECT {fields} FROM events WHERE id <= ? AND ts >= ? AND ts <= ?"
    args = [max_id, scan_start, event_end]
    if history and types:
        marks = ",".join("?" for _ in types)
        sql += (f" UNION ALL SELECT {fields} FROM events WHERE id <= ? AND ts >= ? AND ts < ?"
                f" AND event_type IN ({marks})")
        args += [max_id, iso(parse_iso(scan_start) - history), scan_start, *types]
    if limit is not None:
        sql = f"SELECT * FROM ({sql}) ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _split(rows, scan_start):
    events = [e for e in rows if e["ts"] >= scan_start]
    history_events = [e for e in rows if e["ts"] < scan_start]
    return events, history_events


def _bound(rows):
    """The oldest materialized row. It is the cutoff the read actually reached."""
    if not rows:
        return None
    oldest = min(rows, key=lambda e: (e["ts"], e["id"]))
    return {"ts": oldest["ts"], "id": oldest["id"]}


def _loaded(events, history_events, scan_start, finding_start, capped, incomplete, events_omitted, bound):
    return {"events": events, "history": history_events, "scan_start": scan_start,
            "finding_start": finding_start, "capped": capped, "incomplete": incomplete,
            "events_omitted": events_omitted, "bound": bound}


def _earliest_ms(conn, max_id, event_end, history, types, lo, hi, max_events):
    """Earliest scan start in (lo, hi] whose exact span fits. count(lo) is over the budget."""
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if _count_span(conn, max_id, iso(_from_ms(mid)), event_end, history, types) <= max_events:
            hi = mid
        else:
            lo = mid
    return hi


def _budget(conn, rules, max_id, end, requested_dt, max_events):
    """The rows a detection read of [requested_dt, end] would use, bounded by `max_events`.

    An exact fit keeps every row of the asked window, or of the earliest later window that fits,
    and reports that window. The padded lookback and the type-filtered history before it count
    toward the budget. When even the newest lookback does not fit, only its newest rows are read
    and the result is incomplete: it is not an exact evaluation.
    """
    pad = timedelta(seconds=rules_mod.lookback_seconds(rules))
    history, types = _history_spec(rules)
    end_dt = parse_iso(end)
    event_end = iso(end_dt + pad)  # scan_events widens the end by the same pad; end is already the newest ts
    full_start = iso(requested_dt - pad)
    if _count_span(conn, max_id, full_start, event_end, history, types) <= max_events:
        rows = _fetch_span(conn, max_id, full_start, event_end, history, types)
        events, hist = _split(rows, full_start)
        return _loaded(events, hist, full_start, iso(requested_dt), False, False, 0, None)
    min_dt = end_dt - pad
    min_start = iso(min_dt)
    min_count = _count_span(conn, max_id, min_start, event_end, history, types)
    if min_count > max_events:
        # The newest timestamp can hold more rows than the cap. A scan start is a timestamp, so no
        # exact span can keep some of those ids and drop the rest. Read the newest ids only.
        rows = _fetch_span(conn, max_id, min_start, event_end, history, types, limit=max_events)
        events, hist = _split(rows, min_start)
        finding_start = min((e["ts"] for e in events), default=end)
        return _loaded(events, hist, min_start, finding_start, True, True, min_count - len(rows), _bound(rows))
    lo, hi = _ms(parse_iso(full_start)), _ms(parse_iso(min_start))
    scan_dt = min_dt if lo >= hi else _from_ms(
        _earliest_ms(conn, max_id, event_end, history, types, lo, hi, max_events))
    scan_start = iso(scan_dt)
    rows = _fetch_span(conn, max_id, scan_start, event_end, history, types)
    events, hist = _split(rows, scan_start)
    # The reported window starts a pad later than the rows: the pad is context, as in scan_events.
    return _loaded(events, hist, scan_start, iso(scan_dt + pad), True, False, 0, None)


def backtest(conn, rule_id, new_params, window_days=DEFAULT_WINDOW_DAYS, max_events=MAX_EVENTS,
             running=(True, True), limit=LIST_LIMIT):
    """Replay `rule_id` with its stored params and with `new_params` over the same stored events.

    The window is the last `window_days` (capped at MAX_WINDOW_DAYS) of stored event time, ending at the
    newest stored event. Padded lookback and type-filtered history count toward `max_events`. When the
    asked window does not fit, its start moves later to the earliest exact span that does, and `capped`
    says so. When even the newest lookback does not fit, only that lookback's newest rows are read
    (timestamp, then event id) and `incomplete` is true: those findings are not an exact evaluation.
    `running` is (enabled today, enabled after the change): a rule that is not running fires on nothing.
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
    loaded = _budget(conn, rules, max_id, end, requested, max_events)
    events, history = loaded["events"], loaded["history"]
    scan_start, finding_start = loaded["scan_start"], loaded["finding_start"]
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
        "capped": loaded["capped"],
        "incomplete": loaded["incomplete"],
        "events_omitted": loaded["events_omitted"],
        "bound": loaded["bound"],
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

    Uses the engine's finding filter (engine.rule_findings) on the same span detection would read, including
    lookback and type-filtered history, bounded before those rows are materialized. Findings that end before
    the window are left out. Events scanned are the ones inside the window. When the exact span cannot fit
    in `max_events`, `incomplete` is true and only the newest rows are read. `window_days` is capped at
    MAX_WINDOW_DAYS, the same bound as a rule backtest.
    """
    rule = {"id": rule_id, "params": params}
    max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
    end = conn.execute("SELECT MAX(ts) FROM events WHERE id <= ?", (max_id,)).fetchone()[0]
    out = {"window": None, "max_event_id": max_id, "events_scanned": 0, "synthetic_events": 0,
           "matched_events": 0, "findings": 0, "group_keys": [], "group_keys_omitted": 0,
           "sample_findings": [], "capped": False, "incomplete": False, "events_omitted": 0, "bound": None}
    if end is None:
        return out
    window_days = max(1, min(int(window_days), MAX_WINDOW_DAYS))
    end_dt = parse_iso(end)
    requested = end_dt - timedelta(days=window_days)
    loaded = _budget(conn, [rule], max_id, end, requested, max_events)
    events, history, scan_start = loaded["events"], loaded["history"], loaded["scan_start"]
    start = loaded["finding_start"]
    findings, _ = engine.rule_findings(rule, events, history, scan_start, set())
    findings = [f for f in findings if start <= f["last_seen"] <= end]
    window_events = [e for e in events if start <= e["ts"] <= end]
    keys = sorted({f["group_key"] for f in findings})
    shown = keys[:PREVIEW_GROUP_KEYS]
    newest = sorted(findings, key=lambda f: (f["last_seen"], f["group_key"]), reverse=True)
    out.update(window={"start": start, "end": end}, events_scanned=len(window_events),
               synthetic_events=sum(1 for e in window_events if e["synthetic"]), capped=loaded["capped"],
               incomplete=loaded["incomplete"], events_omitted=loaded["events_omitted"], bound=loaded["bound"],
               matched_events=sum(1 for e in window_events if matches(e)), findings=len(findings),
               group_keys=shown, group_keys_omitted=len(keys) - len(shown),
               sample_findings=[{"group_key": f["group_key"], "event_count": len(f["event_ids"]),
                                 "first_seen": f["first_seen"], "last_seen": f["last_seen"], "title": f["title"]}
                                for f in newest[:PREVIEW_SAMPLE_FINDINGS]])
    return out
