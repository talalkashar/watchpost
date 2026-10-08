"""Log source health: which (source, host) pairs send events, how often, and which have gone quiet.

Computed per query from stored events; nothing new is ingested or parsed. Silence hides attacks: a log
forwarder that stops (crashed, uninstalled, or stopped on purpose) looks exactly like a quiet network.

Clock. Silence is measured from a pair's last *arrival* (`ingested_at`, when Watchpost stored the event)
to the wall clock, not to the newest stored event. Unlike entities.py, which anchors on the newest data so
replayed demo data keeps its meaning, a source going quiet is the very thing to see here, so "now" must be
the real now. Arrival time rather than event time (`ts`) because replayed or back-filled data carries old
timestamps: the demo dataset is dated on the previous weekday and would look like dozens of sources that
died yesterday, while by arrival it is one upload (one arrival, so "learning"). Arrival time is also immune
to a host's clock skew. The cost: a forwarder that buffers and resends looks alive while it resends, and
one upload of a week of logs counts as one arrival. Events stored in one batch share one arrival.

Definitions (thresholds are the module constants below):
- cadence: the median gap between a pair's consecutive arrivals, over the most recent CADENCE_SAMPLE gaps
  inside the CADENCE_WINDOW_SECONDS before its last arrival.
- learning: fewer than MIN_GAPS gaps in that window, or less than MIN_HISTORY_SECONDS since the pair was
  first seen. A burst (40 events in 3 minutes) is not a cadence.
- late: quiet for more than LATE_MULTIPLIER x cadence, more than LATE_FLOOR_SECONDS, and longer than the
  longest gap in the sample.
- silent: quiet for more than SILENT_MULTIPLIER x cadence, more than SILENT_FLOOR_SECONDS, and more than
  twice the longest gap in the sample. The longest-gap terms keep a source that is busy in bursts (a
  nightly backup, office-hours badge readers) from going "silent" every night.
- healthy: none of the above.
Time inside an approved maintenance window for the pair does not count as quiet.
"""

import statistics
from datetime import datetime, timedelta, timezone

from .db import audit, iso, now_iso, parse_iso, transaction, utcnow

RULE_ID = "log_source_silent"

CADENCE_WINDOW_SECONDS = 86400
CADENCE_SAMPLE = 100
MIN_GAPS = 10
MIN_HISTORY_SECONDS = 2 * 3600
LATE_MULTIPLIER, LATE_FLOOR_SECONDS = 3, 15 * 60
SILENT_MULTIPLIER, SILENT_FLOOR_SECONDS = 6, 3600
MAX_WINDOW_DAYS = 30  # a maintenance window always ends

THRESHOLDS = {
    "cadence_window_seconds": CADENCE_WINDOW_SECONDS, "cadence_sample": CADENCE_SAMPLE, "min_gaps": MIN_GAPS,
    "min_history_seconds": MIN_HISTORY_SECONDS, "late_multiplier": LATE_MULTIPLIER,
    "late_floor_seconds": LATE_FLOOR_SECONDS, "silent_multiplier": SILENT_MULTIPLIER,
    "silent_floor_seconds": SILENT_FLOOR_SECONDS, "clock": "ingested_at against the wall clock",
}


class WindowError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _epoch(value):
    return parse_iso(value).timestamp()


def _human(seconds):
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        m, r = divmod(s, 60)
        return f"{m}m" + (f"{r}s" if r else "")
    if s < 86400:
        h, r = divmod(s, 3600)
        return f"{h}h" + (f"{r // 60}m" if r // 60 else "")
    d, r = divmod(s, 86400)
    return f"{d}d" + (f"{r // 3600}h" if r // 3600 else "")


def iso_from(epoch):
    return iso(datetime.fromtimestamp(epoch, tz=timezone.utc))


# --- Pure math -----------------------------------------------------------------------------

def baseline(times, index, first_seen):
    """The cadence of a pair as of arrival `times[index]` (epoch seconds, sorted, distinct), or a reason.

    Returns (baseline, None) or (None, reason). The baseline holds the cadence, the longest gap, the
    sample size, and the late/silent thresholds derived from them.
    """
    end = times[index]
    gaps, j = [], index
    while j > 0 and len(gaps) < CADENCE_SAMPLE and times[j - 1] >= end - CADENCE_WINDOW_SECONDS:
        gaps.append(times[j] - times[j - 1])
        j -= 1
    if len(gaps) < MIN_GAPS:
        return None, f"{len(gaps)} gap(s) between arrivals in the last {_human(CADENCE_WINDOW_SECONDS)}; " \
                     f"{MIN_GAPS} needed to learn a cadence"
    if end - first_seen < MIN_HISTORY_SECONDS:
        return None, f"first seen {_human(end - first_seen)} before its last arrival; " \
                     f"{_human(MIN_HISTORY_SECONDS)} of history needed"
    cadence, longest = statistics.median(gaps), max(gaps)
    return {"cadence": cadence, "longest_gap": longest, "samples": len(gaps),
            "late_after": max(LATE_MULTIPLIER * cadence, LATE_FLOOR_SECONDS, longest),
            "silent_after": max(SILENT_MULTIPLIER * cadence, SILENT_FLOOR_SECONDS, 2 * longest)}, None


def quiet_seconds(start, end, windows=()):
    """Seconds in [start, end] outside every maintenance window ((start, end) epoch pairs)."""
    total = max(0.0, end - start)
    covered, cursor = 0.0, start
    for ws, we in sorted(windows):
        ws, we = max(ws, cursor), min(we, end)
        if we > ws:
            covered += we - ws
            cursor = we
    return max(0.0, total - covered)


def judge(times, first_seen, now, windows=()):
    """Status of one pair at `now` (epoch seconds) from its arrival times: healthy, late, silent, or learning."""
    last = times[-1]
    silence = max(0.0, now - last)
    quiet = quiet_seconds(last, max(now, last), windows)
    base, why = baseline(times, len(times) - 1, first_seen)
    out = {"silence_seconds": round(silence, 3), "quiet_seconds": round(quiet, 3), "cadence_seconds": None,
           "longest_gap_seconds": None, "late_after_seconds": None, "silent_after_seconds": None, "samples": 0}
    if base is None:
        return {**out, "status": "learning", "reasons": [why]}
    out.update(cadence_seconds=round(base["cadence"], 3), longest_gap_seconds=round(base["longest_gap"], 3),
               late_after_seconds=round(base["late_after"], 3), silent_after_seconds=round(base["silent_after"], 3),
               samples=base["samples"])
    excused = f" ({_human(silence - quiet)} of it inside a maintenance window)" if silence - quiet >= 1 else ""
    summary = f"cadence {_human(base['cadence'])} (median of {base['samples']} gaps); quiet for {_human(quiet)}{excused}"
    if quiet > base["silent_after"]:
        return {**out, "status": "silent", "reasons": [f"{summary}, past the silent threshold of {_human(base['silent_after'])}"]}
    if quiet > base["late_after"]:
        return {**out, "status": "late", "reasons": [f"{summary}, past the late threshold of {_human(base['late_after'])}"]}
    return {**out, "status": "healthy", "reasons": [f"{summary}; late after {_human(base['late_after'])}"]}


def _windows_for(windows, source, host):
    return [(w["start"], w["end"]) for w in windows
            if w["source"] == source and (w["host"] is None or w["host"] == host)]


def _arrivals(events):
    """Group events by (source, host) into sorted distinct arrivals, keeping the newest event of each."""
    groups = {}
    for e in events:
        key = (e.get("source") or "", e.get("host") or "")
        when = _epoch(e.get("ingested_at") or e["ts"])
        g = groups.setdefault(key, {"by_time": {}, "first_seen": when})
        if e.get("first_seen"):
            g["first_seen"] = min(g["first_seen"], _epoch(e["first_seen"]))
        g["first_seen"] = min(g["first_seen"], when)
        best = g["by_time"].get(when)
        if best is None or e["id"] > best["id"]:
            g["by_time"][when] = e
    return groups


def log_source_silent(events, params):
    """Detection rule: a (source, host) with a learned cadence went silent.

    Events are judged by arrival (`ingested_at`, or `ts` where events carry none, as in the noise lab).
    Each completed gap is judged against the cadence as of its start; with `params["now"]` (injected by the
    engine and the noise lab, never stored) the current silence is judged too. The evidence is the last event
    before the silence, so one silence episode is one finding however often it is rescanned.
    `params["maintenance"]` lists windows ({source, host or None, start, end} as epochs) that excuse quiet time.
    """
    now = _epoch(params["now"]) if params.get("now") else None
    windows = params.get("maintenance") or []
    findings = []
    for (source, host), g in _arrivals(events).items():
        times = sorted(g["by_time"])
        mine = _windows_for(windows, source, host)
        ends = [(i, times[i]) for i in range(1, len(times))]
        if now is not None and now > times[-1]:
            ends.append((len(times), now))
        for i, end in ends:
            base, _ = baseline(times, i - 1, g["first_seen"])
            if base is None:
                continue
            quiet = quiet_seconds(times[i - 1], end, mine)
            if quiet <= base["silent_after"]:
                continue
            last = g["by_time"][times[i - 1]]
            resumed = i < len(times)
            where = f"{source} on {host}" if host else f"{source} (no host)"
            findings.append({
                "group_key": f"{source}|{host}",
                "event_ids": [last["id"]],
                "first_seen": last["ts"], "last_seen": last["ts"],
                "title": f"Log source silent: {where}",
                "explanation": (
                    f"{where} sent events every {_human(base['cadence'])} (median of {base['samples']} gaps between "
                    f"arrivals) until {iso_from(times[i - 1])}, then nothing for {_human(quiet)} outside maintenance "
                    f"windows{' before it resumed' if resumed else ' so far'}. The silent threshold is "
                    f"{_human(base['silent_after'])} ({SILENT_MULTIPLIER}x cadence, at least {_human(SILENT_FLOOR_SECONDS)}, "
                    f"and twice the longest recent gap). A source can stop because a forwarder crashed or because "
                    f"someone stopped it to hide what happens next: check the agent on the host."),
            })
    return findings


# --- Storage -----------------------------------------------------------------------------------

def _pairs(conn, max_id=None, since=None):
    sql = ("SELECT source, host, MIN(ingested_at) AS first_seen, MAX(ingested_at) AS last_seen,"
           " SUM(ingested_at >= ?) AS events_24h, COUNT(*) AS events FROM events")
    args = [since or iso(utcnow() - timedelta(days=1))]
    if max_id is not None:
        sql += " WHERE id <= ?"
        args.append(max_id)
    return [dict(r) for r in conn.execute(sql + " GROUP BY source, host", args)]


def _recent_arrivals(conn, source, host, max_id=None):
    """The newest CADENCE_SAMPLE + 2 distinct arrivals of one pair, oldest first, each with its newest event."""
    sql = ("SELECT ingested_at, MAX(id) AS id, ts, synthetic FROM events WHERE source = ? AND host IS ?"
           + (" AND id <= ?" if max_id is not None else "") +
           " GROUP BY ingested_at ORDER BY ingested_at DESC LIMIT ?")
    args = [source, host] + ([max_id] if max_id is not None else []) + [CADENCE_SAMPLE + 2]
    return [dict(r) for r in conn.execute(sql, args)][::-1]


def arrival_events(conn, max_id):
    """What the rule reads in a detection run: each pair's recent arrivals, as events with source and host.

    Detection runs after every stored batch, so judging each pair's latest gap and its current silence is
    enough to see every episode; older gaps in the sample are judged again but add nothing new.
    """
    out = []
    for p in _pairs(conn, max_id):
        for a in _recent_arrivals(conn, p["source"], p["host"], max_id):
            out.append({**a, "source": p["source"], "host": p["host"], "first_seen": p["first_seen"]})
    return out


def list_windows(conn):
    now = now_iso()
    rows = [dict(r) for r in conn.execute("SELECT * FROM maintenance_windows ORDER BY starts_at DESC, id DESC")]
    for w in rows:
        end = min(w["ends_at"], w["ended_at"]) if w["ended_at"] else w["ends_at"]
        w["effective_end"] = end
        w["active"] = w["starts_at"] <= now < end
    return rows


def _window_epochs(conn):
    return [{"source": w["source"], "host": w["host"], "start": _epoch(w["starts_at"]),
             "end": _epoch(w["effective_end"])} for w in list_windows(conn)]


def clock_params(conn, params, now=None):
    """The params a detection run hands the rule: the wall clock and the maintenance windows (never stored)."""
    return {**params, "now": now or now_iso(), "maintenance": _window_epochs(conn)}


def inventory(conn, now=None):
    """GET /api/sources/health: every (source, host) with its status, cadence, last arrival, and reasons."""
    now = now or now_iso()
    now_s = _epoch(now)
    listed = list_windows(conn)
    windows = [{"source": w["source"], "host": w["host"], "start": _epoch(w["starts_at"]),
                "end": _epoch(w["effective_end"])} for w in listed]
    rows = []
    for p in _pairs(conn, since=iso_from(now_s - 86400)):
        arrivals = _recent_arrivals(conn, p["source"], p["host"])
        times = [_epoch(a["ingested_at"]) for a in arrivals]
        verdict = judge(times, _epoch(p["first_seen"]), now_s, _windows_for(windows, p["source"], p["host"] or ""))
        active = [w for w in listed if w["active"] and w["source"] == p["source"]
                  and (w["host"] is None or w["host"] == p["host"])]
        rows.append({"source": p["source"], "host": p["host"], "first_seen": p["first_seen"],
                     "last_seen": p["last_seen"], "last_event_ts": arrivals[-1]["ts"], "events_24h": p["events_24h"],
                     "events": p["events"], "synthetic": all(a["synthetic"] for a in arrivals),
                     "maintenance": active[0] if active else None, **verdict})
    order = {"silent": 0, "late": 1, "healthy": 2, "learning": 3}
    rows.sort(key=lambda r: (order[r["status"]], r["source"], r["host"] or ""))
    return {"checked_at": now, "thresholds": THRESHOLDS, "sources": rows,
            "summary": {s: sum(r["status"] == s for r in rows) for s in order},
            "maintenance_windows": [w for w in listed if w["effective_end"] > now]}


# --- Maintenance windows (added through a reviewed change request; ended early by an admin) ------

def validate_window(source, payload, now=None):
    """Check a proposed window. Returns (host or None, starts_at, ends_at) in canonical form."""
    from .normalize import EventError, validate_source
    try:
        validate_source(source)
    except EventError as exc:
        raise WindowError(str(exc))
    if not isinstance(payload, dict) or not set(payload) <= {"host", "start", "end"} or \
            not {"start", "end"} <= set(payload):
        raise WindowError("a maintenance window needs start and end (ISO 8601 UTC) and may name a host")
    host = payload.get("host")
    if host is not None and (not isinstance(host, str) or not 0 < len(host) <= 255):
        raise WindowError("host must be 1-255 characters, or omitted for every host of the source")
    try:
        start, end = parse_iso(payload["start"]), parse_iso(payload["end"])
    except (TypeError, ValueError, AttributeError):
        raise WindowError("start and end must be ISO 8601 timestamps")
    if start.tzinfo is None or end.tzinfo is None:
        raise WindowError("start and end must include a time zone (e.g. Z)")
    if end <= start:
        raise WindowError("end must be after start")
    if end - start > timedelta(days=MAX_WINDOW_DAYS):
        raise WindowError(f"a maintenance window lasts at most {MAX_WINDOW_DAYS} days")
    if iso(end) <= (now or now_iso()):
        raise WindowError("end is in the past; a window only excuses silence it covers")
    return host, iso(start), iso(end)


def add_window(conn, source, payload, reason, proposed_by, approved_by, change_request_id):
    host, start, end = validate_window(source, payload)
    window_id = conn.execute(
        "INSERT INTO maintenance_windows(source, host, starts_at, ends_at, reason, proposed_by, approved_by,"
        " change_request_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (source, host, start, end, reason, proposed_by, approved_by, change_request_id, now_iso())).lastrowid
    audit(conn, approved_by, "maintenance_window_added", source,
          {"id": window_id, "host": host, "start": start, "end": end, "change_request": change_request_id})
    return window_id


def end_window(conn, window_id, actor):
    """End a window early. Ending one only makes detection stricter, so it needs no second person."""
    with transaction(conn):
        row = conn.execute("SELECT * FROM maintenance_windows WHERE id = ?", (window_id,)).fetchone()
        if row is None:
            raise WindowError("maintenance window not found", 404)
        now = now_iso()
        if row["ended_at"] is not None or row["ends_at"] <= now:
            raise WindowError("maintenance window has already ended", 409)
        conn.execute("UPDATE maintenance_windows SET ended_at = ?, ended_by = ? WHERE id = ?",
                     (max(now, row["starts_at"]), actor, window_id))
        audit(conn, actor, "maintenance_window_ended", row["source"], {"id": window_id, "host": row["host"]})
    return next(w for w in list_windows(conn) if w["id"] == window_id)
