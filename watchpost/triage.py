"""Alert triage metrics: time to acknowledge (MTTA), time to resolve (MTTR) and SLA breaches per severity.

Every duration starts at the alert's created_at and ends at acknowledged_at or resolved_at. All three are
wall-clock times of this instance, so the numbers stay honest when replayed synthetic events carry older
timestamps. Alerts only: incidents are out of scope here.
"""

import math
from datetime import timedelta

from .db import iso, now_iso, parse_iso, utcnow
from .normalize import SEVERITIES
from .queries import QueryError

# Per-severity targets in minutes, from alert creation. An alert breaches when the time taken (or, while it
# is still pending, the time elapsed so far) is strictly greater than the target.
SLA_TARGETS = {
    "critical": {"ack": 15, "resolve": 4 * 60},
    "high": {"ack": 60, "resolve": 24 * 60},
    "medium": {"ack": 4 * 60, "resolve": 3 * 24 * 60},
    "low": {"ack": 24 * 60, "resolve": 7 * 24 * 60},
    "info": {"ack": 24 * 60, "resolve": 7 * 24 * 60},
}
WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
           "90d": timedelta(days=90), "all": None}
DEFAULT_WINDOW = "30d"


def median(values):
    values = sorted(values)
    n = len(values)
    if not n:
        return None
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def percentile(values, q):
    """Nearest-rank percentile: the smallest value with at least q of the samples at or below it."""
    values = sorted(values)
    if not values:
        return None
    return values[max(0, math.ceil(q * len(values)) - 1)]


def summarize(minutes):
    if not minutes:
        return {"samples": 0, "mean_minutes": None, "median_minutes": None, "p90_minutes": None}
    return {"samples": len(minutes), "mean_minutes": round(sum(minutes) / len(minutes), 1),
            "median_minutes": round(median(minutes), 1), "p90_minutes": round(percentile(minutes, 0.9), 1)}


def _minutes(start, end):
    return (end - start).total_seconds() / 60


def breaches(alert, now):
    """Which targets this alert missed or is missing: a list holding "ack" and/or "resolve".

    A pending step counts the time elapsed until `now`. An alert that left `open` before acknowledged_at
    existed has no ack time, so its ack is never judged.
    """
    target = SLA_TARGETS.get(alert["severity"])
    if target is None:
        return []
    created = parse_iso(alert["created_at"])
    found = []
    if alert["acknowledged_at"]:
        ack = _minutes(created, parse_iso(alert["acknowledged_at"]))
    else:
        ack = _minutes(created, now) if alert["status"] == "open" else None
    if ack is not None and ack > target["ack"]:
        found.append("ack")
    if alert["resolved_at"]:
        resolve = _minutes(created, parse_iso(alert["resolved_at"]))
    else:
        resolve = _minutes(created, now) if alert["status"] != "resolved" else None
    if resolve is not None and resolve > target["resolve"]:
        found.append("resolve")
    return found


def pending_breaches(alert, now):
    """For the alert list: only targets an unresolved alert is missing right now (a late ack already given
    is history, shown in the metrics, not a badge)."""
    if alert["status"] == "resolved":
        return []
    return [b for b in breaches(alert, now) if b == "resolve" or alert["status"] == "open"]


def triage_metrics(conn, window=None, now=None):
    window = window or DEFAULT_WINDOW
    if window not in WINDOWS:
        raise QueryError(f"window must be one of {', '.join(WINDOWS)}")
    now = now or utcnow()
    since = iso(now - WINDOWS[window]) if WINDOWS[window] else None
    rows = conn.execute("SELECT severity, status, created_at, acknowledged_at, resolved_at, synthetic FROM alerts"
                        + (" WHERE created_at >= ?" if since else ""), (since,) if since else ()).fetchall()
    severities = []
    for sev in reversed(SEVERITIES):  # most severe first
        group = [r for r in rows if r["severity"] == sev]
        target = SLA_TARGETS[sev]
        missed = [breaches(r, now) for r in group]
        severities.append({
            "severity": sev,
            "count": len(group),
            "open": sum(r["status"] == "open" for r in group),
            "unresolved": sum(r["status"] != "resolved" for r in group),
            # Left `open` before 7.0 recorded acknowledgements: excluded from MTTA and ack breaches.
            "ack_unknown": sum(r["status"] != "open" and not r["acknowledged_at"] for r in group),
            "mtta": summarize([_minutes(parse_iso(r["created_at"]), parse_iso(r["acknowledged_at"]))
                               for r in group if r["acknowledged_at"]]),
            "mttr": summarize([_minutes(parse_iso(r["created_at"]), parse_iso(r["resolved_at"]))
                               for r in group if r["resolved_at"]]),
            "sla": {"ack_target_minutes": target["ack"], "resolve_target_minutes": target["resolve"],
                    "ack_breaches": sum("ack" in m for m in missed),
                    "resolve_breaches": sum("resolve" in m for m in missed)},
        })
    synthetic = sum(1 for r in rows if r["synthetic"])
    return {
        "generated_at": now_iso(),
        "window": window,
        "since": since,
        "alerts": len(rows),
        "synthetic": "none" if not synthetic else "all" if synthetic == len(rows) else "some",
        "synthetic_alerts": synthetic,
        "percentile_method": "nearest-rank",
        "sla_targets_minutes": SLA_TARGETS,
        "severities": severities,
    }
