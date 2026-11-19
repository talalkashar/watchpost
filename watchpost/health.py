"""Self-diagnosis: component health checks with honest status and recovery guidance.

Status values, worst last: ok < degraded < failing.
"""

import os
import shutil
import sqlite3
import sys
import threading
import time
from datetime import timedelta, timezone
from pathlib import Path
from types import MethodType

from .db import iso, now_iso, parse_iso, utcnow
from .diagnostics import describe_exception

STATUS_ORDER = {"ok": 0, "degraded": 1, "failing": 2}
_BUILTIN_CHECKS = frozenset({"storage", "ingestion", "detection", "dependencies"})
_CHECKS_LOCK = threading.Lock()
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
LOW_DISK_BYTES = 100 * 1024 * 1024

# Each check explains both fault states, including while it is healthy.
CHECK_MEANS = {
    "storage": (
        "Failing means the event store cannot be read or written, and degraded means "
        "less than 100 MB of disk space remains."
    ),
    "ingestion": (
        "Failing means the ingest check crashed, and degraded means recent batches were "
        "rejected or failed on the server."
    ),
    "detection": (
        "Failing means the last detection run failed, and degraded means rules are off, "
        "a run is stuck, or batches were skipped."
    ),
    "dependencies": (
        "Failing means Python, SQLite, or a writable database directory is missing, "
        "and degraded means console files are missing."
    ),
    "syslog": (
        "Failing means the listener is down, and degraded means a recent batch was dropped."
    ),
    "storyline": (
        "Failing means the storyline check crashed, and degraded means the last replay failed."
    ),
}
DEFAULT_MEANS = "Failing means the component is down, and degraded means it is running with a fault."


def status_means(name):
    return CHECK_MEANS.get(name, DEFAULT_MEANS)

# Optional components (e.g. the syslog listener) register a check while they run.
# Each check is a no-argument callable returning (status, message, guidance, details).
_COMPONENT_CHECKS = {}


def register_check(name, fn):
    with _CHECKS_LOCK:
        _COMPONENT_CHECKS[name] = fn


def unregister_check(name, fn=None):
    with _CHECKS_LOCK:
        current = _COMPONENT_CHECKS.get(name)
        # Accessing a bound method again creates a new method object.
        same_method = (isinstance(current, MethodType) and isinstance(fn, MethodType)
                       and current.__self__ is fn.__self__ and current.__func__ is fn.__func__)
        if fn is None or current is fn or same_method:
            _COMPONENT_CHECKS.pop(name, None)


def _component_checks():
    with _CHECKS_LOCK:
        registered = list(_COMPONENT_CHECKS.items())
    # Run outside the lock so a check can register another one without deadlocking.
    return [
        _check(name, fn) for name, fn in registered if name not in _BUILTIN_CHECKS
    ]


def _coerce_status(check):
    """Keep an unknown status from crashing the report or looking healthy."""
    status = check.get("status")
    if status in STATUS_ORDER:
        return check
    message = check.get("message") or ""
    check["status"] = "failing"
    check["message"] = f"health check returned unknown status {status!r}: {message}"
    if not check.get("guidance"):
        check["guidance"] = "The check must return ok, degraded, or failing."
    return check


def _check(name, fn, *args):
    started = time.perf_counter()
    try:
        status, message, guidance, details = fn(*args)
    except Exception as exc:
        status, details = "failing", {}
        message = f"health check raised {describe_exception(exc)}"
        guidance = "The check itself could not run; the component is most likely unavailable. See error details."
    return _coerce_status({
        "name": name, "status": status, "message": message, "guidance": guidance,
        "means": status_means(name),
        "details": details, "latency_ms": round((time.perf_counter() - started) * 1000, 1),
    })


def _db_file(db_path):
    # A symlinked SIEM_DB lives on the target volume. SQLite puts the WAL beside that file.
    return Path(db_path).resolve()


def _started_at(value):
    # Compare instants, not text. "2026-06-01T11:55:00Z" sorts after a millisecond cutoff
    # ("Z" > ".") and would hide a stuck run.
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = parse_iso(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def check_storage(conn, db_path):
    row = conn.execute("PRAGMA quick_check").fetchone()
    quick = row[0] if row is not None else None
    if quick != "ok":
        shown = "no result" if quick is None else str(quick)[:120]
        return ("failing", f"database integrity check failed: {shown}",
                "Stop the app, back up the database file, and restore from a known-good copy.", {})
    written = now_iso()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("INSERT OR REPLACE INTO health_probe(id, written_at) VALUES (1, ?)", (written,))
        probed = conn.execute("SELECT written_at FROM health_probe WHERE id = 1").fetchone()
        probe_ok = probed is not None and probed[0] == written
    finally:
        conn.execute("ROLLBACK")
    if not probe_ok:
        return ("failing", "database read probe did not return the row just written",
                "Stop the app, back up the database file, and restore from a known-good copy.", {})
    details = {"events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]}
    if db_path != ":memory:":
        db_file = _db_file(db_path)
        free = shutil.disk_usage(db_file.parent).free
        details["free_disk_mb"] = free // (1024 * 1024)
        details["db_size_mb"] = round(db_file.stat().st_size / 1024 / 1024, 2)
        if free < LOW_DISK_BYTES:
            return ("degraded", "less than 100 MB of disk space left",
                    "Free disk space or move SIEM_DB to a larger volume before ingestion starts failing.",
                    details)
    return "ok", "read/write probe and integrity check passed", None, details


def check_ingestion(conn):
    since = iso(utcnow() - timedelta(hours=24))
    row = conn.execute(
        "SELECT COUNT(*) AS batches, COALESCE(SUM(received),0) AS received, COALESCE(SUM(rejected),0) AS rejected,"
        " MAX(created_at) AS last_batch FROM ingest_batches WHERE created_at >= ?", (since,)
    ).fetchone()
    last_ever = conn.execute("SELECT MAX(created_at) FROM ingest_batches").fetchone()[0]
    errors = conn.execute(
        "SELECT COUNT(*) FROM error_log WHERE component = 'ingestion' AND created_at >= ?", (since,)
    ).fetchone()[0]
    details = {"batches_24h": row["batches"], "received_24h": row["received"],
               "rejected_24h": row["rejected"], "server_errors_24h": errors, "last_batch_at": last_ever}
    received = row["received"] or 0
    rejected = row["rejected"] or 0
    # received == 0 with rejections is a 100% reject rate, not a clean window.
    sample = received if received > 0 else rejected
    reject_rate = rejected / sample if sample else 0
    if last_ever is not None:
        details["reject_rate_24h"] = round(reject_rate, 3)
    if errors:
        return ("degraded", f"{errors} ingestion request(s) failed server-side in the last 24h",
                "Open the Errors list on the Health page for the failure type, then resubmit affected batches.",
                details)
    if last_ever is None:
        return ("ok", "no data ingested yet", "Load demo data or POST events to /api/ingest to get started.",
                details)
    if sample >= 20 and reject_rate > 0.25:
        return ("degraded", f"{reject_rate:.0%} of records were rejected in the last 24h",
                "Review rejection reasons under Ingest > Recent batches; usually a wrong format or bad timestamps.",
                details)
    if row["batches"] == 0:
        return "ok", "no batches in the last 24h", None, details
    return "ok", "ingestion is accepting events", None, details


def check_detection(conn):
    enabled = conn.execute("SELECT COUNT(*) FROM rules WHERE enabled = 1").fetchone()[0]
    last = conn.execute("SELECT * FROM detection_runs ORDER BY id DESC LIMIT 1").fetchone()
    last_ok = conn.execute(
        "SELECT finished_at FROM detection_runs WHERE status = 'ok' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    # A successful full scan marks earlier failed batches as 'recovered'.
    failed_batches = conn.execute(
        "SELECT COUNT(*) FROM ingest_batches WHERE detection_status = 'failed'"
    ).fetchone()[0]
    details = {
        "enabled_rules": enabled,
        "last_run": dict(last) if last else None,
        "last_successful_run_at": last_ok["finished_at"] if last_ok else None,
        "unprocessed_failed_batches": failed_batches,
    }
    running_now = False
    if last is not None and last["status"] == "failed":
        error = last["error"] or "no error was recorded"
        return ("failing", f"last detection run failed: {error}",
                "Fix the cause shown (usually a rule configuration problem) and use 'Run detection' on the "
                "Health page. Stored events are kept and will be processed on the next successful run.",
                details)
    if last is not None and last["status"] == "running":
        started = _started_at(last["started_at"])
        restart = "The process may have crashed mid-run. Restart the app and run detection again."
        if started is None:
            return ("degraded", "a detection run is marked running but its start time cannot be read",
                    restart, details)
        # Exactly 5 minutes is still recent. Only an earlier start is stuck.
        if started < utcnow() - timedelta(minutes=5):
            return ("degraded", "a detection run has been running for more than 5 minutes",
                    restart, details)
        running_now = True
    if enabled == 0:
        return ("degraded", "no detection rules are enabled",
                "Enable at least one rule through a reviewed change request on the Rules page.", details)
    if last is None:
        return "ok", "detection has not run yet (no data)", None, details
    if last["status"] not in ("ok", "running"):
        return ("degraded", f"the last detection run ended with an unexpected status: {last['status']}",
                "Use 'Run detection' on the Health page. Stored events are kept.", details)
    if last["correlation"] == "failed":
        return ("degraded", "the last run stored its alerts but could not group them into incidents",
                "Alerts are unaffected. See recent errors (component 'correlation'), fix the cause, and use "
                "'Run detection' to correlate again.", details)
    if failed_batches:
        return ("degraded", f"{failed_batches} batch(es) were ingested while detection was failing",
                "Use 'Run detection' to process them now that detection is healthy.", details)
    if running_now:
        return "ok", "a detection run is in progress", None, details
    return "ok", "last detection run succeeded", None, details


def check_dependencies(db_path):
    details = {
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "static_assets": (STATIC_DIR / "index.html").exists() and (STATIC_DIR / "app.js").exists(),
    }
    problems = []
    if sys.version_info < (3, 10):
        problems.append("Python 3.10+ is required")
    if sqlite3.sqlite_version_info < (3, 35, 0):
        problems.append("SQLite 3.35+ is required")
    if not details["static_assets"]:
        problems.append("web UI files are missing from static/")
    if db_path != ":memory:":
        parent = _db_file(db_path).parent
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            problems.append("the database directory is not writable")
    if problems:
        status = "failing" if any("required" in p or "writable" in p for p in problems) else "degraded"
        return (status, "; ".join(problems),
                "Install the required runtime version or restore the missing files, then restart.", details)
    return "ok", "runtime and bundled assets present (no external services required)", None, details


def run_health_checks(open_conn, db_path):
    """`open_conn` is a callable so a storage outage is reported rather than crashing the check."""
    try:
        conn = open_conn()
    except Exception as exc:
        failing = {
            "name": "storage", "status": "failing",
            "message": f"cannot open database: {describe_exception(exc)}",
            "guidance": "Check that SIEM_DB points to a writable location and the disk is not full, then restart.",
            "means": status_means("storage"),
            "details": {}, "latency_ms": 0,
        }
        checks = [failing, _check("dependencies", check_dependencies, db_path), *_component_checks()]
        return {"status": "failing", "checked_at": now_iso(), "checks": checks}
    try:
        checks = [
            _check("storage", check_storage, conn, db_path),
            _check("ingestion", check_ingestion, conn),
            _check("detection", check_detection, conn),
            _check("dependencies", check_dependencies, db_path),
            *_component_checks(),
        ]
    finally:
        conn.close()
    for check in checks:
        _coerce_status(check)
    overall = max((c["status"] for c in checks), key=STATUS_ORDER.__getitem__)
    return {"status": overall, "checked_at": now_iso(), "checks": checks}
