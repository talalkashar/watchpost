"""Self-diagnosis: component health checks with honest status and recovery guidance.

Status values, worst last: ok < degraded < failing.
"""

import os
import shutil
import sqlite3
import sys
import time
from datetime import timedelta
from pathlib import Path

from .db import iso, now_iso, utcnow
from .diagnostics import describe_exception

STATUS_ORDER = {"ok": 0, "degraded": 1, "failing": 2}
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
LOW_DISK_BYTES = 100 * 1024 * 1024

# Optional components (e.g. the syslog listener) register a check while they run.
# Each check is a no-argument callable returning (status, message, guidance, details).
_COMPONENT_CHECKS = {}


def register_check(name, fn):
    _COMPONENT_CHECKS[name] = fn


def unregister_check(name, fn=None):
    if fn is None or _COMPONENT_CHECKS.get(name) == fn:
        _COMPONENT_CHECKS.pop(name, None)


def _component_checks():
    return [_check(name, fn) for name, fn in list(_COMPONENT_CHECKS.items())]


def _check(name, fn, *args):
    started = time.perf_counter()
    try:
        status, message, guidance, details = fn(*args)
    except Exception as exc:
        status, details = "failing", {}
        message = f"health check raised {describe_exception(exc)}"
        guidance = "The check itself could not run; the component is most likely unavailable. See error details."
    return {
        "name": name, "status": status, "message": message, "guidance": guidance,
        "details": details, "latency_ms": round((time.perf_counter() - started) * 1000, 1),
    }


def check_storage(conn, db_path):
    quick = conn.execute("PRAGMA quick_check").fetchone()[0]
    if quick != "ok":
        return ("failing", f"database integrity check failed: {quick[:120]}",
                "Stop the app, back up the database file, and restore from a known-good copy.", {})
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("INSERT OR REPLACE INTO health_probe(id, written_at) VALUES (1, ?)", (now_iso(),))
        conn.execute("SELECT written_at FROM health_probe WHERE id = 1").fetchone()
    finally:
        conn.execute("ROLLBACK")
    details = {"events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]}
    if db_path != ":memory:":
        free = shutil.disk_usage(Path(db_path).parent).free
        details["free_disk_mb"] = round(free / 1024 / 1024)
        details["db_size_mb"] = round(Path(db_path).stat().st_size / 1024 / 1024, 2)
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
    if last_ever is None:
        return ("ok", "no data ingested yet", "Load demo data or POST events to /api/ingest to get started.",
                details)
    reject_rate = row["rejected"] / row["received"] if row["received"] else 0
    details["reject_rate_24h"] = round(reject_rate, 3)
    if errors:
        return ("degraded", f"{errors} ingestion request(s) failed server-side in the last 24h",
                "Open the Errors list on the Health page for the failure type, then resubmit affected batches.",
                details)
    if row["received"] >= 20 and reject_rate > 0.25:
        return ("degraded", f"{reject_rate:.0%} of records were rejected in the last 24h",
                "Review rejection reasons under Ingest > Recent batches; usually a wrong format or bad timestamps.",
                details)
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
    if enabled == 0:
        return ("degraded", "no detection rules are enabled",
                "Enable at least one rule through a reviewed change request on the Rules page.", details)
    if last is None:
        return "ok", "detection has not run yet (no data)", None, details
    if last["status"] == "failed":
        return ("failing", f"last detection run failed: {last['error']}",
                "Fix the cause shown (usually a rule configuration problem) and use 'Run detection' on the "
                "Health page. Stored events are kept and will be processed on the next successful run.",
                details)
    if last["status"] == "running":
        started = last["started_at"]
        if started < iso(utcnow() - timedelta(minutes=5)):
            return ("degraded", "a detection run has been running for more than 5 minutes",
                    "The process may have crashed mid-run. Restart the app and run detection again.", details)
    if last["correlation"] == "failed":
        return ("degraded", "the last run stored its alerts but could not group them into incidents",
                "Alerts are unaffected. See recent errors (component 'correlation'), fix the cause, and use "
                "'Run detection' to correlate again.", details)
    if failed_batches:
        return ("degraded", f"{failed_batches} batch(es) were ingested while detection was failing",
                "Use 'Run detection' to process them now that detection is healthy.", details)
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
    if db_path != ":memory:" and not os.access(Path(db_path).parent, os.W_OK):
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
    overall = max((c["status"] for c in checks), key=STATUS_ORDER.get)
    return {"status": overall, "checked_at": now_iso(), "checks": checks}
