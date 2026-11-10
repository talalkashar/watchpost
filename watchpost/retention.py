"""Tiered retention: recent events in the database, older ones in compressed files, the oldest elsewhere.

Off unless SIEM_RETENTION_HOT_DAYS is set: by default Watchpost keeps every event in the database and
deletes nothing.

- hot: the events table. Searchable, hunted and read by detection. Events stay SIEM_RETENTION_HOT_DAYS.
- warm: one gzip file of JSON lines per day, in SIEM_ARCHIVE_DIR. Searchable one day at a time, slowly.
- cold: the same files, moved to SIEM_COLD_DIR (meant to be cheaper or separate storage) once they are
  SIEM_RETENTION_WARM_DAYS old. Listed and verified, not searchable until brought back.
- deleted: SIEM_RETENTION_TOTAL_DAYS after arrival the file is removed. Its manifest row stays, as the
  record of what was disposed of and when.

Age counts from arrival (`ingested_at`), not from the event's own timestamp, and a day is the UTC day of
arrival. Nothing therefore leaves a tier sooner than the configured time after Watchpost received it,
whatever clock the sender had. Back-filled old data is kept longer, never shorter.

Order of work, so that a failure never loses an event: write the day's file, read it back and check
it, record it, and only then delete the rows. A move to cold copies, checks the copy, then removes the
original. Each file's SHA-256 goes into the manifest (table `archives`) and into the audit log, whose
hash chain makes a later swap of the file detectable.

What stays in the database:
- Events that are evidence of an alert. They are written to the archive like the rest and not deleted,
  so alerts and incidents keep their evidence.
- Anything the enabled rules still read. The hot window is never shorter than the longest history a
  rule looks back over, whatever SIEM_RETENTION_HOT_DAYS says.

This is retention for a lab on one disk: the files are not encrypted, and the cold directory is only as
separate as the operator makes it.
"""

import gzip
import hashlib
import json
import logging
import math
import os
import shutil
import threading
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import health, rules as rules_mod
from .db import audit, iso, now_iso, row_to_dict, transaction, utcnow
from .queries import QueryError

log = logging.getLogger("watchpost.retention")

DELETE_CHUNK = 5000          # rows per transaction, so ingestion is never locked out for long
SEARCH_LIMIT = 500
THAW_DAYS = 7                # how long an archive brought back from cold stays warm
SEARCH_FIELDS = ("id", "ts", "ingested_at", "source", "host", "event_type", "outcome", "severity", "user",
                 "src_ip", "dest_ip", "dest_port", "message", "synthetic")


class RetentionError(QueryError):
    pass


class Policy(namedtuple("Policy", "hot_days warm_days total_days archive_dir cold_dir")):
    """The configured tiers. warm_days None: archives never go cold. total_days None: never deleted."""

    @classmethod
    def from_config(cls, config):
        """The policy, or None when retention is off. Raises ValueError on settings that contradict each other."""
        hot, warm, total = config.retention_hot_days, config.retention_warm_days, config.retention_total_days
        if hot is None:
            if warm is not None or total is not None:
                raise ValueError("SIEM_RETENTION_WARM_DAYS and SIEM_RETENTION_TOTAL_DAYS need SIEM_RETENTION_HOT_DAYS")
            return None
        if hot < 1:
            raise ValueError("SIEM_RETENTION_HOT_DAYS must be at least 1")
        if warm is not None and warm <= hot:
            raise ValueError("SIEM_RETENTION_WARM_DAYS must be greater than SIEM_RETENTION_HOT_DAYS")
        if total is not None and total <= (warm if warm is not None else hot):
            raise ValueError("SIEM_RETENTION_TOTAL_DAYS must be greater than the hot and warm periods")
        if config.db_path == ":memory:" and not config.archive_dir:
            raise ValueError("an in-memory database needs SIEM_ARCHIVE_DIR for retention")
        archive = Path(config.archive_dir or Path(config.db_path).parent / "archive")
        return cls(hot, warm, total, archive, Path(config.cold_dir or archive / "cold"))

    def describe(self):
        return {"hot_days": self.hot_days, "warm_days": self.warm_days, "total_days": self.total_days}


# --- files ---------------------------------------------------------------------------

def _file_name(day):
    return f"events-{day}.jsonl.gz"


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _lines(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)


def _write(rows, path):
    """Write rows as gzip JSON lines to a temporary file next to `path`. Returns (tmp path, facts about it)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    facts = {"events": 0, "synthetic_events": 0, "first_id": None, "last_id": None, "first_ts": None, "last_ts": None}
    with open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as packed:
        for row in rows:
            record = dict(row)
            packed.write(json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            facts["events"] += 1
            facts["synthetic_events"] += 1 if record["synthetic"] else 0
            facts["first_id"] = record["id"] if facts["first_id"] is None else facts["first_id"]
            facts["last_id"] = record["id"]
            facts["first_ts"] = min(facts["first_ts"] or record["ts"], record["ts"])
            facts["last_ts"] = max(facts["last_ts"] or record["ts"], record["ts"])
        packed.flush()
        raw.flush()
        os.fsync(raw.fileno())
    return tmp, facts


def _copy_checked(source, target, sha256):
    """Copy a file and prove the copy is the same before it replaces anything."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    shutil.copyfile(source, tmp)
    with open(tmp, "rb") as handle:
        os.fsync(handle.fileno())
    if _sha256(tmp) != sha256:
        tmp.unlink(missing_ok=True)
        raise OSError("the copy does not match the original")
    os.replace(tmp, target)


def _path(policy, row):
    return (policy.cold_dir if row["tier"] == "cold" else policy.archive_dir) / row["file"]


# --- one run -------------------------------------------------------------------------

def _day_range(day):
    start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return iso(start), iso(start + timedelta(days=1))


def hot_days_in_force(conn, policy):
    """The hot period actually applied: the configured one, or longer if an enabled rule reads further back."""
    enabled = [row_to_dict(r, ["params"]) for r in conn.execute("SELECT id, params FROM rules WHERE enabled = 1")]
    needed = math.ceil((rules_mod.history_seconds(enabled) + rules_mod.lookback_seconds(enabled)) / 86400) + 1
    return max(policy.hot_days, needed)


def _archive_day(conn, policy, day, summary):
    """Write one arrival day to a warm file (unless it has one) and delete its rows from the database."""
    start, end = _day_range(day)
    manifest = conn.execute("SELECT * FROM archives WHERE day = ?", (day,)).fetchone()
    if manifest is None:
        path = policy.archive_dir / _file_name(day)
        rows = conn.execute("SELECT * FROM events WHERE ingested_at >= ? AND ingested_at < ? ORDER BY id", (start, end))
        tmp, facts = _write(rows, path)
        try:
            if sum(1 for _ in _lines(tmp)) != facts["events"]:
                raise OSError("the archive does not read back with the events that were written")
            sha256, size = _sha256(tmp), tmp.stat().st_size
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
        with transaction(conn):
            conn.execute(
                "INSERT INTO archives(day, tier, file, events, synthetic_events, first_id, last_id, first_ts, last_ts,"
                " bytes, sha256, created_at, verified_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (day, "warm", path.name, facts["events"], facts["synthetic_events"], facts["first_id"], facts["last_id"],
                 facts["first_ts"], facts["last_ts"], size, sha256, now_iso(), now_iso()))
            audit(conn, "retention", "archive_created", day, {"events": facts["events"], "sha256": sha256, "file": path.name})
        manifest = conn.execute("SELECT * FROM archives WHERE day = ?", (day,)).fetchone()
        summary["archived_days"] += 1
        summary["archived_events"] += facts["events"]
    # Only rows the file holds, and never the evidence of an alert.
    removable = ("FROM events WHERE ingested_at >= ? AND ingested_at < ? AND id BETWEEN ? AND ?"
                 " AND id NOT IN (SELECT event_id FROM alert_events)")
    bounds = (start, end, manifest["first_id"] or 0, manifest["last_id"] or 0)
    if not conn.execute(f"SELECT 1 {removable} LIMIT 1", bounds).fetchone():
        return   # an earlier run finished this day; what is left is evidence
    if manifest["tier"] == "deleted" or _sha256(_path(policy, manifest)) != manifest["sha256"]:
        # Rows of a day whose archive is gone or altered are the only copy left: they stay.
        raise OSError("this day's archive is missing or does not match its recorded hash; its events were left in the database")
    while True:
        with transaction(conn):
            removed = conn.execute(f"DELETE FROM events WHERE id IN (SELECT id {removable} LIMIT {DELETE_CHUNK})", bounds).rowcount
        summary["removed_from_hot"] += removed
        if removed < DELETE_CHUNK:
            break
    summary["kept_as_evidence"] += conn.execute(
        "SELECT COUNT(*) FROM events WHERE ingested_at >= ? AND ingested_at < ? AND id IN (SELECT event_id FROM alert_events)",
        (start, end)).fetchone()[0]


def _to_cold(conn, policy, row, summary):
    source, target = policy.archive_dir / row["file"], policy.cold_dir / row["file"]
    if _sha256(source) != row["sha256"]:
        raise OSError("the warm file does not match its recorded hash; it was not moved")
    _copy_checked(source, target, row["sha256"])
    with transaction(conn):
        conn.execute("UPDATE archives SET tier = 'cold', moved_at = ?, warm_until = NULL, problem = NULL WHERE day = ?",
                     (now_iso(), row["day"]))
        audit(conn, "retention", "archive_moved_to_cold", row["day"], {"sha256": row["sha256"]})
    source.unlink(missing_ok=True)
    summary["moved_to_cold"] += 1


def _expire(conn, policy, row, summary):
    with transaction(conn):
        conn.execute("UPDATE archives SET tier = 'deleted', deleted_at = ?, problem = NULL WHERE day = ?", (now_iso(), row["day"]))
        audit(conn, "retention", "archive_deleted", row["day"],
              {"events": row["events"], "sha256": row["sha256"], "retention_days": policy.total_days})
    _path(policy, row).unlink(missing_ok=True)
    summary["deleted_archives"] += 1
    summary["deleted_events"] += row["events"]


_RUNNING = threading.Lock()   # one run at a time in this process: the timer and an admin's "run now" can meet


def run(conn, policy, now=None):
    """Apply the policy once. Returns what was done; a day that fails is reported and the rest carry on."""
    _require(policy)
    if not _RUNNING.acquire(blocking=False):
        raise RetentionError("a retention run is already in progress", 409)
    try:
        return _run(conn, policy, now or utcnow())
    finally:
        _RUNNING.release()


def _run(conn, policy, now):
    hot_days = hot_days_in_force(conn, policy)
    summary = {"started_at": iso(now), "hot_days_in_force": hot_days, "archived_days": 0, "archived_events": 0,
               "removed_from_hot": 0, "kept_as_evidence": 0, "moved_to_cold": 0, "deleted_archives": 0,
               "deleted_events": 0, "errors": []}

    def day_before(days):
        return (now - timedelta(days=days)).strftime("%Y-%m-%d")

    def attempt(what, day, action, *args):
        try:
            action(conn, policy, *args, summary)
        except (OSError, ValueError) as exc:
            problem = f"{what} {day}: {exc}"
            summary["errors"].append(problem)
            conn.execute("UPDATE archives SET problem = ? WHERE day = ?", (str(exc)[:300], day))
            log.error("retention: %s", problem)

    hot_cutoff = day_before(hot_days)   # arrival days before this one leave the database
    days = [r[0] for r in conn.execute(
        "SELECT DISTINCT substr(ingested_at, 1, 10) FROM events WHERE ingested_at < ? ORDER BY 1", (_day_range(hot_cutoff)[0],))]
    for day in days:
        attempt("archiving", day, _archive_day, day)
    if policy.warm_days is not None:
        for row in conn.execute("SELECT * FROM archives WHERE tier = 'warm' AND day < ? AND (warm_until IS NULL OR warm_until < ?)"
                                " ORDER BY day", (day_before(policy.warm_days), iso(now))).fetchall():
            attempt("moving to cold", row["day"], _to_cold, row)
    if policy.total_days is not None:
        for row in conn.execute("SELECT * FROM archives WHERE tier IN ('warm', 'cold') AND day < ? ORDER BY day",
                                (day_before(policy.total_days),)).fetchall():
            attempt("deleting", row["day"], _expire, row)
    summary["finished_at"] = now_iso()
    conn.execute("INSERT INTO meta(key, value) VALUES ('retention_last_run', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (json.dumps(summary),))
    return summary


# --- looking at the archives ---------------------------------------------------------

def verify(conn, policy):
    """Recompute every stored file's hash against the manifest. Returns the problems found."""
    problems = []
    for row in conn.execute("SELECT * FROM archives WHERE tier IN ('warm', 'cold') ORDER BY day").fetchall():
        path = _path(policy, row)
        try:
            problem = None if _sha256(path) == row["sha256"] else "the file does not match its recorded hash"
        except OSError:
            problem = "the file is missing or cannot be read"
        conn.execute("UPDATE archives SET verified_at = ?, problem = ? WHERE day = ?", (now_iso(), problem, row["day"]))
        if problem:
            problems.append({"day": row["day"], "tier": row["tier"], "problem": problem})
    return problems


def status(conn, policy):
    """The policy, what each tier holds, and the last run. Works with retention off (policy None)."""
    hot = conn.execute("SELECT COUNT(*), MIN(ingested_at) FROM events").fetchone()
    archives = [dict(r) for r in conn.execute("SELECT * FROM archives ORDER BY day DESC LIMIT 1000")]
    tiers = {tier: {"archives": 0, "events": 0, "bytes": 0} for tier in ("warm", "cold", "deleted")}
    for row in conn.execute("SELECT tier, COUNT(*), SUM(events), SUM(bytes) FROM archives GROUP BY tier"):
        tiers[row[0]] = {"archives": row[1], "events": row[2], "bytes": row[3] if row[0] != "deleted" else 0}
    last = conn.execute("SELECT value FROM meta WHERE key = 'retention_last_run'").fetchone()
    return {"enabled": policy is not None,
            "policy": {**policy.describe(), "hot_days_in_force": hot_days_in_force(conn, policy)} if policy else None,
            "hot": {"events": hot[0], "oldest_arrival": hot[1]}, "tiers": tiers, "archives": archives,
            "last_run": json.loads(last[0]) if last else None}


def _archive(conn, day):
    row = conn.execute("SELECT * FROM archives WHERE day = ?", (day,)).fetchone()
    if row is None:
        raise RetentionError("no archive for that day", 404)
    return row


def search(conn, policy, day, params):
    """Scan one warm day. Filters: user, ip, host, event_type (exact, case-insensitive) and q (text in the message)."""
    _require(policy)
    row = _archive(conn, day)
    if row["tier"] != "warm":
        raise RetentionError("that archive was deleted at the end of its retention period" if row["tier"] == "deleted"
                             else "that archive is in cold storage; an admin can bring it back to warm first", 409)
    wanted = {name: str(params[name]).lower() for name in ("user", "host", "event_type") if params.get(name)}
    address, text = str(params.get("ip") or "").lower(), str(params.get("q") or "").lower()
    try:
        limit = min(max(int(params.get("limit", 100)), 1), SEARCH_LIMIT)
    except (TypeError, ValueError):
        raise RetentionError("limit must be a number") from None
    scanned, matched, found = 0, 0, []
    try:
        for event in _lines(policy.archive_dir / row["file"]):
            scanned += 1
            if any(str(event.get(name) or "").lower() != value for name, value in wanted.items()):
                continue
            if address and address not in (str(event.get("src_ip") or "").lower(), str(event.get("dest_ip") or "").lower()):
                continue
            if text and text not in str(event.get("message") or "").lower():
                continue
            matched += 1
            if len(found) < limit:
                found.append({name: event.get(name) for name in SEARCH_FIELDS})
    except (OSError, ValueError, EOFError) as exc:
        raise RetentionError(f"the archive could not be read ({type(exc).__name__}); run a verification", 500) from None
    return {"day": day, "scanned": scanned, "matched": matched, "events": found, "truncated": matched > len(found)}


def thaw(conn, policy, day, actor):
    """Bring a cold archive back to warm for THAW_DAYS, so it can be searched."""
    _require(policy)
    row = _archive(conn, day)
    if row["tier"] != "cold":
        raise RetentionError("only an archive in cold storage can be brought back", 409)
    try:
        _copy_checked(policy.cold_dir / row["file"], policy.archive_dir / row["file"], row["sha256"])
    except OSError as exc:
        raise RetentionError(f"the cold file could not be brought back: {exc}", 500) from None
    until = iso(utcnow() + timedelta(days=THAW_DAYS))
    with transaction(conn):
        conn.execute("UPDATE archives SET tier = 'warm', warm_until = ?, problem = NULL WHERE day = ?", (until, day))
        audit(conn, actor, "archive_brought_back", day, {"warm_until": until})
    (policy.cold_dir / row["file"]).unlink(missing_ok=True)
    return dict(_archive(conn, day))


def _require(policy):
    if policy is None:
        raise RetentionError("retention is off (SIEM_RETENTION_HOT_DAYS is not set)", 409)


# --- the scheduled job ---------------------------------------------------------------

class Service:
    """Runs the policy on a timer in its own thread, and reports on it in the health checks."""

    def __init__(self, connect, policy, interval_seconds=3600):
        self.connect, self.policy, self.interval = connect, policy, interval_seconds
        self._stop, self._thread = threading.Event(), None

    def start(self):
        health.register_check("retention", self.health_check)
        self._thread = threading.Thread(target=self._loop, name="retention", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        health.unregister_check("retention", self.health_check)
        if self._thread is not None:
            self._thread.join(30)

    def _loop(self):
        delay = min(60, self.interval)   # the first run comes soon after start, the rest on the interval
        while not self._stop.wait(delay):
            self.run_once()
            delay = self.interval

    def run_once(self):
        conn = self.connect()
        try:
            return run(conn, self.policy)
        except RetentionError:
            return None            # an admin's run is in progress; the next tick will do
        except Exception as exc:   # the thread must outlive a locked database or a full disk
            log.error("retention run failed: %s", type(exc).__name__)
            return None
        finally:
            conn.close()

    def health_check(self):
        conn = self.connect()
        try:
            last = conn.execute("SELECT value FROM meta WHERE key = 'retention_last_run'").fetchone()
            broken = conn.execute("SELECT COUNT(*) FROM archives WHERE problem IS NOT NULL AND tier != 'deleted'").fetchone()[0]
        finally:
            conn.close()
        details = {**self.policy.describe(), "archives_with_problems": broken}
        errors = json.loads(last[0])["errors"] if last else []
        if broken or errors:
            return ("degraded", f"{broken} archive(s) with a problem, {len(errors)} error(s) in the last run",
                    "Open Admin > Retention, run a verification, and check the archive and cold directories.", details)
        if not os.access(self.policy.archive_dir if self.policy.archive_dir.exists() else self.policy.archive_dir.parent, os.W_OK):
            return ("failing", "the archive directory cannot be written",
                    "Check SIEM_ARCHIVE_DIR and its permissions. No event leaves the database until it can be archived.", details)
        return "ok", "retention ran without errors" if last else "retention is on; the first run is pending", None, details


def start_if_enabled(app):
    """Called from main.py. Returns the running service, or None when retention is off."""
    policy = Policy.from_config(app.config)
    if policy is None:
        return None
    log.info("Retention: hot %s days, cold after %s, deleted after %s", policy.hot_days, policy.warm_days or "never",
             policy.total_days or "never")
    return Service(app.conn, policy, app.config.retention_interval_minutes * 60).start()
