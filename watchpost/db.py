"""SQLite storage: connection handling and schema."""

import hashlib
import hmac
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 15

# prev_hash of the first audit entry. Every later entry links to the hash of the one before it.
GENESIS_HASH = "0" * 64
AUDIT_FIELDS = ("id", "created_at", "actor", "action", "target", "detail")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    source TEXT NOT NULL,
    host TEXT,
    event_type TEXT NOT NULL,
    outcome TEXT,
    severity TEXT NOT NULL,
    user TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    message TEXT,
    raw TEXT,
    synthetic INTEGER NOT NULL DEFAULT 0,
    batch_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user, ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_batch ON events(batch_id);
-- 6.0: indexes for the hot read paths, chosen from EXPLAIN QUERY PLAN on a 100k-event load test
-- (scripts/loadtest.py). User and host filters compare case-insensitively, which the BINARY indexes
-- cannot serve; the NOCASE ones also serve `user LIKE 'prefix%'` and `host LIKE 'prefix%'`. dest_ip lets
-- `(src_ip = ? OR dest_ip = ?)` use two index lookups instead of a scan. ingested_at and synthetic back
-- the dashboard and metrics counts. idx_events_host stays for exact (source, host) reads.
CREATE INDEX IF NOT EXISTS idx_events_user_nocase ON events(user COLLATE NOCASE, ts);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host, ts);
CREATE INDEX IF NOT EXISTS idx_events_host_nocase ON events(host COLLATE NOCASE, ts);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, ts);
CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ingested_at);
CREATE INDEX IF NOT EXISTS idx_events_synthetic ON events(synthetic);
-- 10.0: log source health reads each (source, host) pair's arrivals, newest first (watchpost/sources.py).
CREATE INDEX IF NOT EXISTS idx_events_source_host ON events(source, host, ingested_at);
-- Source equality compares with COLLATE NOCASE (ASCII), the same way host does. Grouping by source
-- stays exact and still reads the stored spelling. A source prefix uses this index too.
CREATE INDEX IF NOT EXISTS idx_events_source_nocase ON events(source COLLATE NOCASE, ts);
-- Outcome equality compares with COLLATE NOCASE (ASCII). Grouping by outcome stays exact.
-- An outcome prefix uses this index too.
CREATE INDEX IF NOT EXISTS idx_events_outcome_nocase ON events(outcome COLLATE NOCASE, ts);
-- batch_id equality compares with COLLATE NOCASE (ASCII). A stored uuid hex matches ABCDEF….
-- Grouping by batch_id stays the stored spelling. A prefix uses this index too.
-- Exact batch reads (ingest publish) still use idx_events_batch.
CREATE INDEX IF NOT EXISTS idx_events_batch_nocase ON events(batch_id COLLATE NOCASE, ts);

CREATE TABLE IF NOT EXISTS ingest_batches (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL,
    format TEXT NOT NULL,
    received INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    rejected INTEGER NOT NULL,
    errors TEXT NOT NULL,
    synthetic INTEGER NOT NULL DEFAULT 0,
    submitted_by TEXT NOT NULL,
    detection_status TEXT NOT NULL
);
-- Health counts recent batches; detection recovery updates failed ones by time.
CREATE INDEX IF NOT EXISTS idx_ingest_batches_created ON ingest_batches(created_at);
CREATE INDEX IF NOT EXISTS idx_ingest_batches_detection ON ingest_batches(detection_status, created_at);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    params TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    params TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    approved_by TEXT,
    change_request_id INTEGER,
    note TEXT
);
-- One rule's versions, newest first (watchpost/improve.py list_rule_history).
CREATE INDEX IF NOT EXISTS idx_rule_history_rule ON rule_history(rule_id, version);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    group_key TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    disposition TEXT,
    assignee TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    synthetic INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_group ON alerts(rule_id, group_key);
-- Alert list rule_id compares with COLLATE NOCASE (ASCII). The group index stays exact.
CREATE INDEX IF NOT EXISTS idx_alerts_rule_nocase ON alerts(rule_id COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id);

CREATE TABLE IF NOT EXISTS alert_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
-- Alert detail reads one alert's notes, newest id first.
CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes(alert_id, id);

CREATE TABLE IF NOT EXISTS alert_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
-- Alert detail reads one alert's activity, newest id first.
CREATE INDEX IF NOT EXISTS idx_alert_activity_alert ON alert_activity(alert_id, id);

CREATE TABLE IF NOT EXISTS detection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trigger TEXT NOT NULL,
    status TEXT NOT NULL,
    events_scanned INTEGER NOT NULL DEFAULT 0,
    alerts_created INTEGER NOT NULL DEFAULT 0,
    alerts_updated INTEGER NOT NULL DEFAULT 0,
    max_event_id INTEGER,
    error TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
-- Login deletes expired sessions; the session list keeps ones that have not expired.
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- 8.0: the password step of a login for an account with TOTP enrolled. Short-lived; only the hash is stored.
CREATE TABLE IF NOT EXISTS mfa_pending (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    role TEXT NOT NULL DEFAULT 'analyst',
    capabilities TEXT NOT NULL DEFAULT '["ingest"]',
    expires_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS change_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    payload TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    evaluation TEXT,
    created_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_note TEXT
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    trigger TEXT NOT NULL,
    created_by TEXT NOT NULL,
    change_request_id INTEGER,
    results TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS error_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    component TEXT NOT NULL,
    message TEXT NOT NULL,
    guidance TEXT
);
-- Health counts one component's recent errors.
CREATE INDEX IF NOT EXISTS idx_error_log_component ON error_log(component, created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    prev_hash TEXT,
    hash TEXT
);

CREATE TABLE IF NOT EXISTS health_probe (id INTEGER PRIMARY KEY, written_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    entities TEXT NOT NULL,
    stages TEXT NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    synthetic INTEGER NOT NULL DEFAULT 0,
    assignee TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS incident_alerts (
    alert_id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    added_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident ON incident_alerts(incident_id);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind TEXT NOT NULL,
    criticality TEXT NOT NULL,
    data_tags TEXT NOT NULL,
    addresses TEXT NOT NULL,
    owner TEXT,
    description TEXT,
    synthetic INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    group_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    change_request_id INTEGER,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON suppressions(rule_id, group_key);

-- 12.0: reviewed, time-bounded suppression of every finding from one rule. The row remains as history after
-- expiry or an admin ends it early.
CREATE TABLE IF NOT EXISTS rule_suppression_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    change_request_id INTEGER,
    created_at TEXT NOT NULL,
    ended_at TEXT,
    ended_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_rule_suppression_windows_active
    ON rule_suppression_windows(rule_id, starts_at, expires_at);
-- Every detection reads windows that are open now (ended_at IS NULL).
CREATE INDEX IF NOT EXISTS idx_rule_windows_open
    ON rule_suppression_windows(expires_at, starts_at) WHERE ended_at IS NULL;

-- 5.0: hunting. A saved search stores the query text; time terms like last:24h resolve when it runs.
-- 9.0: imported Sigma rules. The rule itself is a row in `rules` (id sigma_<slug>); this keeps the original
-- YAML, its sha256, and the labeled sample that must pass before the rule can be enabled.
CREATE TABLE IF NOT EXISTS sigma_rules (
    rule_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    sigma_id TEXT,
    sample TEXT,
    imported_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    change_request_id INTEGER,
    created_at TEXT NOT NULL
);

-- 11.0: saved searches promoted to detections. The rule is a row in `rules` (id search_<slug>, params the compiled
-- query, group-by, threshold and window); this keeps the query it was promoted with, the saved search it came
-- from (which may since be deleted), and the labeled sample that must pass before the rule can be enabled.
CREATE TABLE IF NOT EXISTS search_rules (
    rule_id TEXT PRIMARY KEY,
    query TEXT NOT NULL,
    saved_search_id INTEGER,
    sample TEXT,
    proposed_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    change_request_id INTEGER,
    created_at TEXT NOT NULL
);

-- 10.0: planned silence for a log source (host NULL: every host of the source). Added only through an approved
-- change request; an admin can end one early (ended_at). The row stays as history.
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    host TEXT,
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    change_request_id INTEGER,
    created_at TEXT NOT NULL,
    ended_at TEXT,
    ended_by TEXT
);

CREATE TABLE IF NOT EXISTS saved_searches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    query TEXT NOT NULL,
    description TEXT,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 14.0: named dashboard severity filters and ordered panel subsets. Shared views are readable by every role;
-- private views and all mutations are restricted to their owner by the server.
CREATE TABLE IF NOT EXISTS dashboard_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    filters TEXT NOT NULL,
    layout TEXT NOT NULL,
    visibility TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner, name COLLATE NOCASE)
);

-- Response playbooks (playbooks.py). The steps' titles and instructions live in code; these rows hold state.
CREATE TABLE IF NOT EXISTS playbook_runs (
    alert_id INTEGER PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS playbook_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    step_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    actor TEXT,
    note TEXT,
    target TEXT,
    updated_at TEXT,
    UNIQUE(alert_id, step_key)
);

-- Webhook deliveries waiting to be sent, and the record of those that were.
CREATE TABLE IF NOT EXISTS playbook_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    step_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_playbook_outbox_due ON playbook_outbox(status, next_attempt_at);
"""

# Columns added after 1.0. Existing databases gain them in place on startup.
ADDED_COLUMNS = [
    ("rules", "techniques", "TEXT"),
    ("events", "dest_port", "INTEGER"),
    ("events", "bytes", "INTEGER"),
    ("detection_runs", "correlation", "TEXT"),
    # Asset weighting: the rule's severity, the matched assets (JSON), and why the severity changed.
    ("alerts", "base_severity", "TEXT"),
    ("alerts", "assets", "TEXT"),
    ("alerts", "severity_note", "TEXT"),
    ("detection_runs", "alerts_suppressed", "INTEGER NOT NULL DEFAULT 0"),
    # 3.1: an admin can end a tuning exception before it expires; the row stays as history.
    ("suppressions", "revoked_at", "TEXT"),
    ("suppressions", "revoked_by", "TEXT"),
    # 7.0: when an alert first left `open` (triage metrics). Rows from before stay NULL: never backfilled.
    ("alerts", "acknowledged_at", "TEXT"),
    # 8.0: TOTP second factor. The secret is stored as-is (not encrypted at rest). `totp_pending` holds an
    # enrollment until it is confirmed with a valid code; `totp_last_step` refuses a replayed time step.
    ("users", "totp_secret", "TEXT"),
    ("users", "totp_pending", "TEXT"),
    ("users", "totp_last_step", "INTEGER"),
    # 8.0: a non-secret session id (for listing and revoking) and when the session was last used.
    ("sessions", "sid", "TEXT"),
    ("sessions", "last_seen_at", "TEXT"),
    # 13.0: least-privilege bearer tokens. Existing ingest tokens retain their original behavior.
    ("api_tokens", "role", "TEXT NOT NULL DEFAULT 'analyst'"),
    ("api_tokens", "capabilities", "TEXT NOT NULL DEFAULT '[\"ingest\"]'"),
    ("api_tokens", "expires_at", "TEXT"),
    # 15.0: reviewed fields that replace a rule's built-in alert deduplication key.
    ("rules", "grouping", "TEXT NOT NULL DEFAULT '[]'"),
    ("rule_history", "grouping", "TEXT NOT NULL DEFAULT '[]'"),
]


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    """Canonical timestamp format; lexicographic order == chronological order."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_iso():
    return iso(utcnow())


def parse_iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Connection(sqlite3.Connection):
    """A connection that carries the audit chain key (SIEM_AUDIT_KEY), so the key travels with the App's
    connections instead of living in process-wide state that a second App could change."""
    audit_key = None


def connect(db_path, audit_key=None):
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10, isolation_level=None, factory=Connection)
    conn.audit_key = audit_key or None
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_COLUMN_TYPE_RE = re.compile(
    r"(?:TEXT|INTEGER|REAL|BLOB|NUMERIC)"
    r"(?: NOT NULL)?"
    r"(?: DEFAULT (?:NULL|-?\d+|'(?:[^']|'')*'))?\Z"
)


def _sql_ident(name):
    """A quoted identifier. Callers pass schema constants; anything else is refused."""
    if not isinstance(name, str) or len(name) > 64 or _IDENT_RE.fullmatch(name) is None:
        raise ValueError(f"invalid SQL identifier: {name!r}")
    return '"' + name + '"'


def _column_type_sql(kind):
    """A column type ALTER TABLE may add. A quoted default is a string literal, not SQL."""
    if not isinstance(kind, str) or len(kind) > 64 or _COLUMN_TYPE_RE.fullmatch(kind) is None:
        raise ValueError(f"invalid SQL column type: {kind!r}")
    return kind


def _ensure_column(conn, table, column, kind):
    table_sql = _sql_ident(table)
    column_sql = _sql_ident(column)
    type_sql = _column_type_sql(kind)
    existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table_sql})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table_sql} ADD COLUMN {column_sql} {type_sql}")


def _audit_columns_sql():
    return ", ".join(_sql_ident(name) for name in AUDIT_FIELDS)


class TransactionBoundaryError(RuntimeError):
    """The write this call is ending is not the transaction it opened.

    A COMMIT, or the commit executescript issues first, may already have made earlier rows durable.
    Raising does not undo them.
    """


def _tx_depth(conn):
    """How many managed transaction() frames are open, or None when this connection is not in one."""
    depth = getattr(conn, "_tx_depth", None)
    if depth is None:
        return None
    if type(depth) is not int or depth < 0:
        raise ValueError("invalid transaction depth")
    return depth


def _end_transaction(conn, savepoint, commit):
    """Commit or roll back what this call opened.

    A transaction that is already closed raises. So does a savepoint SQLite no longer has.
    Neither error puts those rows back.
    """
    if not conn.in_transaction:
        raise TransactionBoundaryError(
            "transaction closed early; that commit is already durable and cannot be undone")
    if savepoint is None:
        conn.execute("COMMIT" if commit else "ROLLBACK")
        return
    if commit:
        conn.execute(f"RELEASE {savepoint}")
        return
    conn.execute(f"ROLLBACK TO {savepoint}")
    conn.execute(f"RELEASE {savepoint}")


@contextmanager
def transaction(conn):
    """A write transaction. A nested call uses a savepoint on the open transaction.

    The outer BEGIN IMMEDIATE takes the write lock before any read, which the audit chain needs.
    A nested call rolls back only its savepoint. A premature COMMIT, the commit executescript issues
    first, a missing savepoint, or a failed COMMIT raises. An error after an earlier commit does not
    undo that commit. A nested call whose outer transaction is already closed refuses to open another
    one, so that write does not become durable on its own.
    """
    depth = _tx_depth(conn)
    if depth is not None and not conn.in_transaction:
        raise TransactionBoundaryError(
            "transaction closed early; refusing to open another write the caller can no longer roll back")
    savepoint = None
    restore = None
    started = False
    try:
        if conn.in_transaction:
            # An external BEGIN is joined with a savepoint. Our own frames use the next name.
            level = 0 if depth is None else depth
            savepoint = f"wp_{level}"
            conn.execute(f"SAVEPOINT {savepoint}")
            conn._tx_depth = level + 1
            restore = depth
        else:
            conn.execute("BEGIN IMMEDIATE")
            conn._tx_depth = 0
            restore = None
        started = True
        try:
            yield conn
        except BaseException as body_error:
            try:
                _end_transaction(conn, savepoint, False)
            except Exception as boundary_error:
                raise boundary_error from body_error
            raise
        else:
            try:
                _end_transaction(conn, savepoint, True)
            except BaseException:
                try:
                    _end_transaction(conn, savepoint, False)
                except Exception:
                    pass
                raise
    finally:
        if started:
            conn._tx_depth = restore


def init_schema(conn):
    from . import sigma

    # executescript commits an open transaction before it runs. Refuse that so the caller's
    # uncommitted rows do not become durable.
    if _tx_depth(conn) is not None or conn.in_transaction:
        raise TransactionBoundaryError(
            "init_schema cannot run inside a transaction; executescript would commit it")
    conn.executescript(SCHEMA)
    for table, column, kind in ADDED_COLUMNS:
        _ensure_column(conn, table, column, kind)
    # revoked_at is added above (it is not in the 1.0 CREATE TABLE), so this partial index cannot live in SCHEMA.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_suppressions_active ON suppressions(expires_at) WHERE revoked_at IS NULL"
    )
    # Sessions from before 8.0 get an id so they can be listed and revoked like new ones.
    conn.execute("UPDATE sessions SET sid = lower(hex(randomblob(8))) WHERE sid IS NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid)")
    # 4.0: hash-chained audit log. Rows written before the chain existed are never hashed here: the server
    # would be signing whatever the database file says, including rows someone rewrote before a restart.
    with transaction(conn):
        for column in ("prev_hash", "hash"):
            _ensure_column(conn, "audit_log", column, "TEXT")
        _start_audit_chain(conn)
        _check_chain_key(conn)
        sigma.upgrade_stored_rules(conn)
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(SCHEMA_VERSION),)
    )


def row_to_dict(row, json_fields=()):
    if row is None:
        return None
    data = dict(row)
    for field in json_fields:
        if data.get(field) is not None:
            data[field] = json.loads(data[field])
    return data


class AuditKeyError(RuntimeError):
    """The configured SIEM_AUDIT_KEY is not the key the audit chain was started with."""


def audit_key_id(key):
    """A short public identifier for a key (HMAC of a fixed label), recorded in the chain start; None unkeyed."""
    if not key:
        return None
    return hmac.new(key.encode() if isinstance(key, str) else key, b"watchpost audit key id",
                    hashlib.sha256).hexdigest()[:16]


def _key_mismatch(declared, current):
    if declared and current:
        return "the chain was started with a different SIEM_AUDIT_KEY"
    if declared:
        return "the chain was started with SIEM_AUDIT_KEY, but none is set"
    return "the chain was started without SIEM_AUDIT_KEY, but one is set"


def audit_hash(prev_hash, row, key):
    """HMAC-SHA256 (or SHA-256 without a key) over the previous hash and the row's canonical JSON."""
    canonical = json.dumps({f: row[f] for f in AUDIT_FIELDS}, sort_keys=True, separators=(",", ":"))
    payload = ((prev_hash or "") + canonical).encode()
    if key:
        return hmac.new(key.encode() if isinstance(key, str) else key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def _start_audit_chain(conn):
    """Begin the chain with an `audit_chain_started` entry when no entry carries a hash yet.

    That is a new database, a 3.x upgrade, or a log whose hashes were dropped or cleared. Earlier rows stay
    unhashed; verify_chain reports them as legacy and unverified, and this entry records how many there were
    and which key signs the chain (signed, so neither can change afterwards without a break).
    """
    if conn.execute("SELECT 1 FROM audit_log WHERE hash IS NOT NULL LIMIT 1").fetchone():
        return
    count, last_id = conn.execute("SELECT COUNT(*), MAX(id) FROM audit_log").fetchone()
    key_id = audit_key_id(conn.audit_key)
    _set_meta_key_id(conn, key_id)
    audit(conn, "system", "audit_chain_started", None,
          {"legacy_entries": count, "legacy_last_id": last_id, "keyed": bool(key_id), "key_id": key_id})


def _set_meta_key_id(conn, key_id):
    # A copy of the chain start's key id where audit() can read it with one lookup. It only lets the server
    # refuse early; verify_chain trusts the signed chain start, never this row.
    conn.execute("INSERT INTO meta(key, value) VALUES ('audit_key_id', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key_id or "unkeyed",))


def _check_chain_key(conn):
    """At startup: refuse to run with a key other than the one the chain was started with."""
    first = conn.execute(f"SELECT {_audit_columns_sql()} FROM audit_log WHERE hash IS NOT NULL"
                         " ORDER BY id LIMIT 1").fetchone()
    declared = _declared(first)["key_id"] if first else _UNDECLARED
    key_id = audit_key_id(conn.audit_key)
    if declared is not _UNDECLARED and declared != key_id:
        raise AuditKeyError(f"audit log: {_key_mismatch(declared, key_id)}. Restore the original setting: the "
                            "server will not extend the chain under another key.")
    _set_meta_key_id(conn, key_id)


def audit(conn, actor, action, target=None, detail=None):
    # Reading the previous hash and inserting must happen under one write lock, or two writers could link to
    # the same predecessor. Callers inside transaction() already hold it (BEGIN IMMEDIATE); otherwise take it.
    # A managed transaction that has already been committed must not start a second one: that commit would
    # make this audit row durable after the caller has lost the ability to roll the domain write back.
    key = getattr(conn, "audit_key", None)
    depth = _tx_depth(conn)
    if depth is not None and not conn.in_transaction:
        raise TransactionBoundaryError(
            "transaction closed early; refusing to write an audit row the caller can no longer roll back")
    own = depth is None and not conn.in_transaction
    if own:
        conn.execute("BEGIN IMMEDIATE")
    try:
        # Never append links under a key other than the chain's: they would verify under neither.
        expected = conn.execute("SELECT value FROM meta WHERE key = 'audit_key_id'").fetchone()
        if expected and expected[0] != (audit_key_id(key) or "unkeyed"):
            raise AuditKeyError("this connection's SIEM_AUDIT_KEY is not the key the audit chain was started with")
        # Link to the newest hashed entry; an unhashed row after it is reported by verify_chain, not adopted.
        last = conn.execute("SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        # Every column is TEXT: store strings so the values hashed below are exactly the values stored.
        values = (now_iso(), str(actor), str(action), None if target is None else str(target),
                  json.dumps(detail) if detail is not None else None)
        cur = conn.execute("INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)", values)
        # Hash what this call wrote, never the row read back: a trigger in the database file could have changed
        # it, and the server would then sign content it did not write.
        prev_hash = last[0] if last else GENESIS_HASH
        digest = audit_hash(prev_hash, dict(zip(AUDIT_FIELDS, (cur.lastrowid, *values))), key)
        conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev_hash, digest, cur.lastrowid))
    except BaseException:
        if own and conn.in_transaction:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        raise
    else:
        if own and conn.in_transaction:
            try:
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                raise


_CONFIGURED_KEY = object()


def verify_chain(conn, key=_CONFIGURED_KEY):
    """Walk the audit log once, oldest first, and report the first entry that breaks the chain.

    The chain starts at the first hashed entry, which must link to the genesis hash and follow directly after
    any unhashed rows. Those rows are legacy: counted, never verified, and they must match the range its
    `audit_chain_started` detail records (an ordinary first entry declares none). Reasons: `key_mismatch`
    (the chain was started with another key, or with none), `deleted` (an id gap, an empty log, or entries
    missing before the chain start), `modified` (an entry does not match its hash, or has none),
    `broken_link` (an intact entry that does not point at the one before it, including a second chain start),
    and `legacy_mismatch` (rows before the chain start were added or removed).

    `status` is `verified` only when every row is chained and intact, `partial` when the chain is intact but
    legacy rows precede it, `broken` otherwise; `ok` is true only for `verified`. Deleting the newest entries
    leaves a valid shorter chain; only a head recorded elsewhere shows that.
    """
    key = getattr(conn, "audit_key", None) if key is _CONFIGURED_KEY else key
    key_id = audit_key_id(key)
    entries, prev_id, prev_hash, head, first_break, started = 0, None, GENESIS_HASH, None, None, None
    legacy = {"entries": 0, "last_id": None}
    # One SELECT reads one consistent snapshot, even while other connections append.
    cur = conn.execute(
        f"SELECT {_audit_columns_sql()}, {_sql_ident('prev_hash')}, {_sql_ident('hash')} FROM audit_log ORDER BY id"
    )
    for row in cur:
        row_id, stored_prev, stored_hash = row[0], row[6], row[7]
        if started is None and stored_hash is None:
            legacy = {"entries": legacy["entries"] + 1, "last_id": row_id}
            continue
        entries += 1
        head = {"id": row_id, "hash": stored_hash}
        if started is None:
            started = {"id": row_id, "created_at": row[1]}
            declared = _declared(row)
            if declared["key_id"] is not _UNDECLARED and declared["key_id"] != key_id:
                first_break = {"id": row_id, "reason": "key_mismatch",
                               "detail": _key_mismatch(declared["key_id"], key_id)}
            elif stored_hash != audit_hash(stored_prev, dict(zip(AUDIT_FIELDS, row)), key):
                first_break = {"id": row_id, "reason": "modified", "detail": "the entry no longer matches its hash"}
            elif stored_prev != GENESIS_HASH:
                first_break = {"id": row_id, "reason": "deleted", "detail": "entries before this one are missing"}
            elif declared["legacy"] != legacy:
                first_break = {"id": row_id, "reason": "legacy_mismatch",
                               "detail": f"{legacy['entries']} entries precede the chain start, which recorded "
                                         f"{declared['legacy']['entries']}"}
            elif row_id != (legacy["last_id"] or 0) + 1:
                first_break = {"id": row_id, "reason": "deleted",
                               "detail": "entries before the chain start are missing"}
        elif first_break is None:
            if row_id != prev_id + 1:
                first_break = {"id": row_id, "reason": "deleted",
                               "detail": f"entries #{prev_id + 1} to #{row_id - 1} are missing"}
            elif stored_hash != audit_hash(stored_prev, dict(zip(AUDIT_FIELDS, row)), key):
                first_break = {"id": row_id, "reason": "modified",
                               "detail": "the entry no longer matches its hash" if stored_hash else "the entry has no hash"}
            elif stored_prev != prev_hash:
                first_break = {"id": row_id, "reason": "broken_link",
                               "detail": f"the entry does not link to entry #{prev_id}"}
        prev_id, prev_hash = row_id, stored_hash
    if started is None:
        # Every log begins with a chain start, so there is nothing to vouch for: the hashes were cleared (the
        # server only starts a new chain on restart) or the rows were removed.
        first_break = ({"id": legacy["last_id"], "reason": "modified", "detail": "no entry in the log carries a hash"}
                       if legacy["entries"] else
                       {"id": None, "reason": "deleted", "detail": "the audit log is empty"})
    status = "broken" if first_break else "partial" if legacy["entries"] else "verified"
    return {"ok": status == "verified", "status": status, "entries": entries, "keyed": bool(key), "head": head,
            "first_break": first_break, "legacy": legacy, "chain_started": started}


_UNDECLARED = object()


def _declared(row):
    """What a chain start recorded about itself: the legacy range and the key id. Any other first entry (a
    chain from before chain starts existed) declares no legacy rows and no key."""
    if row[3] == "audit_chain_started" and row[5]:
        try:
            detail = json.loads(row[5])
            return {"legacy": {"entries": detail["legacy_entries"], "last_id": detail["legacy_last_id"]},
                    "key_id": detail.get("key_id", _UNDECLARED)}
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
    return {"legacy": {"entries": 0, "last_id": None}, "key_id": _UNDECLARED}
