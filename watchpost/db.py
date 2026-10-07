"""SQLite storage: connection handling and schema."""

import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 4

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

CREATE TABLE IF NOT EXISTS alert_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
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


def connect(db_path):
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def transaction(conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_schema(conn):
    conn.executescript(SCHEMA)
    for table, column, kind in ADDED_COLUMNS:
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
    # 4.0: hash-chained audit log. Add the columns and chain the existing rows in one transaction, so a
    # failed upgrade leaves the old schema rather than a half-chained log.
    audit_columns = {r["name"] for r in conn.execute("PRAGMA table_info(audit_log)")}
    if "hash" not in audit_columns:
        with transaction(conn):
            for column in ("prev_hash", "hash"):
                if column not in audit_columns:
                    conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column} TEXT")
            _chain_existing_audit_rows(conn)
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


# HMAC key for the audit chain, set once at startup from SIEM_AUDIT_KEY (see server.App). Without a key the
# chain falls back to plain SHA-256, which anyone who can write the database file can recompute.
_audit_key = None


def set_audit_key(key):
    global _audit_key
    _audit_key = key or None


def audit_hash(prev_hash, row, key):
    """HMAC-SHA256 (or SHA-256 without a key) over the previous hash and the row's canonical JSON."""
    canonical = json.dumps({f: row[f] for f in AUDIT_FIELDS}, sort_keys=True, separators=(",", ":"))
    payload = ((prev_hash or "") + canonical).encode()
    if key:
        return hmac.new(key.encode() if isinstance(key, str) else key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def _link_audit_row(conn, row_id, prev_hash):
    # Hash the row as stored (column affinity may have changed a value's type), then write prev_hash and hash.
    row = conn.execute(f"SELECT {', '.join(AUDIT_FIELDS)} FROM audit_log WHERE id = ?", (row_id,)).fetchone()
    digest = audit_hash(prev_hash, dict(zip(AUDIT_FIELDS, row)), _audit_key)
    conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev_hash, digest, row_id))
    return digest


def _chain_existing_audit_rows(conn):
    """Schema 4 upgrade: chain the rows written before 4.0 in id order, then record that it happened.

    Runs only when the hash column is first added, so a row inserted later without a hash is reported by
    verify_chain instead of being adopted on the next start.
    """
    ids = [r[0] for r in conn.execute("SELECT id FROM audit_log ORDER BY id")]
    prev_hash = GENESIS_HASH
    for row_id in ids:
        prev_hash = _link_audit_row(conn, row_id, prev_hash)
    if ids:
        audit(conn, "system", "audit_chain_started", None, {"backfilled": len(ids), "keyed": bool(_audit_key)})


def audit(conn, actor, action, target=None, detail=None):
    # Reading the previous hash and inserting must happen under one write lock, or two writers could link to
    # the same predecessor. Callers inside transaction() already hold it (BEGIN IMMEDIATE); otherwise take it.
    own = not conn.in_transaction
    if own:
        conn.execute("BEGIN IMMEDIATE")
    try:
        last = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        cur = conn.execute(
            "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (now_iso(), actor, action, target, json.dumps(detail) if detail is not None else None),
        )
        _link_audit_row(conn, cur.lastrowid, last[0] if last else GENESIS_HASH)
    except BaseException:
        if own:
            conn.execute("ROLLBACK")
        raise
    else:
        if own:
            conn.execute("COMMIT")


_CONFIGURED_KEY = object()


def verify_chain(conn, key=_CONFIGURED_KEY):
    """Walk the audit log once, oldest first, and report the first entry that breaks the chain.

    Reasons: `deleted` (an id gap, or the first entry does not start from the genesis hash), `modified` (the
    entry's own hash does not match its contents), `broken_link` (the entry is intact but does not point at the
    entry before it, e.g. that one was rewritten together with its hash). Deleting the newest entries leaves a
    valid shorter chain; only a head recorded elsewhere shows that.
    """
    key = _audit_key if key is _CONFIGURED_KEY else key
    entries, prev_id, prev_hash, head, first_break = 0, None, GENESIS_HASH, None, None
    # One SELECT reads one consistent snapshot, even while other connections append.
    cur = conn.execute(f"SELECT {', '.join(AUDIT_FIELDS)}, prev_hash, hash FROM audit_log ORDER BY id")
    for row in cur:
        entries += 1
        row_id, stored_prev, stored_hash = row[0], row[6], row[7]
        head = {"id": row_id, "hash": stored_hash}
        if first_break is None:
            if prev_id is not None and row_id != prev_id + 1:
                first_break = {"id": row_id, "reason": "deleted",
                               "detail": f"entries #{prev_id + 1} to #{row_id - 1} are missing"}
            elif stored_hash != audit_hash(stored_prev, dict(zip(AUDIT_FIELDS, row)), key):
                first_break = {"id": row_id, "reason": "modified",
                               "detail": "the entry no longer matches its hash"}
            elif stored_prev != prev_hash:
                first_break = ({"id": row_id, "reason": "deleted",
                                "detail": "entries before this one are missing"} if prev_id is None else
                               {"id": row_id, "reason": "broken_link",
                                "detail": f"the entry does not link to entry #{prev_id}"})
        prev_id, prev_hash = row_id, stored_hash
    return {"ok": first_break is None, "entries": entries, "keyed": bool(key), "head": head,
            "first_break": first_break}
