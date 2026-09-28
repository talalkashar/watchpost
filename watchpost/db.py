"""SQLite storage: connection handling and schema."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 2

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
    detail TEXT
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
"""

# Columns added after 1.0. Existing databases gain them in place on startup.
ADDED_COLUMNS = [
    ("rules", "techniques", "TEXT"),
    ("events", "dest_port", "INTEGER"),
    ("events", "bytes", "INTEGER"),
    ("detection_runs", "correlation", "TEXT"),
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


def audit(conn, actor, action, target=None, detail=None):
    conn.execute(
        "INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
        (now_iso(), actor, action, target, json.dumps(detail) if detail is not None else None),
    )
