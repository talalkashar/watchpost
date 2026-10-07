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
    # 4.0: hash-chained audit log. Rows written before the chain existed are never hashed here: the server
    # would be signing whatever the database file says, including rows someone rewrote before a restart.
    with transaction(conn):
        audit_columns = {r["name"] for r in conn.execute("PRAGMA table_info(audit_log)")}
        for column in ("prev_hash", "hash"):
            if column not in audit_columns:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column} TEXT")
        _start_audit_chain(conn)
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


def _start_audit_chain(conn):
    """Begin the chain with an `audit_chain_started` entry when no entry carries a hash yet.

    That is a new database, a 3.x upgrade, or a log whose hashes were dropped or cleared. Earlier rows stay
    unhashed; verify_chain reports them as legacy and unverified, and this entry records how many there were
    (signed, so the legacy range cannot grow or shrink afterwards without a break).
    """
    if conn.execute("SELECT 1 FROM audit_log WHERE hash IS NOT NULL LIMIT 1").fetchone():
        return
    count, last_id = conn.execute("SELECT COUNT(*), MAX(id) FROM audit_log").fetchone()
    audit(conn, "system", "audit_chain_started", None,
          {"legacy_entries": count, "legacy_last_id": last_id, "keyed": bool(_audit_key)})


def audit(conn, actor, action, target=None, detail=None):
    # Reading the previous hash and inserting must happen under one write lock, or two writers could link to
    # the same predecessor. Callers inside transaction() already hold it (BEGIN IMMEDIATE); otherwise take it.
    own = not conn.in_transaction
    if own:
        conn.execute("BEGIN IMMEDIATE")
    try:
        # Link to the newest hashed entry; an unhashed row after it is reported by verify_chain, not adopted.
        last = conn.execute("SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        # Every column is TEXT: store strings so the values hashed below are exactly the values stored.
        values = (now_iso(), str(actor), str(action), None if target is None else str(target),
                  json.dumps(detail) if detail is not None else None)
        cur = conn.execute("INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)", values)
        # Hash what this call wrote, never the row read back: a trigger in the database file could have changed
        # it, and the server would then sign content it did not write.
        prev_hash = last[0] if last else GENESIS_HASH
        digest = audit_hash(prev_hash, dict(zip(AUDIT_FIELDS, (cur.lastrowid, *values))), _audit_key)
        conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev_hash, digest, cur.lastrowid))
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

    The chain starts at the first hashed entry, which must link to the genesis hash. Unhashed rows before it
    are legacy: counted, never verified, and they must match the range its `audit_chain_started` detail
    records (an ordinary first entry declares none). Reasons: `deleted` (an id gap, or the first hashed entry
    does not start from genesis), `modified` (an entry does not match its hash, or has none), `broken_link`
    (an intact entry that does not point at the one before it, including a second chain start), and
    `legacy_mismatch` (rows before the chain start were added or removed). Deleting the newest entries leaves a
    valid shorter chain; only a head recorded elsewhere shows that.
    """
    key = _audit_key if key is _CONFIGURED_KEY else key
    entries, prev_id, prev_hash, head, first_break, started = 0, None, GENESIS_HASH, None, None, None
    legacy = {"entries": 0, "last_id": None}
    # One SELECT reads one consistent snapshot, even while other connections append.
    cur = conn.execute(f"SELECT {', '.join(AUDIT_FIELDS)}, prev_hash, hash FROM audit_log ORDER BY id")
    for row in cur:
        row_id, stored_prev, stored_hash = row[0], row[6], row[7]
        if started is None and stored_hash is None:
            legacy = {"entries": legacy["entries"] + 1, "last_id": row_id}
            continue
        entries += 1
        head = {"id": row_id, "hash": stored_hash}
        if started is None:
            started = {"id": row_id, "created_at": row[1]}
            if stored_hash != audit_hash(stored_prev, dict(zip(AUDIT_FIELDS, row)), key):
                first_break = {"id": row_id, "reason": "modified", "detail": "the entry no longer matches its hash"}
            elif stored_prev != GENESIS_HASH:
                first_break = {"id": row_id, "reason": "deleted", "detail": "entries before this one are missing"}
            elif _declared_legacy(row) != legacy:
                first_break = {"id": row_id, "reason": "legacy_mismatch",
                               "detail": f"{legacy['entries']} entries precede the chain start, which recorded "
                                         f"{_declared_legacy(row)['entries']}"}
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
    if started is None and legacy["entries"]:
        # Rows but no chain: every hash was cleared. The server only starts a new chain on restart.
        first_break = {"id": legacy["last_id"], "reason": "modified", "detail": "no entry in the log carries a hash"}
    return {"ok": first_break is None, "entries": entries, "keyed": bool(key), "head": head,
            "first_break": first_break, "legacy": legacy, "chain_started": started}


def _declared_legacy(row):
    """The legacy range a chain start recorded about itself; any other first entry declares none."""
    if row[3] == "audit_chain_started" and row[5]:
        try:
            detail = json.loads(row[5])
            return {"entries": detail["legacy_entries"], "last_id": detail["legacy_last_id"]}
        except (ValueError, KeyError, TypeError):
            pass
    return {"entries": 0, "last_id": None}
