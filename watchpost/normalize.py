"""Parse and normalize raw security events into the Watchpost schema.

Normalized event fields:
    ts, source, host, event_type, outcome, severity, user, src_ip, dest_ip, message, raw

Every input record either becomes a normalized event or a rejection with a reason.
Nothing is dropped silently.
"""

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from .db import iso, utcnow
from .diagnostics import redact

EVENT_TYPES = {
    "auth_failure", "auth_success", "account_lockout", "user_created",
    "privilege_use", "process_start", "network_connection", "file_access", "other",
}
SEVERITIES = ["info", "low", "medium", "high", "critical"]
FORMATS = {"json", "jsonl", "csv", "authlog"}

DEFAULT_SEVERITY = {
    "auth_failure": "low",
    "auth_success": "info",
    "account_lockout": "medium",
    "user_created": "medium",
    "privilege_use": "medium",
}

TYPE_ALIASES = {
    "login_failure": "auth_failure", "login_failed": "auth_failure", "failed_login": "auth_failure",
    "logon_failure": "auth_failure", "authentication_failure": "auth_failure",
    "login_success": "auth_success", "login": "auth_success", "logon": "auth_success",
    "successful_login": "auth_success", "authentication_success": "auth_success",
    "lockout": "account_lockout", "account_locked": "account_lockout",
    "process": "process_start", "connection": "network_connection",
}

WINDOWS_EVENT_IDS = {
    4624: "auth_success", 4625: "auth_failure", 4740: "account_lockout",
    4720: "user_created", 4672: "privilege_use", 4688: "process_start",
}

FIELD_ALIASES = {
    "ts": ["ts", "timestamp", "@timestamp", "time", "TimeCreated", "event_time"],
    "source": ["source", "log_source", "Channel"],
    "host": ["host", "hostname", "Computer", "device"],
    "event_type": ["event_type", "type", "action", "category"],
    "outcome": ["outcome", "result", "status"],
    "severity": ["severity", "level"],
    "user": ["user", "username", "user_name", "TargetUserName", "account"],
    "src_ip": ["src_ip", "source_ip", "client_ip", "ip", "IpAddress", "remote_addr"],
    "dest_ip": ["dest_ip", "destination_ip", "server_ip"],
    "message": ["message", "msg", "description"],
}

MAX_LEN = {"source": 64, "host": 128, "user": 128, "message": 2000, "raw": 4000}
MAX_FUTURE = timedelta(days=1)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")


class EventError(ValueError):
    pass


def clean_text(value, field):
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("name")
        if value is None:
            return None
    text = _CONTROL.sub(" ", str(value)).strip()
    if not text or text == "-":
        return None
    return text[: MAX_LEN.get(field, 256)]


def validate_source(source):
    if not source or not _SOURCE_RE.match(source):
        raise EventError("source must be 1-64 chars of letters, digits, _ . : -")
    return source


def parse_timestamp(value, now=None):
    now = now or utcnow()
    if value is None or value == "":
        raise EventError("missing timestamp")
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            seconds = value / 1000 if value > 1e11 else value
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        else:
            text = str(value).strip().replace("Z", "+00:00")
            if " " in text and "T" not in text:
                text = text.replace(" ", "T", 1)
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)  # documented: naive timestamps are UTC
    except (ValueError, OverflowError, OSError):
        raise EventError(f"unparseable timestamp {str(value)[:40]!r}")
    if dt > now + MAX_FUTURE:
        raise EventError("timestamp is more than 1 day in the future")
    if dt.year < 2000:
        raise EventError("timestamp is before year 2000")
    return iso(dt)


def parse_ip(value, field):
    value = clean_text(value, field)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise EventError(f"{field} is not a valid IP address")


def _pick(record, field):
    for key in FIELD_ALIASES[field]:
        if key in record and record[key] not in (None, ""):
            return record[key]
    nested = {"user": ("user", "name"), "src_ip": ("source", "ip"), "host": ("host", "name")}.get(field)
    if nested and isinstance(record.get(nested[0]), dict):
        return record[nested[0]].get(nested[1])
    return None


def normalize_type(record):
    event_id = record.get("EventID", record.get("event_id"))
    if event_id is not None:
        try:
            mapped = WINDOWS_EVENT_IDS.get(int(event_id))
        except (TypeError, ValueError):
            mapped = None
        if mapped:
            return mapped
    raw_type = _pick(record, "event_type")
    if raw_type is None:
        return "other"
    key = re.sub(r"[\s\-]+", "_", str(raw_type).strip().lower())
    key = TYPE_ALIASES.get(key, key)
    return key if key in EVENT_TYPES else "other"


def normalize_record(record, default_source, now=None):
    """Normalize one structured record (dict). Raises EventError on invalid input."""
    if not isinstance(record, dict):
        raise EventError("event must be a JSON object")
    event_type = normalize_type(record)
    severity = _pick(record, "severity")
    if severity is None:
        severity = DEFAULT_SEVERITY.get(event_type, "info")
    severity = str(severity).strip().lower()
    if severity not in SEVERITIES:
        raise EventError(f"severity must be one of {', '.join(SEVERITIES)}")

    source = clean_text(_pick(record, "source"), "source") or default_source
    outcome = clean_text(_pick(record, "outcome"), "outcome")
    if outcome is None and event_type in ("auth_failure", "auth_success"):
        outcome = "failure" if event_type == "auth_failure" else "success"

    raw = json.dumps(record, default=str, sort_keys=True)
    return {
        "ts": parse_timestamp(_pick(record, "ts"), now),
        "source": validate_source(source),
        "host": clean_text(_pick(record, "host"), "host"),
        "event_type": event_type,
        "outcome": outcome,
        "severity": severity,
        "user": clean_text(_pick(record, "user"), "user"),
        "src_ip": parse_ip(_pick(record, "src_ip"), "src_ip"),
        "dest_ip": parse_ip(_pick(record, "dest_ip"), "dest_ip"),
        "message": redact(clean_text(_pick(record, "message"), "message")),
        "raw": redact(raw)[: MAX_LEN["raw"]],
    }


# --- Linux auth.log (OpenSSH) -------------------------------------------------

_SYSLOG_PREFIX = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)\s+(?P<prog>[\w\-/.]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
_SSH_PATTERNS = [
    (re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
                r"(?P<user>\S+) from (?P<ip>\S+)"), "auth_failure"),
    (re.compile(r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
                r"from (?P<ip>\S+)"), "auth_success"),
    (re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)"), "auth_failure"),
    (re.compile(r"^pam_unix\(\S+\): authentication failure;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?"),
     "auth_failure"),
    (re.compile(r"^pam_unix\(sudo:session\): session opened for user (?P<user>\S+)"), "privilege_use"),
]


def normalize_authlog_line(line, default_source, year=None, now=None):
    now = now or utcnow()
    match = _SYSLOG_PREFIX.match(line.strip())
    if not match:
        raise EventError("line is not in syslog format")
    if match.group("iso"):
        ts_value = match.group("iso")
    else:
        # BSD syslog has no year or zone: assume UTC and the given/current year,
        # rolling back a year if that would put the event in the future.
        parts = match.group("bsd").split()
        stamp = f"{parts[0]} {int(parts[1]):02d} {parts[2]}"
        dt = datetime.strptime(f"{year or now.year} {stamp}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        if year is None and dt > now + MAX_FUTURE:
            dt = dt.replace(year=dt.year - 1)
        ts_value = iso(dt)

    message = match.group("msg")
    event_type, user, ip = "other", None, None
    for pattern, kind in _SSH_PATTERNS:
        found = pattern.search(message)
        if found:
            event_type = kind
            user = found.groupdict().get("user")
            ip = found.groupdict().get("ip")
            break

    record = {
        "ts": ts_value, "host": match.group("host"), "event_type": event_type,
        "user": user, "src_ip": ip, "message": message,
        "program": match.group("prog"),
    }
    event = normalize_record(record, default_source, now)
    event["raw"] = redact(line.strip())[: MAX_LEN["raw"]]
    return event


# --- Batch parsing --------------------------------------------------------------

def detect_format(text):
    stripped = text.lstrip()
    if stripped.startswith("[") or (stripped.startswith("{") and "\n{" not in stripped.strip()):
        return "json"
    if stripped.startswith("{"):
        return "jsonl"
    first = stripped.splitlines()[0] if stripped else ""
    if _SYSLOG_PREFIX.match(first):
        return "authlog"
    if "," in first:
        return "csv"
    raise EventError("could not detect format; pass format=json|jsonl|csv|authlog")


def parse_payload(text, fmt, default_source, year=None, now=None, max_events=20000):
    """Return (events, rejections). Rejections are [{"index": n, "reason": str}]."""
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt not in FORMATS:
        raise EventError(f"unsupported format {fmt!r}")

    if fmt == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EventError(f"invalid JSON at line {exc.lineno} column {exc.colno}")
        if isinstance(data, dict):
            data = data.get("events", [data]) if "events" in data else [data]
        if not isinstance(data, list):
            raise EventError("JSON body must be an object, an array, or {\"events\": [...]}")
        items = list(enumerate(data, start=1))
    elif fmt == "csv":
        reader = csv.DictReader(io.StringIO(text))
        items = [(n, {k: v for k, v in row.items() if k}) for n, row in enumerate(reader, start=2)]
    else:
        items = [(n, line) for n, line in enumerate(text.splitlines(), start=1) if line.strip()]

    if len(items) > max_events:
        raise EventError(f"batch has {len(items)} records; the limit is {max_events}")

    events, rejections = [], []
    for index, item in items:
        try:
            if fmt == "jsonl":
                try:
                    item = json.loads(item)
                except json.JSONDecodeError:
                    raise EventError("line is not valid JSON")
            if fmt == "authlog":
                events.append(normalize_authlog_line(item, default_source, year, now))
            else:
                events.append(normalize_record(item, default_source, now))
        except EventError as exc:
            # Only the reason and position are recorded, never the rejected content.
            rejections.append({"index": index, "reason": str(exc)})
    return events, rejections
