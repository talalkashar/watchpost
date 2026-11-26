"""Parse and normalize raw security events into the Watchpost schema.

Normalized event fields:
    ts, source, host, event_type, outcome, severity, user, src_ip, dest_ip, dest_port, bytes, message, raw

Every input record either becomes a normalized event or a rejection with a reason.
Nothing is dropped silently.
"""

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus

from . import firewall
from .db import iso, utcnow
from .diagnostics import redact_cut

EVENT_TYPES = {
    "auth_failure", "auth_success", "account_lockout", "user_created",
    "privilege_use", "process_start", "network_connection", "file_access", "syslog", "other",
    # Watchpost 2.0: web, firewall/VPN, cloud audit, and host activity.
    "web_request", "web_scan", "web_error",
    "fw_deny", "fw_allow", "vpn_login",
    "cloud_api_call", "cloud_iam_change", "cloud_data_access",
    "privilege_escalation",
}
SEVERITIES = ["info", "low", "medium", "high", "critical"]
FORMATS = {"json", "jsonl", "csv", "authlog", "weblog"}

DEFAULT_SEVERITY = {
    "auth_failure": "low",
    "auth_success": "info",
    "account_lockout": "medium",
    "user_created": "medium",
    "privilege_use": "medium",
    "privilege_escalation": "medium",
    "web_scan": "low",
    "web_error": "low",
    "fw_deny": "low",
    "cloud_iam_change": "medium",
}

TYPE_ALIASES = {
    "login_failure": "auth_failure", "login_failed": "auth_failure", "failed_login": "auth_failure",
    "logon_failure": "auth_failure", "authentication_failure": "auth_failure",
    "login_success": "auth_success", "login": "auth_success", "logon": "auth_success",
    "successful_login": "auth_success", "authentication_success": "auth_success",
    "lockout": "account_lockout", "account_locked": "account_lockout",
    "process": "process_start", "connection": "network_connection",
    "deny": "fw_deny", "denied": "fw_deny", "drop": "fw_deny", "dropped": "fw_deny", "block": "fw_deny",
    "blocked": "fw_deny", "reject": "fw_deny", "rejected": "fw_deny", "firewall_deny": "fw_deny",
    "allow": "fw_allow", "allowed": "fw_allow", "accept": "fw_allow", "accepted": "fw_allow",
    "permit": "fw_allow", "pass": "fw_allow", "firewall_allow": "fw_allow",
    "vpn": "vpn_login", "vpn_connect": "vpn_login", "vpn_session": "vpn_login",
    "sudo": "privilege_escalation", "runas": "privilege_escalation", "su": "privilege_escalation",
    "http_request": "web_request", "request": "web_request",
    "file_read": "file_access", "file_open": "file_access",
}

WINDOWS_EVENT_IDS = {
    4624: "auth_success", 4625: "auth_failure", 4740: "account_lockout",
    4720: "user_created", 4672: "privilege_use", 4688: "process_start",
    4648: "privilege_escalation",  # logon with explicit credentials (runas)
    4663: "file_access",
    4771: "auth_failure",  # Kerberos pre-authentication failed
    5145: "file_access",  # detailed file share
    5152: "fw_deny", 5157: "fw_deny",  # Windows Filtering Platform packet blocked
    5156: "fw_allow",
}
# Status 0 is success. A parsed non-zero code is a failure. Missing or unreadable status is not guessed.
WINDOWS_STATUS_IDS = {4768: ("auth_success", "auth_failure"), 4769: ("auth_success", "auth_failure"),
                      4776: ("auth_success", "auth_failure")}
_WINDOWS_STATUS_KEYS = ("Status", "status", "ErrorCode", "ResultCode")

FIELD_ALIASES = {
    "ts": ["ts", "timestamp", "@timestamp", "time", "TimeCreated", "event_time"],
    "source": ["source", "log_source", "Channel"],
    "host": ["host", "hostname", "Computer", "ComputerName", "device"],
    "event_type": ["event_type", "type", "action", "category"],
    "outcome": ["outcome", "result", "status"],
    "severity": ["severity", "level"],
    "user": ["user", "username", "user_name", "TargetUserName", "AccountName", "account"],
    "src_ip": ["src_ip", "source_ip", "client_ip", "ip", "IpAddress", "SourceAddress", "ClientAddress",
               "remote_addr"],
    "dest_ip": ["dest_ip", "destination_ip", "server_ip", "dst_ip", "DestAddress", "DestinationAddress",
                "DestinationIp"],
    "dest_port": ["dest_port", "destination_port", "dst_port", "dport", "DestPort", "DestinationPort"],
    "bytes": ["bytes", "bytes_out", "bytes_sent", "sent_bytes", "out_bytes"],
    "message": ["message", "msg", "description"],
}

MAX_LEN = {"source": 64, "host": 128, "user": 128, "message": 2000, "raw": 4000}
MAX_BYTES = 10 ** 15
MAX_FUTURE = timedelta(days=1)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")


class EventError(ValueError):
    pass


def clean_text(value, field, *, truncate=True):
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("name")
        if value is None:
            return None
    text = _CONTROL.sub(" ", str(value)).strip()
    if not text or text == "-":
        return None
    if not truncate:
        return text
    return text[: MAX_LEN.get(field, 256)]


def stored_text(value, field):
    """Clean, redact the full value, then cut to the field limit."""
    text = clean_text(value, field, truncate=False)
    if text is None:
        return None
    return redact_cut(text, MAX_LEN.get(field, 256))


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
            # Windows SystemTime has 7 fractional digits; fromisoformat stops at 6.
            text = re.sub(r"(\.\d{6})\d+", r"\1", text)
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


def parse_int(value, field, high):
    if value is None or (isinstance(value, str) and value.strip() in ("", "-")):
        return None
    if isinstance(value, bool):
        raise EventError(f"{field} must be an integer")
    try:
        number = int(str(value).strip())
    except ValueError:
        raise EventError(f"{field} must be an integer")
    if not 0 <= number <= high:
        raise EventError(f"{field} must be between 0 and {high}")
    return number


def _pick(record, field):
    for key in FIELD_ALIASES[field]:
        if key in record and record[key] not in (None, ""):
            return record[key]
    nested = {"user": ("user", "name"), "src_ip": ("source", "ip"), "host": ("host", "name")}.get(field)
    if nested and isinstance(record.get(nested[0]), dict):
        return record[nested[0]].get(nested[1])
    return None


def _coerce_event_id(value):
    """Windows exports EventID as an int, a string, or {"#text": 4625}."""
    if isinstance(value, dict):
        for key in ("#text", "Value", "value", "text"):
            if value.get(key) not in (None, ""):
                return value[key]
        return None
    return value


def _event_data_dict(value):
    """EventData as a dict, or as a list of {Name, #text} pairs from an XML export."""
    if isinstance(value, list):
        items = value
    elif isinstance(value, dict):
        nested = value.get("Data", value.get("data"))
        if isinstance(nested, list):
            items = nested
        elif isinstance(nested, dict):
            items = [nested]
        else:
            return {k: v for k, v in value.items() if not str(k).startswith("@")}
    else:
        return {}
    out = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("Name", item.get("@Name", item.get("name")))
        if not name:
            continue
        if "#text" in item:
            text = item["#text"]
        elif "Value" in item:
            text = item["Value"]
        elif "value" in item:
            text = item["value"]
        else:
            text = item.get("text")
        out[str(name)] = text
    return out


def _windows_status_ok(record):
    """True for success, False for a known failure, None when status is missing or unreadable.

    An unreadable code is not a failure and does not raise, so one bad record stays in the batch.
    """
    for key in _WINDOWS_STATUS_KEYS:
        raw = record.get(key)
        if isinstance(raw, dict):
            raw = raw.get("#text", raw.get("Value", raw.get("value")))
        if raw in (None, ""):
            continue
        text = str(raw).strip().lower()
        if text.startswith("0x"):
            try:
                return int(text, 16) == 0
            except ValueError:
                return None
        if text.isascii() and text.isdecimal():
            digits = text.lstrip("0")
            if len(digits) > 10 or (len(digits) == 10 and digits > "4294967295"):
                return None
            return not digits
        if text in {"success", "ok"}:
            return True
        if text in {"failure", "fail", "failed"}:
            return False
        return None
    return None


def _system_time(value):
    if isinstance(value, dict):
        return value.get("SystemTime") or value.get("@SystemTime") or value.get("#text")
    return value


def _flatten_windows(record):
    """Lift Windows Event Log / Winlogbeat nests up. Keys already on the record win."""
    event = record.get("Event") if isinstance(record.get("Event"), dict) else {}
    system = event.get("System") if isinstance(event.get("System"), dict) else None
    if system is None and isinstance(record.get("System"), dict):
        system = record["System"]
    event_data = event.get("EventData") if isinstance(event, dict) and "EventData" in event else None
    if event_data is None:
        event_data = record.get("EventData")
    winlog = record.get("winlog") if isinstance(record.get("winlog"), dict) else None
    ecs_event = record.get("event") if isinstance(record.get("event"), dict) else None
    lifted = {}
    if system:
        eid = _coerce_event_id(system.get("EventID", system.get("EventId")))
        if eid is not None:
            lifted["EventID"] = eid
        created = _system_time(system.get("TimeCreated"))
        if created:
            lifted["TimeCreated"] = created
        if system.get("Computer"):
            lifted["Computer"] = system["Computer"]
        if system.get("Channel"):
            lifted["Channel"] = system["Channel"]
    if winlog:
        if winlog.get("event_id") is not None:
            lifted.setdefault("EventID", winlog["event_id"])
        if winlog.get("computer_name"):
            lifted.setdefault("Computer", winlog["computer_name"])
        if winlog.get("channel"):
            lifted.setdefault("Channel", winlog["channel"])
        if event_data is None:
            event_data = winlog.get("event_data")
    if ecs_event is not None and ecs_event.get("code") is not None:
        lifted.setdefault("EventID", ecs_event["code"])
    for key, value in _event_data_dict(event_data).items():
        lifted.setdefault(key, value)
    coerced = _coerce_event_id(record.get("EventID"))
    if isinstance(record.get("EventID"), dict) and coerced is not None:
        lifted["EventID"] = coerced
    created = record.get("TimeCreated")
    if isinstance(created, dict):
        text = _system_time(created)
        if text:
            lifted["TimeCreated"] = text
    if not lifted:
        return record
    merged = dict(lifted)
    merged.update(record)
    if "EventID" in lifted and isinstance(record.get("EventID"), dict):
        merged["EventID"] = lifted["EventID"]
    if "TimeCreated" in lifted and isinstance(record.get("TimeCreated"), dict):
        merged["TimeCreated"] = lifted["TimeCreated"]
    return merged


def normalize_type(record):
    event_id = _coerce_event_id(record.get("EventID", record.get("event_id")))
    if event_id is not None:
        try:
            number = int(event_id)
        except (TypeError, ValueError):
            number = None
        if number in WINDOWS_STATUS_IDS:
            ok = _windows_status_ok(record)
            if ok is not None:
                return WINDOWS_STATUS_IDS[number][0 if ok else 1]
        elif number is not None:
            mapped = WINDOWS_EVENT_IDS.get(number)
            if mapped:
                return mapped
    raw_type = _pick(record, "event_type")
    if raw_type is None and isinstance(record.get("event"), dict):
        action = record["event"].get("action")
        if isinstance(action, str):
            raw_type = action
    if raw_type is None:
        return "other"
    key = re.sub(r"[\s\-]+", "_", str(raw_type).strip().lower())
    key = TYPE_ALIASES.get(key, key)
    return key if key in EVENT_TYPES else "other"


# --- Cloud audit (CloudTrail-like JSON) -------------------------------------------

_CLOUD_IAM_ACTION = re.compile(r"^(Create|Delete|Attach|Detach|Put|Update|Add|Remove|Set|Enable|Disable|Upload)")
CLOUD_DATA_EVENTS = {"GetObject", "SelectObjectContent", "GetSecretValue", "CopyObject", "DownloadDBLogFilePortion"}


def is_cloudtrail(record):
    return isinstance(record, dict) and "eventName" in record and "eventSource" in record


def from_cloudtrail(record):
    """Flatten a CloudTrail-style record into Watchpost field names."""
    identity = record.get("userIdentity") if isinstance(record.get("userIdentity"), dict) else {}
    arn = str(identity.get("arn") or "")
    user = identity.get("userName") or (arn.rsplit("/", 1)[-1] if "/" in arn else None) \
        or identity.get("principalId")
    service, action = str(record.get("eventSource")), str(record.get("eventName"))
    if service.startswith("iam.") and _CLOUD_IAM_ACTION.match(action):
        event_type = "cloud_iam_change"
    elif action in CLOUD_DATA_EVENTS:
        event_type = "cloud_data_access"
    else:
        event_type = "cloud_api_call"
    ip = record.get("sourceIPAddress")
    try:
        ipaddress.ip_address(str(ip))
    except ValueError:
        ip = None  # e.g. "s3.amazonaws.com" for service-initiated calls
    extra = record.get("additionalEventData") if isinstance(record.get("additionalEventData"), dict) else {}
    error = record.get("errorCode")
    return {
        "ts": record.get("eventTime"), "event_type": event_type, "user": user, "src_ip": ip,
        "host": record.get("recipientAccountId"), "outcome": "failure" if error else "success",
        "bytes": extra.get("bytesTransferredOut"), "severity": record.get("severity"),
        "message": f"{action} on {service}" + (f" ({error})" if error else ""),
    }


def normalize_record(record, default_source, now=None):
    """Normalize one structured record (dict). Raises EventError on invalid input."""
    if not isinstance(record, dict):
        raise EventError("event must be a JSON object")
    original = record
    if is_cloudtrail(record):
        record = {k: v for k, v in from_cloudtrail(record).items() if v is not None}
    else:
        record = _flatten_windows(record)
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

    raw = json.dumps(original, default=str, sort_keys=True)
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
        "dest_port": parse_int(_pick(record, "dest_port"), "dest_port", 65535),
        "bytes": parse_int(_pick(record, "bytes"), "bytes", MAX_BYTES),
        "message": stored_text(_pick(record, "message"), "message"),
        "raw": redact_cut(raw, MAX_LEN["raw"]),
    }


# --- Linux auth.log (OpenSSH) -------------------------------------------------

_SYSLOG_PREFIX = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)\s+(?P<prog>%?[\w\-/.]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
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
    # Host activity: sudo/su elevation, account creation, auditd process and file records.
    (re.compile(r"^(?P<user>\S+) : (?:TTY=\S+ ; )?PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND="), "privilege_escalation"),
    (re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on "), "privilege_escalation"),
    (re.compile(r"^new user: name=(?P<user>[^,\s]+)"), "user_created"),
    (re.compile(r"type=PATH\b.*?\bname=\"(?P<path>[^\"]+)\""), "file_access"),
    (re.compile(r"\bexe=\"(?P<exe>[^\"]+)\"(?:.*?\bAUID=\"(?P<user>[^\"]+)\")?"), "process_start"),
    # Firewall (UFW / iptables-style prefixes) and OpenVPN sessions.
    (re.compile(r"\[(?:UFW )?(?P<action>BLOCK|DENY|DROP|REJECT|ALLOW|ACCEPT)\].*?\bSRC=(?P<ip>\S+) "
                r"DST=(?P<dst>\S+)(?:.*?\bDPT=(?P<dpt>\d+))?"), "firewall"),
    (re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+ \[(?P<user>[^\]]+)\] Peer Connection Initiated"),
     "vpn_login"),
]
_FIREWALL_ACTIONS = {
    "BLOCK": "fw_deny", "DENY": "fw_deny", "DROP": "fw_deny", "REJECT": "fw_deny",
    "DROPPED": "fw_deny", "DENIED": "fw_deny", "REJECTED": "fw_deny", "BLOCKED": "fw_deny",
    "ALLOW": "fw_allow", "ACCEPT": "fw_allow", "PERMIT": "fw_allow", "PERMITTED": "fw_allow",
    "PASS": "fw_allow", "ACCEPTED": "fw_allow",
}
# These run only when the patterns above miss, so a broad "Failed <method>" cannot steal
# "Failed password". A disconnect stays "other", including one tagged [preauth]: OpenSSH
# closed the socket before a password result. The user and address are still stored.
_PREAUTH_USER = re.compile(
    r"^(?:Disconnected from|Connection closed by) (?:(?:authenticating|invalid) )?user "
    r"(?P<user>\S+) (?P<ip>\S+) port \d+ \[preauth\]")
_PREAUTH_IP = re.compile(r"^Connection closed by (?P<ip>\S+) port \d+ \[preauth\]")
_MAX_AUTH = re.compile(
    r"^error: maximum authentication attempts exceeded for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)")
_FAILED_OTHER = re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_FAILLOCK = re.compile(r"Consecutive login failures for user (?P<user>\S+).*locked")
_SUDOERS = re.compile(r"^(?P<user>\S+)(?: is not in the sudoers file| : user NOT in sudoers)")
_PAM_EMPTY_RHOST = re.compile(
    r"^pam_unix\(\S+\): authentication failure;.*\brhost=\s+user=(?P<user>\S+)")
_IPTABLES = re.compile(
    r"\b(?P<action>BLOCKED|DENIED|REJECTED|DROPPED|PERMITTED|ACCEPTED|BLOCK|DENY|DROP|REJECT|"
    r"ALLOW|ACCEPT|PERMIT|PASS)\b.*?\bSRC=(?P<ip>\S+)\s+DST=(?P<dst>\S+)"
    r"(?:.*?\bDPT=(?P<dpt>\d+))?", re.I)
_PRI = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424 = re.compile(
    r"^1 (?P<iso>\S+) (?P<host>\S+) (?P<prog>\S+) \S+ \S+ (?:-|\[[^\]]*\]) (?P<msg>.*)$")
_SYSLOG_LOOSE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)\s+(?P<msg>.*)$")
_FG_DENY = {"deny", "drop", "block", "denied", "dropped", "blocked", "reject", "rejected"}
_FG_ALLOW = {"accept", "allow", "permit", "pass", "accepted", "permitted"}
_FG_SESSION = {"close", "timeout", "client-rst", "server-rst", "ip-conn"}


def _ip_or_none(value):
    """Authlog captures are often hostnames. Keep the line and drop the address."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _firewall_hint(message):
    if not message:
        return False
    folded = message.lower()
    if "srcip=" in folded or "%asa-" in folded or "%ftd-" in folded or "filterlog" in folded:
        return True
    return "SRC=" in message and "DST=" in message


def _syslog_parts(line):
    """BSD, ISO, PRI-wrapped, or RFC5424. A loose header is only for firewall text."""
    text = line.strip()
    pri = _PRI.match(text)
    if pri and int(pri.group("pri")) <= 191:
        text = text[pri.end():]
    match = _SYSLOG_PREFIX.match(text) or _RFC5424.match(text)
    if match:
        groups = match.groupdict()
        prog = groups.get("prog")
        if prog == "-":
            prog = None
    else:
        match = _SYSLOG_LOOSE.match(text)
        if not match or not _firewall_hint(match.group("msg")):
            return None
        groups = match.groupdict()
        prog = "syslog"
    host = groups.get("host")
    if host == "-":
        host = None
    return {"iso": groups.get("iso"), "bsd": groups.get("bsd"), "host": host,
            "prog": prog, "msg": groups.get("msg") or ""}


def _pfsense_fields(message):
    """pfSense filterlog IPv4 CSV. IPv6 and any other CSV stay unmatched."""
    body = message.strip()
    prefix = re.match(r"filterlog(?:\[\d+\])?:\s*(.*)$", body)
    if prefix:
        body = prefix.group(1).strip()
    if not re.match(r"^\d+,,", body):
        return None
    parts = body.split(",")
    if len(parts) < 22 or parts[7] not in ("in", "out") or parts[8] != "4":
        return None
    kind = {"block": "fw_deny", "reject": "fw_deny", "pass": "fw_allow"}.get(parts[6].lower())
    if kind is None or _ip_or_none(parts[18]) is None or _ip_or_none(parts[19]) is None:
        return None
    fields = {"ip": parts[18], "dst": parts[19]}
    if parts[16].lower() in ("tcp", "udp") and parts[21].isdigit():
        fields["dpt"] = parts[21]
    return kind, fields


def _fortigate_fields(message):
    if "srcip=" not in message.lower() and "dstip=" not in message.lower():
        return None
    values = {}
    for key in ("srcip", "dstip", "dstport", "sentbyte", "action", "dport", "src", "dst"):
        found = re.search(rf"(?:^|\s){key}=(\"[^\"]*\"|\S+)", message)
        if found:
            values[key] = found.group(1).strip('"')
    action = (values.get("action") or "").lower()
    if action in _FG_DENY:
        kind = "fw_deny"
    elif action in _FG_ALLOW:
        kind = "fw_allow"
    elif action in _FG_SESSION:
        kind = "network_connection"
    else:
        return None
    src = values.get("srcip") or values.get("src")
    dst = values.get("dstip") or values.get("dst")
    if not src or not dst:
        return None
    fields = {"ip": src, "dst": dst, "dpt": values.get("dstport") or values.get("dport")}
    if values.get("sentbyte"):
        fields["bytes"] = values["sentbyte"]
    return kind, fields


def _match_firewall(message):
    parsed = _pfsense_fields(message)
    if parsed:
        return parsed
    parsed = _fortigate_fields(message)
    if parsed:
        return parsed
    found = _IPTABLES.search(message)
    if found:
        kind = _FIREWALL_ACTIONS.get(found.group("action").upper())
        if kind:
            fields = {key: value for key, value in found.groupdict().items() if key != "action"}
            return kind, fields
    return None


def _match_extra_auth(message):
    for pattern in (_PREAUTH_USER, _PREAUTH_IP):
        found = pattern.search(message)
        if found:
            return "other", found.groupdict()
    for pattern in (_MAX_AUTH, _FAILED_OTHER):
        found = pattern.search(message)
        if found:
            return "auth_failure", found.groupdict()
    found = _FAILLOCK.search(message)
    if found:
        return "account_lockout", found.groupdict()
    found = _SUDOERS.search(message)
    if found:
        return "privilege_escalation", {**found.groupdict(), "outcome": "failure"}
    found = _PAM_EMPTY_RHOST.search(message)
    if found:
        return "auth_failure", {"user": found.group("user")}
    return _match_firewall(message)


def normalize_authlog_line(line, default_source, year=None, now=None):
    now = now or utcnow()
    parts = _syslog_parts(line)
    if not parts:
        raise EventError("line is not in syslog format")
    if parts["iso"]:
        ts_value = parts["iso"]
    else:
        # BSD syslog has no year or zone: assume UTC and the given/current year,
        # rolling back a year if that would put the event in the future.
        bsd = parts["bsd"].split()
        stamp = f"{bsd[0]} {int(bsd[1]):02d} {bsd[2]}"
        try:
            dt = datetime.strptime(f"{year or now.year} {stamp}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            raise EventError("unparseable timestamp")
        if year is None and dt > now + MAX_FUTURE:
            dt = dt.replace(year=dt.year - 1)
        ts_value = iso(dt)

    message = parts["msg"]
    event_type, fields = "other", {}
    for pattern, kind in _SSH_PATTERNS:
        found = pattern.search(message)
        if found:
            fields = found.groupdict()
            event_type = _FIREWALL_ACTIONS[fields["action"]] if kind == "firewall" else kind
            break
    appliance = firewall.parse(parts["prog"], message) if event_type == "other" else None
    if event_type == "other" and not appliance:
        extra = _match_extra_auth(message)
        if extra:
            event_type, fields = extra

    record = {
        "ts": ts_value, "host": parts["host"], "event_type": event_type,
        "user": fields.get("user"), "src_ip": _ip_or_none(fields.get("ip")),
        "dest_ip": _ip_or_none(fields.get("dst")), "dest_port": fields.get("dpt"),
        "message": message, "program": parts["prog"],
    }
    if appliance:
        record.update(appliance)
    if fields.get("outcome"):
        record["outcome"] = fields["outcome"]
    if fields.get("bytes") is not None:
        record["bytes"] = fields["bytes"]
    event = normalize_record(record, default_source, now)
    event["raw"] = redact_cut(line.strip(), MAX_LEN["raw"])
    return event


# --- Web server access logs (nginx / Apache combined) --------------------------------

_WEBLOG = re.compile(
    r'^(?:(?P<vhost>\S+) )?(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?:-|(?P<method>[A-Z]{3,10}) (?P<path>\S+)(?: [^"]*)?)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
_APACHE_ERROR = re.compile(
    r"^\[(?P<time>[A-Za-z]{3} [A-Za-z]{3} [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]"
    r".*?\[client (?P<ip>[^\]]+)\] (?P<msg>.*)$")
_IIS_DIRECTIVE = re.compile(r"^#(Software|Version|Date|Fields)\b", re.I)
_IIS_DATA = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s|$)")
_IIS_DEFAULT_FIELDS = (
    "date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port",
    "cs-username", "c-ip", "cs(user-agent)", "cs(referer)", "sc-status",
    "sc-substatus", "sc-win32-status", "time-taken",
)
SCAN_PATHS = ("/.env", "/.git", "/.svn", "/.aws", "/.ds_store", "/.htaccess", "/wp-login.php", "/wp-admin",
              "/xmlrpc.php", "/phpmyadmin", "/pma/", "/server-status", "/cgi-bin/", "/actuator",
              "/vendor/phpunit", "/boot.ini", "/etc/passwd", "/config.php", "/admin.php", "/manager/html",
              "/wp-config.php", "/.ssh/", "/id_rsa", "/hnap1", "/boaform/", "/jmx-console",
              "/invoker/jmxinvokerservlet", "/solr/admin", "/manager/text")
_SCAN_PATTERN = re.compile(
    r"union\s+(?:all\s+)?select|'\s*or\s+'?\d|\bor\s+1\s*=\s*1|sleep\(\s*\d|benchmark\(|information_schema"
    r"|\.\./|<script|\$\{jndi:", re.I)
_SCANNER_AGENT = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix", re.I)


def classify_web_request(path, status, agent=None):
    """web_scan for scanner paths, injection patterns, or scanner user agents; web_error for 5xx."""
    decoded = path or ""
    for _ in range(2):  # %252e%252e is still encoded after one pass
        nxt = unquote_plus(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    decoded = decoded.lower()
    if any(p in decoded for p in SCAN_PATHS) or _SCAN_PATTERN.search(decoded) \
            or (agent and _SCANNER_AGENT.search(agent)):
        return "web_scan"
    if status >= 500:
        return "web_error"
    return "web_request"


def _vhost_name(value):
    if not value or value.count(":") != 1:
        return value
    host, port = value.rsplit(":", 1)
    return host if port.isdigit() and host else value


def _apache_record(match):
    stamp = re.sub(r"\.\d+", "", match.group("time"))
    stamp = re.sub(r" +", " ", stamp.strip())
    try:
        dt = datetime.strptime(stamp, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        raise EventError("unparseable access log timestamp")
    ip = match.group("ip")
    if ip.count(":") == 1 and ip.rsplit(":", 1)[1].isdigit():
        ip = ip.rsplit(":", 1)[0]
    msg = match.group("msg")
    return {
        "ts": iso(dt), "src_ip": ip, "event_type": classify_web_request(msg, 500),
        "outcome": "failure", "message": msg,
    }


def _iis_record(line, fields):
    parts = line.split()
    if not fields:
        if len(parts) != len(_IIS_DEFAULT_FIELDS):
            raise EventError("IIS line has no #Fields header")
        names = _IIS_DEFAULT_FIELDS
    elif len(parts) != len(fields):
        raise EventError("IIS line does not match #Fields")
    else:
        names = fields
    data = dict(zip(names, parts))
    if "date" not in data or "time" not in data:
        raise EventError("IIS line does not match #Fields")
    stem = data.get("cs-uri-stem") or "/"
    query = data.get("cs-uri-query")
    path = stem if query in (None, "", "-") else f"{stem}?{query}"
    try:
        status = int(data.get("sc-status", ""))
    except ValueError:
        raise EventError("IIS line does not match #Fields")
    agent = data.get("cs(user-agent)")
    if agent in (None, "", "-"):
        agent = None
    method = data.get("cs-method") or "-"
    record = {
        "ts": f"{data['date']}T{data['time']}",
        "event_type": classify_web_request(path, status, agent),
        "user": data.get("cs-username"), "src_ip": data.get("c-ip"), "dest_ip": data.get("s-ip"),
        "dest_port": data.get("s-port"), "outcome": "failure" if status >= 400 else "success",
        "message": f"{method} {path[:500]} -> {status}" + (f" ua={agent[:120]}" if agent else ""),
    }
    if data.get("sc-bytes") not in (None, "", "-"):
        record["bytes"] = data["sc-bytes"]
    return record


def normalize_weblog_line(line, default_source, now=None, fields=None):
    text = line.strip()
    if _IIS_DIRECTIVE.match(text):
        raise EventError("log header directive")
    apache = _APACHE_ERROR.match(text)
    if apache:
        record = _apache_record(apache)
    else:
        match = _WEBLOG.match(text)
        if match:
            try:
                dt = datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                raise EventError("unparseable access log timestamp")
            status = int(match.group("status"))
            path = match.group("path") or "-"
            method = match.group("method") or "-"
            agent = match.group("agent")
            record = {
                "ts": iso(dt), "event_type": classify_web_request(match.group("path"), status, agent),
                "user": match.group("user"), "src_ip": match.group("ip"),
                "outcome": "failure" if status >= 400 else "success",
                "bytes": match.group("size"),
                "message": f"{method} {path[:500]} -> {status}"
                           + (f" ua={agent[:120]}" if agent not in (None, "", "-") else ""),
            }
            host = _vhost_name(match.group("vhost"))
            if host:
                record["host"] = host
        elif _IIS_DATA.match(text):
            record = _iis_record(text, fields)
        else:
            raise EventError("line is not in combined access log format")
    event = normalize_record(record, default_source, now)
    event["raw"] = redact_cut(text, MAX_LEN["raw"])
    return event


# --- Batch parsing --------------------------------------------------------------

def _looks_like_json_array(text):
    """`[{...}]` is JSON. An Apache error line starts with `[Tue` and is not."""
    if not text.startswith("["):
        return False
    rest = text[1:].lstrip()
    if not rest:
        return True
    return rest[0] in '{["0123456789-tfn]'


def detect_format(text):
    stripped = text.lstrip()
    if _looks_like_json_array(stripped) or (stripped.startswith("{") and "\n{" not in stripped.strip()):
        return "json"
    if stripped.startswith("{"):
        return "jsonl"
    first = stripped.splitlines()[0] if stripped else ""
    if _syslog_parts(first):
        return "authlog"
    if (_WEBLOG.match(first) or _IIS_DIRECTIVE.match(first) or _IIS_DATA.match(first)
            or _APACHE_ERROR.match(first)):
        return "weblog"
    if "," in first:
        return "csv"
    raise EventError("could not detect format; pass format=json|jsonl|csv|authlog|weblog")


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
            if "events" in data:
                data = data["events"]
            elif isinstance(data.get("Records"), list):  # CloudTrail log file
                data = data["Records"]
            else:
                data = [data]
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
    iis_fields = None
    for index, item in items:
        try:
            if fmt == "jsonl":
                try:
                    item = json.loads(item)
                except json.JSONDecodeError:
                    raise EventError("line is not valid JSON")
            if fmt == "weblog" and isinstance(item, str) and item.lstrip().lower().startswith("#fields:"):
                iis_fields = [part.lower() for part in item.split(":", 1)[1].split()]
            if fmt == "authlog":
                events.append(normalize_authlog_line(item, default_source, year, now))
            elif fmt == "weblog":
                events.append(normalize_weblog_line(item, default_source, now, iis_fields))
            else:
                events.append(normalize_record(item, default_source, now))
        except EventError as exc:
            # Only the reason and position are recorded, never the rejected content.
            rejections.append({"index": index, "reason": str(exc)})
    return events, rejections
