"""Runtime configuration, read from environment variables only.

Secrets are never hard-coded. Blank values count as unset. If SIEM_ADMIN_PASSWORD /
SIEM_ANALYST_PASSWORD are unset on first start, random passwords are generated and
written once to data/initial_credentials.txt (mode 0600) instead of being logged.
A read-only `viewer` account is created only when SIEM_VIEWER_PASSWORD is set.
"""

import ipaddress
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Cookie Max-Age and the other counters are signed 32-bit at the edge that consumes them.
_INT_MAX = 2**31 - 1
_PORT_MIN, _PORT_MAX = 0, 65535
# storyline.build rejects anything outside this. A bad speed fails the demo thread, not startup.
_SPEED_MIN, _SPEED_MAX = 0.1, 10_000.0
_INT_RE = re.compile(r"[+-]?\d+\Z")
_FLOAT_RE = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\Z")


def _is_blank(value):
    return value is None or (isinstance(value, str) and value.strip() == "")


def _clean_token(text):
    """Strip whitespace and one matching pair of quotes. Env files often leave both on."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text


def _has_control(text):
    return any(ord(char) < 32 or ord(char) == 127 for char in text)


def _int_error(name, minimum, maximum):
    return ValueError(f"{name} must be an integer between {minimum} and {maximum}")


def _parse_int_token(name, text, minimum, maximum):
    text = _clean_token(text)
    if text == "":
        return None
    if _INT_RE.fullmatch(text):
        number = int(text, 10)
    elif _FLOAT_RE.fullmatch(text):
        try:
            number_f = float(text)
        except ValueError:
            raise _int_error(name, minimum, maximum) from None
        if not math.isfinite(number_f) or not number_f.is_integer():
            raise _int_error(name, minimum, maximum)
        number = int(number_f)
    else:
        raise _int_error(name, minimum, maximum)
    if number < minimum or number > maximum:
        raise _int_error(name, minimum, maximum)
    return number


def _coerce_int(name, value, minimum, maximum, default):
    if isinstance(value, bool):
        raise _int_error(name, minimum, maximum)
    if isinstance(value, int):
        if value < minimum or value > maximum:
            raise _int_error(name, minimum, maximum)
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise _int_error(name, minimum, maximum)
        number = int(value)
        if number < minimum or number > maximum:
            raise _int_error(name, minimum, maximum)
        return number
    if _is_blank(value):
        return default
    if isinstance(value, str):
        parsed = _parse_int_token(name, value, minimum, maximum)
        return default if parsed is None else parsed
    raise _int_error(name, minimum, maximum)


def _parse_float_token(name, text):
    text = _clean_token(text)
    if text == "":
        return None
    if not _FLOAT_RE.fullmatch(text):
        raise ValueError(f"{name} must be a finite number")
    try:
        number = float(text)
    except ValueError:
        raise ValueError(f"{name} must be a finite number") from None
    if not math.isfinite(number):
        raise ValueError(f"{name} must be a finite number")
    return number


def _coerce_rate(name, value, default):
    """Events per minute. The limiter divides by this rate; a tiny value underflows to 0."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive finite number")
    if isinstance(value, (int, float)):
        number = float(value)
    elif _is_blank(value):
        return float(default)
    elif isinstance(value, str):
        parsed = _parse_float_token(name, value)
        number = float(default) if parsed is None else parsed
    else:
        raise ValueError(f"{name} must be a positive finite number")
    if not math.isfinite(number) or not (number / 60.0) > 0:
        raise ValueError(f"{name} must be a positive finite number")
    return float(number)


def _coerce_speed(value):
    name = "SIEM_DEMO_LOOP_SPEED"
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number between {_SPEED_MIN} and {_SPEED_MAX:g}")
    if isinstance(value, (int, float)):
        number = float(value)
    elif _is_blank(value):
        return 1.0
    elif isinstance(value, str):
        parsed = _parse_float_token(name, value)
        number = 1.0 if parsed is None else parsed
    else:
        raise ValueError(f"{name} must be a number between {_SPEED_MIN} and {_SPEED_MAX:g}")
    if not math.isfinite(number) or number < _SPEED_MIN or number > _SPEED_MAX:
        raise ValueError(f"{name} must be a number between {_SPEED_MIN} and {_SPEED_MAX:g}")
    return float(number)


def _coerce_flag(name, value, default):
    """Documented switches are exactly 0 or 1. Anything else is a mistake, not a silent default."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if _is_blank(value):
        return default
    if isinstance(value, str):
        token = _clean_token(value)
        if token == "":
            return default
        if token == "1":
            return True
        if token == "0":
            return False
    raise ValueError(f"{name} must be 0 or 1")


def _coerce_host(name, value, default):
    # "" is every interface for HTTPServer. A blank SIEM_HOST must stay on loopback.
    if _is_blank(value):
        return default
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a bind address")
    text = _clean_token(value)
    if text == "":
        return default
    if text.startswith("[") and text.endswith("]"):
        try:
            ipaddress.ip_address(text[1:-1])
        except ValueError:
            raise ValueError(f"{name} must be a bind address") from None
        text = text[1:-1]
    if _has_control(text) or any(char.isspace() for char in text) or "://" in text or "/" in text:
        raise ValueError(f"{name} must be a bind address")
    return text


def _coerce_db_path(value):
    if _is_blank(value):
        return str(BASE_DIR / "data" / "watchpost.db")
    if not isinstance(value, str):
        raise ValueError("SIEM_DB must be a filesystem path")
    text = _clean_token(value)
    if text == "":
        return str(BASE_DIR / "data" / "watchpost.db")
    if text == ":memory:":
        return text
    if _has_control(text):
        raise ValueError("SIEM_DB must be a filesystem path")
    if text.startswith("~"):
        text = str(Path(text).expanduser())
    if text == "" or _has_control(text):
        raise ValueError("SIEM_DB must be a filesystem path")
    return text


def _coerce_allow(value):
    if _is_blank(value):
        return ""
    if not isinstance(value, str):
        raise ValueError("SIEM_SYSLOG_ALLOW must be a comma-separated list of IPs or CIDR networks")
    text = _clean_token(value)
    if text == "":
        return ""
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"SIEM_SYSLOG_ALLOW entry is not an IP or CIDR network: {item}") from None
    return text


def _coerce_secret(name, value):
    """Whitespace-only is unset. A real value is kept as written, spaces included."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if value.strip() == "":
        return None
    return value


def _env_port_choice():
    """SIEM_PORT wins. A blank SIEM_PORT falls through to PORT, then 8080."""
    primary = os.environ.get("SIEM_PORT")
    if not _is_blank(primary):
        return primary, "SIEM_PORT"
    fallback = os.environ.get("PORT")
    if not _is_blank(fallback):
        return fallback, "PORT"
    return None, "SIEM_PORT"


@dataclass
class Config:
    db_path: str
    host: str
    port: int
    session_ttl_seconds: int
    secure_cookies: bool
    max_upload_bytes: int
    max_batch_events: int
    admin_password: str | None
    analyst_password: str | None
    # Live syslog listener (off unless SIEM_SYSLOG=1). Loopback by default: syslog is unauthenticated.
    syslog_enabled: bool = False
    syslog_bind: str = "127.0.0.1"
    syslog_port: int = 5514
    syslog_allow: str = ""
    # Read-only demo account, created on start when set and no `viewer` user exists yet.
    viewer_password: str | None = None
    # Per-IP token buckets: a strict one for POST /api/auth/login, a looser one for everything else.
    rate_limit_enabled: bool = True
    login_rate_burst: int = 10
    login_rate_per_minute: float = 10.0
    rate_burst: int = 300
    rate_per_minute: float = 1200.0
    # Behind a reverse proxy on loopback, take the client IP from the last entry of the one X-Forwarded-For header.
    trust_proxy: bool = False
    # Attack storyline auto-replay for public demos (off unless SIEM_DEMO_LOOP=<minutes between runs>).
    demo_loop_minutes: int = 0
    demo_loop_speed: float = 1.0
    # HMAC key for the hash-chained audit log. Unset: plain SHA-256, which detects edits but not a full rewrite.
    audit_key: str | None = None

    def __post_init__(self):
        self.db_path = _coerce_db_path(self.db_path)
        self.host = _coerce_host("SIEM_HOST", self.host, "127.0.0.1")
        self.port = _coerce_int("SIEM_PORT", self.port, _PORT_MIN, _PORT_MAX, 8080)
        self.session_ttl_seconds = _coerce_int(
            "SIEM_SESSION_TTL", self.session_ttl_seconds, 1, _INT_MAX, 28800)
        self.secure_cookies = _coerce_flag("SIEM_SECURE_COOKIES", self.secure_cookies, False)
        self.max_upload_bytes = _coerce_int(
            "SIEM_MAX_UPLOAD_BYTES", self.max_upload_bytes, 1, _INT_MAX, 5 * 1024 * 1024)
        self.max_batch_events = _coerce_int(
            "SIEM_MAX_BATCH_EVENTS", self.max_batch_events, 1, _INT_MAX, 20000)
        self.admin_password = _coerce_secret("SIEM_ADMIN_PASSWORD", self.admin_password)
        self.analyst_password = _coerce_secret("SIEM_ANALYST_PASSWORD", self.analyst_password)
        self.syslog_enabled = _coerce_flag("SIEM_SYSLOG", self.syslog_enabled, False)
        self.syslog_bind = _coerce_host("SIEM_SYSLOG_BIND", self.syslog_bind, "127.0.0.1")
        self.syslog_port = _coerce_int("SIEM_SYSLOG_PORT", self.syslog_port, _PORT_MIN, _PORT_MAX, 5514)
        self.syslog_allow = _coerce_allow(self.syslog_allow)
        self.viewer_password = _coerce_secret("SIEM_VIEWER_PASSWORD", self.viewer_password)
        self.rate_limit_enabled = _coerce_flag("SIEM_RATE_LIMIT", self.rate_limit_enabled, True)
        self.login_rate_burst = _coerce_int(
            "SIEM_LOGIN_RATE_BURST", self.login_rate_burst, 1, _INT_MAX, 10)
        self.login_rate_per_minute = _coerce_rate(
            "SIEM_LOGIN_RATE_PER_MIN", self.login_rate_per_minute, 10.0)
        self.rate_burst = _coerce_int("SIEM_RATE_BURST", self.rate_burst, 1, _INT_MAX, 300)
        self.rate_per_minute = _coerce_rate("SIEM_RATE_PER_MIN", self.rate_per_minute, 1200.0)
        self.trust_proxy = _coerce_flag("SIEM_TRUST_PROXY", self.trust_proxy, False)
        self.demo_loop_minutes = _coerce_int("SIEM_DEMO_LOOP", self.demo_loop_minutes, 0, _INT_MAX, 0)
        self.demo_loop_speed = _coerce_speed(self.demo_loop_speed)
        self.audit_key = _coerce_secret("SIEM_AUDIT_KEY", self.audit_key)

    @classmethod
    def from_env(cls, **overrides):
        values = dict(
            db_path=os.environ.get("SIEM_DB"),
            host=os.environ.get("SIEM_HOST"),
            port=None,
            session_ttl_seconds=os.environ.get("SIEM_SESSION_TTL"),
            secure_cookies=os.environ.get("SIEM_SECURE_COOKIES"),
            max_upload_bytes=os.environ.get("SIEM_MAX_UPLOAD_BYTES"),
            max_batch_events=os.environ.get("SIEM_MAX_BATCH_EVENTS"),
            admin_password=os.environ.get("SIEM_ADMIN_PASSWORD"),
            analyst_password=os.environ.get("SIEM_ANALYST_PASSWORD"),
            syslog_enabled=os.environ.get("SIEM_SYSLOG"),
            syslog_bind=os.environ.get("SIEM_SYSLOG_BIND"),
            syslog_port=os.environ.get("SIEM_SYSLOG_PORT"),
            syslog_allow=os.environ.get("SIEM_SYSLOG_ALLOW"),
            viewer_password=os.environ.get("SIEM_VIEWER_PASSWORD"),
            rate_limit_enabled=os.environ.get("SIEM_RATE_LIMIT"),
            login_rate_burst=os.environ.get("SIEM_LOGIN_RATE_BURST"),
            login_rate_per_minute=os.environ.get("SIEM_LOGIN_RATE_PER_MIN"),
            rate_burst=os.environ.get("SIEM_RATE_BURST"),
            rate_per_minute=os.environ.get("SIEM_RATE_PER_MIN"),
            trust_proxy=os.environ.get("SIEM_TRUST_PROXY"),
            demo_loop_minutes=os.environ.get("SIEM_DEMO_LOOP"),
            demo_loop_speed=os.environ.get("SIEM_DEMO_LOOP_SPEED"),
            audit_key=os.environ.get("SIEM_AUDIT_KEY"),
        )
        values.update(overrides)
        if "port" not in overrides:
            # Name the variable that was actually set. A bad PORT must not be blamed on SIEM_PORT.
            text, name = _env_port_choice()
            values["port"] = _coerce_int(name, text, _PORT_MIN, _PORT_MAX, 8080)
        return cls(**values)
