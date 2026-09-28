"""Redaction and error recording.

Errors are stored with the exception *type* and a redacted message only.
Raw log lines, request bodies, and credentials are never written to the error log.
"""

import logging
import re

from .db import now_iso

log = logging.getLogger("watchpost")

_REDACTIONS = [
    # HTTP bearer / basic credentials (before key=value, which would otherwise eat the scheme word)
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    # key=value / key: value style secrets
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session)"
                r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"), r"\1\2[REDACTED]"),
    # Watchpost ingest tokens
    (re.compile(r"\bwp_[A-Za-z0-9_-]{16,}"), "wp_[REDACTED]"),
    # JSON "password": "..."
    (re.compile(r'(?i)("(?:password|passwd|secret|token|api_key)"\s*:\s*)"[^"]*"'), r'\1"[REDACTED]"'),
]


def redact(text):
    if text is None:
        return None
    text = str(text)
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


def configure_logging(level=logging.INFO):
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    log.handlers[:] = [handler]
    log.setLevel(level)
    log.propagate = False


def describe_exception(exc):
    """Type plus redacted, truncated message. No tracebacks with local variables."""
    return f"{type(exc).__name__}: {redact(str(exc))[:300]}"


def record_error(conn, component, exc_or_message, guidance=None):
    message = (
        describe_exception(exc_or_message)
        if isinstance(exc_or_message, BaseException)
        else redact(exc_or_message)[:500]
    )
    log.error("[%s] %s", component, message)
    if conn is None:
        return message
    try:
        conn.execute(
            "INSERT INTO error_log(created_at, component, message, guidance) VALUES (?,?,?,?)",
            (now_iso(), component, message, guidance),
        )
    except Exception as write_exc:  # storage itself may be the failure
        log.error("[diagnostics] could not persist error: %s", describe_exception(write_exc))
    return message
