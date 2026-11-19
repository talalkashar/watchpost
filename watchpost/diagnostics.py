"""Redaction and error recording.

Errors are stored with the exception *type* and a redacted message only.
Raw log lines, request bodies, and credentials are never written to the error log.
"""

import logging
import re

from .db import now_iso

log = logging.getLogger("watchpost")

# JSON and key=value share this list. Longer names come before token and secret.
# session_id is not a name here: the word session stops before the underscore.
_SECRET_NAMES = (
    "password|passwd|pwd|client_secret|private_key|access_token|refresh_token|id_token|"
    "secret|token|api[_-]?key|authorization|cookie|session"
)

# =, :, or a percent-encoded equals (%3D, and the double-encoded %253D seen in web logs).
_SEPARATOR = r"(\s*(?:=|:|%253d|%3d)\s*)"
# An escaped quote stays inside the value. Stopping at the first quote leaks the rest.
# An unclosed quote runs to the end of the text so the tail is not left in the clear.
_QUOTED_VALUE = r"\"(?:\\.|[^\"\\])*(?:\"|$)|'(?:\\.|[^'\\])*(?:'|$)"

_REDACTIONS = [
    # HTTP bearer / basic credentials (before key=value, which would otherwise eat the scheme word).
    # A quoted token must keep its own closer; a JSON string's closing quote is not that closer.
    (re.compile(r"(?i)\b(bearer|basic)\s+(?:(['\"])[A-Za-z0-9._~+/=-]{8,}\2"
                r"|[A-Za-z0-9._~+/=-]{8,})"), r"\1 [REDACTED]"),
    # user:password@host. host:port has a colon and no @, so it stays.
    (re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]*:)[^/\s@]+@"), r"\1[REDACTED]@"),
    # key=value / key: value. A single quote glued to the name is a Python repr key
    # ({'password': 'hunter2'}); JSON double quotes are handled below, not here.
    # A value that opens with { or [ is a container and is replaced as a whole later.
    (re.compile(r"(?i)\b(" + _SECRET_NAMES + r")('?)" + _SEPARATOR
                + r"(" + _QUOTED_VALUE + r"|(?![{[])[^\s,;&]+)"),
     r"\1\2\3[REDACTED]"),
    # Watchpost ingest tokens
    (re.compile(r"\bwp_[A-Za-z0-9_-]{16,}"), "wp_[REDACTED]"),
    # JSON keys. Same names as key=value above. An escaped quote stays inside the value.
    (re.compile(r'(?i)("(?:' + _SECRET_NAMES + r')"'
                r'\s*:\s*)"(?:\\.|[^"\\])*"'), r'\1"[REDACTED]"'),
    # Unquoted JSON values (a PIN, true/false/null, a bare token). Not strings or containers.
    (re.compile(r'(?i)("(?:' + _SECRET_NAMES + r')"\s*:\s*)'
                r"(?![\"'[{\]])[^\s,}\]]+"), r"\1[REDACTED]"),
]

# "password": { ... } and 'password': { ... } and password={ ... }. The value is replaced whole
# so a nested secret whose key is not itself a secret name does not survive.
_CONTAINER_KEY = re.compile(
    "(?i)"
    + r'(?:"(?:' + _SECRET_NAMES + r')"\s*:'
    + r"|'(?:" + _SECRET_NAMES + r")'\s*:"
    + r"|\b(?:" + _SECRET_NAMES + r")\s*(?:=|:|%253d|%3d))"
    + r"\s*"
)


def _opening_quote_ok(text, index):
    """A quote that opens a key is escaped when an odd run of backslashes precedes it."""
    if text[index] not in "'\"":
        return True
    slashes = 0
    i = index - 1
    while i >= 0 and text[i] == "\\":
        slashes += 1
        i -= 1
    return slashes % 2 == 0


def _string_end(text, start):
    """Index just past a ' or \" string that starts at start, or None if it never closes."""
    quote = text[start]
    i = start + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return None


def _container_end(text, start):
    """Index just past a {...} or [...] value. Strings hide brackets. None if it never closes."""
    pairs = {"{": "}", "[": "]"}
    if start >= len(text) or text[start] not in pairs:
        return None
    stack = [pairs[text[start]]]
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch in "'\"":
            i = _string_end(text, i)
            if i is None:
                return None
            continue
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch == stack[-1]:
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return None


def _redact_containers(text):
    parts = []
    pos = 0
    for match in _CONTAINER_KEY.finditer(text):
        if match.start() < pos or not _opening_quote_ok(text, match.start()):
            continue
        start = match.end()
        if start >= len(text) or text[start] not in "{[":
            continue
        end = _container_end(text, start)
        if end is None:
            continue
        parts.append(text[pos:start])
        parts.append("[REDACTED]")
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def redact(text):
    if text is None:
        return None
    text = str(text)
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return _redact_containers(text)


def redact_cut(text, limit):
    """Redact the whole text, then cut it.

    A quoted secret needs its closing quote. Cutting first leaves the secret
    in the stored prefix when that quote sits past the limit.
    """
    if text is None:
        return None
    return redact(text)[:limit]


def _as_text(value):
    """String form of a logged value. None and a broken __str__ must not raise."""
    if value is None:
        return "None"
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        try:
            return repr(value)
        except Exception:
            return ""


def _rendered_message(record):
    """The line a handler would emit. A bad %-format must not skip the secret in args."""
    try:
        return record.getMessage()
    except Exception:
        args = record.args
        if isinstance(args, dict):
            extras = list(args.values())
        elif isinstance(args, tuple):
            extras = list(args)
        elif args:
            extras = [args]
        else:
            extras = []
        chunks = []
        for part in (record.msg, *extras):
            chunks.append(_as_text(part) if part is not None else "")
        return " ".join(chunks)


class RedactingFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(_rendered_message(record))
        record.args = ()
        # Formatter.format appends traceback text after filters run. Render it here
        # so the secret inside the exception message is redacted, then drop exc_info
        # so the formatter does not append the raw traceback beside it.
        if record.exc_info and not record.exc_text:
            exc = record.exc_info[1] if len(record.exc_info) > 1 else None
            try:
                if record.exc_info[0]:
                    record.exc_text = logging.Formatter().formatException(record.exc_info)
            except Exception:
                record.exc_text = describe_exception(exc) if isinstance(exc, BaseException) else ""
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        record.exc_info = None
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
    return f"{type(exc).__name__}: {redact(_as_text(exc))[:300]}"


def record_error(conn, component, exc_or_message, guidance=None):
    message = (
        describe_exception(exc_or_message)
        if isinstance(exc_or_message, BaseException)
        else redact(_as_text(exc_or_message))[:500]
    )
    if guidance is not None:
        guidance = redact(_as_text(guidance))
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
