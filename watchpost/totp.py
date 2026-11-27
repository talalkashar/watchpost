"""TOTP second factor (RFC 6238 over RFC 4226 HOTP): HMAC-SHA1, 6 digits, 30-second steps."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
STEP_SECONDS = 30
DRIFT_STEPS = 1  # accept the previous and the next step too (clock skew, slow typing)
ISSUER = "Watchpost"
_MAX_COUNTER = 2**64 - 1  # RFC 4226 counter is an unsigned 64-bit integer


def now():
    """The clock TOTP reads; tests replace it to step through time."""
    return time.time()


def generate_secret():
    """160 random bits (the RFC 4226 recommended length) as unpadded base32."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def decode_secret(secret):
    # Grouped secrets use spaces, newlines, or other Unicode whitespace. None of that is base32.
    secret = "".join(secret.split()).upper()
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def hotp(key, counter, digits=DIGITS):
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def step_at(timestamp):
    return int(timestamp // STEP_SECONDS)


def code_at(secret, timestamp, digits=DIGITS):
    return hotp(decode_secret(secret), step_at(timestamp), digits)


def verify(secret, code, last_step=None, timestamp=None):
    """Return the time step `code` matches within the drift window, or None.

    A step at or before `last_step` (the last one accepted for the account) is refused, so a code
    cannot be replayed, and neither can an older code once a newer one has been used.
    A bad code, secret, or timestamp returns None. It does not raise.
    """
    if not isinstance(code, str):
        return None
    code = "".join(code.split())
    # `isdigit` is true for Arabic-Indic and fullwidth digits. compare_digest then raises
    # TypeError on the non-ASCII string, which became a 500 on the sign-in routes.
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return None
    try:
        key = decode_secret(secret)
    except (AttributeError, TypeError, ValueError):
        return None
    # An empty key is not a secret: its code is public. Refuse it.
    if not key:
        return None
    try:
        current = step_at(now() if timestamp is None else timestamp)
    except (ArithmeticError, TypeError, ValueError):
        return None
    # Drift can step off either end of the unsigned counter range. struct.pack('>Q') raises
    # there, including for every check during the first 30 seconds of the Unix epoch.
    first = current - DRIFT_STEPS
    last = current + DRIFT_STEPS
    if last < 0 or first > _MAX_COUNTER:
        return None
    if first < 0:
        first = 0
    if last > _MAX_COUNTER:
        last = _MAX_COUNTER
    matched = None
    for step in range(first, last + 1):
        if hmac.compare_digest(hotp(key, step), code) and matched is None:
            matched = step
    if matched is None:
        return None
    if last_step is not None:
        try:
            if matched <= last_step:
                return None
        except TypeError:
            return None
    return matched


def otpauth_uri(username, secret):
    return f"otpauth://totp/{ISSUER}:{quote(username)}?secret={secret}&issuer={ISSUER}"
