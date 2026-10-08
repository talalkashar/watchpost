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


def now():
    """The clock TOTP reads; tests replace it to step through time."""
    return time.time()


def generate_secret():
    """160 random bits (the RFC 4226 recommended length) as unpadded base32."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def decode_secret(secret):
    secret = secret.strip().replace(" ", "").upper()
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
    """
    if not isinstance(code, str):
        return None
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = decode_secret(secret)
    current = step_at(now() if timestamp is None else timestamp)
    matched = None
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if hmac.compare_digest(hotp(key, step), code) and matched is None:
            matched = step
    if matched is None or (last_step is not None and matched <= last_step):
        return None
    return matched


def otpauth_uri(username, secret):
    return f"otpauth://totp/{ISSUER}:{quote(username)}?secret={secret}&issuer={ISSUER}"
