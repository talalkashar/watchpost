"""Users, sessions, API tokens, and role checks."""

import base64
import hashlib
import hmac
import os
import secrets
from datetime import timedelta
from pathlib import Path

from .db import audit, iso, now_iso, parse_iso, utcnow

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
PBKDF2_ITERATIONS = int(os.environ.get("SIEM_PBKDF2_ITERATIONS", "310000"))
_DUMMY_HASH = None


class AuthError(Exception):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


def hash_password(password, iterations=None):
    iterations = iterations or PBKDF2_ITERATIONS
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password, stored):
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(candidate, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_password_strength(password):
    if not isinstance(password, str) or len(password) < 12:
        raise AuthError("password must be at least 12 characters", 400)
    if len(password) > 256:
        raise AuthError("password is too long", 400)


def create_user(conn, username, password, role, actor="system"):
    if role not in ROLES:
        raise AuthError(f"role must be one of {', '.join(ROLES)}", 400)
    if not isinstance(username, str) or not (3 <= len(username) <= 32) or not username.replace("_", "").isalnum():
        raise AuthError("username must be 3-32 letters, digits, or underscores", 400)
    validate_password_strength(password)
    conn.execute(
        "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
        (username, hash_password(password), role, now_iso()),
    )
    audit(conn, actor, "user_created", username, {"role": role})


def bootstrap_users(conn, config, data_dir):
    """Create the initial admin and analyst accounts on an empty database.

    Passwords come from environment variables; otherwise they are generated and
    written to a 0600 file, never printed to logs.
    """
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return None
    generated = {}
    for username, role, supplied in (("admin", "admin", config.admin_password),
                                     ("analyst", "analyst", config.analyst_password)):
        password = supplied or secrets.token_urlsafe(15)
        if not supplied:
            generated[username] = password
        create_user(conn, username, password, role)
    if generated:
        path = Path(data_dir) / "initial_credentials.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write("# Watchpost initial credentials. Store them safely, then delete this file.\n")
            for username, password in generated.items():
                handle.write(f"{username}: {password}\n")
        return str(path)
    return None


def get_setting_int(conn, key, default):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return int(row["value"]) if row else default


def login(conn, username, password, ttl_seconds):
    global _DUMMY_HASH
    threshold = get_setting_int(conn, "login_lockout_threshold", 5)
    lock_minutes = get_setting_int(conn, "login_lockout_minutes", 15)
    user = conn.execute("SELECT * FROM users WHERE username = ?", (str(username)[:64],)).fetchone()
    if user is None:
        # Spend comparable time so response timing does not reveal valid usernames.
        _DUMMY_HASH = _DUMMY_HASH or hash_password("dummy-password-for-timing")
        verify_password(str(password), _DUMMY_HASH)
        audit(conn, "anonymous", "login_failed", None, {"reason": "unknown user"})
        raise AuthError("invalid username or password")
    if user["disabled"]:
        raise AuthError("invalid username or password")
    if user["locked_until"] and parse_iso(user["locked_until"]) > utcnow():
        audit(conn, user["username"], "login_blocked", None, {"reason": "locked"})
        raise AuthError("account temporarily locked after repeated failures; try again later", 429)
    if not verify_password(str(password), user["pw_hash"]):
        failures = user["failed_logins"] + 1
        locked_until = None
        if failures >= threshold:
            locked_until = iso(utcnow() + timedelta(minutes=lock_minutes))
            failures = 0
        conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                     (failures, locked_until, user["id"]))
        audit(conn, user["username"], "login_failed", None, {"locked": bool(locked_until)})
        raise AuthError("invalid username or password")
    conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at) VALUES (?,?,?,?,?)",
        (sha256(token), user["id"], csrf, now_iso(), iso(utcnow() + timedelta(seconds=ttl_seconds))),
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso(),))
    audit(conn, user["username"], "login", None)
    return token, csrf, {"username": user["username"], "role": user["role"]}


def logout(conn, token):
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (sha256(token),))


def session_user(conn, token):
    if not token:
        return None
    row = conn.execute(
        "SELECT u.username, u.role, u.disabled, s.csrf_token, s.expires_at FROM sessions s"
        " JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (sha256(token),),
    ).fetchone()
    if row is None or row["disabled"] or parse_iso(row["expires_at"]) < utcnow():
        return None
    return {"username": row["username"], "role": row["role"], "csrf": row["csrf_token"], "via": "session"}


def create_api_token(conn, name, actor):
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= 64):
        raise AuthError("token name must be 1-64 characters", 400)
    token = "wp_" + secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO api_tokens(name, token_hash, prefix, created_by, created_at) VALUES (?,?,?,?,?)",
        (name.strip(), sha256(token), token[:7], actor, now_iso()),
    )
    audit(conn, actor, "api_token_created", name.strip())
    return token


def token_user(conn, token):
    """API tokens are ingest-only credentials; they map to a limited 'ingest' principal."""
    if not token or not token.startswith("wp_"):
        return None
    row = conn.execute(
        "SELECT id, name FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL", (sha256(token),)
    ).fetchone()
    if row is None:
        return None
    conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now_iso(), row["id"]))
    return {"username": f"token:{row['name']}", "role": "ingest", "via": "token"}


def has_role(user, minimum):
    return user is not None and ROLES.get(user["role"], 0) >= ROLES[minimum]
