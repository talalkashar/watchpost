"""Users, sessions, API tokens, and role checks."""

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import timedelta
from pathlib import Path

from . import totp
from .db import audit, iso, now_iso, parse_iso, transaction, utcnow

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
TOKEN_CAPABILITIES = {"read", "ingest", "triage"}
PBKDF2_ITERATIONS = int(os.environ.get("SIEM_PBKDF2_ITERATIONS", "310000"))
_DUMMY_HASH = None
MFA_TOKEN_TTL_SECONDS = 300
SESSION_SEEN_INTERVAL_SECONDS = 60  # last_seen_at is refreshed at most this often per session


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
    written to a 0600 file, never printed to logs. The read-only `viewer` account is
    created only when SIEM_VIEWER_PASSWORD is set, on any start where no user named
    `viewer` exists yet (so an existing database can gain one). It is never generated.
    """
    path = None
    if not conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        path = _bootstrap_initial(conn, config, data_dir)
    viewer_password = getattr(config, "viewer_password", None)
    if viewer_password and conn.execute("SELECT 1 FROM users WHERE username = 'viewer'").fetchone() is None:
        create_user(conn, "viewer", viewer_password, "viewer")
    return path


def _bootstrap_initial(conn, config, data_dir):
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


class MfaChallenge:
    """The password was right, but the account has TOTP enrolled: a code must follow with this token."""

    def __init__(self, mfa_token):
        self.mfa_token = mfa_token


def _lockout_settings(conn):
    return get_setting_int(conn, "login_lockout_threshold", 5), get_setting_int(conn, "login_lockout_minutes", 15)


def _check_not_locked(conn, user):
    if user["locked_until"] and parse_iso(user["locked_until"]) > utcnow():
        audit(conn, user["username"], "login_blocked", None, {"reason": "locked"})
        raise AuthError("account temporarily locked after repeated failures; try again later", 429)


def _count_failure(conn, user_id):
    """Add one failure to the account inside the caller's transaction, locking it at the threshold.

    The count is re-read under BEGIN IMMEDIATE, so concurrent attempts cannot overwrite each other's increment.
    Returns True when this failure locks the account.
    """
    threshold, lock_minutes = _lockout_settings(conn)
    failures = conn.execute("SELECT failed_logins FROM users WHERE id = ?", (user_id,)).fetchone()[0] + 1
    locked_until = None
    if failures >= threshold:
        locked_until = iso(utcnow() + timedelta(minutes=lock_minutes))
        failures = 0
    conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?", (failures, locked_until, user_id))
    return bool(locked_until)


def _record_failure(conn, user, detail=None):
    """Count a failed password toward the per-account lockout. Returns True when it locks."""
    with transaction(conn):
        locked = _count_failure(conn, user["id"])
        audit(conn, user["username"], "login_failed", None, {**(detail or {}), "locked": locked})
    return locked


def _reserve_code_attempt(conn, user_id):
    """Spend one attempt before a TOTP code is checked: refuse when locked, else count it as a failure now.

    Checking the lock and counting happen in one transaction, so parallel guesses cannot all slip in before
    the lock lands: at most `threshold` codes are ever checked per lockout window. A correct code then
    clears the count and the lock (_start_session), and a TOTP step can only be used once, so counting first
    loses nothing. Returns True when this attempt set the lock.
    """
    with transaction(conn):
        row = conn.execute("SELECT username, locked_until FROM users WHERE id = ?", (user_id,)).fetchone()
        if row["locked_until"] and parse_iso(row["locked_until"]) > utcnow():
            audit(conn, row["username"], "login_blocked", None, {"reason": "locked"})
            locked_out = True
        else:
            locked_out = False
            locked = _count_failure(conn, user_id)
    if locked_out:
        raise AuthError("account temporarily locked after repeated failures; try again later", 429)
    return locked


def _start_session(conn, user, ttl_seconds, detail=None):
    conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    created = now_iso()
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at, sid, last_seen_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (sha256(token), user["id"], csrf, created, iso(utcnow() + timedelta(seconds=ttl_seconds)),
         secrets.token_hex(8), created),
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso(),))
    audit(conn, user["username"], "login", None, detail)
    return token, csrf, {"username": user["username"], "role": user["role"]}


def login(conn, username, password, ttl_seconds):
    """Check the password. Returns (token, csrf, user), or an MfaChallenge when the account has TOTP enrolled.

    For an enrolled account the password step does not reset the failure count: only a correct code does,
    so knowing the password does not buy unlimited code guesses.
    """
    global _DUMMY_HASH
    user = conn.execute("SELECT * FROM users WHERE username = ?", (str(username)[:64],)).fetchone()
    if user is None:
        # Spend comparable time so response timing does not reveal valid usernames.
        _DUMMY_HASH = _DUMMY_HASH or hash_password("dummy-password-for-timing")
        verify_password(str(password), _DUMMY_HASH)
        audit(conn, "anonymous", "login_failed", None, {"reason": "unknown user"})
        raise AuthError("invalid username or password")
    if user["disabled"]:
        raise AuthError("invalid username or password")
    _check_not_locked(conn, user)
    if not verify_password(str(password), user["pw_hash"]):
        _record_failure(conn, user)
        raise AuthError("invalid username or password")
    if user["totp_secret"]:
        mfa_token = secrets.token_urlsafe(32)
        conn.execute("DELETE FROM mfa_pending WHERE expires_at < ?", (now_iso(),))
        conn.execute("INSERT INTO mfa_pending(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                     (sha256(mfa_token), user["id"], now_iso(),
                      iso(utcnow() + timedelta(seconds=MFA_TOKEN_TTL_SECONDS))))
        audit(conn, user["username"], "login_mfa_challenge", None)
        return MfaChallenge(mfa_token)
    return _start_session(conn, user, ttl_seconds)


def complete_mfa(conn, mfa_token, code, ttl_seconds):
    """Second login step: a pending token from login() plus a current TOTP code. Returns (token, csrf, user).

    A wrong code counts toward the same lockout as a wrong password. The pending token may be retried until
    it expires or the account locks, and is consumed by the first success.
    """
    if not isinstance(mfa_token, str) or not mfa_token:
        raise AuthError("sign-in step expired; sign in again")
    pending = conn.execute(
        "SELECT p.expires_at, u.* FROM mfa_pending p JOIN users u ON u.id = p.user_id WHERE p.token_hash = ?",
        (sha256(mfa_token),),
    ).fetchone()
    if pending is None or parse_iso(pending["expires_at"]) < utcnow() or pending["disabled"] \
            or not pending["totp_secret"]:
        raise AuthError("sign-in step expired; sign in again")
    locked = _reserve_code_attempt(conn, pending["id"])
    step = totp.verify(pending["totp_secret"], code, pending["totp_last_step"])
    if step is None:
        if locked:
            conn.execute("DELETE FROM mfa_pending WHERE user_id = ?", (pending["id"],))
        audit(conn, pending["username"], "login_failed", None, {"reason": "mfa", "locked": locked})
        raise AuthError("invalid authentication code")
    # Both checks are single statements, so two requests racing with the same token or code cannot both win.
    if not conn.execute("DELETE FROM mfa_pending WHERE token_hash = ?", (sha256(mfa_token),)).rowcount:
        raise AuthError("sign-in step expired; sign in again")
    if not _claim_step(conn, pending["id"], step):
        if locked:
            conn.execute("DELETE FROM mfa_pending WHERE user_id = ?", (pending["id"],))
        audit(conn, pending["username"], "login_failed", None, {"reason": "mfa", "locked": locked})
        raise AuthError("invalid authentication code")
    return _start_session(conn, pending, ttl_seconds, {"mfa": True})


def _claim_step(conn, user_id, step):
    return conn.execute(
        "UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
        (step, user_id, step),
    ).rowcount == 1


def logout(conn, token):
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (sha256(token),))


def session_user(conn, token):
    if not token:
        return None
    row = conn.execute(
        "SELECT u.username, u.role, u.disabled, s.csrf_token, s.expires_at, s.sid, s.last_seen_at FROM sessions s"
        " JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (sha256(token),),
    ).fetchone()
    if row is None or row["disabled"] or parse_iso(row["expires_at"]) < utcnow():
        return None
    now = utcnow()
    if not row["last_seen_at"] or \
            (now - parse_iso(row["last_seen_at"])).total_seconds() >= SESSION_SEEN_INTERVAL_SECONDS:
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (iso(now), sha256(token)))
    return {"username": row["username"], "role": row["role"], "csrf": row["csrf_token"], "via": "session",
            "sid": row["sid"]}


# --- TOTP enrollment ------------------------------------------------------------------------

def _user_row(conn, username):
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        raise AuthError("user not found", 404)
    return user


def mfa_status(conn, username):
    user = _user_row(conn, username)
    return {"enabled": bool(user["totp_secret"]), "pending": bool(user["totp_pending"]),
            "available": ROLES.get(user["role"], 0) >= ROLES["analyst"]}


def mfa_enroll(conn, username):
    """Start (or restart) an enrollment: a new pending secret, active only once confirmed with a code."""
    user = _user_row(conn, username)
    if ROLES.get(user["role"], 0) < ROLES["analyst"]:
        raise AuthError("this account cannot enroll in two-factor authentication", 403)
    if user["totp_secret"]:
        raise AuthError("two-factor authentication is already on; disable it first", 409)
    secret = totp.generate_secret()
    conn.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (secret, user["id"]))
    audit(conn, username, "mfa_enroll_started", username)
    return {"secret": secret, "otpauth_uri": totp.otpauth_uri(username, secret)}


def mfa_confirm(conn, username, code):
    user = _user_row(conn, username)
    if not user["totp_pending"]:
        raise AuthError("no enrollment in progress; start one first", 409)
    step = totp.verify(user["totp_pending"], code)
    if step is None:
        raise AuthError("invalid authentication code", 400)
    # The confirming step is recorded as used, so the same code cannot also sign in.
    conn.execute("UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ? WHERE id = ?",
                 (step, user["id"]))
    audit(conn, username, "mfa_enabled", username)
    return {"enabled": True}


def _clear_mfa(conn, user_id):
    conn.execute("UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?",
                 (user_id,))
    conn.execute("DELETE FROM mfa_pending WHERE user_id = ?", (user_id,))


def mfa_disable(conn, username, code):
    """Turn TOTP off for your own account; needs a current code (or cancels an unconfirmed enrollment)."""
    user = _user_row(conn, username)
    if not user["totp_secret"]:
        if user["totp_pending"]:
            _clear_mfa(conn, user["id"])
            audit(conn, username, "mfa_enroll_cancelled", username)
            return {"enabled": False}
        raise AuthError("two-factor authentication is not on", 409)
    # Same budget as signing in, so a stolen session cannot guess codes to turn the second factor off.
    _reserve_code_attempt(conn, user["id"])
    step = totp.verify(user["totp_secret"], code, user["totp_last_step"])
    if step is None or not _claim_step(conn, user["id"], step):
        audit(conn, username, "mfa_disable_failed", username)
        raise AuthError("invalid authentication code", 400)
    conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    _clear_mfa(conn, user["id"])
    audit(conn, username, "mfa_disabled", username)
    return {"enabled": False}


def mfa_admin_reset(conn, username, actor):
    """The recovery path: an admin turns off another user's TOTP. There are no recovery codes."""
    if username == actor:
        raise AuthError("use your own disable step (with a current code) for your account", 400)
    user = _user_row(conn, username)
    if not user["totp_secret"] and not user["totp_pending"]:
        raise AuthError("that user has no two-factor authentication to reset", 409)
    _clear_mfa(conn, user["id"])
    audit(conn, actor, "mfa_reset", username)
    return {"enabled": False}


# --- Sessions -------------------------------------------------------------------------------

def list_sessions(conn, username=None, current_sid=None):
    """Active sessions (all users when `username` is None). Never includes the token or its hash."""
    sql = ("SELECT s.sid, u.username, s.created_at, s.last_seen_at, s.expires_at FROM sessions s"
           " JOIN users u ON u.id = s.user_id WHERE s.expires_at >= ?")
    args = [now_iso()]
    if username is not None:
        sql += " AND u.username = ?"
        args.append(username)
    rows = conn.execute(sql + " ORDER BY s.created_at DESC", args).fetchall()
    return [{"id": r["sid"], "username": r["username"], "created_at": r["created_at"],
             "last_seen_at": r["last_seen_at"], "expires_at": r["expires_at"],
             "current": r["sid"] == current_sid} for r in rows]


def revoke_session(conn, sid, actor, owner=None):
    """End one session by its id. With `owner`, only that user's sessions match (404 otherwise)."""
    sql = "SELECT s.token_hash, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.sid = ?"
    args = [str(sid)]
    if owner is not None:
        sql += " AND u.username = ?"
        args.append(owner)
    row = conn.execute(sql, args).fetchone()
    if row is None:
        raise AuthError("session not found", 404)
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
    audit(conn, actor, "session_revoked", row["username"], {"session": sid})
    return {"ok": True}


def create_api_token(conn, name, actor, role="analyst", capabilities=None, expires_in_days=None):
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= 64):
        raise AuthError("token name must be 1-64 characters", 400)
    capabilities = ["ingest"] if capabilities is None else capabilities
    if role not in ("viewer", "analyst"):
        raise AuthError("token role must be viewer or analyst", 400)
    if not isinstance(capabilities, list) or not capabilities or any(
            not isinstance(item, str) for item in capabilities):
        raise AuthError("capabilities must be a non-empty list", 400)
    if len(set(capabilities)) != len(capabilities) or not set(capabilities) <= TOKEN_CAPABILITIES:
        raise AuthError("capabilities must be unique and chosen from read, ingest, triage", 400)
    if role == "viewer" and capabilities != ["read"]:
        raise AuthError("viewer tokens can only have the read capability", 400)
    if expires_in_days is not None and (isinstance(expires_in_days, bool)
                                        or not isinstance(expires_in_days, int)
                                        or not 1 <= expires_in_days <= 365):
        raise AuthError("expires_in_days must be an integer from 1 to 365", 400)
    expires_at = iso(utcnow() + timedelta(days=expires_in_days)) if expires_in_days is not None else None
    token = "wp_" + secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO api_tokens(name, token_hash, prefix, created_by, created_at, role, capabilities, expires_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (name.strip(), sha256(token), token[:7], actor, now_iso(), role, json.dumps(capabilities), expires_at),
    )
    audit(conn, actor, "api_token_created", name.strip(),
          {"role": role, "capabilities": capabilities, "expires_at": expires_at})
    return token


def token_user(conn, token):
    """Return a bearer principal when the token is active and unexpired."""
    if not token or not token.startswith("wp_"):
        return None
    row = conn.execute(
        "SELECT id, name, role, capabilities, expires_at FROM api_tokens"
        " WHERE token_hash = ? AND revoked_at IS NULL", (sha256(token),)
    ).fetchone()
    if row is None or row["role"] not in ("viewer", "analyst"):
        return None
    try:
        capabilities = json.loads(row["capabilities"])
        expired = row["expires_at"] and parse_iso(row["expires_at"]) <= utcnow()
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if expired or not isinstance(capabilities, list) or not capabilities \
            or any(not isinstance(item, str) for item in capabilities) \
            or len(set(capabilities)) != len(capabilities) or not set(capabilities) <= TOKEN_CAPABILITIES \
            or row["role"] == "viewer" and capabilities != ["read"]:
        return None
    conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now_iso(), row["id"]))
    return {"username": f"token:{row['name']}", "role": row["role"],
            "capabilities": capabilities, "via": "token"}


def has_role(user, minimum):
    return user is not None and ROLES.get(user["role"], 0) >= ROLES[minimum]
