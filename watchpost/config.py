"""Runtime configuration, read from environment variables only.

Secrets are never hard-coded. If SIEM_ADMIN_PASSWORD / SIEM_ANALYST_PASSWORD are
unset on first start, random passwords are generated and written once to
data/initial_credentials.txt (mode 0600) instead of being logged. A read-only
`viewer` account is created only when SIEM_VIEWER_PASSWORD is set.
"""

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _days(name):
    """A whole number of days from the environment, or None when the variable is unset or empty."""
    value = os.environ.get(name, "").strip()
    return int(value) if value else None


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
    # Live syslog listener (off unless SIEM_SYSLOG=1). Loopback by default: plain syslog is unauthenticated.
    syslog_enabled: bool = False
    syslog_bind: str = "127.0.0.1"
    syslog_port: int = 5514
    syslog_allow: str = ""
    # Syslog over TLS (RFC 5425), on when a certificate and key are set. A client CA makes senders present a
    # certificate it signed. TLS replaces the plaintext UDP/TCP listeners unless syslog_plaintext is True.
    syslog_tls_cert: str | None = None
    syslog_tls_key: str | None = None
    syslog_tls_client_ca: str | None = None
    syslog_tls_port: int = 6514
    syslog_plaintext: bool | None = None  # None: plaintext only when TLS is not configured
    # Read-only demo account, created on start when set and no `viewer` user exists yet.
    viewer_password: str | None = None
    # Per-IP token buckets: a strict one for POST /api/auth/login, a looser one for everything else.
    rate_limit_enabled: bool = True
    login_rate_burst: int = 10
    login_rate_per_minute: float = 10.0
    rate_burst: int = 300
    rate_per_minute: float = 1200.0
    # Behind a reverse proxy on loopback, take the client IP from the last X-Forwarded-For entry.
    trust_proxy: bool = False
    # Attack storyline auto-replay for public demos (off unless SIEM_DEMO_LOOP=<minutes between runs>).
    demo_loop_minutes: int = 0
    demo_loop_speed: float = 1.0
    # HMAC key for the hash-chained audit log. Unset: plain SHA-256, which detects edits but not a full rewrite.
    audit_key: str | None = None
    # Tiered retention (retention.py). Off, and nothing is ever deleted, unless retention_hot_days is set.
    # Days count from arrival: hot in the database, then warm files, cold after warm_days, deleted after total_days.
    retention_hot_days: int | None = None
    retention_warm_days: int | None = None
    retention_total_days: int | None = None
    archive_dir: str | None = None       # default: "archive" next to the database
    cold_dir: str | None = None          # default: "cold" inside the archive directory
    retention_interval_minutes: int = 60
    # Response playbooks (playbooks.py): where notifications and response-action requests are posted. Unset:
    # nothing leaves Watchpost. The secret signs each body. Synthetic alerts are sent only when asked for.
    playbook_webhook_url: str | None = None
    playbook_webhook_secret: str | None = None
    playbook_webhook_cafile: str | None = None
    playbook_webhook_synthetic: bool = False

    @classmethod
    def from_env(cls, **overrides):
        values = dict(
            db_path=os.environ.get("SIEM_DB", str(BASE_DIR / "data" / "watchpost.db")),
            # Loopback by default. Binding 0.0.0.0 (e.g. on Replit) is an explicit choice.
            host=os.environ.get("SIEM_HOST", "127.0.0.1"),
            port=int(os.environ.get("SIEM_PORT", os.environ.get("PORT", "8080"))),
            session_ttl_seconds=int(os.environ.get("SIEM_SESSION_TTL", "28800")),
            secure_cookies=os.environ.get("SIEM_SECURE_COOKIES", "0") == "1",
            max_upload_bytes=int(os.environ.get("SIEM_MAX_UPLOAD_BYTES", str(5 * 1024 * 1024))),
            max_batch_events=int(os.environ.get("SIEM_MAX_BATCH_EVENTS", "20000")),
            admin_password=os.environ.get("SIEM_ADMIN_PASSWORD") or None,
            analyst_password=os.environ.get("SIEM_ANALYST_PASSWORD") or None,
            syslog_enabled=os.environ.get("SIEM_SYSLOG", "0") == "1",
            syslog_bind=os.environ.get("SIEM_SYSLOG_BIND", "127.0.0.1"),
            syslog_port=int(os.environ.get("SIEM_SYSLOG_PORT", "5514")),
            syslog_allow=os.environ.get("SIEM_SYSLOG_ALLOW", ""),
            syslog_tls_cert=os.environ.get("SIEM_SYSLOG_TLS_CERT") or None,
            syslog_tls_key=os.environ.get("SIEM_SYSLOG_TLS_KEY") or None,
            syslog_tls_client_ca=os.environ.get("SIEM_SYSLOG_TLS_CLIENT_CA") or None,
            syslog_tls_port=int(os.environ.get("SIEM_SYSLOG_TLS_PORT", "6514")),
            syslog_plaintext=(os.environ["SIEM_SYSLOG_PLAINTEXT"] == "1"
                              if os.environ.get("SIEM_SYSLOG_PLAINTEXT") else None),
            viewer_password=os.environ.get("SIEM_VIEWER_PASSWORD") or None,
            rate_limit_enabled=os.environ.get("SIEM_RATE_LIMIT", "1") != "0",
            login_rate_burst=int(os.environ.get("SIEM_LOGIN_RATE_BURST", "10")),
            login_rate_per_minute=float(os.environ.get("SIEM_LOGIN_RATE_PER_MIN", "10")),
            rate_burst=int(os.environ.get("SIEM_RATE_BURST", "300")),
            rate_per_minute=float(os.environ.get("SIEM_RATE_PER_MIN", "1200")),
            trust_proxy=os.environ.get("SIEM_TRUST_PROXY", "0") == "1",
            demo_loop_minutes=int(os.environ.get("SIEM_DEMO_LOOP", "0")),
            demo_loop_speed=float(os.environ.get("SIEM_DEMO_LOOP_SPEED", "1")),
            audit_key=os.environ.get("SIEM_AUDIT_KEY") or None,
            retention_hot_days=_days("SIEM_RETENTION_HOT_DAYS"),
            retention_warm_days=_days("SIEM_RETENTION_WARM_DAYS"),
            retention_total_days=_days("SIEM_RETENTION_TOTAL_DAYS"),
            archive_dir=os.environ.get("SIEM_ARCHIVE_DIR") or None,
            cold_dir=os.environ.get("SIEM_COLD_DIR") or None,
            retention_interval_minutes=int(os.environ.get("SIEM_RETENTION_INTERVAL_MINUTES", "60")),
            playbook_webhook_url=os.environ.get("SIEM_PLAYBOOK_WEBHOOK_URL") or None,
            playbook_webhook_secret=os.environ.get("SIEM_PLAYBOOK_WEBHOOK_SECRET") or None,
            playbook_webhook_cafile=os.environ.get("SIEM_PLAYBOOK_WEBHOOK_CAFILE") or None,
            playbook_webhook_synthetic=os.environ.get("SIEM_PLAYBOOK_WEBHOOK_SYNTHETIC", "0") == "1",
        )
        values.update(overrides)
        return cls(**values)
