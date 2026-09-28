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
    # Behind a reverse proxy on loopback, take the client IP from the last X-Forwarded-For entry.
    trust_proxy: bool = False
    # Attack storyline auto-replay for public demos (off unless SIEM_DEMO_LOOP=<minutes between runs>).
    demo_loop_minutes: int = 0
    demo_loop_speed: float = 1.0

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
            viewer_password=os.environ.get("SIEM_VIEWER_PASSWORD") or None,
            rate_limit_enabled=os.environ.get("SIEM_RATE_LIMIT", "1") != "0",
            login_rate_burst=int(os.environ.get("SIEM_LOGIN_RATE_BURST", "10")),
            login_rate_per_minute=float(os.environ.get("SIEM_LOGIN_RATE_PER_MIN", "10")),
            rate_burst=int(os.environ.get("SIEM_RATE_BURST", "300")),
            rate_per_minute=float(os.environ.get("SIEM_RATE_PER_MIN", "1200")),
            trust_proxy=os.environ.get("SIEM_TRUST_PROXY", "0") == "1",
            demo_loop_minutes=int(os.environ.get("SIEM_DEMO_LOOP", "0")),
            demo_loop_speed=float(os.environ.get("SIEM_DEMO_LOOP_SPEED", "1")),
        )
        values.update(overrides)
        return cls(**values)
