"""Runtime configuration, read from environment variables only.

Secrets are never hard-coded. If SIEM_ADMIN_PASSWORD / SIEM_ANALYST_PASSWORD are
unset on first start, random passwords are generated and written once to
data/initial_credentials.txt (mode 0600) instead of being logged.
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
        )
        values.update(overrides)
        return cls(**values)
