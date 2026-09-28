"""Entry point: `python3 main.py` (used by Replit's Run button and start.sh).

Set SIEM_SYSLOG=1 to also start the UDP/TCP syslog listener (see docs/LIVE_INGEST.md).
"""

from watchpost.server import main
from watchpost.syslog_listener import start_if_enabled

if __name__ == "__main__":
    main(before_serve=start_if_enabled)
