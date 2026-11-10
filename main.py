"""Entry point: `python3 main.py` (used by Replit's Run button and start.sh).

Set SIEM_SYSLOG=1 to also start the syslog listener: UDP/TCP, or TLS when SIEM_SYSLOG_TLS_CERT and
SIEM_SYSLOG_TLS_KEY are set (see docs/LIVE_INGEST.md).
Set SIEM_DEMO_LOOP=<minutes> to replay the synthetic attack storyline on a timer (public demos).
Set SIEM_RETENTION_HOT_DAYS to move older events from the database to archive files (see watchpost/retention.py).
Set SIEM_PLAYBOOK_WEBHOOK_URL to have response playbooks post notifications and action requests there.
"""

from watchpost import playbooks, retention, storyline, syslog_listener
from watchpost.server import main


class _Services:
    def __init__(self, *services):
        self.services = [s for s in services if s is not None]

    def stop(self):
        for service in self.services:
            service.stop()


def start_services(app):
    return _Services(syslog_listener.start_if_enabled(app), storyline.start_if_enabled(app),
                     playbooks.start_if_enabled(app), retention.start_if_enabled(app))


if __name__ == "__main__":
    main(before_serve=start_services)
