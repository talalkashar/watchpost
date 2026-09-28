"""Entry point: `python3 main.py` (used by Replit's Run button and start.sh).

Set SIEM_SYSLOG=1 to also start the UDP/TCP syslog listener (see docs/LIVE_INGEST.md).
Set SIEM_DEMO_LOOP=<minutes> to replay the synthetic attack storyline on a timer (public demos).
"""

from watchpost import storyline, syslog_listener
from watchpost.server import main


class _Services:
    def __init__(self, *services):
        self.services = [s for s in services if s is not None]

    def stop(self):
        for service in self.services:
            service.stop()


def start_services(app):
    return _Services(syslog_listener.start_if_enabled(app), storyline.start_if_enabled(app))


if __name__ == "__main__":
    main(before_serve=start_services)
