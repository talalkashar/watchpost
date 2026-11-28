"""Start the browser console and configured background services."""

from watchpost import playbooks, retention, storyline, syslog_listener, threat_intel
from watchpost.server import main


class _Services:
    def __init__(self, *services):
        self.services = [s for s in services if s is not None]

    def stop(self):
        for service in self.services:
            service.stop()


def start_services(app):
    return _Services(syslog_listener.start_if_enabled(app), storyline.start_if_enabled(app),
                     playbooks.start_if_enabled(app), retention.start_if_enabled(app),
                     threat_intel.start_if_enabled(app))


def run():
    main(before_serve=start_services)
