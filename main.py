"""Entry point: `python3 main.py` (used by Replit's Run button and start.sh).

Set SIEM_SYSLOG=1 to also start the syslog listener: UDP/TCP, or TLS when SIEM_SYSLOG_TLS_CERT and
SIEM_SYSLOG_TLS_KEY are set (see docs/LIVE_INGEST.md).
Set SIEM_DEMO_LOOP=<minutes> to replay the synthetic attack storyline on a timer (public demos).
Set SIEM_RETENTION_HOT_DAYS to move older events from the database to archive files (see watchpost/retention.py).
Set SIEM_THREAT_FEEDS to fetch lists of hostile addresses on a timer (see watchpost/threat_intel.py).
Set SIEM_PLAYBOOK_WEBHOOK_URL to have response playbooks post notifications and action requests there.
"""

from watchpost.launcher import main, start_services


if __name__ == "__main__":
    main(before_serve=start_services)
