"""Incident assets include a destination that exists only past the events page.

The events page stays the first 1000 evidence events. events_omitted stays that
count. An asset matched only by a destination on the page still appears. A host
on an omitted event is not an extra asset. A destination on another incident
is not.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, iso
from watchpost.incidents import INCIDENT_EVENT_LIMIT, evidence_dest_ips, get_incident

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)
PAGE_DEST = "198.51.100.51"
OMITTED_DEST = "198.51.100.50"
SRC = "203.0.113.7"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_asset(conn, name, address=None):
    addresses = json.dumps([address] if address else [])
    conn.execute(
        "INSERT INTO assets(name, kind, criticality, data_tags, addresses, owner, description,"
        " synthetic, created_at, updated_at, updated_by)"
        " VALUES (?, 'server', 'high', '[]', ?, 'ops', 'synthetic host', 1, ?, ?, 'admin')",
        (name, addresses, SEEN, SEEN))


def add_event(conn, minutes, dest_ip=None, host="web01"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, dest_ip, message,"
        " synthetic) VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", host, "auth", "low", dest_ip, "[SYNTHETIC] incident dest"))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_ids):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        ("synthetic_rule", 1, "web01", "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, len(event_ids), SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)",
        [(alert_id, event_id) for event_id in event_ids])
    return alert_id


def add_incident(conn, alert_ids, hosts=None, src_ips=None):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("Synthetic probe", "high", "open", SEEN, SEEN,
         json.dumps({"src_ip": src_ips or [], "user": [], "host": hosts or ["web01"]}),
         json.dumps(["Initial Access"]), len(alert_ids), 1, SEEN, SEEN))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, SEEN) for alert_id in alert_ids])
    return incident_id


def page_and_omitted(conn, page_dest, omitted_dest, omitted_host="web01"):
    """One later event past 1000 earlier events. The later row is the one left out."""
    late_id = add_event(conn, minutes=10, dest_ip=omitted_dest, host=omitted_host)
    early_ids = [add_event(conn, minutes=0, dest_ip=page_dest) for _ in range(INCIDENT_EVENT_LIMIT)]
    return late_id, early_ids


class IncidentAssetDestTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_a_destination_past_the_page_still_matches_an_asset(self):
        add_asset(self.conn, "pay-db", OMITTED_DEST)
        add_asset(self.conn, "page-gw", PAGE_DEST)
        late_id, early_ids = page_and_omitted(self.conn, PAGE_DEST, OMITTED_DEST)
        incident_id = add_incident(self.conn, [add_alert(self.conn, [late_id] + early_ids)])

        detail = get_incident(self.conn, incident_id)
        self.assertEqual([row["name"] for row in detail["assets"]], ["page-gw", "pay-db"])
        self.assertEqual([row["id"] for row in detail["events"]], early_ids)
        self.assertNotIn(late_id, {row["id"] for row in detail["events"]})
        self.assertEqual(detail["events_omitted"], 1)
        self.assertEqual(len(detail["events"]), INCIDENT_EVENT_LIMIT)
        self.assertEqual(evidence_dest_ips(self.conn, incident_id), {PAGE_DEST, OMITTED_DEST})

    def test_a_paged_destination_still_matches_when_the_omitted_event_has_none(self):
        add_asset(self.conn, "page-gw", PAGE_DEST)
        add_asset(self.conn, "quiet", "198.51.100.90")
        late_id, early_ids = page_and_omitted(self.conn, PAGE_DEST, None)
        incident_id = add_incident(self.conn, [add_alert(self.conn, [late_id] + early_ids)])

        detail = get_incident(self.conn, incident_id)
        self.assertEqual([row["name"] for row in detail["assets"]], ["page-gw"])
        self.assertNotIn(late_id, {row["id"] for row in detail["events"]})
        self.assertEqual(detail["events_omitted"], 1)
        self.assertEqual(evidence_dest_ips(self.conn, incident_id), {PAGE_DEST})

    def test_hosts_and_source_addresses_stay_the_entity_lists(self):
        add_asset(self.conn, "web01")
        add_asset(self.conn, "edge", SRC)
        add_asset(self.conn, "pay-db", OMITTED_DEST)
        add_asset(self.conn, "db01")
        late_id, early_ids = page_and_omitted(
            self.conn, None, OMITTED_DEST, omitted_host="db01")
        incident_id = add_incident(
            self.conn, [add_alert(self.conn, [late_id] + early_ids)],
            hosts=["web01"], src_ips=[SRC])

        detail = get_incident(self.conn, incident_id)
        self.assertEqual([row["name"] for row in detail["assets"]], ["edge", "pay-db", "web01"])
        self.assertNotIn("db01", [row["name"] for row in detail["assets"]])
        self.assertEqual(detail["events_omitted"], 1)

    def test_a_blank_destination_and_another_incident_do_not_match(self):
        add_asset(self.conn, "pay-db", OMITTED_DEST)
        blank_id = add_event(self.conn, minutes=10, dest_ip="")
        other_id = add_event(self.conn, minutes=0, dest_ip=OMITTED_DEST)
        early_ids = [add_event(self.conn, minutes=0, dest_ip=None) for _ in range(INCIDENT_EVENT_LIMIT)]
        incident_id = add_incident(self.conn, [add_alert(self.conn, [blank_id] + early_ids)])
        add_incident(self.conn, [add_alert(self.conn, [other_id])])

        detail = get_incident(self.conn, incident_id)
        self.assertEqual(detail["assets"], [])
        self.assertEqual(detail["events_omitted"], 1)
        self.assertEqual(evidence_dest_ips(self.conn, incident_id), set())
        self.assertEqual(evidence_dest_ips(self.conn, incident_id + 1), {OMITTED_DEST})

    def test_a_short_incident_still_matches_its_only_destination(self):
        add_asset(self.conn, "pay-db", OMITTED_DEST)
        event_id = add_event(self.conn, minutes=0, dest_ip=OMITTED_DEST)
        incident_id = add_incident(self.conn, [add_alert(self.conn, [event_id])])

        detail = get_incident(self.conn, incident_id)
        self.assertEqual([row["name"] for row in detail["assets"]], ["pay-db"])
        self.assertEqual(len(detail["events"]), 1)
        self.assertEqual(detail["events_omitted"], 0)

    def test_the_docs_name_destinations_past_the_page(self):
        row = next(line for line in API.read_text().splitlines()
                   if line.startswith("| `GET /api/incidents/{id}`"))
        self.assertIn(
            "every evidence `dest_ip`, including a destination that appears only on an event"
            " left out of `events`",
            row)
        self.assertIn("that event is not added to `events`", row)


class IncidentAssetDestApiTests(ServerTestCase):
    def test_incident_detail_returns_the_omitted_destination_asset(self):
        conn = connect(self.db_path)
        try:
            add_asset(conn, "pay-db", OMITTED_DEST)
            add_asset(conn, "page-gw", PAGE_DEST)
            late_id, early_ids = page_and_omitted(conn, PAGE_DEST, OMITTED_DEST)
            incident_id = add_incident(conn, [add_alert(conn, [late_id] + early_ids)])
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/incidents/{incident_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["name"] for row in detail["assets"]], ["page-gw", "pay-db"])
        self.assertEqual(detail["events_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in detail["events"]})
        self.assertEqual(detail["events"][0]["message"], "[SYNTHETIC] incident dest")
        self.assertEqual(detail["assets"][0]["synthetic"], 1)

        status, body, _ = self.client().get(f"/api/incidents/{incident_id}")
        self.assertEqual(status, 401)
        self.assertNotIn("assets", body)
