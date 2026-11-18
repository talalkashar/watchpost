"""Alert and incident reports say how many merged timeline events the 200-row cap dropped.

The rows stay the earliest 200 by ts, then id. A second alert that saw the same event is
still one row. A timeline that fits returns timeline_omitted 0, and Markdown and PDF
name the count only when it is not 0.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.pdfparse import ParsedPDF
from watchpost.db import connect, init_schema, iso
from watchpost.engine import seed_rules
from watchpost.report import TIMELINE_LIMIT, build, build_from_alert, to_markdown, to_pdf_bytes

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
BASE = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
SEEN = iso(BASE)
NOTE = f"First {TIMELINE_LIMIT} of {TIMELINE_LIMIT + 1} timeline events shown."


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    seed_rules(conn)
    return conn


def add_event(conn, minutes, user="alice", host="web01", message="[SYNTHETIC] report timeline"):
    ts = iso(BASE + timedelta(minutes=minutes))
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, message, synthetic)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (ts, ts, "lab", host, "auth", "low", user, message))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_alert(conn, event_id, group_key="alice"):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,1,1,?,?)",
        ("brute_force_ip", 1, group_key, "high", "synthetic alert", "synthetic", "open",
         SEEN, SEEN, SEEN, SEEN))
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, event_id))
    return alert_id


def add_incident(conn, alert_ids):
    conn.execute(
        "INSERT INTO incidents(title, severity, first_seen, last_seen, entities, stages, alert_count,"
        " synthetic, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,1,'open',?,?)",
        ("synthetic incident", "high", SEEN, SEEN, json.dumps({}), json.dumps(["Credential Access"]),
         len(alert_ids), SEEN, SEEN))
    incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.executemany(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        [(alert_id, incident_id, SEEN) for alert_id in alert_ids])
    return incident_id


class ReportTimelineTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_a_later_event_with_a_lower_id_is_the_one_past_the_cap(self):
        # Later time, then the earlier rows. ts wins, so the lower id is the omitted event.
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(TIMELINE_LIMIT)]
        # Outside the 30-minute pad. It matches the account and must not count as omitted.
        outside_id = add_event(self.conn, minutes=31)
        alert_id = add_alert(self.conn, early_ids[0])

        model = build_from_alert(self.conn, alert_id)
        self.assertEqual([row["id"] for row in model["timeline"]], early_ids)
        self.assertEqual(model["timeline_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in model["timeline"]})
        self.assertNotIn(outside_id, {row["id"] for row in model["timeline"]})
        self.assertTrue(model["timeline"][0]["is_evidence"])
        self.assertFalse(any(row["is_evidence"] for row in model["timeline"][1:]))
        self.assertEqual(model["timeline"][0]["message"], "[SYNTHETIC] report timeline")

        text = to_markdown(model)
        self.assertIn(f"_{NOTE}_", text)
        pdf = " ".join(ParsedPDF(to_pdf_bytes(model)).text().split())
        self.assertIn(NOTE, pdf)

    def test_the_same_timestamp_keeps_the_lower_ids(self):
        ids = [add_event(self.conn, minutes=0) for _ in range(TIMELINE_LIMIT + 1)]
        model = build_from_alert(self.conn, add_alert(self.conn, ids[0]))
        self.assertEqual([row["id"] for row in model["timeline"]], ids[:TIMELINE_LIMIT])
        self.assertEqual(model["timeline_omitted"], 1)
        self.assertNotIn(ids[-1], {row["id"] for row in model["timeline"]})

    def test_a_short_timeline_and_an_exact_cap_omit_nothing(self):
        one = add_event(self.conn, minutes=0, user="one", host="one-host")
        short = build_from_alert(self.conn, add_alert(self.conn, one, "one"))
        self.assertEqual([row["id"] for row in short["timeline"]], [one])
        self.assertEqual(short["timeline_omitted"], 0)
        self.assertNotIn("timeline events shown", to_markdown(short))
        self.assertNotIn("timeline events shown", ParsedPDF(to_pdf_bytes(short)).text())

        exact_ids = [add_event(self.conn, minutes=1, user="exact", host="exact-host")
                     for _ in range(TIMELINE_LIMIT)]
        exact = build_from_alert(self.conn, add_alert(self.conn, exact_ids[0], "exact"))
        self.assertEqual([row["id"] for row in exact["timeline"]], exact_ids)
        self.assertEqual(exact["timeline_omitted"], 0)
        self.assertNotIn("timeline events shown", to_markdown(exact))

        blank = add_event(self.conn, minutes=0, user=None, host=None)
        empty = build_from_alert(self.conn, add_alert(self.conn, blank, "blank"))
        self.assertEqual(empty["timeline"], [])
        self.assertEqual(empty["timeline_omitted"], 0)

    def test_an_incident_counts_a_shared_event_once(self):
        late_id = add_event(self.conn, minutes=10)
        early_ids = [add_event(self.conn, minutes=0) for _ in range(TIMELINE_LIMIT)]
        first = add_alert(self.conn, early_ids[0], "first")
        second = add_alert(self.conn, early_ids[0], "second")
        incident_id = add_incident(self.conn, [first, second])

        model = build(self.conn, incident_id)
        self.assertEqual([row["id"] for row in model["timeline"]], early_ids)
        self.assertEqual(model["timeline_omitted"], 1)
        self.assertNotIn(late_id, {row["id"] for row in model["timeline"]})
        shared = model["timeline"][0]
        self.assertEqual(shared["alert_ids"], [first, second])
        self.assertTrue(shared["is_evidence"])
        self.assertIn(f"_{NOTE}_", to_markdown(model))
        pdf = " ".join(ParsedPDF(to_pdf_bytes(model)).text().split())
        self.assertIn(NOTE, pdf)

    def test_the_api_docs_name_the_cap_and_the_omitted_count(self):
        text = API.read_text()
        self.assertIn(
            "a merged timeline (the first 200 events by `ts`, then `id`; one row per event even when"
            " two alerts share it; evidence events marked; `timeline_omitted` is how many merged events"
            " were past that cap, and 0 when the timeline fits; Markdown and PDF name that count when"
            " it is not 0)",
            text)
