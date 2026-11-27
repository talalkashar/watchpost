"""Alert detail says how many notes and activity rows the 100-row cap dropped.

The rows stay the newest 100 by id, then id order. A shorter list returns 0.
A later created_at on a lower id is still the older row. The 5000-character note write stays.
"""

import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema, now_iso
from watchpost.queries import ACTIVITY_LIMIT, NOTE_LIMIT, QueryError, add_note, get_alert

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alert(conn):
    now = now_iso()
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)",
        ("synthetic_rule", 1, "web01", "high", "synthetic alert", "synthetic", "open",
         now, now, 0, now, now))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_notes(conn, alert_id, count, created_at="2026-10-07T12:00:00Z"):
    conn.executemany(
        "INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
        [(alert_id, "analyst", f"[SYNTHETIC] note {i}", created_at) for i in range(count)])


def add_activity(conn, alert_id, count, created_at="2026-10-07T12:00:00Z"):
    conn.executemany(
        "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
        [(alert_id, "analyst", "status_changed", f"[SYNTHETIC] step {i}", created_at) for i in range(count)])


class NotesOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_the_lowest_id_is_the_one_past_the_cap(self):
        alert_id = add_alert(self.conn)
        # Highest id, earliest time: newest is id, so this row stays and the first insert is dropped.
        add_notes(self.conn, alert_id, 1, created_at="2026-10-08T12:00:00Z")
        add_notes(self.conn, alert_id, NOTE_LIMIT, created_at="2026-10-07T12:00:00Z")
        add_activity(self.conn, alert_id, 1, created_at="2026-10-08T12:00:00Z")
        add_activity(self.conn, alert_id, ACTIVITY_LIMIT, created_at="2026-10-07T12:00:00Z")
        # Another alert's rows are not this alert's omitted count.
        other = add_alert(self.conn)
        add_notes(self.conn, other, 3)
        add_activity(self.conn, other, 3)

        detail = get_alert(self.conn, alert_id)
        note_ids = [row["id"] for row in detail["notes"]]
        activity_ids = [row["id"] for row in detail["activity"]]
        self.assertEqual(note_ids, list(range(2, NOTE_LIMIT + 2)))
        self.assertEqual(activity_ids, list(range(2, ACTIVITY_LIMIT + 2)))
        self.assertEqual(note_ids, sorted(note_ids))
        self.assertEqual(activity_ids, sorted(activity_ids))
        self.assertEqual(detail["notes_omitted"], 1)
        self.assertEqual(detail["activity_omitted"], 1)
        self.assertEqual(detail["notes"][0]["body"], "[SYNTHETIC] note 0")
        self.assertNotIn("2026-10-08T12:00:00Z", {row["created_at"] for row in detail["notes"]})
        self.assertNotIn("2026-10-08T12:00:00Z", {row["created_at"] for row in detail["activity"]})

    def test_a_short_list_and_an_exact_cap_omit_nothing(self):
        one = add_alert(self.conn)
        add_notes(self.conn, one, 1)
        add_activity(self.conn, one, 1)
        exact = add_alert(self.conn)
        add_notes(self.conn, exact, NOTE_LIMIT)
        add_activity(self.conn, exact, ACTIVITY_LIMIT)
        empty = add_alert(self.conn)

        short = get_alert(self.conn, one)
        self.assertEqual(len(short["notes"]), 1)
        self.assertEqual(len(short["activity"]), 1)
        self.assertEqual(short["notes_omitted"], 0)
        self.assertEqual(short["activity_omitted"], 0)
        capped = get_alert(self.conn, exact)
        self.assertEqual(len(capped["notes"]), NOTE_LIMIT)
        self.assertEqual(len(capped["activity"]), ACTIVITY_LIMIT)
        self.assertEqual(capped["notes_omitted"], 0)
        self.assertEqual(capped["activity_omitted"], 0)
        quiet = get_alert(self.conn, empty)
        self.assertEqual(quiet["notes"], [])
        self.assertEqual(quiet["activity"], [])
        self.assertEqual(quiet["notes_omitted"], 0)
        self.assertEqual(quiet["activity_omitted"], 0)

    def test_one_list_can_omit_while_the_other_fits(self):
        alert_id = add_alert(self.conn)
        add_notes(self.conn, alert_id, NOTE_LIMIT + 1)
        add_activity(self.conn, alert_id, 1)
        detail = get_alert(self.conn, alert_id)
        self.assertEqual(detail["notes_omitted"], 1)
        self.assertEqual(len(detail["notes"]), NOTE_LIMIT)
        self.assertEqual(detail["activity_omitted"], 0)
        self.assertEqual(len(detail["activity"]), 1)

    def test_a_note_of_5000_characters_is_stored_and_5001_is_refused(self):
        alert_id = add_alert(self.conn)
        stored = add_note(self.conn, alert_id, "analyst", "s" * 5000)
        self.assertEqual(len(stored["body"]), 5000)
        with self.assertRaises(QueryError) as caught:
            add_note(self.conn, alert_id, "analyst", "s" * 5001)
        self.assertEqual(str(caught.exception), "note must be 5000 characters or fewer")
        detail = get_alert(self.conn, alert_id)
        self.assertEqual(len(detail["notes"]), 1)
        self.assertEqual(detail["notes_omitted"], 0)

    def test_the_api_docs_name_both_caps_and_the_note_length(self):
        text = API.read_text()
        self.assertIn(
            "`notes` (the newest 100 by `id`, returned in `id` order), `notes_omitted`"
            " (how many older notes were left out; 0 when the alert has 100 or fewer), "
            "`activity` (the newest 100 by `id`, returned in `id` order), `activity_omitted`"
            " (how many older activity rows were left out; 0 when the alert has 100 or fewer). "
            "A note body is still at most 5000 characters.",
            text)


class NotesOmittedApiTests(ServerTestCase):
    def test_alert_detail_reports_the_dropped_rows(self):
        conn = connect(self.db_path)
        try:
            alert_id = add_alert(conn)
            add_notes(conn, alert_id, NOTE_LIMIT + 1)
            add_activity(conn, alert_id, ACTIVITY_LIMIT + 1)
            conn.commit()
        finally:
            conn.close()

        status, detail, _ = self.client("viewer").get(f"/api/alerts/{alert_id}")
        self.assertEqual(status, 200, detail)
        self.assertEqual([row["id"] for row in detail["notes"]], list(range(2, NOTE_LIMIT + 2)))
        self.assertEqual([row["id"] for row in detail["activity"]], list(range(2, ACTIVITY_LIMIT + 2)))
        self.assertEqual(detail["notes_omitted"], 1)
        self.assertEqual(detail["activity_omitted"], 1)
        self.assertEqual(detail["notes"][0]["body"], "[SYNTHETIC] note 1")
        self.assertEqual(detail["activity"][0]["detail"], "[SYNTHETIC] step 1")
