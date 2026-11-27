"""Exact owner and unassigned filters on the alert queue, and case ids on detail.

`assignee` matches the stored spelling with no ASCII fold. `unassigned=1` or
`unassigned=true` keeps alerts whose assignee is NULL. A blank assignee is not
that set. The omitted count uses the same filters. Detail adds `cases`
(incident ids, lowest first, at most one) and `cases_omitted`. No membership
is an empty list. A membership whose incident row is missing is still that id.
The list stays a bare array, without `cases`, and `X-Watchpost-Omitted` stays
the leftover count.
"""

import sqlite3
import unittest

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.queries import CASE_MEMBERSHIP_LIMIT, QueryError, get_alert, list_alerts

OMITTED = "X-Watchpost-Omitted"
NOW = "2026-06-01T00:00:00.000Z"
DENIED = "API token does not have the required capability"


def add_alert(conn, alert_id, assignee, title, last_seen):
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_version, group_key, severity, title, explanation, status,"
        " assignee, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,1,?,?,?,?,?,?,?,?,1,1,?,?)",
        (alert_id, "synthetic_rule", f"g{alert_id}", "high", title, "synthetic", "open",
         assignee, NOW, last_seen, NOW, NOW))


def add_incident(conn):
    conn.execute(
        "INSERT INTO incidents(title, severity, status, first_seen, last_seen, entities, stages,"
        " alert_count, synthetic, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("Synthetic case", "high", "open", NOW, NOW, "{}", "[]", 1, 1, NOW, NOW))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def link(conn, alert_id, incident_id):
    conn.execute(
        "INSERT INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
        (alert_id, incident_id, NOW))


def load(conn):
    """Two owners, one unowned pair, a blank assignee, and two kinds of membership.

    Returns the id of the incident that really exists. Alert 5 points at 9001,
    which is not an incidents row. Alert 4 is in no incident.
    """
    conn.execute("DELETE FROM incident_alerts")
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM alerts")
    add_alert(conn, 1, "ada", "ada-old", "2026-06-01T00:00:00.000Z")
    add_alert(conn, 2, "ada", "ada-new", "2026-06-03T00:00:00.000Z")
    add_alert(conn, 3, "ada", "ada-mid", "2026-06-02T00:00:00.000Z")
    add_alert(conn, 4, "ben", "ben-only", "2026-06-04T00:00:00.000Z")
    add_alert(conn, 5, None, "unowned-new", "2026-07-02T00:00:00.000Z")
    add_alert(conn, 6, None, "unowned-old", "2026-07-01T00:00:00.000Z")
    add_alert(conn, 7, "", "blank-owner", "2026-08-01T00:00:00.000Z")
    add_alert(conn, 8, "Ada", "ada-folded", "2026-06-05T00:00:00.000Z")
    incident_id = add_incident(conn)
    link(conn, 2, incident_id)
    link(conn, 5, 9001)
    return incident_id


class QueueOwnerFilterTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.incident_id = load(self.conn)

    def titles(self, **params):
        rows, omitted = list_alerts(self.conn, params)
        return [row["title"] for row in rows], omitted, rows

    def test_an_exact_owner_leaves_the_other_spelling_out(self):
        titles, omitted, rows = self.titles(assignee="ada", limit="2")
        self.assertEqual(titles, ["ada-new", "ada-mid"])
        self.assertEqual(omitted, 1)
        self.assertNotIn("ada-old", titles)
        self.assertNotIn("ada-folded", titles)
        self.assertNotIn("ben-only", titles)
        self.assertTrue(all(row["assignee"] == "ada" for row in rows))
        self.assertNotIn("cases", rows[0])
        folded, folded_omitted, _ = self.titles(assignee="Ada")
        self.assertEqual(folded, ["ada-folded"])
        self.assertEqual(folded_omitted, 0)
        ben, ben_omitted, _ = self.titles(assignee="ben")
        self.assertEqual((ben, ben_omitted), (["ben-only"], 0))

    def test_unassigned_is_only_a_null_assignee_and_the_cap_counts_those(self):
        titles, omitted, rows = self.titles(unassigned="1", limit="1")
        self.assertEqual(titles, ["unowned-new"])
        self.assertEqual(omitted, 1)
        self.assertIsNone(rows[0]["assignee"])
        self.assertNotIn("blank-owner", titles)
        titles, omitted, _ = self.titles(unassigned="TRUE")
        self.assertEqual(titles, ["unowned-new", "unowned-old"])
        self.assertEqual(omitted, 0)
        for bad in ("0", "false", "yes", "none", 1):
            with self.subTest(bad=bad):
                with self.assertRaises(QueryError) as caught:
                    list_alerts(self.conn, {"unassigned": bad})
                self.assertEqual(str(caught.exception), "unassigned must be 1 or true")
                self.assertEqual(caught.exception.status, 400)

    def test_a_blank_owner_filter_is_off_and_both_filters_match_nothing(self):
        titles, omitted, rows = self.titles(assignee="")
        self.assertIn("blank-owner", titles)
        self.assertIn("ada-new", titles)
        self.assertIn("unowned-new", titles)
        self.assertEqual(omitted, 0)
        self.assertNotIn("cases", rows[0])
        none, none_omitted, _ = self.titles(assignee="ada", unassigned="1")
        self.assertEqual(none, [])
        self.assertEqual(none_omitted, 0)
        with self.assertRaises(QueryError) as caught:
            list_alerts(self.conn, {"assignee": 1})
        self.assertEqual(str(caught.exception), "assignee must be a username")

    def test_the_omitted_count_follows_the_owner_and_the_status(self):
        self.conn.execute("UPDATE alerts SET status = 'resolved' WHERE id = 3")
        titles, omitted, _ = self.titles(assignee="ada", status="open", limit="1")
        self.assertEqual(titles, ["ada-new"])
        self.assertEqual(omitted, 1)
        self.assertNotIn("ada-mid", titles)


class AlertCaseMembershipTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        self.incident_id = load(self.conn)

    def test_zero_one_and_a_missing_incident_row(self):
        self.assertIsNone(self.conn.execute("SELECT 1 FROM incidents WHERE id = 9001").fetchone())
        quiet = get_alert(self.conn, 4)
        linked = get_alert(self.conn, 2)
        orphan = get_alert(self.conn, 5)
        self.assertEqual(quiet["cases"], [])
        self.assertEqual(quiet["cases_omitted"], 0)
        self.assertEqual(linked["cases"], [self.incident_id])
        self.assertEqual(linked["cases_omitted"], 0)
        self.assertEqual(orphan["cases"], [9001])
        self.assertEqual(orphan["cases_omitted"], 0)
        for detail in (quiet, linked, orphan):
            self.assertLessEqual(len(detail["cases"]), CASE_MEMBERSHIP_LIMIT)
            self.assertEqual(detail["evidence_omitted"], 0)
        self.assertEqual(linked["assignee"], "ada")
        self.assertIsNone(orphan["assignee"])
        with self.assertRaises(QueryError) as caught:
            get_alert(self.conn, 99)
        self.assertEqual(caught.exception.status, 404)


class QueueCasePivotApiTests(ServerTestCase):
    def load_db(self):
        with sqlite3.connect(self.db_path) as db:
            return load(db)

    def test_viewer_and_analyst_see_the_same_filtered_queue_and_cases(self):
        incident_id = self.load_db()
        for role in ("viewer", "analyst"):
            client = self.client(role)
            with self.subTest(role=role):
                status, body, headers = client.get("/api/alerts?assignee=ada&limit=2")
                self.assertEqual(status, 200, body)
                self.assertIsInstance(body, list)
                self.assertEqual([row["title"] for row in body], ["ada-new", "ada-mid"])
                self.assertEqual(headers[OMITTED], "1")
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertTrue(all(row["assignee"] == "ada" and "cases" not in row for row in body))
                status, folded, headers = client.get("/api/alerts?assignee=Ada")
                self.assertEqual(status, 200, folded)
                self.assertEqual([row["title"] for row in folded], ["ada-folded"])
                self.assertEqual(headers[OMITTED], "0")
                status, unowned, headers = client.get("/api/alerts?unassigned=1&limit=1")
                self.assertEqual(status, 200, unowned)
                self.assertEqual([row["title"] for row in unowned], ["unowned-new"])
                self.assertIsNone(unowned[0]["assignee"])
                self.assertEqual(headers[OMITTED], "1")
                status, detail, headers = client.get("/api/alerts/2")
                self.assertEqual(status, 200, detail)
                self.assertEqual(detail["cases"], [incident_id])
                self.assertEqual(detail["cases_omitted"], 0)
                self.assertIsNone(headers.get(OMITTED))
                status, quiet, _ = client.get("/api/alerts/4")
                self.assertEqual(status, 200, quiet)
                self.assertEqual((quiet["cases"], quiet["cases_omitted"], quiet["assignee"]),
                                 ([], 0, "ben"))
                status, orphan, _ = client.get("/api/alerts/5")
                self.assertEqual(status, 200, orphan)
                self.assertEqual(orphan["cases"], [9001])
                self.assertEqual(orphan["cases_omitted"], 0)

    def test_a_bad_unassigned_value_does_not_send_the_header(self):
        self.load_db()
        status, body, headers = self.client("viewer").get("/api/alerts?unassigned=none")
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"], "unassigned must be 1 or true")
        self.assertIsNone(headers.get(OMITTED))

    def test_a_token_without_read_stays_denied(self):
        self.load_db()
        admin, bot = self.client("admin"), self.client()

        def bearer(body):
            status, data, _ = admin.post("/api/tokens", body)
            self.assertEqual(status, 201, data)
            return {"Authorization": f"Bearer {data['token']}"}

        ingest = bearer({"name": "ingest-only", "role": "analyst", "capabilities": ["ingest"]})
        triage = bearer({"name": "triage-only", "role": "analyst", "capabilities": ["triage"]})
        for headers in (ingest, triage):
            for path in ("/api/alerts?assignee=ada", "/api/alerts?unassigned=1", "/api/alerts/2"):
                with self.subTest(path=path, capabilities=headers):
                    status, body, _ = bot.get(path, headers=headers)
                    self.assertEqual(status, 403, body)
                    self.assertEqual(body["error"], DENIED)
        reader = bearer({"name": "readonly", "role": "viewer", "capabilities": ["read"]})
        status, body, headers = bot.get("/api/alerts?assignee=ben", headers=reader)
        self.assertEqual(status, 200, body)
        self.assertEqual([row["title"] for row in body], ["ben-only"])
        self.assertEqual(headers[OMITTED], "0")
        status, detail, _ = bot.get("/api/alerts/4", headers=reader)
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail["cases"], [])
        self.assertEqual(detail["cases_omitted"], 0)
