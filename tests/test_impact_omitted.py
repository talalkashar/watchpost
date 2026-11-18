"""Rule-change and exception evidence name the matching alerts past the recent cap.

`recent` stays the newest 5 matching alerts by id. `recent_omitted` is the rest
(0 when the list fits, including none). `proposer_verdict_changes.recent` stays
the newest 5 status changes by that proposer, and `omitted` is the rest.
`alerts` and `count` stay the full totals. An alert that does not match is neither.
"""

import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.improve import LIVE_IMPACT_RECENT, _ignore_additions, _live_impact

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
SEEN = "2026-10-07T12:00:00.000Z"
LATER = "2026-11-01T12:00:00.000Z"
KEY = "192.0.2.50"
OTHER = "198.51.100.8"
RULE = "brute_force_ip"


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def add_alert(conn, group_key, title, rule_id=RULE, status="open", disposition=None, seen=SEEN):
    conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1,1,?,?)",
        (rule_id, 1, group_key, "high", title, "[SYNTHETIC] impact cap", status, disposition,
         seen, seen, seen, seen))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_event(conn, src_ip, user="svc"):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip,"
        " message, synthetic) VALUES (?,?,?,?,?,?,?,?,?,1)",
        (SEEN, SEEN, "lab", "web01", "auth_failure", "low", user, src_ip, "[SYNTHETIC] impact cap"))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def link(conn, alert_id, event_id):
    conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?,?)", (alert_id, event_id))


def add_status(conn, alert_id, actor, detail, created_at=SEEN):
    conn.execute(
        "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
        (alert_id, actor, "status_changed", detail, created_at))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


class ImpactOmittedTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_six_matching_alerts_leave_out_the_lowest_id(self):
        # Later last_seen on the lowest id. Order is id, so this row is the one past the cap.
        dropped = add_alert(self.conn, KEY, "oldest", status="resolved", disposition="false_positive", seen=LATER)
        kept = [add_alert(self.conn, KEY, f"kept-{n}") for n in range(LIVE_IMPACT_RECENT)]
        other = add_alert(self.conn, OTHER, "other key")
        other_rule = add_alert(self.conn, KEY, "other rule", rule_id="password_spray")
        add_status(self.conn, dropped, "analyst", "open -> resolved (true_positive)", LATER)

        impact = _live_impact(self.conn, RULE, KEY, set(), "analyst")
        self.assertEqual(impact["alerts"], 6)
        self.assertEqual(impact["recent_omitted"], 1)
        self.assertEqual([row["id"] for row in impact["recent"]], list(reversed(kept)))
        self.assertNotIn(dropped, [row["id"] for row in impact["recent"]])
        self.assertNotIn(other, [row["id"] for row in impact["recent"]])
        self.assertNotIn(other_rule, [row["id"] for row in impact["recent"]])
        self.assertEqual(impact["by_status"], {"open": 5, "resolved": 1})
        self.assertEqual(impact["by_disposition"], {"false_positive": 1})
        self.assertEqual(impact["ever_true_positive"], 1)
        self.assertEqual(self.conn.execute("SELECT last_seen FROM alerts WHERE id = ?", (dropped,)).fetchone()[0],
                         LATER)

    def test_six_proposer_changes_leave_out_the_lowest_activity_id(self):
        alert_id = add_alert(self.conn, KEY, "one")
        other = add_alert(self.conn, OTHER, "other")
        dropped = add_status(self.conn, alert_id, "analyst", "open -> investigating", LATER)
        for n in range(LIVE_IMPACT_RECENT):
            add_status(self.conn, alert_id, "analyst", f"note {n}")
        admin = add_status(self.conn, alert_id, "admin", "investigating -> open")
        elsewhere = add_status(self.conn, other, "analyst", "open -> resolved (benign)")

        own = _live_impact(self.conn, RULE, KEY, set(), "analyst")["proposer_verdict_changes"]
        self.assertEqual(own["count"], 6)
        self.assertEqual(own["omitted"], 1)
        self.assertEqual([row["detail"] for row in own["recent"]], [f"note {n}" for n in range(4, -1, -1)])
        self.assertTrue(all(row["created_at"] == SEEN and row["alert_id"] == alert_id for row in own["recent"]))
        self.assertNotIn("open -> investigating", [row["detail"] for row in own["recent"]])
        self.assertNotIn("investigating -> open", [row["detail"] for row in own["recent"]])
        self.assertNotIn("benign", [row["detail"] for row in own["recent"]])
        self.assertEqual(self.conn.execute(
            "SELECT created_at FROM alert_activity WHERE id = ?", (dropped,)).fetchone()[0], LATER)
        self.assertNotEqual(elsewhere, admin)

    def test_a_list_that_fits_and_none_omit_nothing(self):
        empty = _live_impact(self.conn, RULE, KEY, set(), "analyst")
        self.assertEqual(empty["alerts"], 0)
        self.assertEqual(empty["recent"], [])
        self.assertEqual(empty["recent_omitted"], 0)
        self.assertEqual(empty["proposer_verdict_changes"], {"count": 0, "recent": [], "omitted": 0})

        ids = [add_alert(self.conn, KEY, f"fit-{n}") for n in range(LIVE_IMPACT_RECENT)]
        for alert_id in ids:
            add_status(self.conn, alert_id, "analyst", "open -> investigating")
        impact = _live_impact(self.conn, RULE, KEY, set(), "analyst")
        self.assertEqual(impact["alerts"], LIVE_IMPACT_RECENT)
        self.assertEqual(impact["recent_omitted"], 0)
        self.assertEqual([row["id"] for row in impact["recent"]], list(reversed(ids)))
        own = impact["proposer_verdict_changes"]
        self.assertEqual(own["count"], LIVE_IMPACT_RECENT)
        self.assertEqual(own["omitted"], 0)
        self.assertEqual(len(own["recent"]), LIVE_IMPACT_RECENT)

    def test_a_rule_change_uses_the_same_cap(self):
        dropped = add_alert(self.conn, "203.0.113.9", "oldest", seen=LATER)
        link(self.conn, dropped, add_event(self.conn, "203.0.113.9"))
        kept = []
        for n in range(LIVE_IMPACT_RECENT):
            alert_id = add_alert(self.conn, f"key-{n}", f"kept-{n}")
            link(self.conn, alert_id, add_event(self.conn, "203.0.113.9"))
            kept.append(alert_id)
        other = add_alert(self.conn, "198.51.100.9", "other address")
        link(self.conn, other, add_event(self.conn, "198.51.100.9"))
        for alert_id in [dropped, *kept]:
            add_status(self.conn, alert_id, "analyst", "open -> investigating")

        added = _ignore_additions(self.conn, RULE, {"ignore_ips": []},
                                  {"ignore_ips": ["203.0.113.9"]}, "analyst")
        self.assertEqual(len(added), 1)
        impact = added[0]["live_impact"]
        self.assertEqual(impact["alerts"], 6)
        self.assertEqual(impact["recent_omitted"], 1)
        self.assertEqual([row["id"] for row in impact["recent"]], list(reversed(kept)))
        self.assertNotIn(dropped, [row["id"] for row in impact["recent"]])
        self.assertNotIn(other, [row["id"] for row in impact["recent"]])
        self.assertEqual(impact["proposer_verdict_changes"]["count"], 6)
        self.assertEqual(impact["proposer_verdict_changes"]["omitted"], 1)
        self.assertEqual(len(impact["proposer_verdict_changes"]["recent"]), LIVE_IMPACT_RECENT)

    def test_the_docs_name_both_omitted_counts(self):
        text = API.read_text()
        self.assertIn(
            "`recent_omitted` and `proposer_verdict_changes.omitted` are how many of those rows "
            "were past that cap (0 when the list fits, including none)",
            text)
        self.assertIn("`alerts` and `proposer_verdict_changes.count` stay the full counts", text)


class ImpactOmittedApiTests(ServerTestCase):
    def test_an_exception_and_a_rule_change_return_the_counts(self):
        analyst = self.client("analyst")
        with sqlite3.connect(self.db_path) as db:
            dropped = add_alert(db, KEY, "oldest", seen=LATER)
            link(db, dropped, add_event(db, KEY))
            kept = []
            for n in range(LIVE_IMPACT_RECENT):
                alert_id = add_alert(db, KEY, f"kept-{n}")
                link(db, alert_id, add_event(db, KEY))
                kept.append(alert_id)
            add_status(db, dropped, "analyst", "open -> investigating", LATER)
            for alert_id in kept:
                add_status(db, alert_id, "analyst", "open -> investigating")

        status, change, _ = analyst.post(
            f"/api/rules/{RULE}/suppressions",
            {"group_key": KEY, "days": 30, "reason": "Authorized synthetic scanner."})
        self.assertEqual(status, 201, change)
        impact = change["evaluation"]["live_impact"]
        self.assertEqual(impact["alerts"], 6)
        self.assertEqual(impact["recent_omitted"], 1)
        self.assertEqual([row["id"] for row in impact["recent"]], list(reversed(kept)))
        self.assertEqual(impact["proposer_verdict_changes"]["count"], 6)
        self.assertEqual(impact["proposer_verdict_changes"]["omitted"], 1)
        self.assertEqual(len(impact["proposer_verdict_changes"]["recent"]), LIVE_IMPACT_RECENT)

        status, proposed, _ = analyst.post(
            f"/api/rules/{RULE}/proposals",
            {"params": {"ignore_ips": [KEY]}, "reason": "authorized synthetic scanner"})
        self.assertEqual(status, 201, proposed)
        added = proposed["evaluation"]["ignore_additions"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["live_impact"]["alerts"], 6)
        self.assertEqual(added[0]["live_impact"]["recent_omitted"], 1)
        self.assertEqual([row["id"] for row in added[0]["live_impact"]["recent"]], list(reversed(kept)))
        self.assertEqual(added[0]["live_impact"]["proposer_verdict_changes"]["omitted"], 1)


if __name__ == "__main__":
    unittest.main()
