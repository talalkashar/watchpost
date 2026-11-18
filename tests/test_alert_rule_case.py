"""GET /api/alerts?rule_id= matches ASCII case and leaves accented names apart.

Brute_Force_Ip returns alerts stored as brute_force_ip. An unknown rule is an
empty 200, not 400. Érin_rule does not match érin_rule. The omitted count
counts only the matched alerts.
"""

import sqlite3
import unittest
from pathlib import Path
from urllib.parse import quote

from watchpost.db import connect, init_schema
from watchpost.queries import list_alerts

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
STAMP = "2026-01-01T00:00:00.000Z"


def add_alerts(db, rule_id, count, title):
    db.executemany(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,1,?,?,?,'synthetic','open',?,?,1,1,?,?)",
        [(rule_id, f"{title}-{i}", "medium", title, STAMP, STAMP, STAMP, STAMP) for i in range(count)])


class AlertRuleCaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        self.addCleanup(self.conn.close)
        add_alerts(self.conn, "brute_force_ip", 101, "spray")
        add_alerts(self.conn, "other_rule", 5, "other")
        add_alerts(self.conn, "Érin_rule", 2, "accent-upper")
        add_alerts(self.conn, "érin_rule", 1, "accent-lower")

    def test_ascii_case_matches_and_an_accent_stays_apart(self):
        rows, omitted = list_alerts(self.conn, {"rule_id": "Brute_Force_Ip", "limit": "100"})
        self.assertEqual(len(rows), 100)
        self.assertTrue(all(row["rule_id"] == "brute_force_ip" for row in rows))
        self.assertEqual(omitted, 1)
        self.assertNotIn("other", [row["title"] for row in rows])
        rows, omitted = list_alerts(self.conn, {"rule_id": "érin_rule"})
        self.assertEqual([row["rule_id"] for row in rows], ["érin_rule"])
        self.assertEqual(omitted, 0)
        rows, omitted = list_alerts(self.conn, {"rule_id": "ÉRIN_rule"})
        self.assertEqual(sorted(row["rule_id"] for row in rows), ["Érin_rule", "Érin_rule"])
        self.assertEqual(omitted, 0)
        rows, omitted = list_alerts(self.conn, {"rule_id": "no_such_rule"})
        self.assertEqual(rows, [])
        self.assertEqual(omitted, 0)

    def test_the_comparison_uses_the_nocase_index(self):
        seen = []
        real = self.conn.execute

        def wrapped(sql, args=()):
            seen.append(sql)
            return real(sql, args)

        self.conn.execute = wrapped
        list_alerts(self.conn, {"rule_id": "Brute_Force_Ip"})
        self.assertTrue(any("rule_id = ? COLLATE NOCASE" in sql for sql in seen))
        plan = " ".join(row[3] for row in real(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM alerts WHERE rule_id = ? COLLATE NOCASE",
            ("Brute_Force_Ip",)))
        self.assertIn("idx_alerts_rule_nocase", plan)


class AlertRuleCaseApiTests(ServerTestCase):
    def _load(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM alerts")
            add_alerts(db, "brute_force_ip", 101, "spray")
            add_alerts(db, "other_rule", 5, "other")
            add_alerts(db, "Érin_rule", 2, "accent-upper")
            add_alerts(db, "érin_rule", 1, "accent-lower")

    def test_the_list_folds_ascii_and_an_unknown_rule_is_empty(self):
        self._load()
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/alerts?rule_id=Brute_Force_Ip")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 100)
        self.assertTrue(all(row["rule_id"] == "brute_force_ip" for row in body))
        self.assertEqual(headers[OMITTED], "1")
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, missed, headers = viewer.get("/api/alerts?rule_id=" + quote("érin_rule"))
        self.assertEqual(status, 200, missed)
        self.assertEqual([row["rule_id"] for row in missed], ["érin_rule"])
        self.assertEqual(headers[OMITTED], "0")
        status, folded, headers = viewer.get("/api/alerts?rule_id=" + quote("ÉRIN_rule"))
        self.assertEqual(status, 200, folded)
        self.assertEqual(sorted(row["rule_id"] for row in folded), ["Érin_rule", "Érin_rule"])
        self.assertEqual(headers[OMITTED], "0")
        status, empty, headers = viewer.get("/api/alerts?rule_id=no_such_rule")
        self.assertEqual(status, 200, empty)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_the_docs_name_the_fold(self):
        api = API.read_text()
        self.assertIn(
            "`rule_id` compares with `COLLATE NOCASE` (ASCII): `Brute_Force_Ip` matches `brute_force_ip`",
            api)
        self.assertIn("`Érin_rule` does not match `érin_rule`", api)
        self.assertIn("An unknown rule is an empty 200, not 400", api)


if __name__ == "__main__":
    unittest.main()
