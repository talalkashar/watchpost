"""Coverage counts each technique id once per rule.

A rule that lists the same technique twice adds its alerts once. A second,
different technique on that rule still receives those alerts. A built-in rule
that lists a technique once keeps that number. A disabled rule stays listed
and does not set covered by itself.
"""

import json
import sqlite3
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost import attack, rules

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"
ANCHOR = "2026-09-15T12:00:00Z"
SENTENCE = ("A technique id listed twice on one rule counts that rule's alerts once. "
            "A second technique on that rule still receives those alerts.")


def rule_row(rule_id, enabled, technique_ids, hits_name=None):
    listed = [attack.technique(technique_id) for technique_id in technique_ids]
    return {"id": rule_id, "name": hits_name or rule_id, "enabled": enabled, "techniques": listed}


class CoverageTechniqueOnceTests(unittest.TestCase):
    def test_a_repeated_technique_id_counts_the_rule_once(self):
        guess = rule_row("guess", True, ["T1110.001", "T1110.001", "T1110"])
        spray = rule_row("spray", True, ["T1110.001"])
        result = attack.coverage([guess, spray], {"guess": 4, "spray": 2})
        by_id = {row["id"]: row for row in result["techniques"]}
        parent = by_id["T1110"]
        child = by_id["T1110.001"]
        self.assertEqual(parent["hits"], 4)
        self.assertEqual([row["id"] for row in parent["rules"]], ["guess"])
        self.assertEqual(child["hits"], 6)
        self.assertEqual([row["id"] for row in child["rules"]], ["guess", "spray"])
        self.assertEqual(child["rules"][0]["hits"], 4)
        self.assertTrue(child["covered"])

    def test_a_disabled_rule_listed_twice_does_not_cover_the_technique(self):
        off = rule_row("off", False, ["T1567", "T1567"])
        other = rule_row("other", True, ["T1046"])
        result = attack.coverage([off, other], {"off": 4, "other": 1})
        by_id = {row["id"]: row for row in result["techniques"]}
        quiet = by_id["T1567"]
        self.assertEqual(quiet["hits"], 4)
        self.assertEqual(quiet["rules"], [{"id": "off", "name": "off", "enabled": False, "hits": 4}])
        self.assertFalse(quiet["covered"])
        self.assertEqual(by_id["T1046"]["hits"], 1)
        self.assertEqual([row["id"] for row in by_id["T1046"]["rules"]], ["other"])

    def test_a_built_in_rule_that_lists_a_technique_once_keeps_its_count(self):
        brute = next(row for row in rules.DEFAULT_RULES if row["id"] == "brute_force_ip")
        self.assertEqual([row["id"] for row in brute["techniques"]], ["T1110.001"])
        listed = [{**row, "enabled": True} for row in rules.DEFAULT_RULES]
        result = attack.coverage(listed, {"brute_force_ip": 3, "success_after_failures": 2})
        by_id = {row["id"]: row for row in result["techniques"]}
        self.assertEqual(by_id["T1110.001"]["hits"], 3)
        matches = [row for row in by_id["T1110.001"]["rules"] if row["id"] == "brute_force_ip"]
        self.assertEqual(matches, [{"id": "brute_force_ip", "name": brute["name"], "enabled": True, "hits": 3}])
        # success_after_failures maps T1110 once, so those two alerts stay 2.
        self.assertEqual(by_id["T1110"]["hits"], 2)

    def test_the_docs_name_the_single_count(self):
        self.assertIn(SENTENCE, API.read_text())
        self.assertIn(SENTENCE, REFERENCE.read_text())
        self.assertIn("does not set `covered` by itself", REFERENCE.read_text())


def store_techniques(db, rule_id, technique_ids, enabled=1):
    listed = [attack.technique(technique_id) for technique_id in technique_ids]
    db.execute("UPDATE rules SET techniques = ?, enabled = ? WHERE id = ?",
               (json.dumps(listed), enabled, rule_id))


def insert_alerts(db, rule_id, count):
    for index in range(count):
        db.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
            " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rule_id, 1, f"k{index}", "medium", "synthetic alert", "why", "open", ANCHOR, ANCHOR, 1, 1,
             ANCHOR, ANCHOR))


class CoverageTechniqueOnceApiTests(ServerTestCase):
    def test_the_coverage_endpoint_counts_a_repeated_technique_once(self):
        viewer = self.client("viewer")
        before = {row["id"]: row for row in viewer.get("/api/attack/coverage")[1]["techniques"]}
        with sqlite3.connect(self.db_path) as db:
            # brute_force_ip maps T1110.001 once. Listing it twice must not double the alerts.
            store_techniques(db, "brute_force_ip", ["T1110.001", "T1110.001", "T1046"])
            insert_alerts(db, "brute_force_ip", 3)
        status, body, headers = viewer.get("/api/attack/coverage")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        by_id = {row["id"]: row for row in body["techniques"]}
        child = by_id["T1110.001"]
        self.assertEqual(child["hits"], before["T1110.001"]["hits"] + 3)
        guess_rows = [row for row in child["rules"] if row["id"] == "brute_force_ip"]
        self.assertEqual(len(guess_rows), 1)
        self.assertEqual(guess_rows[0]["hits"], 3)
        self.assertEqual(by_id["T1046"]["hits"], before["T1046"]["hits"] + 3)
        sweep = [row for row in by_id["T1046"]["rules"] if row["id"] == "brute_force_ip"]
        self.assertEqual(len(sweep), 1)
        self.assertEqual(sweep[0]["hits"], 3)

    def test_a_disabled_rule_stays_listed_and_does_not_cover(self):
        viewer = self.client("viewer")
        with sqlite3.connect(self.db_path) as db:
            store_techniques(db, "brute_force_ip", ["T1110.001", "T1110.001"], enabled=0)
            insert_alerts(db, "brute_force_ip", 2)
        status, body, _ = viewer.get("/api/attack/coverage")
        self.assertEqual(status, 200, body)
        child = next(row for row in body["techniques"] if row["id"] == "T1110.001")
        rows = [row for row in child["rules"] if row["id"] == "brute_force_ip"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["enabled"], rows[0]["hits"], child["hits"]), (False, 2, 2))
        self.assertFalse(child["covered"])
        self.assertEqual(child["level"], "disabled")

    def test_a_rejected_request_has_no_coverage(self):
        status, body, _ = self.client().get("/api/attack/coverage")
        self.assertEqual(status, 401)
        self.assertNotIn("techniques", body)
