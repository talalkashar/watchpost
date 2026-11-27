"""GET /api/rules stays a bare array and names the rules past 100.

The order stays id ascending. The rule that sorts last is the one left out.
Performance and the latest evaluation stay on the rows that remain, and a
Sigma rule on that page still includes its YAML and sample. A rule past the
cap is not a row and is counted. X-Watchpost-Omitted is that count, including
0 when there are 100 or fewer, and when there are none. A 401 sends no header.
"""

import json
import sqlite3
from pathlib import Path

from tests.helpers import ServerTestCase

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
OMITTED = "X-Watchpost-Omitted"
STAMP = "2026-01-01T00:00:00.000Z"
KEPT_YAML = "title: Kept synthetic Sigma\n"
OMITTED_YAML = "title: Omitted synthetic Sigma YAML\n"
DETECTION = {"op": "match", "field": "event_type", "mod": "eq", "values": ["auth_failure"], "all": False}
SAMPLE = {"malicious": [{"event_type": "auth_failure"}], "benign": [{"event_type": "auth_success"}]}


def _ids(count):
    return [f"sigma_{i:03d}" for i in range(count)]


def _replace(db, count):
    """Drop the seeded catalog and insert `count` Sigma rules, sigma_000 first by id."""
    params = json.dumps({"title": "synthetic", "detection": DETECTION})
    db.execute("DELETE FROM sigma_rules")
    db.execute("DELETE FROM rules")
    db.executemany(
        "INSERT INTO rules(id, name, description, severity, enabled, params, updated_at, updated_by)"
        " VALUES (?, ?, 'synthetic', 'medium', 0, ?, ?, 'test')",
        [(rule_id, rule_id, params, STAMP) for rule_id in _ids(count)])
    for rule_id, source in (("sigma_000", KEPT_YAML), ("sigma_100", OMITTED_YAML)):
        if rule_id not in _ids(count):
            continue
        db.execute(
            "INSERT INTO sigma_rules(rule_id, source, sha256, sample, imported_by, approved_by, created_at)"
            " VALUES (?, ?, ?, ?, 'analyst', 'admin', ?)",
            (rule_id, source, "ab" * 32, json.dumps(SAMPLE), STAMP))
    db.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " disposition, first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES ('sigma_001', 1, 'k', 'medium', 'synthetic alert', 'why', 'open', 'true_positive',"
        " ?, ?, 1, 1, ?, ?)",
        (STAMP, STAMP, STAMP, STAMP))
    db.execute("DELETE FROM evaluation_runs")
    db.execute(
        "INSERT INTO evaluation_runs(created_at, trigger, created_by, results) VALUES (?, 'manual', 'analyst', ?)",
        (STAMP, json.dumps({"rules": {"sigma_000": {"recall": 1.0}}})))


class RuleListOmittedApiTests(ServerTestCase):
    def _load(self, count):
        with sqlite3.connect(self.db_path) as db:
            _replace(db, count)

    def test_the_seeded_catalog_fits_and_sends_zero(self):
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/rules")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 15)
        self.assertEqual([row["id"] for row in body], sorted(row["id"] for row in body))
        self.assertEqual(headers[OMITTED], "0")
        self.assertEqual(headers["Cache-Control"], "no-store")
        brute = next(row for row in body if row["id"] == "brute_force_ip")
        self.assertEqual(brute["performance"]["open"], 0)
        self.assertIsNone(brute["evaluation"])
        self.assertNotIn("sigma", brute)

    def test_the_last_id_is_the_one_left_out(self):
        self._load(101)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/rules")
        self.assertEqual(status, 200, body)
        self.assertIsInstance(body, list)
        self.assertEqual([row["id"] for row in body], _ids(100))
        self.assertEqual(headers[OMITTED], "1")
        self.assertNotIn("sigma_100", [row["id"] for row in body])
        by_id = {row["id"]: row for row in body}
        kept = by_id["sigma_000"]
        self.assertEqual(kept["sigma"]["source"], KEPT_YAML)
        self.assertEqual(kept["sigma"]["sample"], SAMPLE)
        self.assertIn("event_type", kept["sigma"]["conditions"])
        self.assertEqual(kept["evaluation"], {"recall": 1.0})
        self.assertEqual(kept["performance"]["total"], 0)
        scored = by_id["sigma_001"]
        self.assertEqual(scored["performance"]["open"], 1)
        self.assertEqual(scored["performance"]["tp"], 1)
        self.assertEqual(scored["performance"]["precision"], 1.0)
        self.assertIsNone(scored["evaluation"])
        self.assertIsNone(scored["sigma"])
        self.assertNotIn(OMITTED_YAML, json.dumps(body))
        status, exported, export_headers = viewer.get("/api/rules/export")
        self.assertEqual(status, 200)
        self.assertEqual(len(exported["rules"]), 101)
        self.assertIn("sigma_100", [row["id"] for row in exported["rules"]])
        self.assertIsNone(export_headers.get(OMITTED))

    def test_an_exact_cap_and_an_empty_table_return_zero(self):
        self._load(100)
        viewer = self.client("viewer")
        status, body, headers = viewer.get("/api/rules")
        self.assertEqual(status, 200)
        self.assertEqual([row["id"] for row in body], _ids(100))
        self.assertIn("sigma_000", [row["id"] for row in body])
        self.assertEqual(headers[OMITTED], "0")
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM sigma_rules")
            db.execute("DELETE FROM rules")
        status, empty, headers = viewer.get("/api/rules")
        self.assertEqual(status, 200)
        self.assertEqual(empty, [])
        self.assertEqual(headers[OMITTED], "0")

    def test_a_rejected_request_does_not_send_the_header(self):
        self._load(101)
        status, _body, headers = self.client().get("/api/rules")
        self.assertEqual(status, 401)
        self.assertIsNone(headers.get(OMITTED))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_docs_name_the_header(self):
        line = next(row for row in API.read_text().splitlines()
                    if row.startswith("| `GET /api/rules`"))
        self.assertIn("The body stays a bare array", line)
        self.assertIn("first 100 rules by `id`", line)
        self.assertIn("YAML and sample", line)
        self.assertIn(
            "`X-Watchpost-Omitted` is how many rules were past that cap "
            "(0 when there are 100 or fewer, including none)",
            line)
