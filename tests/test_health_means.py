"""Each health check carries one sentence about what failing or degraded means on this demo."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.helpers import ServerTestCase
from watchpost.db import connect, init_schema
from watchpost.engine import seed_rules
from watchpost.health import (
    CHECK_MEANS, DEFAULT_MEANS, _check, run_health_checks, status_means,
)

STATIC = Path(__file__).resolve().parent.parent / "static"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class HealthMeansTests(unittest.TestCase):
    def test_each_known_check_explains_both_fault_states_in_one_sentence(self):
        sentences = {**CHECK_MEANS, "other": DEFAULT_MEANS}
        self.assertEqual(set(CHECK_MEANS), {"storage", "ingestion", "detection", "dependencies", "syslog", "storyline"})
        for name, text in sentences.items():
            self.assertEqual(status_means(name), text)
            self.assertTrue(text.startswith("Failing means "))
            self.assertIn(", and degraded means ", text)
            self.assertEqual(text.count("."), 1)
            self.assertTrue(text.endswith("."))

    def test_a_healthy_report_and_a_crashed_check_keep_the_sentence(self):
        def open_conn():
            conn = connect(":memory:")
            init_schema(conn)
            seed_rules(conn)
            return conn

        report = run_health_checks(open_conn, ":memory:")
        by_name = {c["name"]: c for c in report["checks"]}
        self.assertTrue({"storage", "ingestion", "detection", "dependencies"} <= set(by_name))
        for name in ("storage", "ingestion", "detection", "dependencies"):
            self.assertEqual(by_name[name]["means"], CHECK_MEANS[name])
            self.assertEqual(by_name[name]["status"], "ok")

        def boom():
            raise RuntimeError("disk")

        failed = _check("storage", boom)
        self.assertEqual(failed["status"], "failing")
        self.assertEqual(failed["means"], CHECK_MEANS["storage"])
        self.assertIn("health check raised", failed["message"])

    def test_an_unopenable_database_still_names_what_storage_means(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        blocked = os.path.join(tmp.name, "blocked")
        with open(blocked, "w") as handle:
            handle.write("not a directory")
        path = os.path.join(blocked, "sub", "x.db")
        report = run_health_checks(lambda: connect(path), path)
        storage = report["checks"][0]
        self.assertEqual(storage["name"], "storage")
        self.assertEqual(storage["status"], "failing")
        self.assertEqual(storage["means"], CHECK_MEANS["storage"])
        deps = next(c for c in report["checks"] if c["name"] == "dependencies")
        self.assertEqual(deps["means"], CHECK_MEANS["dependencies"])

    def test_optional_and_unknown_components_use_their_sentence(self):
        def idle():
            return "ok", "idle", None, {}

        self.assertEqual(_check("syslog", idle)["means"], CHECK_MEANS["syslog"])
        self.assertEqual(_check("storyline", idle)["means"], CHECK_MEANS["storyline"])
        self.assertEqual(_check("widget", idle)["means"], DEFAULT_MEANS)


class HealthMeansApiTests(ServerTestCase):
    def test_details_include_means_and_the_public_check_stays_a_status(self):
        status, data, _ = self.client("viewer").get("/api/health/details")
        self.assertEqual(status, 200)
        names = {c["name"] for c in data["checks"]}
        self.assertTrue({"storage", "ingestion", "detection", "dependencies", "storyline"} <= names)
        for check in data["checks"]:
            self.assertEqual(check["means"], status_means(check["name"]))
        code, public, _ = self.client().get("/api/health")
        self.assertEqual(code, 200)
        self.assertTrue(all(isinstance(value, str) for value in public["checks"].values()))
        self.assertNotIn("this demo", json.dumps(public))


class HealthMeansPageTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.app = read("app.js")

    def means(self, check):
        script = function_body(self.app, "checkMeans") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(checkMeans(input)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps(check),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_a_server_sentence_is_trimmed_and_a_blank_one_is_dropped(self):
        sentence = CHECK_MEANS["detection"]
        self.assertEqual(self.means({"means": sentence}), sentence)
        self.assertEqual(self.means({"means": "  " + sentence + "  "}), sentence)
        for missing in ({}, {"means": ""}, {"means": "   "}, {"means": 30}, None):
            self.assertEqual(self.means(missing), "")

    def test_the_sentence_sits_under_the_check(self):
        page = function_body(self.app, "health")
        card = page.index('class: "check"')
        message = page.index("c.message", card)
        guidance = page.index('class: "guidance"', card)
        means = page.index('class: "check-means"', card)
        details = page.index('"details"', card)
        self.assertLess(message, guidance)
        self.assertLess(guidance, details)
        self.assertLess(details, means)
        self.assertIn("checkMeans(c)", page)
        css = read("style.css")
        self.assertIn(
            ".check-means { grid-column: 1 / -1; margin: 0; color: var(--ink-2); font-size: 13px; line-height: 1.45; }",
            css)


if __name__ == "__main__":
    unittest.main()
