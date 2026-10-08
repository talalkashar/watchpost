"""Scale: the schema 6 indexes, the query plans they buy, history on ingest rescans, and the load script."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import ADMIN_PW, ANALYST_PW
from watchpost import engine, hunt, queries, rules, simulate
from watchpost.config import Config
from watchpost.db import SCHEMA_VERSION, audit, connect, init_schema, verify_chain
from watchpost.normalize import parse_payload

NEW_INDEXES = ("idx_events_user_nocase", "idx_events_host", "idx_events_dest_ip", "idx_events_severity",
               "idx_events_ingested", "idx_events_synthetic")


class SchemaSixUpgradeTests(unittest.TestCase):
    def test_v5_database_gains_the_indexes_and_keeps_its_audit_chain(self):
        from watchpost.server import App
        with tempfile.TemporaryDirectory() as tmp:
            config = Config.from_env(db_path=os.path.join(tmp, "v5.db"), admin_password=ADMIN_PW,
                                     analyst_password=ANALYST_PW)
            App(config)
            conn = connect(config.db_path)
            audit(conn, "alice", "before_upgrade")
            for name in NEW_INDEXES:  # what a 5.x database looked like
                conn.execute(f"DROP INDEX {name}")
            conn.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'")
            chain = [tuple(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
            conn.close()

            App(config)
            conn = connect(config.db_path)
            self.addCleanup(conn.close)
            self.assertEqual(conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0],
                             str(SCHEMA_VERSION))
            self.assertEqual(SCHEMA_VERSION, 15)
            indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
            self.assertLessEqual(set(NEW_INDEXES), indexes)
            # The upgrade writes no audit entry and rewrites none: the chain is byte-for-byte what it was.
            self.assertEqual([tuple(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")], chain)
            self.assertTrue(verify_chain(conn)["ok"])


class QueryPlanTests(unittest.TestCase):
    """The statements the read paths actually run, captured and explained. Cheap: plans need no data."""

    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def plans(self, call):
        statements = []
        self.conn.set_trace_callback(statements.append)
        try:
            call()
        finally:
            self.conn.set_trace_callback(None)
        return ["; ".join(r[3] for r in self.conn.execute("EXPLAIN QUERY PLAN " + sql))
                for sql in statements if sql.lstrip().upper().startswith("SELECT")]

    def assert_all_use(self, plans, index):
        self.assertTrue(plans)
        for plan in plans:
            self.assertIn(index, plan)
            self.assertNotRegex(plan, r"SCAN events(?! USING)")

    def test_case_insensitive_user_lookup_uses_the_nocase_index(self):
        self.assert_all_use(self.plans(lambda: queries.search_events(self.conn, {"user": "Alice"})),
                            "idx_events_user_nocase (user=?)")
        self.assert_all_use(self.plans(lambda: hunt.run(self.conn, {"q": "user:alice"})), "idx_events_user_nocase")

    def test_user_prefix_is_a_range_on_the_nocase_index(self):
        for plan in self.plans(lambda: queries.search_events(self.conn, {"user": "ali*"})):
            self.assertIn("idx_events_user_nocase (user>? AND user<?)", plan)

    def test_ip_filter_searches_source_and_destination_indexes(self):
        for plan in self.plans(lambda: queries.search_events(self.conn, {"ip": "10.0.0.5"})):
            self.assertIn("MULTI-INDEX OR", plan)
            self.assertIn("idx_events_src_ip", plan)
            self.assertIn("idx_events_dest_ip", plan)

    def test_host_and_severity_filters_use_their_indexes(self):
        self.assert_all_use(self.plans(lambda: queries.search_events(self.conn, {"host": "web01"})),
                            "idx_events_host")
        self.assert_all_use(self.plans(lambda: queries.search_events(
            self.conn, {"severity": "high", "severity_mode": "min"})), "idx_events_severity")


class HistoryOnIngestTests(unittest.TestCase):
    def test_every_rule_with_history_declares_the_types_it_reads(self):
        with_history = {r["id"] for r in rules.DEFAULT_RULES if "history_seconds" in r["params"]}
        self.assertEqual(set(rules.HISTORY_EVENT_TYPES), with_history)

    def test_history_from_an_earlier_batch_reaches_the_rescan(self):
        # admin_action_from_new_source needs three earlier privileged actions: they arrive a batch before the
        # attack, days earlier, so the second batch's rescan only sees them through the history fetch.
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        events = simulate.build(["admin_new_source"])["admin_new_source"]
        for batch in (events[:-2], events[-2:]):
            normalized, rejections = parse_payload(json.dumps(batch), "json", "demo:admin_new_source")
            run = engine.ingest(conn, normalized, rejections, "demo:admin_new_source", "json", "test", True)
            self.assertEqual(run["detection"]["status"], "ok")
        alerts = conn.execute("SELECT group_key FROM alerts WHERE rule_id = 'admin_action_from_new_source'")
        self.assertEqual([r[0] for r in alerts], ["ops-admin|198.51.100.77"])


class LoadScriptTests(unittest.TestCase):
    def test_tiny_run_ingests_detects_and_times_every_read_path(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        self.addCleanup(sys.path.pop, 0)
        import loadtest
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                loadtest.main(["--events", "500", "--repeat", "1", "--json", "--db", os.path.join(tmp, "l.db")])
        report = json.loads(out.getvalue())
        self.assertEqual((report["events"], report["events_stored"]), (500, 500))
        self.assertEqual(report["full_detection_status"], "ok")
        self.assertGreater(report["alerts"], 0)
        self.assertGreater(report["ingest_events_per_s"], 0)
        self.assertEqual({"python", "platform", "machine", "cpus"}, set(report["machine"]))
        self.assertGreaterEqual(len(report["reads"]), 20)
        self.assertIn("| Read path", loadtest.markdown(report))


if __name__ == "__main__":
    unittest.main()
