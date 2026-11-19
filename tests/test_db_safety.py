"""SQL identifier checks, hot-path indexes, and transaction boundaries in watchpost.db."""

import sqlite3
import unittest

from watchpost.db import (
    ADDED_COLUMNS,
    SCHEMA_VERSION,
    TransactionBoundaryError,
    _column_type_sql,
    _ensure_column,
    _sql_ident,
    audit,
    connect,
    init_schema,
    transaction,
    verify_chain,
)

NEW_INDEXES = {
    "idx_alert_notes_alert",
    "idx_alert_activity_alert",
    "idx_rule_history_rule",
    "idx_suppressions_active",
    "idx_rule_windows_open",
    "idx_ingest_batches_created",
    "idx_ingest_batches_detection",
    "idx_error_log_component",
    "idx_sessions_expires",
}


def _indexes(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}


def _columns(conn, table):
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({_sql_ident(table)})")}


def _plan(conn, sql, args=()):
    return "\n".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, args))


class SafetyCase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)


class SchemaTests(SafetyCase):
    def test_schema_version_stays_15_and_new_indexes_exist(self):
        self.assertEqual(SCHEMA_VERSION, 15)
        self.assertEqual(
            self.conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "15"
        )
        indexes = _indexes(self.conn)
        self.assertTrue(NEW_INDEXES <= indexes)
        self.assertTrue({"idx_events_ts", "idx_alerts_rule_nocase", "idx_sessions_sid",
                         "idx_suppressions_rule"} <= indexes)

    def test_init_schema_is_idempotent_and_restores_a_dropped_column(self):
        self.conn.execute("ALTER TABLE events DROP COLUMN dest_port")
        self.assertNotIn("dest_port", _columns(self.conn, "events"))
        init_schema(self.conn)
        self.assertIn("dest_port", _columns(self.conn, "events"))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 1)
        self.assertTrue(verify_chain(self.conn)["ok"])
        self.assertTrue(NEW_INDEXES <= _indexes(self.conn))


class IdentifierTests(SafetyCase):
    def test_added_column_kinds_are_accepted(self):
        for _table, _column, kind in ADDED_COLUMNS:
            self.assertEqual(_column_type_sql(kind), kind)

    def test_identifiers_are_quoted_and_hostile_sql_is_refused(self):
        self.assertEqual(_sql_ident("events"), '"events"')
        hostile = [
            ("events; DROP TABLE events", "pwned", "TEXT"),
            ("events", "pwned; --", "TEXT"),
            ('events"', "pwned", "TEXT"),
            ("", "pwned", "TEXT"),
            ("events", "", "TEXT"),
            ("events", "pwned", "INTEGER DEFAULT (SELECT 1)"),
            ("events", "pwned", "TEXT; DROP TABLE events"),
            ("events", "pwned", "INTEGER PRIMARY KEY"),
            ("events", "pwned", "TEXT NOT NULL DEFAULT (SELECT 1)"),
        ]
        for table, column, kind in hostile:
            with self.assertRaises(ValueError):
                _ensure_column(self.conn, table, column, kind)
        self.assertIn("events", {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")})
        self.assertNotIn("pwned", _columns(self.conn, "events"))
        self.assertTrue(verify_chain(self.conn)["ok"])


class QueryPlanTests(SafetyCase):
    def test_hot_reads_use_the_new_indexes(self):
        plans = {
            "idx_alert_notes_alert": _plan(
                self.conn,
                "SELECT * FROM (SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY id DESC LIMIT ?)"
                " ORDER BY id",
                (1, 5),
            ),
            "idx_alert_activity_alert": _plan(
                self.conn,
                "SELECT * FROM (SELECT * FROM alert_activity WHERE alert_id = ? ORDER BY id DESC LIMIT ?)"
                " ORDER BY id",
                (1, 5),
            ),
            "idx_rule_history_rule": _plan(
                self.conn,
                "SELECT * FROM rule_history WHERE rule_id = ? ORDER BY version DESC LIMIT ?",
                ("x", 50),
            ),
            "idx_suppressions_active": _plan(
                self.conn,
                "SELECT rule_id, group_key FROM suppressions WHERE expires_at > ? AND revoked_at IS NULL",
                ("2026",),
            ),
            "idx_rule_windows_open": _plan(
                self.conn,
                "SELECT rule_id FROM rule_suppression_windows"
                " WHERE starts_at <= ? AND expires_at > ? AND ended_at IS NULL",
                ("2026", "2026"),
            ),
            "idx_ingest_batches_created": _plan(
                self.conn,
                "SELECT COUNT(*) FROM ingest_batches WHERE created_at >= ?",
                ("2026",),
            ),
            "idx_ingest_batches_detection": _plan(
                self.conn,
                "SELECT COUNT(*) FROM ingest_batches WHERE detection_status = 'failed'",
            ),
            "idx_error_log_component": _plan(
                self.conn,
                "SELECT COUNT(*) FROM error_log WHERE component = 'ingestion' AND created_at >= ?",
                ("2026",),
            ),
            "idx_sessions_expires": _plan(
                self.conn,
                "DELETE FROM sessions WHERE expires_at < ?",
                ("2026",),
            ),
        }
        for index, plan in plans.items():
            self.assertIn(index, plan, plan)
        self.assertNotIn("USE TEMP B-TREE", plans["idx_rule_history_rule"], plans["idx_rule_history_rule"])


class TransactionTests(SafetyCase):
    def _meta(self, key):
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    def test_commit_persists_and_a_body_error_rolls_back(self):
        with transaction(self.conn):
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_ok', '1')")
        self.assertEqual(self._meta("safety_ok"), "1")
        with self.assertRaises(RuntimeError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_no', '1')")
                raise RuntimeError("nope")
        self.assertIsNone(self._meta("safety_no"))
        with transaction(self.conn):
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_later', '1')")
        self.assertEqual(self._meta("safety_later"), "1")
        self.assertFalse(self.conn.in_transaction)

    def test_nested_savepoint_commits_with_the_outer_transaction(self):
        with transaction(self.conn):
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_outer_ok', '1')")
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_inner_ok', '1')")
        self.assertEqual(self._meta("safety_outer_ok"), "1")
        self.assertEqual(self._meta("safety_inner_ok"), "1")
        self.assertFalse(self.conn.in_transaction)

    def test_nested_savepoint_rolls_back_only_itself(self):
        with transaction(self.conn):
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_outer', '1')")
            try:
                with transaction(self.conn):
                    self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_inner', '1')")
                    raise RuntimeError("nope")
            except RuntimeError:
                pass
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_after', '1')")
        self.assertEqual(self._meta("safety_outer"), "1")
        self.assertIsNone(self._meta("safety_inner"))
        self.assertEqual(self._meta("safety_after"), "1")
        self.assertFalse(self.conn.in_transaction)

    def test_outer_rollback_undoes_a_released_savepoint(self):
        with self.assertRaises(RuntimeError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_outer2', '1')")
                with transaction(self.conn):
                    self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_inner2', '1')")
                raise RuntimeError("nope")
        self.assertIsNone(self._meta("safety_outer2"))
        self.assertIsNone(self._meta("safety_inner2"))
        self.assertFalse(self.conn.in_transaction)

    def test_early_commit_stays_durable_and_a_later_audit_is_refused(self):
        before = self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        with self.assertRaises(TransactionBoundaryError) as caught:
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_early', '1')")
                self.conn.execute("COMMIT")
                raise RuntimeError("too late")
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        # The COMMIT already happened. Reporting the error does not remove the row.
        self.assertEqual(self._meta("safety_early"), "1")
        with self.assertRaises(TransactionBoundaryError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_early_audit', '1')")
                self.conn.execute("COMMIT")
                audit(self.conn, "alice", "should_not_land", "t")
        self.assertEqual(self._meta("safety_early_audit"), "1")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], before)
        self.assertNotIn(
            "should_not_land",
            [r[0] for r in self.conn.execute("SELECT action FROM audit_log")],
        )
        with transaction(self.conn):
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_follow', '1')")
        self.assertEqual(self._meta("safety_follow"), "1")
        self.assertFalse(self.conn.in_transaction)

    def test_executescript_implicit_commit_stays_durable(self):
        with self.assertRaises(TransactionBoundaryError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_script_a', '1')")
                self.conn.executescript("INSERT INTO meta(key, value) VALUES ('safety_script_b', '2');")
        self.assertEqual(self._meta("safety_script_a"), "1")
        self.assertEqual(self._meta("safety_script_b"), "2")
        self.assertFalse(self.conn.in_transaction)

    def test_missing_savepoint_surfaces_and_the_outer_transaction_rolls_back(self):
        with self.assertRaises(sqlite3.OperationalError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_sp', '1')")
                with transaction(self.conn):
                    self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_sp_inner', '1')")
                    self.conn.execute("RELEASE wp_0")
        self.assertIsNone(self._meta("safety_sp"))
        self.assertIsNone(self._meta("safety_sp_inner"))
        self.assertFalse(self.conn.in_transaction)

    def test_commit_failure_surfaces_and_rolls_back(self):
        self.conn.execute("CREATE TABLE safety_parent(id INTEGER PRIMARY KEY)")
        self.conn.execute(
            "CREATE TABLE safety_child(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL"
            " REFERENCES safety_parent(id) DEFERRABLE INITIALLY DEFERRED)"
        )
        inserted = False
        with self.assertRaises(sqlite3.IntegrityError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO safety_child(parent_id) VALUES (99)")
                inserted = True
        self.assertTrue(inserted)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM safety_child").fetchone()[0], 0)
        self.assertFalse(self.conn.in_transaction)
        with transaction(self.conn):
            self.conn.execute("INSERT INTO safety_parent(id) VALUES (1)")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM safety_parent").fetchone()[0], 1)

    def test_domain_write_and_audit_commit_or_roll_back_together(self):
        with transaction(self.conn):
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_domain', '1')")
            audit(self.conn, "alice", "domain_kept", "meta")
        self.assertEqual(self._meta("safety_domain"), "1")
        with self.assertRaises(RuntimeError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_domain_no', '1')")
                audit(self.conn, "alice", "domain_lost", "meta")
                raise RuntimeError("nope")
        self.assertIsNone(self._meta("safety_domain_no"))
        actions = [r[0] for r in self.conn.execute("SELECT action FROM audit_log ORDER BY id")]
        self.assertEqual(actions, ["audit_chain_started", "domain_kept"])
        self.assertTrue(verify_chain(self.conn)["ok"])
        self.assertFalse(self.conn.in_transaction)

    def test_init_schema_refuses_to_commit_an_open_transaction(self):
        with self.assertRaises(TransactionBoundaryError):
            with transaction(self.conn):
                self.conn.execute("INSERT INTO meta(key, value) VALUES ('safety_schema', '1')")
                init_schema(self.conn)
        self.assertIsNone(self._meta("safety_schema"))
        self.assertFalse(self.conn.in_transaction)
        self.assertTrue(verify_chain(self.conn)["ok"])

    def test_audit_follows_the_transaction_that_contains_it(self):
        before = self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        with self.assertRaises(RuntimeError):
            with transaction(self.conn):
                audit(self.conn, "alice", "rolled_back", "t")
                raise RuntimeError("nope")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], before)
        with transaction(self.conn):
            audit(self.conn, "alice", "outer", "t")
            try:
                with transaction(self.conn):
                    audit(self.conn, "alice", "inner", "t")
                    raise RuntimeError("nope")
            except RuntimeError:
                pass
        audit(self.conn, "alice", "outside", "t")
        actions = [r[0] for r in self.conn.execute("SELECT action FROM audit_log ORDER BY id")]
        self.assertEqual(actions, ["audit_chain_started", "outer", "outside"])
        self.assertTrue(verify_chain(self.conn)["ok"])
        self.assertFalse(self.conn.in_transaction)


if __name__ == "__main__":
    unittest.main()
