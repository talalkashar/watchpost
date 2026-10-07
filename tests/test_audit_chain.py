"""Tamper-evident audit log: the hash chain, its verification, and the schema 4 upgrade."""

import os
import sqlite3
import tempfile
import threading
import unittest

from tests.helpers import ServerTestCase
from watchpost import db
from watchpost.db import GENESIS_HASH, audit, connect, init_schema, transaction, verify_chain


class ChainTestCase(unittest.TestCase):
    key = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "chain.db")
        db.set_audit_key(self.key)
        self.addCleanup(db.set_audit_key, None)
        self.conn = connect(self.db_path)
        self.addCleanup(self.conn.close)
        init_schema(self.conn)

    def write(self, n):
        for i in range(n):
            audit(self.conn, "alice", "test_action", f"t{i}", {"i": i})

    def ids(self):
        return [r[0] for r in self.conn.execute("SELECT id FROM audit_log ORDER BY id")]


class ChainTests(ChainTestCase):
    def test_append_and_verify(self):
        self.write(5)
        rows = self.conn.execute("SELECT id, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        for prev, row in zip(rows, rows[1:]):
            self.assertEqual(row["prev_hash"], prev["hash"])
        result = verify_chain(self.conn)
        self.assertTrue(result["ok"])
        self.assertEqual(result["entries"], 5)
        self.assertFalse(result["keyed"])
        self.assertEqual(result["head"], {"id": rows[-1]["id"], "hash": rows[-1]["hash"]})
        self.assertIsNone(result["first_break"])

    def test_empty_log_verifies(self):
        result = verify_chain(self.conn)
        self.assertEqual((result["ok"], result["entries"], result["head"]), (True, 0, None))

    def test_edited_detail_is_detected_at_that_row(self):
        self.write(5)
        target = self.ids()[2]
        self.conn.execute("UPDATE audit_log SET detail = '{\"i\": 99}' WHERE id = ?", (target,))
        result = verify_chain(self.conn)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["id"], target)
        self.assertEqual(result["first_break"]["reason"], "modified")

    def test_deleted_middle_row_is_detected(self):
        self.write(5)
        ids = self.ids()
        self.conn.execute("DELETE FROM audit_log WHERE id = ?", (ids[2],))
        result = verify_chain(self.conn)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["id"], ids[3])
        self.assertEqual(result["first_break"]["reason"], "deleted")

    def test_deleted_first_row_is_detected(self):
        self.write(3)
        ids = self.ids()
        self.conn.execute("DELETE FROM audit_log WHERE id = ?", (ids[0],))
        result = verify_chain(self.conn)
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (ids[1], "deleted"))

    def test_rewritten_row_with_recomputed_hash_breaks_the_next_link(self):
        self.write(4)
        ids = self.ids()
        row = dict(self.conn.execute("SELECT * FROM audit_log WHERE id = ?", (ids[1],)).fetchone())
        row["actor"] = "mallory"
        new_hash = db.audit_hash(row["prev_hash"], row, None)
        self.conn.execute("UPDATE audit_log SET actor = 'mallory', hash = ? WHERE id = ?", (new_hash, ids[1]))
        result = verify_chain(self.conn)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["id"], ids[2])
        self.assertEqual(result["first_break"]["reason"], "broken_link")

    def test_deleting_the_newest_row_is_not_detectable_from_the_chain_alone(self):
        # The limitation the README describes: the remaining rows are still a valid chain. Only a head
        # recorded somewhere else (or the next append leaving an id gap) shows the loss.
        self.write(4)
        head_before = verify_chain(self.conn)["head"]
        self.conn.execute("DELETE FROM audit_log WHERE id = ?", (self.ids()[-1],))
        result = verify_chain(self.conn)
        self.assertTrue(result["ok"])
        self.assertEqual(result["entries"], 3)
        self.assertNotEqual(result["head"], head_before)
        # The next entry links to the surviving head, but its id skips the deleted one.
        audit(self.conn, "alice", "after_delete")
        self.assertEqual(verify_chain(self.conn)["first_break"]["reason"], "deleted")

    def test_unkeyed_chain_can_be_recomputed_by_anyone_with_write_access(self):
        # Honest limitation of the fallback mode: a full rewrite of every hash verifies again.
        self.write(3)
        ids = self.ids()
        self.conn.execute("UPDATE audit_log SET detail = '{\"i\": 42}' WHERE id = ?", (ids[0],))
        prev = GENESIS_HASH
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
            h = db.audit_hash(prev, dict(row), None)
            self.conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev, h, row["id"]))
            prev = h
        self.assertTrue(verify_chain(self.conn)["ok"])


class KeyedChainTests(ChainTestCase):
    key = "test-audit-key-1"

    def test_keyed_chain_verifies_and_says_so(self):
        self.write(3)
        result = verify_chain(self.conn)
        self.assertTrue(result["ok"])
        self.assertTrue(result["keyed"])

    def test_rewrite_without_the_key_is_detected(self):
        # Same full recompute as the unkeyed test, but an attacker without the key can only use SHA-256.
        self.write(3)
        prev = GENESIS_HASH
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
            h = db.audit_hash(prev, dict(row), None)
            self.conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev, h, row["id"]))
            prev = h
        result = verify_chain(self.conn)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["id"], self.ids()[0])
        self.assertEqual(result["first_break"]["reason"], "modified")

    def test_wrong_key_fails_verification(self):
        self.write(2)
        self.assertFalse(verify_chain(self.conn, key="another-key")["ok"])
        self.assertTrue(verify_chain(self.conn, key=self.key)["ok"])


class ConcurrencyTests(ChainTestCase):
    def test_concurrent_writers_keep_one_linear_chain(self):
        # Separate connections in separate threads, some inside an outer transaction and some not. Reading the
        # previous hash and inserting outside one write transaction would let two rows share a prev_hash.
        threads, per_thread, errors = 8, 40, []

        def worker(n):
            conn = connect(self.db_path)
            try:
                for i in range(per_thread):
                    if i % 2:
                        with transaction(conn):
                            audit(conn, f"w{n}", "concurrent", str(i))
                    else:
                        audit(conn, f"w{n}", "concurrent", str(i))
            except Exception as exc:  # surfaced below; a thread exception would otherwise be swallowed
                errors.append(exc)
            finally:
                conn.close()

        pool = [threading.Thread(target=worker, args=(n,)) for n in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        self.assertEqual(errors, [])
        result = verify_chain(self.conn)
        self.assertTrue(result["ok"], result["first_break"])
        self.assertEqual(result["entries"], threads * per_thread)
        dupes = self.conn.execute(
            "SELECT COUNT(*) FROM (SELECT prev_hash FROM audit_log GROUP BY prev_hash HAVING COUNT(*) > 1)").fetchone()[0]
        self.assertEqual(dupes, 0)

    def test_failed_outer_transaction_rolls_back_the_entry(self):
        self.write(1)
        with self.assertRaises(RuntimeError):
            with transaction(self.conn):
                audit(self.conn, "alice", "rolled_back")
                raise RuntimeError("boom")
        self.write(1)
        result = verify_chain(self.conn)
        self.assertTrue(result["ok"], result["first_break"])
        self.assertEqual(result["entries"], 2)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "old.db")
        self.addCleanup(db.set_audit_key, None)

    def make_v3_database(self, rows):
        conn = connect(self.db_path)
        init_schema(conn)
        conn.execute("ALTER TABLE audit_log DROP COLUMN prev_hash")
        conn.execute("ALTER TABLE audit_log DROP COLUMN hash")
        conn.execute("UPDATE meta SET value = '3' WHERE key = 'schema_version'")
        for i in range(rows):
            conn.execute("INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
                         (f"2026-01-01T00:00:0{i}.000Z", "admin", "old_action", None, None))
        conn.close()

    def test_upgrade_backfills_existing_rows_in_id_order(self):
        self.make_v3_database(4)
        db.set_audit_key("upgrade-key")
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        init_schema(conn)
        rows = conn.execute("SELECT action, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
        self.assertEqual([r["action"] for r in rows], ["old_action"] * 4 + ["audit_chain_started"])
        self.assertTrue(all(r["hash"] for r in rows))
        result = verify_chain(conn)
        self.assertTrue(result["ok"], result["first_break"])
        self.assertTrue(result["keyed"])
        self.assertEqual(result["entries"], 5)
        self.assertEqual(conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "4")
        # A second start does not backfill or announce again.
        init_schema(conn)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 5)

    def test_rows_with_no_hash_after_the_upgrade_are_not_silently_adopted(self):
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        init_schema(conn)
        audit(conn, "alice", "real")
        conn.execute("INSERT INTO audit_log(created_at, actor, action) VALUES ('2026-01-01T00:00:00.000Z', 'x', 'forged')")
        init_schema(conn)
        result = verify_chain(conn)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["reason"], "modified")


class VerifyRouteTests(ServerTestCase):
    def test_verify_route_is_admin_only_and_reports_the_chain(self):
        self.assertEqual(self.client("analyst").get("/api/audit/verify")[0], 403)
        self.assertEqual(self.client("viewer").get("/api/audit/verify")[0], 403)
        admin = self.client("admin")
        status, result, _ = admin.get("/api/audit/verify")
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        newest = admin.get("/api/audit")[1][0]
        self.assertEqual(result["head"], {"id": newest["id"], "hash": newest["hash"]})
        with sqlite3.connect(self.db_path) as raw:
            raw.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = ?", (newest["id"],))
        broken = admin.get("/api/audit/verify")[1]
        self.assertFalse(broken["ok"])
        self.assertEqual(broken["first_break"]["id"], newest["id"])


if __name__ == "__main__":
    unittest.main()
