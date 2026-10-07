"""Tamper-evident audit log: the hash chain, its verification, and the schema 4 upgrade."""

import json
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
        rows = self.conn.execute("SELECT id, created_at, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        for prev, row in zip(rows, rows[1:]):
            self.assertEqual(row["prev_hash"], prev["hash"])
        result = verify_chain(self.conn)
        self.assertTrue(result["ok"])
        self.assertEqual(result["entries"], 6)  # the chain start plus five
        self.assertFalse(result["keyed"])
        self.assertEqual(result["head"], {"id": rows[-1]["id"], "hash": rows[-1]["hash"]})
        self.assertIsNone(result["first_break"])
        self.assertEqual(result["legacy"], {"entries": 0, "last_id": None})
        self.assertEqual(result["chain_started"], {"id": rows[0]["id"], "created_at": rows[0]["created_at"]})

    def test_fresh_log_starts_with_a_chain_start_entry(self):
        rows = self.conn.execute("SELECT action, detail FROM audit_log").fetchall()
        self.assertEqual([r["action"] for r in rows], ["audit_chain_started"])
        self.assertEqual(json.loads(rows[0]["detail"]), {"legacy_entries": 0, "legacy_last_id": None, "keyed": False})
        init_schema(self.conn)  # a restart does not start another chain
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 1)
        self.assertTrue(verify_chain(self.conn)["ok"])

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
        self.assertEqual(result["entries"], 4)
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

    def test_a_trigger_cannot_get_its_content_signed(self):
        # A trigger lives in the database file. If the server hashed the row as read back, this one would have
        # the server sign attacker-chosen content with the key.
        self.write(1)
        self.conn.execute("CREATE TRIGGER forge AFTER INSERT ON audit_log BEGIN"
                          " UPDATE audit_log SET actor = 'mallory', detail = '{\"forged\":1}' WHERE id = NEW.id; END")
        audit(self.conn, "alice", "login")
        forged = self.ids()[-1]
        self.assertEqual(self.conn.execute("SELECT actor FROM audit_log WHERE id = ?", (forged,)).fetchone()[0], "mallory")
        result = verify_chain(self.conn)
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (forged, "modified"))

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
        self.assertEqual(result["entries"], threads * per_thread + 1)
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
        self.assertEqual(result["entries"], 3)


class UpgradeTests(unittest.TestCase):
    """The server never signs rows it did not write: older rows stay unchained and are reported as legacy."""

    key = "upgrade-key"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "old.db")
        db.set_audit_key(self.key)
        self.addCleanup(db.set_audit_key, None)

    def restart(self):
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        init_schema(conn)
        return conn

    def make_v3_database(self, rows):
        conn = connect(self.db_path)
        conn.executescript(db.SCHEMA)
        conn.execute("ALTER TABLE audit_log DROP COLUMN prev_hash")
        conn.execute("ALTER TABLE audit_log DROP COLUMN hash")
        for i in range(rows):
            conn.execute("INSERT INTO audit_log(created_at, actor, action, target, detail) VALUES (?,?,?,?,?)",
                         (f"2026-01-01T00:00:0{i}.000Z", "admin", "old_action", None, None))
        conn.close()

    def assert_legacy(self, conn, entries, last_id):
        result = verify_chain(conn)
        self.assertTrue(result["ok"], result["first_break"])
        self.assertEqual(result["legacy"], {"entries": entries, "last_id": last_id})
        start = conn.execute("SELECT id, created_at, prev_hash, detail FROM audit_log"
                             " WHERE action = 'audit_chain_started' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(result["chain_started"], {"id": start["id"], "created_at": start["created_at"]})
        self.assertEqual(start["prev_hash"], GENESIS_HASH)
        self.assertEqual(json.loads(start["detail"]),
                         {"legacy_entries": entries, "legacy_last_id": last_id, "keyed": True})
        # Nothing at or before the legacy boundary carries a hash: the server vouched for none of it.
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE id <= ? AND hash IS NOT NULL",
                                      (last_id,)).fetchone()[0], 0)
        return result

    def chained_database(self, n=4):
        conn = self.restart()
        for i in range(n):
            audit(conn, "alice", "real", str(i))
        return conn

    def test_upgrade_leaves_existing_rows_unchained_and_starts_the_chain(self):
        self.make_v3_database(4)
        conn = self.restart()
        rows = conn.execute("SELECT action, hash FROM audit_log ORDER BY id").fetchall()
        self.assertEqual([r["action"] for r in rows], ["old_action"] * 4 + ["audit_chain_started"])
        result = self.assert_legacy(conn, 4, 4)
        self.assertEqual(result["entries"], 1)
        self.assertTrue(result["keyed"])
        self.assertEqual(conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0], "4")
        audit(conn, "alice", "after_upgrade")
        init_schema(conn)  # another start writes no second chain start
        self.assertEqual(self.assert_legacy(conn, 4, 4)["entries"], 2)

    def test_dropping_the_hash_column_does_not_launder_a_rewritten_row(self):
        # The attack: rewrite history, drop the column so the upgrade path runs again, restart.
        conn = self.chained_database()
        victim = conn.execute("SELECT id FROM audit_log WHERE action = 'real' ORDER BY id LIMIT 1").fetchone()[0]
        conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = ?", (victim,))
        self.assertFalse(verify_chain(conn)["ok"])
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        conn.execute("ALTER TABLE audit_log DROP COLUMN hash")
        conn.close()
        conn = self.restart()
        # The old chain start and the four rows after it are all legacy now: reported, not vouched for.
        result = self.assert_legacy(conn, total, total)
        self.assertGreater(result["chain_started"]["id"], victim)
        self.assertEqual(result["entries"], 1)
        self.assertIsNone(conn.execute("SELECT hash FROM audit_log WHERE id = ?", (victim,)).fetchone()[0])

    def test_recreated_table_with_forged_rows_is_reported_as_legacy(self):
        conn = self.chained_database()
        conn.execute("DROP TABLE audit_log")
        conn.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,"
                     " actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail TEXT)")
        for _ in range(3):
            conn.execute("INSERT INTO audit_log(created_at, actor, action) VALUES ('2026-01-01T00:00:00.000Z',"
                         " 'admin', 'forged')")
        conn.close()
        conn = self.restart()
        self.assertEqual(self.assert_legacy(conn, 3, 3)["entries"], 1)

    def test_clearing_every_hash_and_restarting_is_reported_as_legacy(self):
        conn = self.chained_database()
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        conn.execute("UPDATE audit_log SET hash = NULL, prev_hash = NULL")
        result = verify_chain(conn)  # before a restart: no chain at all
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["reason"], "modified")
        conn.close()
        conn = self.restart()
        self.assert_legacy(conn, total, total)

    def test_clearing_hashes_on_the_oldest_chained_rows_breaks_the_chain(self):
        # Trying to push signed rows into "legacy" without a restart: the first hashed row left does not
        # start from genesis.
        conn = self.chained_database()
        ids = [r[0] for r in conn.execute("SELECT id FROM audit_log ORDER BY id")]
        conn.execute("UPDATE audit_log SET hash = NULL WHERE id <= ?", (ids[1],))
        result = verify_chain(conn)
        self.assertFalse(result["ok"])
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (ids[2], "deleted"))

    def test_legacy_rows_removed_or_added_after_the_chain_start_are_detected(self):
        self.make_v3_database(3)
        conn = self.restart()
        start = verify_chain(conn)["chain_started"]["id"]
        conn.execute("DELETE FROM audit_log WHERE id = 2")
        result = verify_chain(conn)
        self.assertFalse(result["ok"])
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (start, "legacy_mismatch"))
        self.assertEqual(result["legacy"], {"entries": 2, "last_id": 3})
        conn.execute("INSERT INTO audit_log(id, created_at, actor, action) VALUES (2, 'x', 'admin', 'old_action')")
        self.assertTrue(verify_chain(conn)["ok"])  # legacy contents are not verified; only their count and range
        conn.execute("INSERT INTO audit_log(id, created_at, actor, action) VALUES (0, 'x', 'mallory', 'forged')")
        self.assertEqual(verify_chain(conn)["first_break"]["reason"], "legacy_mismatch")

    def test_legacy_rows_before_an_ordinary_first_entry_are_detected(self):
        # A chain whose first entry is not a chain start (a 4.0 database from before this rule) declares no
        # legacy rows, so an unhashed row slipped in before it is a mismatch.
        conn = self.chained_database()
        conn.execute("DELETE FROM audit_log WHERE action = 'audit_chain_started'")
        prev = GENESIS_HASH
        for row in conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
            h = db.audit_hash(prev, dict(row), self.key)
            conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev, h, row["id"]))
            prev = h
        first = conn.execute("SELECT MIN(id) FROM audit_log").fetchone()[0]
        self.assertTrue(verify_chain(conn)["ok"])
        conn.execute("INSERT INTO audit_log(id, created_at, actor, action) VALUES (0, 'x', 'mallory', 'forged')")
        result = verify_chain(conn)
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (first, "legacy_mismatch"))

    def test_rows_with_no_hash_after_the_chain_start_are_not_silently_adopted(self):
        conn = self.chained_database(1)
        conn.execute("INSERT INTO audit_log(created_at, actor, action) VALUES ('2026-01-01T00:00:00.000Z', 'x', 'forged')")
        forged = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]
        init_schema(conn)
        audit(conn, "alice", "after_forgery")
        result = verify_chain(conn)
        self.assertFalse(result["ok"])
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (forged, "modified"))


class SecondChainStartTests(ChainTestCase):
    def test_a_second_chain_start_inside_the_chain_is_a_broken_link(self):
        # Unkeyed, so this test can forge a correctly hashed entry that restarts from genesis.
        self.write(2)
        cur = self.conn.execute("INSERT INTO audit_log(created_at, actor, action, detail) VALUES (?,?,?,?)",
                                ("2026-01-01T00:00:00.000Z", "system", "audit_chain_started",
                                 '{"keyed":false,"legacy_entries":0,"legacy_last_id":null}'))
        row = dict(self.conn.execute("SELECT * FROM audit_log WHERE id = ?", (cur.lastrowid,)).fetchone())
        self.conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?",
                          (GENESIS_HASH, db.audit_hash(GENESIS_HASH, row, None), cur.lastrowid))
        result = verify_chain(self.conn)
        self.assertFalse(result["ok"])
        self.assertEqual((result["first_break"]["id"], result["first_break"]["reason"]), (cur.lastrowid, "broken_link"))


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
