"""_check_chain_key refuses a connection key other than the one the first hashed row declares.

Startup refusal through init_schema is already covered in tests/test_audit_chain.py. These tests call
watchpost.db._check_chain_key by name, including the meta write on a matching key.
"""

import json
import os
import tempfile
import unittest

from watchpost import db


KEY_A = "gap16-audit-key-a"
KEY_B = "gap16-audit-key-b"


class CheckChainKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "chain.db")
        starter = db.connect(self.path, audit_key=KEY_A)
        self.addCleanup(starter.close)
        db.init_schema(starter)
        detail = json.loads(starter.execute(
            "SELECT detail FROM audit_log WHERE hash IS NOT NULL ORDER BY id LIMIT 1"
        ).fetchone()["detail"])
        self.declared = detail["key_id"]
        self.assertEqual(self.declared, db.audit_key_id(KEY_A))

    def connect(self, key):
        conn = db.connect(self.path, audit_key=key)
        self.addCleanup(conn.close)
        return conn

    def meta_key_id(self, conn):
        row = conn.execute("SELECT value FROM meta WHERE key = 'audit_key_id'").fetchone()
        return None if row is None else row["value"]

    def test_a_chain_declaring_key_a_rejects_key_b_or_an_unset_key(self):
        cases = (
            (KEY_B, "the chain was started with a different SIEM_AUDIT_KEY"),
            (None, "the chain was started with SIEM_AUDIT_KEY, but none is set"),
        )
        for key, message in cases:
            conn = self.connect(key)
            with self.assertRaises(db.AuditKeyError) as caught:
                db._check_chain_key(conn)
            self.assertIn(message, str(caught.exception))
            # Refusal happens before the meta copy is rewritten.
            self.assertEqual(self.meta_key_id(conn), self.declared)

    def test_the_same_key_passes_and_writes_audit_key_id(self):
        conn = self.connect(KEY_A)
        conn.execute("DELETE FROM meta WHERE key = 'audit_key_id'")
        self.assertIsNone(self.meta_key_id(conn))
        db._check_chain_key(conn)
        self.assertEqual(self.meta_key_id(conn), self.declared)


if __name__ == "__main__":
    unittest.main()
