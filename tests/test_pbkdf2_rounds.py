"""PBKDF2 defaults to 600,000 rounds. Older hashes still verify and upgrade on sign-in.

SIEM_PBKDF2_ITERATIONS still overrides the default. A wrong password does not rewrite the hash.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.test_login_username import memory_db
from watchpost import auth
from watchpost.auth import AuthError
from watchpost.db import now_iso

PASSWORD = "stored-password-1"
OLD_ROUNDS = 310_000
NEW_ROUNDS = 600_000
ROOT = Path(__file__).resolve().parents[1]


def _rounds(stored):
    return int(stored.split("$")[1])


class Pbkdf2RoundTests(unittest.TestCase):
    def test_default_iterations_is_600000_without_env_override(self):
        env = os.environ.copy()
        env.pop("SIEM_PBKDF2_ITERATIONS", None)
        env["PYTHONPATH"] = str(ROOT)
        out = subprocess.check_output(
            [sys.executable, "-c", "import watchpost.auth as auth; print(auth.PBKDF2_ITERATIONS)"],
            cwd=ROOT,
            env=env,
            text=True,
        )
        self.assertEqual(out.strip(), str(NEW_ROUNDS))

    def test_new_hash_uses_600000_rounds(self):
        with mock.patch.object(auth, "PBKDF2_ITERATIONS", NEW_ROUNDS):
            stored = auth.hash_password(PASSWORD)
        self.assertEqual(_rounds(stored), NEW_ROUNDS)
        self.assertTrue(auth.verify_password(PASSWORD, stored))

    def test_old_310000_round_hash_still_verifies(self):
        stored = auth.hash_password(PASSWORD, OLD_ROUNDS)
        self.assertEqual(_rounds(stored), OLD_ROUNDS)
        self.assertTrue(auth.verify_password(PASSWORD, stored))
        self.assertFalse(auth.verify_password("wrong-password-xx", stored))

    def test_successful_sign_in_upgrades_an_old_hash(self):
        conn = memory_db()
        self.addCleanup(conn.close)
        stored = auth.hash_password(PASSWORD, OLD_ROUNDS)
        conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
            ("alice", stored, "analyst", now_iso()),
        )
        with mock.patch.object(auth, "PBKDF2_ITERATIONS", NEW_ROUNDS):
            token, _csrf, user = auth.login(conn, "alice", PASSWORD, 3600)
        self.assertTrue(token)
        self.assertEqual(user["username"], "alice")
        upgraded = conn.execute("SELECT pw_hash FROM users WHERE username = 'alice'").fetchone()[0]
        self.assertEqual(_rounds(upgraded), NEW_ROUNDS)
        self.assertNotEqual(upgraded, stored)
        self.assertTrue(auth.verify_password(PASSWORD, upgraded))

    def test_wrong_password_does_not_upgrade(self):
        conn = memory_db()
        self.addCleanup(conn.close)
        stored = auth.hash_password(PASSWORD, OLD_ROUNDS)
        conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)",
            ("alice", stored, "analyst", now_iso()),
        )
        with mock.patch.object(auth, "PBKDF2_ITERATIONS", NEW_ROUNDS):
            with self.assertRaises(AuthError):
                auth.login(conn, "alice", "wrong-password-xx", 3600)
        current = conn.execute("SELECT pw_hash FROM users WHERE username = 'alice'").fetchone()[0]
        self.assertEqual(current, stored)
        self.assertEqual(_rounds(current), OLD_ROUNDS)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
