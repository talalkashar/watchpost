"""The public quickstart must run on the shipped files without a database on disk."""

import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


class DemoTests(unittest.TestCase):
    def test_launcher_examples(self):
        cases = [
            ([], "19 accepted | 1 rejected | alerts: 2", "brute_force_ip"),
            (["windows"], "8 accepted | 1 rejected | alerts: 1", "success_after_failures"),
            (["firewall"], "24 accepted | 1 rejected | alerts: 2", "firewall_port_sweep"),
        ]
        for args, counts, rule in cases:
            with self.subTest(sample=args), TemporaryDirectory() as tmp:
                db = Path(tmp) / "untouched.db"
                result = subprocess.run([ROOT / "start.sh", "--demo", *args], cwd=tmp,
                                        env={"PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
                                             "SIEM_DB": str(db)}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(counts, result.stdout)
                self.assertIn(rule, result.stdout)
                self.assertFalse(db.exists())
