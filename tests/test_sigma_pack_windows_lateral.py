"""Windows lateral-movement Sigma examples: each rule loads, matches, and spares a benign event."""

import unittest
from pathlib import Path

from watchpost import sigma
from watchpost.attack import TECHNIQUES

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "windows-lateral"

# filename, rule id, sigma id, technique, severity, malicious event, benign events
CASES = [
    (
        "rdp_remote_interactive_logon.yml",
        "sigma_windows_remote_interactive_rdp_logon",
        "53c421d9-06e1-4a73-8501-4a177756d217",
        "T1021.001",
        "medium",
        {"event_type": "auth_success", "user": "alice", "host": "wkstn04.corp.example",
         "src_ip": "10.2.8.40",
         "message": "An account was successfully logged on. Logon Type: 10 Source Network Address: 10.2.8.40"},
        [
            {"event_type": "auth_success", "user": "alice", "host": "wkstn04.corp.example",
             "src_ip": "10.2.8.40",
             "message": "An account was successfully logged on. Logon Type: 2 Interactive"},
            {"event_type": "auth_success", "user": "alice", "host": "wkstn04.corp.example",
             "src_ip": "127.0.0.1",
             "message": "An account was successfully logged on. Logon Type: 10 Source Network Address: 127.0.0.1"},
        ],
    ),
    (
        "admin_share_access.yml",
        "sigma_windows_admin_share_lateral_access",
        "bef36f11-5455-48f3-8d0d-200e6b3bbc1d",
        "T1021.002",
        "high",
        {"event_type": "process_start", "user": "alice", "host": "jump01.corp.example",
         "message": "net.exe use \\\\dc01\\ADMIN$ /user:CORP\\alice"},
        [
            {"event_type": "process_start", "user": "alice", "host": "jump01.corp.example",
             "message": "net.exe use \\\\fileserver\\Finance /user:CORP\\alice"},
        ],
    ),
    (
        "mmc_dcom_remote_execution.yml",
        "sigma_windows_mmc_dcom_remote_execution",
        "23397177-989d-4b3b-8b57-fc369eb489a9",
        "T1021.003",
        "high",
        {"event_type": "process_start", "host": "wkstn04.corp.example",
         "message": "C:\\Windows\\System32\\mmc.exe -Embedding"},
        [
            {"event_type": "process_start", "host": "wkstn04.corp.example",
             "message": "C:\\Windows\\System32\\mmc.exe C:\\Windows\\System32\\compmgmt.msc"},
        ],
    ),
    (
        "winrm_session.yml",
        "sigma_windows_remote_management_winrm_session",
        "d7fac8ee-4a19-4663-8cb5-698ed0c17ee1",
        "T1021.006",
        "medium",
        {"event_type": "network_connection", "src_ip": "10.2.8.40", "dest_ip": "10.2.8.55",
         "dest_port": 5985, "message": "allowed wsman to wkstn04"},
        [
            {"event_type": "network_connection", "src_ip": "10.2.8.40", "dest_ip": "10.2.8.55",
             "dest_port": 443, "message": "allowed https to intranet"},
            {"event_type": "network_connection", "src_ip": "127.0.0.1", "dest_ip": "127.0.0.1",
             "dest_port": 5985, "message": "local winrm"},
        ],
    ),
    (
        "wmi_remote_process.yml",
        "sigma_windows_wmi_remote_process_creation",
        "4b577444-5e45-475a-9e9d-fd17247d63ec",
        "T1047",
        "high",
        {"event_type": "process_start", "user": "alice", "host": "jump01.corp.example",
         "message": "wmic.exe /node:10.2.8.55 /user:CORP\\alice process call create \"cmd.exe /c whoami\""},
        [
            {"event_type": "process_start", "user": "alice", "host": "jump01.corp.example",
             "message": "wmic.exe os get caption"},
        ],
    ),
    (
        "lateral_tool_transfer.yml",
        "sigma_windows_lateral_tool_transfer_to_admin_share",
        "7d96a854-a7b1-4a6f-b6a3-5eb00b151440",
        "T1570",
        "high",
        {"event_type": "process_start", "user": "alice", "host": "jump01.corp.example",
         "message": "cmd.exe /c copy C:\\Users\\Public\\payload.exe \\\\wkstn04\\ADMIN$\\Temp\\payload.exe"},
        [
            {"event_type": "process_start", "user": "alice", "host": "jump01.corp.example",
             "message": "cmd.exe /c copy C:\\tools\\putty.exe C:\\Users\\alice\\Desktop\\putty.exe"},
        ],
    ),
]


class WindowsLateralPackTests(unittest.TestCase):
    def test_six_rules_load_match_and_spare_benign(self):
        on_disk = {path.name for path in PACK.glob("*.yml")}
        self.assertEqual(on_disk, {case[0] for case in CASES})
        seen_ids = set()
        for name, rule_id, sigma_id, technique, severity, malicious, benigns in CASES:
            with self.subTest(rule=name):
                compiled = sigma.compile_rule((PACK / name).read_text())
                self.assertEqual(compiled["rule_id"], rule_id)
                self.assertEqual(compiled["sigma_id"], sigma_id)
                self.assertNotIn(sigma_id, seen_ids)
                seen_ids.add(sigma_id)
                self.assertEqual(compiled["severity"], severity)
                self.assertTrue(sigma.matches(compiled["params"], malicious), compiled["conditions"])
                for benign in benigns:
                    self.assertFalse(sigma.matches(compiled["params"], benign), benign)
                mapped = [item["id"] for item in compiled["techniques"]]
                tag = "attack." + technique.lower()
                if technique in TECHNIQUES:
                    self.assertIn(technique, mapped)
                else:
                    self.assertTrue(any(tag in warning for warning in compiled["warnings"]), compiled["warnings"])

    def test_titles_and_ids_are_unique_in_sigma_examples(self):
        mine = {}
        for path in sorted(PACK.glob("*.yml")):
            doc = sigma.parse_yaml(path.read_text())
            mine[path.name] = (doc["title"], doc["id"])
        titles = [title for title, _ in mine.values()]
        ids = [sigma_id for _, sigma_id in mine.values()]
        self.assertEqual(len(titles), len(set(titles)))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(mine), 6)
        for path in sorted(PACK.parent.rglob("*.yml")):
            if path.parent == PACK:
                continue
            try:
                doc = sigma.parse_yaml(path.read_text())
            except sigma.SigmaError:
                continue
            self.assertNotIn(doc.get("title"), titles, path.name)
            self.assertNotIn(doc.get("id"), ids, path.name)



class WinrmManagementFilterTests(unittest.TestCase):
    def test_listed_management_hosts_do_not_match(self):
        compiled = sigma.compile_rule((PACK / "winrm_session.yml").read_text())
        session = {"event_type": "network_connection", "src_ip": "10.2.8.40", "dest_ip": "10.2.8.55",
                   "dest_port": 5986, "message": "allowed wsman to wkstn04"}
        self.assertTrue(sigma.matches(compiled["params"], session))
        # A configuration-management server listed in filter_management_hosts opens WinRM all day.
        self.assertFalse(sigma.matches(compiled["params"], {**session, "src_ip": "198.18.4.10"}))


if __name__ == "__main__":
    unittest.main()
