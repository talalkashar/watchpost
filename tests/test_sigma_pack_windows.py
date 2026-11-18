"""Windows Sigma pack: each example loads, maps one catalog technique, fires on its attack event, and ignores look-alikes."""

import unittest
from pathlib import Path

from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "windows"


def ev(**fields):
    return {"id": 1, "ts": "2026-11-18T15:00:00+00:00", **fields}


# One malicious list and one benign list per file. Filenames are the whole pack.
CASES = {
    "privileged_password_guessing.yml": {
        "rule_id": "sigma_windows_privileged_password_guessing",
        "technique": "T1110.001",
        "severity": "high",
        "malicious": [
            ev(event_type="auth_failure", user="Administrator", src_ip="203.0.113.44",
               host="dc01.corp.example", message="An account failed to log on."),
            ev(event_type="auth_failure", user="krbtgt", src_ip="2001:db8::44",
               host="dc01.corp.example", message="An account failed to log on."),
        ],
        "benign": [
            ev(event_type="auth_failure", user="Administrator", src_ip="10.8.0.14",
               host="dc01.corp.example", message="An account failed to log on."),
            ev(event_type="auth_failure", user="jsmith", src_ip="203.0.113.44",
               host="dc01.corp.example", message="An account failed to log on."),
            ev(event_type="auth_failure", user="Administrator", src_ip="-",
               host="dc01.corp.example", message="An account failed to log on."),
            ev(event_type="auth_success", user="Administrator", src_ip="203.0.113.44",
               host="dc01.corp.example", message="An account was successfully logged on."),
        ],
    },
    "password_spray_unknown_user.yml": {
        "rule_id": "sigma_windows_password_spray_unknown_user",
        "technique": "T1110.003",
        "severity": "high",
        "malicious": [
            ev(event_type="auth_failure", user="nina.voss", src_ip="198.51.100.23", host="dc01.corp.example",
               message="Logon Type: 3 Status: 0xC000006D Sub Status: 0xC0000064"),
        ],
        "benign": [
            ev(event_type="auth_failure", user="nina.voss", src_ip="198.51.100.23", host="dc01.corp.example",
               message="Logon Type: 3 Status: 0xC000006D Sub Status: 0xC000006A"),
            ev(event_type="auth_failure", user="nina.voss", src_ip="192.168.5.5", host="dc01.corp.example",
               message="Logon Type: 3 Status: 0xC000006D Sub Status: 0xC0000064"),
            ev(event_type="auth_failure", user="nina.voss", src_ip="-", host="dc01.corp.example",
               message="Sub Status: 0xC0000064"),
        ],
    },
    "external_rdp_logon.yml": {
        "rule_id": "sigma_windows_external_remote_desktop_logon",
        "technique": "T1133",
        "severity": "high",
        "malicious": [
            ev(event_type="auth_success", user="jsmith", src_ip="203.0.113.8", host="jump01",
               message="An account was successfully logged on. Logon Type: 10"),
            ev(event_type="auth_success", user="jsmith", src_ip="198.51.100.40", host="jump01",
               dest_port=3389, message="An account was successfully logged on."),
        ],
        "benign": [
            ev(event_type="auth_success", user="jsmith", src_ip="203.0.113.8", host="jump01",
               message="An account was successfully logged on. Logon Type: 3"),
            ev(event_type="auth_success", user="jsmith", src_ip="10.1.1.8", host="jump01",
               message="An account was successfully logged on. Logon Type: 10"),
            ev(event_type="auth_failure", user="jsmith", src_ip="203.0.113.8", host="jump01",
               message="An account failed to log on. Logon Type: 10"),
        ],
    },
    "local_admin_network_logon.yml": {
        "rule_id": "sigma_windows_local_administrator_network_logon",
        "technique": "T1078.003",
        "severity": "high",
        "malicious": [
            ev(event_type="auth_success", user="Administrator", src_ip="10.2.3.4", host="fileserver",
               message="An account was successfully logged on. Logon Type: 3"),
        ],
        "benign": [
            ev(event_type="auth_success", user="Administrator", src_ip="10.2.3.4", host="fileserver",
               message="An account was successfully logged on. Logon Type: 2"),
            ev(event_type="auth_success", user="jsmith", src_ip="10.2.3.4", host="fileserver",
               message="An account was successfully logged on. Logon Type: 3"),
            ev(event_type="auth_success", user="Administrator", src_ip="10.2.3.4", host="fileserver",
               message="An account was successfully logged on. Logon Type: 10"),
        ],
    },
    "port_scan_tool.yml": {
        "rule_id": "sigma_windows_port_scan_tool_started",
        "technique": "T1046",
        "severity": "medium",
        "malicious": [
            ev(event_type="process_start", user="mallory", host="wrk-01",
               message=r"C:\Tools\nmap.exe -sS -p 22,80,445 198.51.100.0/24"),
            ev(event_type="process_start", user="mallory", host="wrk-01",
               message='powershell.exe -Command "Test-NetConnection 10.0.0.8 -Port 445"'),
        ],
        "benign": [
            ev(event_type="process_start", user="SYSTEM", host="wrk-01",
               message=r"C:\Windows\System32\svchost.exe -k netsvcs"),
            ev(event_type="process_start", user="jsmith", host="wrk-01",
               message='powershell.exe -Command "Get-Process"'),
            ev(event_type="web_request", host="mail01", src_ip="203.0.113.10",
               message="GET /nmap.exe HTTP/1.1"),
        ],
    },
    "security_log_tampering.yml": {
        "rule_id": "sigma_windows_security_log_tampering",
        "technique": "T1562.006",
        "severity": "critical",
        "malicious": [
            ev(event_type="process_start", user="mallory", host="dc01",
               message=r"C:\Windows\System32\wevtutil.exe cl Security"),
            ev(event_type="other", host="dc01", message="The audit log was cleared."),
            ev(event_type="process_start", user="mallory", host="dc01",
               message="wevtutil sl Security /e:false"),
            ev(event_type="process_start", user="mallory", host="dc01",
               message=r'auditpol /set /category:"Account Logon" /success:disable /failure:disable'),
        ],
        "benign": [
            ev(event_type="process_start", user="jsmith", host="dc01",
               message=r"C:\Windows\System32\wevtutil.exe qe Security /c:5 /rd:true"),
            ev(event_type="process_start", user="jsmith", host="dc01",
               message="auditpol /set /category:Logon /success:enable"),
            ev(event_type="process_start", user="jsmith", host="dc01",
               message="wevtutil sl Security /e:true"),
        ],
    },
    "external_smb_connection.yml": {
        "rule_id": "sigma_windows_smb_to_external_host",
        "technique": "T1048",
        "severity": "high",
        "malicious": [
            ev(event_type="network_connection", user="mallory", host="wrk-01",
               dest_ip="203.0.113.77", dest_port=445, message="SMB Tree Connect"),
            ev(event_type="network_connection", user="mallory", host="wrk-01",
               dest_ip="2001:db8::77", dest_port=139, message="SMB Tree Connect"),
        ],
        "benign": [
            ev(event_type="network_connection", user="jsmith", host="wrk-01",
               dest_ip="10.0.0.20", dest_port=445, message="SMB Tree Connect"),
            ev(event_type="network_connection", user="jsmith", host="wrk-01",
               dest_ip="203.0.113.77", dest_port=443, message="HTTPS"),
            ev(event_type="network_connection", user="jsmith", host="wrk-01",
               dest_ip="-", dest_port=445, message="SMB Tree Connect"),
            ev(event_type="fw_allow", host="edge", dest_ip="203.0.113.77", dest_port=445,
               message="allow smb"),
        ],
    },
    "exchange_exploit_request.yml": {
        "rule_id": "sigma_windows_exchange_exploit_request",
        "technique": "T1190",
        "severity": "high",
        "malicious": [
            ev(event_type="web_request", host="mail01", src_ip="203.0.113.10", dest_port=443,
               message="GET /autodiscover/autodiscover.json?@evil.example/owa/?&Email=autodiscover/autodiscover.json%3f@evil.example HTTP/1.1"),
            ev(event_type="web_error", host="mail01", src_ip="203.0.113.10", dest_port=443,
               message="GET /ecp/default.flt HTTP/1.1"),
        ],
        "benign": [
            ev(event_type="web_request", host="mail01", src_ip="203.0.113.10", dest_port=443,
               message="GET /autodiscover/autodiscover.json?Email=ada@corp.example&Protocol=Autodiscoverv1 HTTP/1.1"),
            ev(event_type="web_request", host="mail01", src_ip="203.0.113.10", dest_port=443,
               message="GET /owa/auth/logon.aspx HTTP/1.1"),
            ev(event_type="process_start", user="analyst", host="wrk-01",
               message="curl https://mail01/autodiscover/autodiscover.json?@evil.example"),
        ],
    },
}


class WindowsSigmaPackTests(unittest.TestCase):
    def test_eight_rules_load_match_and_spare_benign(self):
        files = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(files, sorted(CASES))
        for name, case in CASES.items():
            with self.subTest(rule=name):
                compiled = sigma.compile_rule((PACK / name).read_text())
                self.assertEqual(compiled["logsource"].get("product"), "windows")
                self.assertEqual(compiled["rule_id"], case["rule_id"])
                self.assertEqual(compiled["severity"], case["severity"])
                self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])
                params = compiled["params"]
                for event in case["malicious"]:
                    self.assertTrue(sigma.matches(params, event), event)
                    self.assertEqual(len(sigma.run([event], params)), 1)
                for event in case["benign"]:
                    self.assertFalse(sigma.matches(params, event), event)
                    self.assertEqual(sigma.run([event], params), [])


if __name__ == "__main__":
    unittest.main()
