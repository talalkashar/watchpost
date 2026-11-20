"""Email Sigma examples: each rule loads, maps one catalog technique, and separates hits from benign events."""

import unittest
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma

PACK = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "email"

# SSH failure for a privileged account from a public address. The built-in external-admin example
# matches this shape. None of the email rules may.
UNRELATED = {
    "event_type": "auth_failure",
    "user": "root",
    "src_ip": "203.0.113.5",
    "dest_port": 22,
    "host": "web01",
    "message": "Failed password for root from 203.0.113.5 port 22 ssh2",
}

CASES = [
    {
        "file": "exchange_proxylogon_proxyshell.yml",
        "rule_id": "sigma_exchange_proxylogon_or_proxyshell_ssrf",
        "technique": "T1190",
        "malicious": [
            {
                "event_type": "web_error",
                "src_ip": "203.0.113.10",
                "dest_port": 443,
                "host": "exch01",
                "message": "POST /ecp/y.js Cookie: X-BEResource=exch01.example/EWS/Exchange.asmx?a=~1942062522; -> 500",
            },
            {
                "event_type": "web_request",
                "src_ip": "203.0.113.11",
                "dest_port": 443,
                "host": "exch01",
                "message": "GET /autodiscover/autodiscover.json?@evil.example/mapi/emsmdb?&Email=autodiscover/autodiscover.json%3f@evil.example -> 401",
            },
        ],
        "benign": [
            {
                "event_type": "web_request",
                "src_ip": "203.0.113.12",
                "dest_port": 443,
                "host": "exch01",
                "message": "GET /autodiscover/autodiscover.json?Email=ada@contoso.example&Protocol=ActiveSync -> 200",
            },
            {
                "event_type": "web_request",
                "src_ip": "10.1.1.8",
                "dest_port": 443,
                "host": "exch01",
                "message": "GET /ecp/default.aspx -> 200",
            },
        ],
    },
    {
        "file": "external_mailbox_password_guessing.yml",
        "rule_id": "sigma_external_mailbox_password_guessing",
        "technique": "T1110.001",
        "malicious": [
            {
                "event_type": "auth_failure",
                "user": "ada",
                "src_ip": "203.0.113.8",
                "dest_port": 993,
                "host": "mail01",
                "message": "imap-login: auth failed, 1 attempts: user=<ada>, method=PLAIN",
            },
            {
                "event_type": "auth_failure",
                "user": "ada",
                "src_ip": "2001:db8::8",
                "dest_port": 587,
                "host": "mail01",
                "message": "postfix: SASL LOGIN authentication failed from 2001:db8::8",
            },
        ],
        "benign": [
            {
                "event_type": "auth_failure",
                "user": "ada",
                "src_ip": "10.8.8.8",
                "dest_port": 993,
                "host": "mail01",
                "message": "imap-login: auth failed, 1 attempts: user=<ada>, method=PLAIN",
            },
            {
                "event_type": "auth_failure",
                "user": "ada",
                "src_ip": "fd12:3456::7",
                "dest_port": 993,
                "host": "mail01",
                "message": "imap-login: auth failed, 1 attempts: user=<ada>, method=PLAIN",
            },
            {
                "event_type": "auth_failure",
                "user": "root",
                "src_ip": "203.0.113.8",
                "dest_port": 22,
                "host": "web01",
                "message": "sshd: authentication failed for root",
            },
        ],
    },
    {
        "file": "mail_password_spray_tool.yml",
        "rule_id": "sigma_mail_password_spray_tool",
        "technique": "T1110.003",
        "malicious": [
            {
                "event_type": "web_request",
                "src_ip": "203.0.113.20",
                "dest_port": 443,
                "host": "exch01",
                "message": "POST /owa/auth.owa user=ada@contoso.example User-Agent: MSOLSpray/2.0 -> 401",
            },
            {
                "event_type": "auth_failure",
                "user": "ada",
                "src_ip": "203.0.113.21",
                "host": "exch01",
                "message": "Identity protection password spray against mailbox ada@contoso.example",
            },
        ],
        "benign": [
            {
                "event_type": "web_request",
                "src_ip": "203.0.113.22",
                "dest_port": 443,
                "host": "exch01",
                "message": "GET /owa/auth/logon.aspx -> 200",
            },
            {
                "event_type": "web_request",
                "src_ip": "203.0.113.23",
                "dest_port": 443,
                "host": "intranet",
                "message": "Reviewed the MSOLSpray write-up in the team wiki",
            },
        ],
    },
    {
        "file": "legacy_basic_auth_mailbox_signin.yml",
        "rule_id": "sigma_legacy_basic_auth_mailbox_sign_in",
        "technique": "T1078.004",
        "malicious": [
            {
                "event_type": "auth_success",
                "user": "ada",
                "src_ip": "203.0.113.44",
                "dest_port": 993,
                "host": "outlook.office365.com",
                "message": "Exchange Online IMAP AuthType: Basic authentication succeeded",
            },
        ],
        "benign": [
            {
                "event_type": "auth_success",
                "user": "ada",
                "src_ip": "203.0.113.44",
                "dest_port": 993,
                "host": "outlook.office365.com",
                "message": "Exchange Online IMAP modern authentication succeeded",
            },
            {
                "event_type": "auth_success",
                "user": "copier",
                "src_ip": "10.2.2.40",
                "dest_port": 993,
                "host": "mail01",
                "message": "Exchange Online IMAP AuthType: Basic authentication succeeded",
            },
        ],
    },
    {
        "file": "internal_direct_smtp_to_internet.yml",
        "rule_id": "sigma_internal_host_direct_smtp_to_the_internet",
        "technique": "T1048",
        "malicious": [
            {
                "event_type": "fw_allow",
                "src_ip": "10.4.8.21",
                "dest_ip": "203.0.113.80",
                "dest_port": 25,
                "host": "wrk-21",
                "message": "tcp outbound permitted",
            },
            {
                "event_type": "network_connection",
                "src_ip": "192.168.4.15",
                "dest_ip": "198.51.100.25",
                "dest_port": 587,
                "host": "wrk-15",
                "message": "smtp submission to an external host",
            },
        ],
        "benign": [
            {
                "event_type": "fw_allow",
                "src_ip": "10.4.8.21",
                "dest_ip": "10.1.1.25",
                "dest_port": 25,
                "host": "wrk-21",
                "message": "tcp to the internal mail relay",
            },
            {
                "event_type": "fw_allow",
                "src_ip": "203.0.113.9",
                "dest_ip": "198.51.100.10",
                "dest_port": 25,
                "host": "edge",
                "message": "smtp from the internet",
            },
        ],
    },
    {
        "file": "owa_logon_from_outside.yml",
        "rule_id": "sigma_outlook_web_access_logon_from_outside",
        "technique": "T1133",
        "malicious": [
            {
                "event_type": "auth_success",
                "user": "ceo",
                "src_ip": "198.51.100.40",
                "dest_port": 443,
                "host": "exch01",
                "message": "Outlook Web App logon /owa/auth.owa succeeded",
            },
        ],
        "benign": [
            {
                "event_type": "auth_success",
                "user": "ceo",
                "src_ip": "10.0.5.5",
                "dest_port": 443,
                "host": "exch01",
                "message": "Outlook Web App logon /owa/auth.owa succeeded",
            },
            {
                "event_type": "auth_success",
                "user": "ceo",
                "src_ip": "198.51.100.40",
                "dest_port": 22,
                "host": "jump01",
                "message": "Accepted password for ceo",
            },
        ],
    },
]


def _stamp(event, number):
    return {"id": number, "ts": "2026-11-18T15:00:00+00:00", **event}


class EmailSigmaPackTests(unittest.TestCase):
    def test_pack_is_six_rules(self):
        found = sorted(p.name for p in PACK.glob("*.yml"))
        self.assertEqual(found, sorted(case["file"] for case in CASES))

    def test_each_rule_loads_matches_and_ignores_benign(self):
        self.assertEqual(len(CASES), 6)
        for case in CASES:
            with self.subTest(rule=case["file"]):
                compiled = sigma.compile_rule((PACK / case["file"]).read_text())
                self.assertEqual(compiled["rule_id"], case["rule_id"])
                self.assertNotIn(compiled["rule_id"], rules_mod.RULE_FUNCTIONS)
                self.assertEqual([t["id"] for t in compiled["techniques"]], [case["technique"]])
                params = compiled["params"]
                for event in case["malicious"]:
                    self.assertTrue(sigma.matches(params, event), event["message"])
                    self.assertEqual(len(sigma.run([_stamp(event, 1)], params)), 1)
                for event in case["benign"]:
                    self.assertFalse(sigma.matches(params, event), event["message"])
                    self.assertEqual(sigma.run([_stamp(event, 1)], params), [])
                self.assertFalse(sigma.matches(params, UNRELATED))
                self.assertEqual(sigma.run([_stamp(UNRELATED, 1)], params), [])



class EmailNoiseFilterTests(unittest.TestCase):
    def _compiled(self, name):
        return sigma.compile_rule((PACK / name).read_text())

    def test_owa_from_outside_is_low_and_spares_known_egress(self):
        compiled = self._compiled("owa_logon_from_outside.yml")
        self.assertEqual(compiled["severity"], "low")
        logon = {"event_type": "auth_success", "user": "ceo", "src_ip": "198.51.100.40",
                 "message": "Outlook Web App logon /owa/auth.owa succeeded"}
        self.assertTrue(sigma.matches(compiled["params"], logon))
        self.assertFalse(sigma.matches(compiled["params"], {**logon, "src_ip": "192.0.2.80"}))

    def test_direct_smtp_spares_listed_mail_servers(self):
        compiled = self._compiled("internal_direct_smtp_to_internet.yml")
        workstation = {"event_type": "fw_allow", "src_ip": "10.4.8.21", "dest_ip": "203.0.113.80",
                       "dest_port": 25, "host": "wrk-21", "message": "tcp outbound permitted"}
        self.assertTrue(sigma.matches(compiled["params"], workstation))
        # The mail server delivering to public MX hosts is listed in filter_mail_servers.
        mta = {**workstation, "src_ip": "10.255.255.25", "host": "mta01"}
        self.assertFalse(sigma.matches(compiled["params"], mta))
        self.assertEqual(sigma.run([_stamp(mta, 1)], compiled["params"]), [])
