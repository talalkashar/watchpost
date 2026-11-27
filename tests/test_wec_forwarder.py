"""The PowerShell forwarder for a Windows Event Collector (scripts/wec_forwarder.ps1).

Two kinds of check. The static ones always run: the script must stay in step with the Python collector and
must not use syntax that Windows PowerShell 5.1 lacks. The live one runs only where PowerShell is installed:
it starts a Watchpost server, lets tests/wec_forwarder_check.ps1 drive the script against a stand-in for
Get-WinEvent, and then checks what was stored. Set WATCHPOST_PWSH to run PowerShell some other way, such as
in a container: the command is run from the repository root.

Neither proves anything about a real Windows host. All event data is synthetic.
"""

import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import unittest
from pathlib import Path

from .helpers import ServerTestCase

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "wec_forwarder.ps1"
_spec = importlib.util.spec_from_file_location("wef_collector", ROOT / "scripts" / "wef_collector.py")
wef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wef)

PWSH = shlex.split(os.environ.get("WATCHPOST_PWSH", "")) or ([shutil.which("pwsh")] if shutil.which("pwsh") else None)


def _list(source, name):
    """The strings of a PowerShell array assigned to $name."""
    body = re.search(rf"\${name} = @\((.*?)\n?\)", source, re.S).group(1)
    return re.findall(r"'([^']*)'", body)


class StaticTests(unittest.TestCase):
    def setUp(self):
        self.source = SCRIPT.read_text()

    def test_reserved_names_match_the_python_collector(self):
        self.assertEqual(set(_list(self.source, "ReservedFields")), set(wef.RESERVED_FIELDS))
        self.assertEqual(set(_list(self.source, "WindowsFields")), set(wef.WINDOWS_FIELDS))
        self.assertEqual(sorted(int(n) for n in re.search(r"\$SkipStatuses = ([\d, ]+)", self.source).group(1).split(",")),
                         sorted(wef.SKIP_STATUSES))
        for name, value in (("MaxDataFields", wef.MAX_DATA_FIELDS), ("MaxValue", wef.MAX_VALUE)):
            self.assertIn(f"${name} = {value}\n", self.source)

    def test_it_stays_within_windows_powershell_5_1(self):
        code = "\n".join(line for line in self.source.split("#>", 1)[1].splitlines() if not line.strip().startswith("#"))
        for newer in ("??", "?.", "&&", "||", "-SkipCertificateCheck", "-SkipHttpErrorCheck", "ForEach-Object -Parallel",
                      "-AsHashtable", "Join-String"):
            self.assertNotIn(newer, code, f"{newer} needs PowerShell 7")
        self.assertNotRegex(code, r"\?\s*[^:\n]+\s:\s", "the ?: operator needs PowerShell 7")
        self.assertNotRegex(code, r"\$event\b", "$event is an automatic variable")

    def test_the_token_never_comes_from_the_command_line_and_the_label_is_there(self):
        parameters = re.search(r"\[CmdletBinding\(\)\]\s*param\((.*?)\n\)", self.source, re.S).group(1)
        self.assertNotRegex(parameters, r"(?i)\$token\b")
        self.assertIn("$TokenPath", parameters)
        self.assertIn("EXPERIMENTAL", self.source)
        self.assertIn("It has not been run on Windows", self.source)
        self.assertNotIn("Write-Output", self.source.split("#>", 1)[1].replace("Write-Host, not Write-Output", ""))


@unittest.skipUnless(PWSH, "PowerShell is not installed (set WATCHPOST_PWSH to a command that runs it)")
class LiveTests(ServerTestCase):
    def test_the_forwarder_against_a_stand_in_log_and_a_real_server(self):
        status, token, _ = self.client("admin").post("/api/tokens", {"name": "wec"})
        self.assertEqual(status, 201)
        done = subprocess.run([*PWSH, "-NoLogo", "-NoProfile", "-File", "tests/wec_forwarder_check.ps1", "-Url", self.base],
                              cwd=ROOT, env={**os.environ, "WATCHPOST_TOKEN": token["token"]}, capture_output=True, text=True,
                              timeout=300)
        output = done.stdout + done.stderr
        self.assertEqual(done.returncode, 0, output)
        self.assertIn("WEC FORWARDER CHECK OK", output)
        self.assertNotIn("FAIL", output)
        self.assertNotIn(token["token"], output)

        analyst = self.client("analyst")

        def stored(source):
            return analyst.get(f"/api/events?source={source}&limit=200")[1]["events"]

        live = stored("wec")
        self.assertEqual(len(live), 9, [e["message"] for e in live])       # 2 + 5 + 1 + 1; the refused and the unreadable are not there
        self.assertEqual({e["event_type"] for e in live}, {"auth_failure", "auth_success"})
        self.assertEqual({(e["host"], e["user"], e["src_ip"]) for e in live}, {("dc01.corp.example", "jsmith", "198.51.100.60")})
        self.assertEqual(len(stored("wec-replay")), 12)                     # thirteen sent, the one dated 2999 refused by Watchpost
        self.assertEqual([(e["event_type"], e["user"]) for e in stored("wec-main")], [("auth_success", "jsmith")])


if __name__ == "__main__":
    unittest.main()
