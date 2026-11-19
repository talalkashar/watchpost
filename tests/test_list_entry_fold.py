"""An unknown list parameter folds ASCII letters only.

The five known lists stay as they are. ÉRIN on an unknown parameter is Érin
and is not érin. list_entry does not call str.lower().
"""

import inspect
import unittest
from pathlib import Path

from watchpost import rules

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"


class ListEntryFoldTests(unittest.TestCase):
    def test_unknown_param_folds_ascii_letters_only(self):
        self.assertEqual(rules.list_entry("other_param", "ÉRIN"), "Érin")
        self.assertNotEqual(rules.list_entry("other_param", "ÉRIN"), "érin")
        self.assertEqual(rules.list_entry("other_param", "ALICE"), "alice")
        self.assertEqual(rules.list_entry("other_param", "josé"), "josé")
        dotted = "H\u0130GH"
        stored = rules.list_entry("other_param", dotted)
        self.assertEqual(stored, "h\u0130gh")
        self.assertNotIn("\u0307", stored)
        self.assertNotEqual(stored, "high")

    def test_the_five_lists_stay(self):
        self.assertEqual(rules.list_entry("ignore_ips", "2001:DB8::1"), "2001:db8::1")
        self.assertEqual(rules.list_entry("ignore_ips", "not-an-ip"), "not-an-ip")
        self.assertEqual(rules.list_entry("ignore_users", "ÉRIN"), "Érin")
        self.assertEqual(rules.list_entry("ignore_users", "ALICE"), "alice")
        self.assertEqual(rules.list_entry("privileged_users", "ÉRIN"), "Érin")
        self.assertEqual(rules.list_entry("sanctioned_services", ".ÉRIN.EXAMPLE"), "Érin.example")
        self.assertEqual(rules.list_entry("logging_actions", "GET"), "get")
        self.assertEqual(rules.list_entry("logging_actions", "ÉRIN"), "Érin")

    def test_list_entry_does_not_call_lower(self):
        source = inspect.getsource(rules.list_entry)
        self.assertNotIn(".lower(", source.replace("str.lower()", ""))
        self.assertNotIn("casefold", source)

    def test_the_docs_name_the_fold(self):
        sentence = "A parameter outside those five folds ASCII letters only."
        api = (
            "A list parameter outside `ignore_ips`, `ignore_users`, `privileged_users`, "
            "`sanctioned_services`, and `logging_actions` folds ASCII letters only. "
            "`ÉRIN` is `Érin` and is not `érin`. `ALICE` is `alice`.")
        self.assertIn(sentence, REFERENCE.read_text())
        self.assertIn("`ÉRIN` is `Érin` and is not `érin`", REFERENCE.read_text())
        self.assertIn(api, API.read_text())
