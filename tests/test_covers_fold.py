"""An unknown list parameter matches an event account on the ASCII fold.

list_entry already stores ÉRIN as Érin. covers must use that same fold.
Event user ÉRIN matches. Event user érin does not. covers does not call
str.lower(). The five known lists stay as they are.
"""

import inspect
import unittest
from pathlib import Path

from watchpost import rules

API = Path(__file__).resolve().parent.parent / "docs" / "API.md"
REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md"


class CoversFoldTests(unittest.TestCase):
    def test_unknown_param_matches_the_ascii_fold(self):
        erin = {rules.list_entry("other_param", "ÉRIN")}
        self.assertEqual(erin, {"Érin"})
        self.assertTrue(rules.covers("other_param", erin, {"user": "ÉRIN"}))
        self.assertFalse(rules.covers("other_param", erin, {"user": "érin"}))
        alice = {rules.list_entry("other_param", "ALICE")}
        self.assertTrue(rules.covers("other_param", alice, {"user": "ALICE"}))
        self.assertTrue(rules.covers("other_param", alice, {"user": "alice"}))
        dotted = "H\u0130GH"
        stored = {rules.list_entry("other_param", dotted)}
        self.assertEqual(stored, {"h\u0130gh"})
        self.assertNotIn("\u0307", rules._ascii_fold(dotted))
        self.assertTrue(rules.covers("other_param", stored, {"user": dotted}))
        self.assertFalse(rules.covers("other_param", stored, {"user": "high"}))

    def test_the_five_lists_stay(self):
        self.assertTrue(rules.covers(
            "ignore_ips", {rules.list_entry("ignore_ips", "2001:DB8::1")},
            {"src_ip": "2001:DB8::1"}))
        self.assertTrue(rules.covers(
            "ignore_users", {rules.list_entry("ignore_users", "ALICE")}, {"user": "alice"}))
        self.assertFalse(rules.covers(
            "ignore_users", {rules.list_entry("ignore_users", "ÉRIN")}, {"user": "érin"}))
        self.assertTrue(rules.covers(
            "privileged_users", {rules.list_entry("privileged_users", "ALICE")}, {"user": "ALICE"}))
        self.assertTrue(rules.covers(
            "sanctioned_services", {rules.list_entry("sanctioned_services", "MAIL.EXAMPLE")},
            {"message": "GetObject on mail.example"}))
        self.assertFalse(rules.covers(
            "sanctioned_services", {rules.list_entry("sanctioned_services", "Érin.example")},
            {"message": "GetObject on érin.example"}))
        self.assertTrue(rules.covers(
            "logging_actions", {rules.list_entry("logging_actions", "GET")},
            {"message": "Get on cloudtrail.amazonaws.com"}))
        self.assertFalse(rules.covers(
            "logging_actions", {rules.list_entry("logging_actions", "GÉT")},
            {"message": "gét on cloudtrail.amazonaws.com"}))

    def test_covers_does_not_call_lower(self):
        source = inspect.getsource(rules.covers)
        self.assertNotIn(".lower(", source.replace("str.lower()", ""))
        self.assertNotIn("casefold", source)

    def test_the_docs_name_the_match(self):
        sentence = (
            "An unknown list parameter matches an event account with that same fold. "
            "Event user `ÉRIN` matches the stored entry and event user `érin` does not.")
        self.assertIn(sentence, API.read_text())
        self.assertIn(sentence, REFERENCE.read_text())
        self.assertIn(
            "A list parameter outside `ignore_ips`, `ignore_users`, `privileged_users`, "
            "`sanctioned_services`, and `logging_actions` folds ASCII letters only. "
            "`ÉRIN` is `Érin` and is not `érin`. `ALICE` is `alice`.",
            API.read_text())
        self.assertIn(
            "A parameter outside those five folds ASCII letters only. "
            "`ÉRIN` is `Érin` and is not `érin`. `ALICE` is `alice`.",
            REFERENCE.read_text())
