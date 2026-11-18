"""Edge cases for watchpost.attack that tests/test_attack.py does not assert."""

import unittest

from watchpost import attack


class TacticRankTests(unittest.TestCase):
    def test_known_tactics_rank_in_kill_chain_and_unknowns_sort_last(self):
        last = len(attack.TACTICS)
        self.assertEqual(attack.tactic_rank("Reconnaissance"), 0)
        self.assertEqual(attack.tactic_rank("Command and Control"), 11)
        self.assertEqual(attack.tactic_rank("Impact"), last - 1)
        # Case, blanks, and names outside the catalog share one sentinel past the last tactic.
        self.assertEqual(attack.tactic_rank("impact"), last)
        self.assertEqual(attack.tactic_rank(""), last)
        self.assertEqual(attack.tactic_rank("not a tactic"), last)


class TacticOrderTests(unittest.TestCase):
    def test_empty_input_is_empty(self):
        self.assertEqual(attack.tactic_order([]), [])
        self.assertEqual(attack.tactic_order(()), [])

    def test_unknowns_follow_the_kill_chain_and_sort_by_name(self):
        # Alphabetically Impact and "" would lead; kill-chain rank has to win, then the name.
        self.assertEqual(
            attack.tactic_order(["impact", "Collection", "nope", "Impact", "aaa", "Initial Access", "nope", ""]),
            ["Initial Access", "Collection", "Impact", "", "aaa", "impact", "nope"],
        )


class CoverageEdgeTests(unittest.TestCase):
    def test_no_rules_leaves_every_technique_uncovered_in_catalog_order(self):
        result = attack.coverage([], {})
        ids = [t["id"] for t in result["techniques"]]
        self.assertEqual(result["tactics"], attack.tactics())
        self.assertEqual(ids, sorted(ids, key=lambda i: (attack.tactic_rank(attack.TECHNIQUES[i][1]), i)))
        self.assertEqual(ids[0], "T1595.001")
        self.assertLess(ids.index("T1078"), ids.index("T1078.003"))
        self.assertLess(ids.index("T1110"), ids.index("T1110.001"))
        self.assertLess(ids.index("T1530"), ids.index("T1048"))
        self.assertTrue(all(t["rules"] == [] and t["hits"] == 0 and t["covered"] is False
                            for t in result["techniques"]))
        self.assertEqual(result["summary"], {"techniques": len(ids), "covered": 0, "with_hits": 0})

    def test_unknown_techniques_are_skipped_and_hits_follow_rule_order(self):
        techniques = [{"id": "T1048"}, {"id": "T9999"}, {"id": ""}, {"id": "T1567"}]
        rules = [
            {"id": "z", "name": "Zed", "enabled": 0, "techniques": techniques},
            {"id": "a", "name": "Ay", "enabled": 1, "techniques": [{"id": "T1048"}, {"id": "t1048"}]},
            {"id": "m", "name": "Em", "enabled": False},
            {"id": "n", "name": "En", "enabled": True, "techniques": None},
        ]
        hits = {"z": 4, "unused": 100}
        result = attack.coverage(rules, hits)
        by_id = {t["id"]: t for t in result["techniques"]}

        exfil = by_id["T1048"]
        self.assertEqual([r["id"] for r in exfil["rules"]], ["z", "a"])
        self.assertIs(exfil["rules"][0]["enabled"], False)
        self.assertIs(exfil["rules"][1]["enabled"], True)
        self.assertEqual([r["hits"] for r in exfil["rules"]], [4, 0])
        self.assertEqual(exfil["hits"], 4)
        self.assertIs(exfil["covered"], True)

        web = by_id["T1567"]
        self.assertEqual([r["id"] for r in web["rules"]], ["z"])
        self.assertEqual(web["hits"], 4)
        self.assertIs(web["covered"], False)

        self.assertEqual(by_id["T1110"]["rules"], [])
        self.assertEqual(result["summary"]["covered"], 1)
        self.assertEqual(result["summary"]["with_hits"], 2)
        self.assertEqual(techniques, [{"id": "T1048"}, {"id": "T9999"}, {"id": ""}, {"id": "T1567"}])
        self.assertEqual(hits, {"z": 4, "unused": 100})
        self.assertNotIn("covered", rules[0])


class MappedWhyTests(unittest.TestCase):
    def test_no_enabled_rule_returns_none(self):
        scenarios = {"bare": {"malicious": True, "techniques": []}}
        self.assertIsNone(attack.mapped_why("T1190", [], scenarios))
        self.assertIsNone(attack.mapped_why("T1190", [
            {"id": "off", "enabled": False, "detected": ["bare"]},
            {"id": "also", "detected": ["bare"]},
        ], scenarios))

    def test_clauses_keep_order_drop_unknowns_and_collapse_duplicates(self):
        scenarios = {
            "bare": {"malicious": True, "techniques": []},
            "shown": {"malicious": True, "techniques": ["T1046", "T1110"]},
            "calm": {"malicious": False, "techniques": ["T1567"]},
            "nightly": {"malicious": False, "techniques": []},
        }
        rules = [
            {"id": "one", "enabled": True, "detected": ["ghost", "bare", "bare"]},
            {"id": "one", "enabled": True, "detected": ["bare"]},
            {"id": "two", "enabled": True, "detected": ["shown", "calm"]},
            {"id": "three", "enabled": True, "detected": ["nightly", "calm"]},
            {"id": "four", "enabled": True, "detected": None},
            {"id": "off", "enabled": 0, "detected": ["shown"]},
        ]
        self.assertEqual(
            attack.mapped_why("T1190", rules, scenarios),
            "one detects bare, which is not tagged with it, not T1190; "
            "two detects shown, which exercises T1046, T1110, not T1190; "
            "three fires only on benign scenario(s) (nightly, calm), not a labeled attack; "
            "four detects no labeled scenario.",
        )


class EvidenceEdgeTests(unittest.TestCase):
    def test_later_lab_row_wins_and_only_enabled_rules_prove(self):
        rules = [
            {"id": "guess", "name": "Guess", "enabled": True,
             "techniques": [{"id": "T1110.001"}, {"id": "T1110"}]},
            {"id": "off", "name": "Off", "enabled": False, "techniques": [{"id": "T1110.001"}]},
            {"id": "bare", "name": "Bare", "enabled": True, "techniques": [{"id": "T1046"}]},
        ]
        cov = attack.coverage(rules, {"guess": 2, "off": 8})
        scenarios = {
            "zeta": {"malicious": True, "techniques": ["T1110.001"]},
            "alpha": {"malicious": True, "techniques": ["T1110.001"]},
            "side": {"malicious": True, "techniques": ["T1046"]},
        }
        lab = [
            {"rule_id": "guess", "verdict": "stale", "detected": ["side"],
             "lookalikes_fired": ["old"], "other_benign_fired": ["older"]},
            {"rule_id": "guess", "verdict": "noisy",
             "detected": ["zeta", "not-in-scenarios", "alpha"],
             "lookalikes_tested": ["twin"], "lookalikes_fired": ["fp"],
             "other_benign_fired": ["nightly"]},
            {"rule_id": "off", "verdict": "disabled", "detected": ["alpha", "zeta"],
             "lookalikes_fired": ["x"], "other_benign_fired": ["y"]},
        ]
        result = attack.evidence(cov, lab, scenarios)
        by_id = {t["id"]: t for t in result["techniques"]}

        guessing = by_id["T1110.001"]
        self.assertEqual((guessing["level"], guessing["covered"], guessing["scenarios"], guessing["hits"]),
                         ("validated", True, ["alpha", "zeta"], 10))
        by_rule = {r["id"]: r for r in guessing["rules"]}
        self.assertEqual(by_rule["guess"]["verdict"], "noisy")
        self.assertEqual(by_rule["guess"]["proves"], ["alpha", "zeta"])
        self.assertEqual(by_rule["guess"]["lookalikes_tested"], ["twin"])
        self.assertEqual(by_rule["guess"]["lookalikes_fired"], ["fp", "nightly"])
        self.assertEqual(by_rule["guess"]["hits"], 2)
        self.assertNotIn("detected", by_rule["guess"])
        self.assertEqual(by_rule["off"]["proves"], [])
        self.assertEqual(by_rule["off"]["lookalikes_fired"], ["x", "y"])
        self.assertEqual(by_rule["off"]["hits"], 8)

        parent = by_id["T1110"]
        self.assertEqual((parent["level"], parent["scenarios"]), ("mapped", []))
        self.assertEqual(
            parent["why"],
            "guess detects zeta, which exercises T1110.001, not T1110; "
            "guess detects alpha, which exercises T1110.001, not T1110.",
        )
        self.assertNotIn("side", parent["why"])
        self.assertNotIn("not-in-scenarios", parent["why"])

        bare = by_id["T1046"]
        self.assertEqual(bare["level"], "mapped")
        self.assertEqual(bare["rules"][0]["verdict"], None)
        self.assertEqual(bare["rules"][0]["proves"], [])
        self.assertEqual(bare["rules"][0]["lookalikes_fired"], [])
        self.assertEqual(bare["rules"][0]["lookalikes_tested"], [])


if __name__ == "__main__":
    unittest.main()
