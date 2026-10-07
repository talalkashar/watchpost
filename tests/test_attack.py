import unittest

from watchpost import attack, geo, rules


class CatalogTests(unittest.TestCase):
    def test_every_rule_technique_is_in_the_catalog(self):
        tactic_names = {t["name"] for t in attack.tactics()}
        for rule in rules.DEFAULT_RULES:
            for t in rule["techniques"]:
                with self.subTest(rule=rule["id"], technique=t["id"]):
                    self.assertEqual(attack.technique(t["id"]), t)
                    self.assertIn(t["tactic"], tactic_names)

    def test_catalog_only_holds_used_techniques(self):
        used = {t["id"] for r in rules.DEFAULT_RULES for t in r["techniques"]}
        self.assertEqual(set(attack.TECHNIQUES), used)
        self.assertTrue(15 <= len(attack.TECHNIQUES) <= 25)
        with self.assertRaises(KeyError):
            attack.technique("T9999")

    def test_tactic_order(self):
        names = [t["name"] for t in attack.tactics()]
        self.assertEqual((names[0], names[-1], len(names)), ("Reconnaissance", "Impact", 14))
        self.assertEqual(attack.tactic_order(["Exfiltration", "Reconnaissance", "Credential Access", "Exfiltration"]),
                         ["Reconnaissance", "Credential Access", "Exfiltration"])

    def test_coverage(self):
        rule_list = [{**r, "enabled": r["id"] != "web_scanner"} for r in rules.DEFAULT_RULES]
        result = attack.coverage(rule_list, {"brute_force_ip": 3, "success_after_failures": 2})
        by_id = {t["id"]: t for t in result["techniques"]}
        self.assertEqual(len(by_id), len(attack.TECHNIQUES))
        self.assertEqual(by_id["T1110.001"]["hits"], 3)
        self.assertEqual(by_id["T1110"]["hits"], 2)  # success_after_failures also maps to T1110
        self.assertEqual({r["id"] for r in by_id["T1078"]["rules"]},
                         {"success_after_failures", "impossible_geo_login", "privilege_escalation_after_login"})
        self.assertFalse(by_id["T1595.003"]["covered"])  # only the disabled web_scanner covers it
        self.assertEqual(result["summary"]["techniques"], len(attack.TECHNIQUES))


class NavigatorLayerTests(unittest.TestCase):
    def layer(self, hits):
        rule_list = [{**r, "enabled": r["id"] != "web_scanner"} for r in rules.DEFAULT_RULES]
        return attack.navigator_layer(attack.coverage(rule_list, hits))

    def test_layer_follows_the_navigator_format(self):
        layer = self.layer({"brute_force_ip": 3, "success_after_failures": 2})
        self.assertEqual(set(layer), {"name", "versions", "domain", "description", "techniques", "gradient"})
        self.assertEqual(layer["domain"], "enterprise-attack")
        # The static table states no ATT&CK release, so the layer claims none: only the layer format version.
        self.assertEqual(layer["versions"], {"layer": "4.5"})
        self.assertIn("synthetic demo data", layer["description"].lower())
        self.assertEqual(layer["gradient"]["minValue"], 0)
        self.assertEqual(layer["gradient"]["maxValue"], 3)
        self.assertGreaterEqual(len(layer["gradient"]["colors"]), 2)
        for t in layer["techniques"]:
            with self.subTest(technique=t["techniqueID"]):
                self.assertEqual(set(t), {"techniqueID", "tactic", "score", "comment"})
                self.assertRegex(t["tactic"], r"^[a-z]+(-[a-z]+)*$")

    def test_one_entry_per_covered_technique_with_hits_and_rule_names(self):
        by_id = {t["techniqueID"]: t for t in self.layer({"brute_force_ip": 3, "success_after_failures": 2})["techniques"]}
        covered = {t["id"] for r in rules.DEFAULT_RULES if r["id"] != "web_scanner" for t in r["techniques"]}
        self.assertEqual(set(by_id), covered)
        self.assertNotIn("T1595.003", by_id)  # only the disabled web_scanner maps to it
        self.assertEqual((by_id["T1110.001"]["score"], by_id["T1110.001"]["tactic"]), (3, "credential-access"))
        self.assertEqual(by_id["T1110"]["score"], 2)
        self.assertEqual(by_id["T1046"]["score"], 0)
        for rule_id in ("success_after_failures", "impossible_geo_login", "privilege_escalation_after_login"):
            self.assertIn(rule_id, by_id["T1078"]["comment"])
        self.assertEqual(self.layer({})["gradient"]["maxValue"], 1)  # no alerts yet: still a valid range


class GeoTests(unittest.TestCase):
    def test_documentation_and_private_ranges_are_synthetic(self):
        for ip in ["192.0.2.77", "198.51.100.140", "203.0.113.150", "10.0.1.24", "172.16.5.5", "192.168.1.1"]:
            with self.subTest(ip=ip):
                where = geo.locate(ip)
                self.assertEqual(set(where), {"city", "lat", "lon", "synthetic"})
                self.assertTrue(where["synthetic"])

    def test_other_addresses_are_never_guessed(self):
        for ip in ["8.8.8.8", "2001:db8::1", "not-an-ip", None, ""]:
            with self.subTest(ip=ip):
                self.assertIsNone(geo.locate(ip))

    def test_distance(self):
        hq, far = geo.locate("10.0.0.1"), geo.locate("203.0.113.150")
        self.assertEqual(geo.distance_km(hq, hq), 0)
        self.assertGreater(geo.distance_km(hq, far), 8000)


if __name__ == "__main__":
    unittest.main()
