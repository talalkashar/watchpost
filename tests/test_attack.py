import json
import unittest
from pathlib import Path

from unittest import mock

from watchpost import attack, engine, geo, improve, incidents, rules, sigma, simulate
from watchpost.db import connect, init_schema, now_iso


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
        self.assertEqual((names[0], names[-1], len(names)), ("Reconnaissance", "Impact", 15))
        priv = names.index("Privilege Escalation")
        self.assertEqual(names[priv:priv + 4],
                         ["Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access"])
        self.assertEqual(attack.tactic_order(["Exfiltration", "Reconnaissance", "Credential Access", "Exfiltration"]),
                         ["Reconnaissance", "Credential Access", "Exfiltration"])

    def test_revoked_ids_resolve_to_current_attack(self):
        cloud = {
            "id": "T1685.002",
            "name": "Disable or Modify Tools: Disable or Modify Cloud Log",
            "tactic": "Defense Impairment",
        }
        tools = {"id": "T1685", "name": "Disable or Modify Tools", "tactic": "Defense Impairment"}
        self.assertEqual(attack.technique("T1562.008"), cloud)
        self.assertEqual(attack.technique("T1685.002"), cloud)
        self.assertEqual(attack.technique("T1562.006"), tools)
        self.assertEqual(attack.technique("T1685"), tools)
        self.assertNotIn("T1562.006", attack.TECHNIQUES)
        self.assertNotIn("T1562.008", attack.TECHNIQUES)

    def test_coverage(self):
        rule_list = [{**r, "enabled": r["id"] != "web_scanner"} for r in rules.DEFAULT_RULES]
        result = attack.coverage(rule_list, {"brute_force_ip": 3, "success_after_failures": 2})
        by_id = {t["id"]: t for t in result["techniques"]}
        self.assertEqual(len(by_id), len(attack.TECHNIQUES))
        self.assertEqual(by_id["T1110.001"]["hits"], 3)
        self.assertEqual(by_id["T1110"]["hits"], 2)  # success_after_failures also maps to T1110
        self.assertEqual({r["id"] for r in by_id["T1078"]["rules"]},
                         {"success_after_failures", "impossible_geo_login", "privilege_escalation_after_login",
                          "admin_action_from_new_source"})
        self.assertFalse(by_id["T1595.003"]["covered"])  # only the disabled web_scanner covers it
        self.assertEqual(result["summary"]["techniques"], len(attack.TECHNIQUES))


def rule(rule_id, enabled, *technique_ids):
    return {"id": rule_id, "name": rule_id, "enabled": enabled, "techniques": attack.techniques(*technique_ids)}


def lab_row(rule_id, detected=(), verdict="quiet", fired=()):
    return {"rule_id": rule_id, "verdict": verdict, "detected": list(detected), "lookalikes_tested": ["benign_twin"],
            "lookalikes_fired": list(fired), "other_benign_fired": []}


# Scenario labels as simulate.SCENARIOS carries them: `techniques` names what the events actually show.
SCENARIOS = {
    "guessing": {"malicious": True, "techniques": ["T1110.001"]},
    "probe": {"malicious": True, "techniques": ["T1595.002"]},
    "sweep": {"malicious": True, "techniques": ["T1046"]},
    "copy_out": {"malicious": True, "techniques": ["T1048"]},
    "benign_twin": {"malicious": False, "techniques": ["T1567"]},  # a benign scenario never proves anything
}


class EvidenceTests(unittest.TestCase):
    def evidence(self, rule_list, lab, hits=None):
        return attack.evidence(attack.coverage(rule_list, hits or {}), lab, SCENARIOS)

    def setUp(self):
        rule_list = [
            rule("guess", True, "T1110.001"),
            rule("probe", True, "T1595.002", "T1190"),  # the probe scenario exercises only T1595.002
            rule("sweep", True, "T1046"),               # maps T1046 but detects nothing
            rule("copy", False, "T1048"),               # would detect copy_out, but is disabled
            rule("upload", True, "T1567"),              # fires only on a benign scenario
        ]
        lab = [lab_row("guess", ["guessing"], "noisy", ["benign_twin"]), lab_row("probe", ["probe"]),
               lab_row("sweep", [], "blind"), lab_row("copy", ["copy_out"], "disabled"),
               lab_row("upload", ["benign_twin"])]
        self.result = self.evidence(rule_list, lab, {"guess": 4, "probe": 1})
        self.by_id = {t["id"]: t for t in self.result["techniques"]}

    def test_validated_needs_an_enabled_rule_that_detects_a_labeled_attack_exercising_it(self):
        t = self.by_id["T1110.001"]
        self.assertEqual((t["level"], t["covered"], t["scenarios"], t["hits"]), ("validated", True, ["guessing"], 4))
        self.assertEqual(t["rules"][0]["proves"], ["guessing"])
        self.assertEqual(self.by_id["T1595.002"]["level"], "validated")

    def test_a_mapped_rule_without_a_proving_scenario_is_mapped_not_validated(self):
        # The probe rule detects its scenario, but that scenario does not exercise T1190.
        t = self.by_id["T1190"]
        self.assertEqual((t["level"], t["covered"], t["scenarios"]), ("mapped", False, []))
        self.assertEqual(t["rules"][0]["proves"], [])
        self.assertNotIn("detected", t["rules"][0])
        self.assertEqual(t["why"], "probe detects probe, which exercises T1595.002, not T1190.")
        self.assertEqual(self.by_id["T1046"]["level"], "mapped")  # maps it, detects nothing
        self.assertEqual(self.by_id["T1046"]["why"], "sweep detects no labeled scenario.")

    def test_a_benign_scenario_never_validates(self):
        t = self.by_id["T1567"]
        self.assertEqual(t["level"], "mapped")
        self.assertEqual(t["why"], "upload fires only on benign scenario(s) (benign_twin), not a labeled attack.")

    def test_only_mapped_techniques_carry_a_reason(self):
        self.assertIsNone(self.by_id["T1110.001"]["why"])
        self.assertIsNone(self.by_id["T1048"]["why"])  # disabled
        self.assertIsNone(self.by_id["T1530"]["why"])  # gap

    def test_only_disabled_rules_is_disabled_even_when_the_rule_would_detect(self):
        t = self.by_id["T1048"]
        self.assertEqual((t["level"], t["covered"], t["scenarios"]), ("disabled", False, []))
        self.assertEqual(t["rules"][0]["verdict"], "disabled")

    def test_no_rule_is_a_gap(self):
        t = self.by_id["T1530"]
        self.assertEqual((t["level"], t["rules"], t["covered"]), ("gap", [], False))

    def test_rules_carry_noise_verdicts_and_their_own_hits(self):
        r = self.by_id["T1110.001"]["rules"][0]
        self.assertEqual((r["verdict"], r["lookalikes_fired"], r["lookalikes_tested"], r["hits"]),
                         ("noisy", ["benign_twin"], ["benign_twin"], 4))

    def test_summary_counts_levels_and_never_counts_mapped_as_covered(self):
        summary = self.result["summary"]
        self.assertEqual(summary["levels"], {"validated": 2, "mapped": 3, "disabled": 1,
                                             "gap": len(attack.TECHNIQUES) - 6})
        self.assertEqual(summary["covered"], summary["levels"]["validated"])
        self.assertEqual(summary["techniques"], len(attack.TECHNIQUES))
        self.assertEqual(sum(summary["levels"].values()), summary["techniques"])
        self.assertEqual(summary["with_hits"], 3)  # the probe rule maps two techniques
        self.assertEqual(self.result["levels"], list(attack.LEVELS))

    def test_input_is_not_mutated(self):
        cov = attack.coverage([rule("guess", True, "T1110.001")], {})
        lab = [lab_row("guess", ["guessing"])]
        attack.evidence(cov, lab, SCENARIOS)
        self.assertNotIn("level", cov["techniques"][0])
        self.assertNotIn("proves", lab[0])


class ScenarioTechniqueTests(unittest.TestCase):
    def test_tags_are_honest_and_minimal(self):
        for name, spec in simulate.SCENARIOS.items():
            with self.subTest(scenario=name):
                tags = spec.get("techniques", [])
                if not spec["malicious"]:
                    self.assertEqual(tags, [])
                    continue
                self.assertTrue(tags)
                canonical = {attack.technique(t)["id"] for t in tags}
                mapped = {t["id"] for rid in spec["expected"] for r in rules.DEFAULT_RULES if r["id"] == rid
                          for t in r["techniques"]}
                # Every tag is a catalog technique that one of the scenario's expected rules maps to.
                self.assertLessEqual(canonical, mapped)

    def test_default_rules_on_the_labeled_scenarios(self):
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        engine.seed_rules(conn)
        result = attack.evidence(attack.coverage(engine.load_rules(conn, enabled_only=False), {}),
                                 improve.noise_lab(conn)["rules"], simulate.SCENARIOS)
        levels = {t["id"]: t["level"] for t in result["techniques"]}
        by_id = {t["id"]: t for t in result["techniques"]}
        # web_scan probes and injects but never exploits; exfiltration reads storage with no protocol shown.
        self.assertEqual({i for i, lvl in levels.items() if lvl != "validated"}, {"T1190", "T1048", "T1595.001"})
        self.assertEqual(by_id["T1190"]["why"],
                         "web_scanner detects web_scan, which probes and injects but never exploits.")
        self.assertEqual(by_id["T1595.001"]["why"],
                         "firewall_port_sweep detects port_sweep, which sweeps one host's ports "
                         "and never scans IP blocks.")
        self.assertEqual(by_id["T1048"]["why"],
                         "data_exfil_volume detects exfiltration, which reads cloud storage "
                         "and never shows an exfiltration channel.")
        self.assertTrue(all(t["why"] is None for t in result["techniques"] if t["level"] != "mapped"))
        layer = {t["techniqueID"]: t for t in attack.navigator_layer(result)["techniques"]}
        self.assertIn(by_id["T1190"]["why"], layer["T1190"]["comment"])
        self.assertNotIn("never exploits", layer["T1110"]["comment"])
        self.assertEqual(len(attack.TECHNIQUES), 20)  # cloud-log and log-source rules, now T1685.002 and T1685
        self.assertEqual(result["summary"]["levels"],
                         {"validated": len(attack.TECHNIQUES) - 3, "mapped": 3, "disabled": 0, "gap": 0})
        # Each of those rules proves its technique with its own scenario, not by borrowing another rule's.
        self.assertEqual(by_id["T1685.002"]["scenarios"], ["logging_disabled"])
        self.assertEqual({r["id"]: r["proves"] for r in by_id["T1685.002"]["rules"]},
                         {"cloud_logging_disabled": ["logging_disabled"]})
        self.assertEqual(by_id["T1685"]["scenarios"], ["log_source_stops"])
        proves = {r["id"]: r["proves"] for r in by_id["T1078.004"]["rules"]}
        self.assertEqual(proves["admin_action_from_new_source"], ["admin_new_source"])
        self.assertEqual(proves["cloud_iam_change_by_new_principal"], ["cloud_new_principal"])
        # The new-source rule also maps T1078, but its scenario is tagged only with what it shows.
        self.assertNotIn("admin_new_source", by_id["T1078"]["scenarios"])


class NoiseLabCacheTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        improve._NOISE_LAB_CACHE.clear()

    def test_reused_until_rules_or_exceptions_change(self):
        with mock.patch.object(improve, "evaluate", wraps=improve.evaluate) as spy:
            first = improve.cached_noise_lab(self.conn)
            self.assertIs(improve.cached_noise_lab(self.conn), first)
            self.assertEqual(spy.call_count, 1)
            self.conn.execute("UPDATE rules SET enabled = 0, version = version + 1 WHERE id = 'web_scanner'")
            row = {r["rule_id"]: r for r in improve.cached_noise_lab(self.conn)["rules"]}["web_scanner"]
            self.assertEqual((spy.call_count, row["verdict"]), (2, "disabled"))
            self.conn.execute("INSERT INTO suppressions(rule_id, group_key, reason, expires_at, proposed_by,"
                              " approved_by, created_at) VALUES ('brute_force_ip', '10.0.50.5', 'scanner',"
                              " '2999-01-01T00:00:00Z', 'a', 'b', ?)", (now_iso(),))
            improve.cached_noise_lab(self.conn)
            self.assertEqual(spy.call_count, 3)


class NavigatorLayerTests(unittest.TestCase):
    def layer(self, hits):
        rule_list = [{**r, "enabled": r["id"] != "web_scanner"} for r in rules.DEFAULT_RULES]
        lab = [lab_row(r["id"], [n for n, s in simulate.SCENARIOS.items() if r["id"] in s["expected"]])
               for r in rules.DEFAULT_RULES]
        return attack.navigator_layer(attack.evidence(attack.coverage(rule_list, hits), lab, simulate.SCENARIOS))

    def test_layer_follows_the_navigator_format(self):
        layer = self.layer({"brute_force_ip": 3, "success_after_failures": 2})
        self.assertEqual(set(layer), {"name", "versions", "domain", "description", "techniques", "gradient",
                                      "legendItems"})
        self.assertEqual(layer["domain"], "enterprise-attack")
        # The static table states no ATT&CK release, so the layer claims none: only the layer format version.
        self.assertEqual(layer["versions"], {"layer": "4.5"})
        self.assertIn("synthetic", layer["description"].lower())
        self.assertEqual(layer["gradient"]["minValue"], 0)
        self.assertEqual(layer["gradient"]["maxValue"], 3)
        self.assertGreaterEqual(len(layer["gradient"]["colors"]), 2)
        self.assertEqual([i["label"] for i in layer["legendItems"]], [lvl.capitalize() for lvl in attack.LEVELS])
        for t in layer["techniques"]:
            with self.subTest(technique=t["techniqueID"]):
                self.assertEqual(set(t), {"techniqueID", "tactic", "score", "color", "comment"})
                self.assertRegex(t["tactic"], r"^[a-z]+(-[a-z]+)*$")
                self.assertRegex(t["color"], r"^#[0-9a-f]{6}$")

    def test_every_technique_colored_by_level_with_hits_and_rule_names(self):
        by_id = {t["techniqueID"]: t for t in self.layer({"brute_force_ip": 3, "success_after_failures": 2})["techniques"]}
        self.assertEqual(set(by_id), set(attack.TECHNIQUES))
        self.assertEqual((by_id["T1110.001"]["score"], by_id["T1110.001"]["tactic"]), (3, "credential-access"))
        self.assertEqual(by_id["T1685"]["tactic"], "defense-impairment")
        self.assertEqual(by_id["T1685.002"]["tactic"], "defense-impairment")
        self.assertEqual(by_id["T1110"]["score"], 2)
        self.assertEqual(by_id["T1046"]["score"], 0)
        self.assertTrue(by_id["T1110.001"]["comment"].startswith("Validated"))
        self.assertEqual(by_id["T1110.001"]["color"], attack.LEVEL_COLORS["validated"])
        # Only the disabled web_scanner maps to T1595.003; T1190 is mapped but no scenario exercises it.
        self.assertTrue(by_id["T1595.003"]["comment"].startswith("Disabled"))
        self.assertIn("web_scanner (disabled)", by_id["T1595.003"]["comment"])
        self.assertEqual(by_id["T1595.003"]["color"], attack.LEVEL_COLORS["disabled"])
        self.assertTrue(by_id["T1048"]["comment"].startswith("Mapped"))
        self.assertIn("not counted as covered", by_id["T1048"]["comment"].lower())
        self.assertIn("never shows an exfiltration channel", by_id["T1048"]["comment"])
        for rule_id in ("success_after_failures", "impossible_geo_login", "privilege_escalation_after_login"):
            self.assertIn(rule_id, by_id["T1078"]["comment"])
        self.assertEqual(self.layer({})["gradient"]["maxValue"], 1)  # no alerts yet: still a valid range


class CoverageDetailUiTests(unittest.TestCase):
    def test_mapped_reason_is_on_the_detail_and_the_gap_list(self):
        app = (Path(__file__).resolve().parent.parent / "static" / "app.js").read_text()
        detail = app.split("function coverageDetail", 1)[1].split("\nasync function coverageView", 1)[0]
        view = app.split("async function coverageView", 1)[1].split("\n// ---------- health", 1)[0]
        self.assertIn('t.level === "mapped" && t.why', detail)
        self.assertIn('class: "cov-why"', detail)
        self.assertIn('t.level === "mapped" && t.why', view)
        css = (Path(__file__).resolve().parent.parent / "static" / "style.css").read_text()
        self.assertIn(".cov-why", css)
        self.assertIn(".cov-gaps .cov-why", css)


# Shape stored before the catalog moved T1562.008. The name and tactic are the old ones on purpose:
# coverage must publish the catalog's, not these.
_OLD_CLOUD_LOG = {
    "id": "T1562.008",
    "name": "Impair Defenses: Disable or Modify Cloud Logs",
    "tactic": "Defense Evasion",
}
_NEW_CLOUD_LOG = {
    "id": "T1685.002",
    "name": "Disable or Modify Tools: Disable or Modify Cloud Log",
    "tactic": "Defense Impairment",
}


def _sigma_source(title, message, tags):
    tags_block = "tags:\n" + "".join(f"  - {tag}\n" for tag in tags) if tags else ""
    return (
        f"title: {title}\nstatus: test\n"
        f"description: Imported before the catalog moved this technique.\n"
        f"{tags_block}"
        f"logsource:\n  category: cloud\n"
        f"detection:\n  selection:\n    message: {message}\n  condition: selection\n"
        f"level: high\n"
    )


def _passing_sample(message):
    return {
        "malicious": [{"message": message, "src_ip": "203.0.113.10", "ts": "2026-01-01T00:00:00Z"}],
        "benign": [{"message": "ordinary cloud read", "src_ip": "203.0.113.11", "ts": "2026-01-01T00:00:01Z"}],
    }


class PersistedMappingTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        improve._NOISE_LAB_CACHE.clear()
        self.addCleanup(improve._NOISE_LAB_CACHE.clear)

    def insert_sigma(self, title, message, techniques, enabled, hits, tags, sample=True):
        """Compile a real Sigma rule, then overwrite techniques with the pre-upgrade JSON."""
        source = _sigma_source(title, message, tags)
        compiled = sigma.compile_rule(source)
        now = now_iso()
        self.conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at,"
            " updated_by, techniques) VALUES (?,?,?,?,?,?,1,?,?,?)",
            (compiled["rule_id"], compiled["title"], compiled["description"][:2000], compiled["severity"],
             int(enabled), json.dumps(compiled["params"]), now, "tester",
             None if techniques is None else json.dumps(techniques)))
        self.conn.execute(
            "INSERT INTO sigma_rules(rule_id, source, sha256, sigma_id, sample, imported_by, approved_by,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (compiled["rule_id"], source, compiled["sha256"], compiled["sigma_id"],
             json.dumps(_passing_sample(message)) if sample else None, "tester", "tester", now))
        for i in range(hits):
            self.conn.execute(
                "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
                " first_seen, last_seen, event_count, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (compiled["rule_id"], 1, f"{compiled['rule_id']}-{i}", "low", "t", "e", now, now, 1, now, now))
        return compiled["rule_id"]

    def test_live_coverage_keeps_legacy_imported_mappings(self):
        builtin = json.loads(self.conn.execute(
            "SELECT techniques FROM rules WHERE id = 'cloud_logging_disabled'").fetchone()[0])
        self.assertEqual([t["id"] for t in builtin], ["T1685.002"])
        now = now_iso()
        for i in range(2):
            self.conn.execute(
                "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
                " first_seen, last_seen, event_count, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("cloud_logging_disabled", 1, f"cloud-{i}", "low", "t", "e", now, now, 1, now, now))
        both = self.insert_sigma(
            "Both Spellings Cloud Log", "both-spellings-cloud-log-marker",
            [_OLD_CLOUD_LOG, _NEW_CLOUD_LOG], True, 5, ("attack.t1562.008", "attack.defense_evasion"))
        disabled = self.insert_sigma(
            "Disabled Cloud Log", "disabled-cloud-log-marker",
            [_OLD_CLOUD_LOG], False, 4, ("attack.t1562.008",))
        legacy = self.insert_sigma(
            "Legacy Cloud Log Marker", "legacy-cloud-log-marker",
            [_OLD_CLOUD_LOG, {"id": "T9999", "name": "Nope", "tactic": "Execution"},
             {"id": "Defense Evasion", "name": "header", "tactic": "Defense Evasion"}],
            True, 3, ("attack.t1562.008", "attack.defense_evasion"))
        unknown = self.insert_sigma(
            "Unknown Technique Marker", "unknown-technique-marker",
            [{"id": "T9999", "name": "Nope", "tactic": "Execution"}],
            True, 9, ("attack.t9999",))
        missing = self.insert_sigma(
            "Missing Mapping Marker", "missing-mapping-marker",
            [{"tactic": "Defense Evasion"}], True, 8, ("attack.defense_evasion",), sample=False)
        self.assertEqual((both, disabled, legacy, unknown, missing), (
            "sigma_both_spellings_cloud_log", "sigma_disabled_cloud_log", "sigma_legacy_cloud_log_marker",
            "sigma_unknown_technique_marker", "sigma_missing_mapping_marker"))
        # seed_rules rewrites built-ins only. The imported row must still say T1562.008.
        stored = json.loads(self.conn.execute(
            "SELECT techniques FROM rules WHERE id = ?", (legacy,)).fetchone()[0])
        self.assertEqual(stored[0]["id"], "T1562.008")

        result = incidents.coverage(self.conn)
        by_id = {t["id"]: t for t in result["techniques"]}
        self.assertEqual(set(by_id), set(attack.TECHNIQUES))
        cloud = by_id["T1685.002"]
        self.assertEqual((cloud["id"], cloud["name"], cloud["tactic"]), (
            "T1685.002", "Disable or Modify Tools: Disable or Modify Cloud Log", "Defense Impairment"))
        self.assertEqual([r["id"] for r in cloud["rules"]], [
            "cloud_logging_disabled", both, disabled, legacy])
        self.assertEqual([r["hits"] for r in cloud["rules"]], [2, 5, 4, 3])
        self.assertEqual([r["enabled"] for r in cloud["rules"]], [True, True, False, True])
        self.assertEqual(cloud["hits"], 14)  # 5 once, not twice for the two spellings
        self.assertEqual((cloud["level"], cloud["covered"]), ("validated", True))
        self.assertEqual(cloud["scenarios"], [
            "logging_disabled",
            "sigma_sample:sigma_both_spellings_cloud_log",
            "sigma_sample:sigma_legacy_cloud_log_marker",
        ])
        self.assertEqual({r["id"]: r["proves"] for r in cloud["rules"]}, {
            "cloud_logging_disabled": ["logging_disabled"],
            both: ["sigma_sample:sigma_both_spellings_cloud_log"],
            disabled: [],
            legacy: ["sigma_sample:sigma_legacy_cloud_log_marker"],
        })
        for technique in result["techniques"]:
            ids = {r["id"] for r in technique["rules"]}
            self.assertNotIn(unknown, ids)
            self.assertNotIn(missing, ids)
            self.assertNotIn("sigma_sample:" + unknown, technique["scenarios"])

        # The stock fixtures stay mapped-only; the cloud read and the one-host sweep stay proved.
        self.assertEqual(by_id["T1190"]["level"], "mapped")
        self.assertEqual(by_id["T1190"]["scenarios"], [])
        self.assertIn("never exploits", by_id["T1190"]["why"])
        self.assertEqual((by_id["T1048"]["level"], by_id["T1048"]["scenarios"]), ("mapped", []))
        self.assertIn("never shows an exfiltration channel", by_id["T1048"]["why"])
        self.assertEqual((by_id["T1595.001"]["level"], by_id["T1595.001"]["scenarios"]), ("mapped", []))
        self.assertIn("never scans IP blocks", by_id["T1595.001"]["why"])
        self.assertEqual((by_id["T1530"]["level"], by_id["T1530"]["scenarios"]), ("validated", ["exfiltration"]))
        self.assertEqual((by_id["T1046"]["level"], by_id["T1046"]["scenarios"]), ("validated", ["port_sweep"]))

        layer = {t["techniqueID"]: t for t in attack.navigator_layer(result)["techniques"]}
        self.assertNotIn("T1562.008", layer)
        self.assertNotIn("T9999", layer)
        row = layer["T1685.002"]
        self.assertEqual((row["score"], row["tactic"]), (14, "defense-impairment"))
        self.assertTrue(row["comment"].startswith("Validated"))
        self.assertIn(
            "Detected on synthetic scenario(s): logging_disabled, "
            "sigma_sample:sigma_both_spellings_cloud_log, sigma_sample:sigma_legacy_cloud_log_marker.",
            row["comment"])
        self.assertIn(
            "Rules: cloud_logging_disabled, sigma_both_spellings_cloud_log, "
            "sigma_disabled_cloud_log (disabled), sigma_legacy_cloud_log_marker",
            row["comment"])
        self.assertNotIn(unknown, row["comment"])
        self.assertNotIn(missing, row["comment"])

    def test_stored_spellings_count_once_through_the_catalog(self):
        imported = {
            "id": "imported", "name": "Imported", "enabled": True,
            "techniques": ["T1562.008", _NEW_CLOUD_LOG, "T9999", {"tactic": "Defense Evasion"},
                           {"id": ""}, {"id": 1562}],
        }
        listed = [imported, imported,  # the same rule twice still counts once
                  {"id": "lone", "name": "Lone", "enabled": 0, "techniques": "T1562.006"},
                  {"id": "one", "name": "One", "enabled": True,
                   "techniques": {"id": "T1562.008", "name": "stored", "tactic": "Defense Evasion"}},
                  {"id": "blank", "name": "Blank", "enabled": True, "techniques": None},
                  {"id": "junk", "name": "Junk", "enabled": True, "techniques": {"nope": True}}]
        result = attack.coverage(listed, {"imported": 5, "lone": 7, "one": 1, "junk": 9})
        by_id = {t["id"]: t for t in result["techniques"]}
        self.assertEqual(set(by_id), set(attack.TECHNIQUES))
        cloud = by_id["T1685.002"]
        self.assertEqual([r["id"] for r in cloud["rules"]], ["imported", "one"])
        self.assertEqual([r["hits"] for r in cloud["rules"]], [5, 1])
        self.assertEqual(cloud["hits"], 6)
        self.assertEqual(cloud["tactic"], "Defense Impairment")
        self.assertNotEqual(cloud["name"], "stored")
        tools = by_id["T1685"]
        self.assertEqual([(r["id"], r["enabled"], r["hits"]) for r in tools["rules"]], [("lone", False, 7)])
        self.assertEqual((tools["hits"], tools["covered"]), (7, False))
        self.assertEqual(result["summary"]["with_hits"], 2)


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
