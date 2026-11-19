"""Sigma subset import: the YAML-subset parser, the compiled detection, and the reviewed import workflow."""

import json
import time
import unittest
from datetime import timedelta
from pathlib import Path

from watchpost import rules as rules_mod
from watchpost import sigma
from watchpost.db import iso, utcnow

from .helpers import ServerTestCase

EXAMPLE = Path(__file__).resolve().parent.parent / "docs" / "sigma-examples" / "failed_logins_from_external_source.yml"


def rule_yaml(detection, title="Test Rule", tags=("attack.t1190",), level="high"):
    tag_lines = "".join(f"  - {t}\n" for t in tags)
    return (f"title: {title}\nstatus: test\nlevel: {level}\ntags:\n{tag_lines}"
            f"logsource:\n  category: webserver\ndetection:\n{detection}")


def compiled(detection):
    return sigma.compile_rule(rule_yaml(detection))["params"]


class YamlSubsetTests(unittest.TestCase):
    def test_leading_zero_numbers_stay_text(self):
        doc = sigma.parse_yaml("ids:\n  - 00000429\n  - 00050429\n  - 0\n  - 7\n  - -3\n")
        self.assertEqual(doc["ids"], ["00000429", "00050429", 0, 7, -3])

    def test_supported_subset(self):
        doc = sigma.parse_yaml(
            "---\n"
            "# a comment\n"
            "title: 'It''s quoted'   # trailing comment\n"
            "plain: some text\n"
            "dq: \"a\\\\b \\\"c\\\"\"\n"
            "num: 4625\n"
            "nothing: null\n"
            "flag: true\n"
            "flow: [a, 'b c', 3]\n"
            "text: |\n"
            "  line one\n"
            "  line two # kept\n"
            "folded: >-\n"
            "  one\n"
            "  two\n"
            "list:\n"
            "- x\n"
            "- y\n"
            "nested:\n"
            "  CommandLine|contains|all:\n"
            "    - foo\n"
            "    - bar\n"
            "  maps:\n"
            "    - a: 1\n"
            "      b: 2\n"
            "    - c: 3\n")
        self.assertEqual(doc["title"], "It's quoted")
        self.assertEqual(doc["plain"], "some text")
        self.assertEqual(doc["dq"], 'a\\b "c"')
        self.assertEqual((doc["num"], doc["nothing"], doc["flag"]), (4625, None, True))
        self.assertEqual(doc["flow"], ["a", "b c", 3])
        self.assertEqual(doc["text"], "line one\nline two # kept\n")
        self.assertEqual(doc["folded"], "one two")
        self.assertEqual(doc["list"], ["x", "y"])
        self.assertEqual(doc["nested"]["CommandLine|contains|all"], ["foo", "bar"])
        self.assertEqual(doc["nested"]["maps"], [{"a": 1, "b": 2}, {"c": 3}])

    def test_refusals(self):
        cases = {
            "a: &anchor x\nb: 1\n": "anchors",
            "a: x\nb: *alias\n": "aliases",
            "a: 1\n---\nb: 2\n": "multiple YAML documents",
            "a: !!str 1\n": "tags",
            "a: {b: 1}\n": "flow mappings",
            "a:\n\t- x\n": "tabs",
            "a: 1\na: 2\n": "duplicate key",
            "a: [b, [c]]\n": "simple [a, b] lists",
            "a: 'open\n": "unterminated",
            "? complex\n": "complex keys",
            "%YAML 1.2\na: 1\n": "directives",
            "- a\n- b\n": "mapping",
        }
        for text, reason in cases.items():
            with self.subTest(text=text):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    sigma.parse_yaml(text)
                self.assertIn(reason, str(ctx.exception))

    def test_size_cap(self):
        with self.assertRaises(sigma.SigmaError) as ctx:
            sigma.parse_yaml("a: " + "x" * sigma.MAX_SOURCE_BYTES)
        self.assertIn("at most", str(ctx.exception))


    def test_condition_expansion_is_capped(self):
        # 15 selections of 100 values fit the source cap; naming them 75 times would compile to ~8 MB.
        values = "".join(f"      - v{i:05d}{'x' * 26}\n" for i in range(100))
        selections = "".join(f"  s{j}:\n    message|contains:\n{values}" for j in range(15))
        text = ("title: t\nlevel: low\ndetection:\n" + selections
                + "  condition: " + " or ".join(["1 of them"] * 75) + "\n")
        self.assertLess(len(text), sigma.MAX_SOURCE_BYTES)
        with self.assertRaises(sigma.SigmaError) as ctx:
            sigma.compile_rule(text)
        self.assertIn("too large", str(ctx.exception))
        # The stored-params path (a rule_update) is held to the same budget.
        big = {"op": "match", "field": "message", "mod": "contains", "all": False,
               "values": ["x"] * (sigma.MAX_COMPILED_VALUES + 1)}
        with self.assertRaises(sigma.SigmaError):
            sigma.validate_params({"title": "t", "detection": big})


class CompileTests(unittest.TestCase):
    def test_leading_zero_values_match_literal_text(self):
        # Keyboard layout IDs such as 00000429 are text. Read as the number 429 they would match any value with "429".
        p = compiled("  sel:\n    message|contains:\n      - 00000429\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "00000429"}))
        self.assertFalse(sigma.matches(p, {"message": "retry after 429 seconds"}))

    def test_modifiers(self):
        p = compiled("  sel:\n    message|contains: Union Select\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "id=1 UNION SELECT pw"}))  # case-insensitive
        self.assertFalse(sigma.matches(p, {"message": "select"}))
        p = compiled("  sel:\n    message|startswith: GET /admin\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "GET /admin/login"}))
        self.assertFalse(sigma.matches(p, {"message": "POST GET /admin"}))
        p = compiled("  sel:\n    message|endswith: .php\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "GET /wp-login.php"}))
        self.assertFalse(sigma.matches(p, {"message": "GET /wp-login.php?x"}))
        p = compiled("  sel:\n    message|contains|all:\n      - ../\n      - etc/passwd\n  condition: sel\n")
        self.assertEqual(p["detection"], {"op": "match", "field": "message", "mod": "contains", "all": True,
                                          "values": ["../", "etc/passwd"]})
        self.assertTrue(sigma.matches(p, {"message": "GET /../../etc/passwd"}))
        self.assertFalse(sigma.matches(p, {"message": "GET /etc/passwd"}))
        p = compiled("  sel:\n    src_ip|cidr: 203.0.113.0/24\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"src_ip": "203.0.113.9"}))
        self.assertFalse(sigma.matches(p, {"src_ip": "198.51.100.1"}))
        self.assertFalse(sigma.matches(p, {"src_ip": "not-an-ip"}))
        # Plain values: exact (case-insensitive), with * and ? wildcards; null matches an empty field.
        p = compiled("  sel:\n    user: adm?n*\n    dest_port: 22\n    host: null\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"user": "Admin01", "dest_port": 22}))
        self.assertFalse(sigma.matches(p, {"user": "Admin01", "dest_port": 22, "host": "web01"}))
        self.assertFalse(sigma.matches(p, {"user": "xadmin", "dest_port": 22}))
        p = compiled("  sel:\n    message: 'a\\*b'\n  condition: sel\n")  # an escaped star is literal
        self.assertTrue(sigma.matches(p, {"message": "a*b"}))
        self.assertFalse(sigma.matches(p, {"message": "axxb"}))

    def test_cidr_rejects_host_bits(self):
        for det in (
            "  sel:\n    src_ip|cidr: 192.168.1.1/24\n  condition: sel\n",
            "  sel:\n    src_ip|cidr: '2001:db8::1/64'\n  condition: sel\n",
        ):
            with self.subTest(detection=det):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    compiled(det)
                self.assertIn("not a CIDR", str(ctx.exception))
        p = compiled("  sel:\n    src_ip|cidr: '2001:db8::/32'\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"src_ip": "2001:db8::1"}))
        self.assertFalse(sigma.matches(p, {"src_ip": "2001:db9::1"}))
        p = compiled("  sel:\n    src_ip|cidr: 203.0.113.9\n  condition: sel\n")  # a bare address is a /32
        self.assertTrue(sigma.matches(p, {"src_ip": "203.0.113.9"}))
        self.assertFalse(sigma.matches(p, {"src_ip": "203.0.113.10"}))
        # A stored rule compiled under the old host-bit acceptance must fail closed, not widen.
        stored = {"title": "t", "detection": {
            "op": "match", "field": "src_ip", "mod": "cidr", "all": False, "values": ["192.168.1.1/24"],
        }}
        self.assertFalse(sigma.matches(stored, {"src_ip": "192.168.1.50"}))
        self.assertFalse(sigma.matches(stored, {"src_ip": "192.168.1.1"}))

    def test_empty_field_matches_star_and_empty_string(self):
        star = compiled("  sel:\n    message: '*'\n  condition: sel\n")
        self.assertTrue(sigma.matches(star, {"message": ""}))
        self.assertTrue(sigma.matches(star, {"message": "x"}))
        self.assertFalse(sigma.matches(star, {}))
        self.assertFalse(sigma.matches(star, {"message": None}))
        empty = compiled("  sel:\n    message: ''\n  condition: sel\n")
        self.assertTrue(sigma.matches(empty, {"message": ""}))
        self.assertFalse(sigma.matches(empty, {"message": "x"}))
        self.assertFalse(sigma.matches(empty, {}))
        for mod in ("startswith", "endswith", "contains"):
            p = compiled(f"  sel:\n    message|{mod}: ''\n  condition: sel\n")
            self.assertTrue(sigma.matches(p, {"message": ""}), mod)
            self.assertTrue(sigma.matches(p, {"message": "x"}), mod)
        one = compiled("  sel:\n    message: '?'\n  condition: sel\n")
        self.assertFalse(sigma.matches(one, {"message": ""}))
        self.assertTrue(sigma.matches(one, {"message": "a"}))
        self.assertFalse(sigma.matches(one, {"message": "ab"}))

    def test_windash_base64_and_base64offset(self):
        p = compiled("  sel:\n    message|windash|contains: '-enc'\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"message": "powershell -enc AA"}))
        self.assertTrue(sigma.matches(p, {"message": "powershell /enc AA"}))
        self.assertTrue(sigma.matches(p, {"message": "powershell \u2013enc AA"}))
        self.assertFalse(sigma.matches(p, {"message": "powershell enc AA"}))
        # A dash between two word characters is not a Windows parameter dash.
        inner = compiled("  sel:\n    message|windash|contains: param-name\n  condition: sel\n")
        self.assertEqual(inner["detection"]["values"], ["param-name"])
        self.assertFalse(sigma.matches(inner, {"message": "param/name"}))
        # An en dash already in the rule is not a second expansion source.
        typed = compiled("  sel:\n    message|windash|contains: '\u2013enc'\n  condition: sel\n")
        self.assertTrue(sigma.matches(typed, {"message": "\u2013enc"}))
        self.assertFalse(sigma.matches(typed, {"message": "-enc"}))
        spec = compiled("  sel:\n    message|windash|contains: '-param-1 -param2'\n  condition: sel\n")
        self.assertEqual(len(spec["detection"]["values"]), 25)
        self.assertTrue(sigma.matches(spec, {"message": "run -param-1 /param2"}))
        self.assertTrue(sigma.matches(spec, {"message": "run \u2013param-1 -param2"}))
        self.assertFalse(sigma.matches(spec, {"message": "run param-1 param2"}))
        both = compiled("  sel:\n    message|windash|contains|all:\n      - '-enc'\n      - '-w'\n"
                        "  condition: sel\n")
        self.assertEqual(both["detection"]["op"], "and")
        self.assertTrue(sigma.matches(both, {"message": "powershell -enc AA -w hidden"}))
        self.assertTrue(sigma.matches(both, {"message": "powershell /enc AA \u2013w hidden"}))
        self.assertFalse(sigma.matches(both, {"message": "powershell -enc AA"}))
        # windash runs before base64, so the slash form is encoded too.
        encoded = compiled("  sel:\n    message|windash|base64: '-a'\n  condition: sel\n")
        self.assertTrue(sigma.matches(encoded, {"message": "LWE="}))
        self.assertTrue(sigma.matches(encoded, {"message": "L2E="}))
        self.assertFalse(sigma.matches(encoded, {"message": "-a"}))
        plain = compiled("  sel:\n    message|base64: foobar\n  condition: sel\n")
        self.assertTrue(sigma.matches(plain, {"message": "Zm9vYmFy"}))
        self.assertFalse(sigma.matches(plain, {"message": "foobar"}))
        literal = compiled("  sel:\n    message|base64: 'x\\*y'\n  condition: sel\n")
        self.assertTrue(sigma.matches(literal, {"message": "eCp5"}))
        offset = compiled("  sel:\n    message|base64offset|contains: 'cmd\\?.exe'\n  condition: sel\n")
        for frag in ("Y21kPy5leG", "NtZD8uZXhl", "jbWQ/LmV4Z"):
            self.assertTrue(sigma.matches(offset, {"message": f"prefix {frag} suffix"}), frag)
        self.assertFalse(sigma.matches(offset, {"message": "cmd.exe"}))
        refused = {
            "  sel:\n    message|windash: '-a -b -c -d'\n  condition: sel\n": "at most three",
            "  sel:\n    message|base64: 'foo*bar'\n  condition: sel\n": "wildcard",
            "  sel:\n    message|contains|base64: foobar\n  condition: sel\n": "unmodified",
            "  sel:\n    message|base64: 123\n  condition: sel\n": "applies to strings",
            "  sel:\n    src_ip|cidr|windash: 10.0.0.0/8\n  condition: sel\n": "cidr cannot",
        }
        for det, reason in refused.items():
            with self.subTest(detection=det):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    compiled(det)
                self.assertIn(reason, str(ctx.exception))

    def test_short_transforms_do_not_match_unrelated_text(self):
        benign = {"message": "the host finished a health check"}
        refused = (
            "  sel:\n    message|base64offset|contains: a\n  condition: sel\n",
            "  sel:\n    message|base64offset|contains: ''\n  condition: sel\n",
            "  sel:\n    message|base64: ''\n  condition: sel\n",
            "  sel:\n    message|base64offset: ab\n  condition: sel\n",
            "  sel:\n    message|base64offset|contains: AAA\n  condition: sel\n",
            "  sel:\n    message|windash|contains: ''\n  condition: sel\n",
        )
        for det in refused:
            with self.subTest(detection=det):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    compiled(det)
                self.assertIn("ambiguous", str(ctx.exception))
        one = compiled("  sel:\n    message|base64: a\n  condition: sel\n")
        self.assertEqual(one["detection"]["values"], ["YQ=="])
        self.assertTrue(sigma.matches(one, {"message": "YQ=="}))
        self.assertFalse(sigma.matches(one, benign))
        offset = compiled("  sel:\n    message|base64offset|contains: AAAA\n  condition: sel\n")
        self.assertEqual(offset["detection"]["values"], ["QUFBQ", "FBQU", "BQUFB"])
        for frag in offset["detection"]["values"]:
            self.assertTrue(sigma.matches(offset, {"message": f"xx{frag}yy"}), frag)
        self.assertFalse(sigma.matches(offset, benign))
        cmd = compiled("  sel:\n    message|base64offset|contains: 'cmd\\?.exe'\n  condition: sel\n")
        self.assertTrue(sigma.matches(cmd, {"message": "prefix Y21kPy5leG suffix"}))
        self.assertFalse(sigma.matches(cmd, benign))

    def test_stored_short_offset_matches_nothing(self):
        def legacy(values, mod="contains", all_flag=False):
            return {"title": "legacy", "detection": {
                "op": "match", "field": "message", "mod": mod, "all": all_flag, "values": values}}

        benign = {"message": "the host finished a health check"}
        stored = legacy(["Y", "", "h"])
        self.assertEqual(sigma.validate_params(stored), stored)
        self.assertEqual(rules_mod.validate_params("sigma_legacy_offset", stored), stored)
        for mod in ("contains", "startswith", "endswith"):
            p = legacy(["Y", "", "h"], mod)
            self.assertFalse(sigma.matches(p, benign), mod)
            self.assertFalse(sigma.matches(p, {"message": "hello"}), mod)
            self.assertFalse(sigma.matches(p, {"message": ""}), mod)
        blank = legacy(["", "", ""], all_flag=True)
        self.assertFalse(sigma.matches(blank, benign))
        self.assertFalse(sigma.matches(blank, {"message": ""}))
        events = [
            {"id": 1, "ts": "2026-09-15T12:00:00+00:00", "src_ip": "198.51.100.8", "message": benign["message"]},
            {"id": 2, "ts": "2026-09-15T12:00:01+00:00", "src_ip": "198.51.100.9", "message": "hello"},
        ]
        self.assertEqual(sigma.run(events, stored), [])
        valid = legacy(["Y21kPy5leG", "NtZD8uZXhl", "jbWQ/LmV4Z"])
        self.assertTrue(sigma.matches(valid, {"message": "prefix Y21kPy5leG suffix"}))
        self.assertFalse(sigma.matches(valid, benign))
        exact = legacy(["Y", "", "h"], "eq")
        self.assertFalse(sigma.matches(exact, benign))
        self.assertTrue(sigma.matches(exact, {"message": "h"}))
        self.assertTrue(sigma.matches(exact, {"message": ""}))

    def test_intentional_empty_equality_stays(self):
        benign = {"message": "the host finished a health check"}
        empty = compiled("  sel:\n    message: ''\n  condition: sel\n")
        self.assertTrue(sigma.matches(empty, {"message": ""}))
        self.assertFalse(sigma.matches(empty, benign))
        for mod in ("contains", "startswith", "endswith"):
            p = compiled(f"  sel:\n    message|{mod}: ''\n  condition: sel\n")
            self.assertTrue(sigma.matches(p, {"message": ""}), mod)
            self.assertTrue(sigma.matches(p, benign), mod)
        letter = compiled("  sel:\n    message|contains: h\n  condition: sel\n")
        self.assertTrue(sigma.matches(letter, {"message": "hello"}))
        self.assertFalse(sigma.matches(letter, {"message": "benign"}))
        author = compiled("  sel:\n    message|contains:\n      - ''\n      - ab\n  condition: sel\n")
        self.assertTrue(sigma.matches(author, benign))

    def test_transform_expansion_is_capped_before_allocation(self):
        one = compiled("  sel:\n    message|windash|contains: '-a -b -c'\n  condition: sel\n")
        self.assertEqual(len(one["detection"]["values"]), 125)
        self.assertTrue(sigma.matches(one, {"message": "run -a -b -c"}))
        lines = "".join(f"      - '-a -b -c {i:02d}'\n" for i in range(17))
        started = time.monotonic()
        with self.assertRaises(sigma.SigmaError) as ctx:
            compiled(f"  sel:\n    message|windash|contains:\n{lines}  condition: sel\n")
        self.assertIn("too large", str(ctx.exception))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_conditions(self):
        det = ("  sel_a:\n    user: alice\n  sel_b:\n    src_ip: 203.0.113.9\n  other:\n    host: web01\n"
               "  condition: {}\n")
        events = {"a": {"user": "alice"}, "b": {"src_ip": "203.0.113.9"}, "ab": {"user": "alice", "src_ip": "203.0.113.9"},
                  "abo": {"user": "alice", "src_ip": "203.0.113.9", "host": "web01"}, "o": {"host": "web01"}}
        cases = {
            "sel_a": {"a", "ab", "abo"},
            "sel_a and sel_b": {"ab", "abo"},
            "sel_a or sel_b": {"a", "b", "ab", "abo"},
            "not sel_a": {"b", "o"},
            "(sel_a or sel_b) and not other": {"a", "b", "ab"},
            "1 of sel_*": {"a", "b", "ab", "abo"},
            "all of sel_*": {"ab", "abo"},
            "all of them": {"abo"},
            "1 of them": {"a", "b", "ab", "abo", "o"},
        }
        for cond, want in cases.items():
            with self.subTest(condition=cond):
                p = compiled(det.format(cond))
                self.assertEqual({k for k, e in events.items() if sigma.matches(p, e)}, want)

    def test_list_of_maps_and_keywords(self):
        p = compiled("  sel:\n    - user: alice\n    - user: bob\n      host: web01\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"user": "alice"}))
        self.assertTrue(sigma.matches(p, {"user": "bob", "host": "web01"}))
        self.assertFalse(sigma.matches(p, {"user": "bob"}))
        p = compiled("  keywords:\n    - sqlmap\n    - nikto\n  condition: keywords\n")
        self.assertTrue(sigma.matches(p, {"message": "UA: Nikto/2.5"}))
        self.assertFalse(sigma.matches(p, {"message": "curl"}))

    def test_field_names_map_from_ecs_and_sigma(self):
        p = compiled("  sel:\n    source.ip: 1.2.3.4\n    DestinationPort: 3389\n    TargetUserName: bob\n"
                     "    Computer: dc01\n    event.action: auth_failure\n  condition: sel\n")
        self.assertTrue(sigma.matches(p, {"src_ip": "1.2.3.4", "dest_port": 3389, "user": "bob", "host": "dc01",
                                          "event_type": "auth_failure"}))

    def test_refusals(self):
        cases = {
            "  sel:\n    CommandLine: x\n  condition: sel\n": "field 'CommandLine'",
            "  sel:\n    EventID: 4625\n  condition: sel\n": "field 'EventID'",
            "  sel:\n    message|re: '.*'\n  condition: sel\n": "'re' refused",
            "  sel:\n    message|wide: x\n  condition: sel\n": "encoding",
            "  sel:\n    message|foo: x\n  condition: sel\n": "'foo' is not supported",
            "  sel:\n    user: x\n  condition: sel | count() by src_ip > 5\n": "aggregations",
            "  sel:\n    user: x\n  condition: sel near other\n": "near",
            "  sel:\n    user: x\n  timeframe: 5m\n  condition: sel\n": "timeframe",
            "  sel:\n    user: x\n  condition: nope\n": "unknown selection 'nope'",
            "  sel:\n    user: x\n  condition: 2 of sel*\n": "only '1 of' and 'all of'",
            "  sel:\n    user: x\n  condition: 1 of foo*\n": "matches no selection",
            "  sel:\n    user: x\n  condition: (sel\n": "ends too early",
            "  sel:\n    user: x\n  condition:\n    - sel\n": "lists of conditions",
            "  sel:\n    src_ip|cidr: banana\n  condition: sel\n": "not a CIDR",
        }
        for det, reason in cases.items():
            with self.subTest(detection=det):
                with self.assertRaises(sigma.SigmaError) as ctx:
                    sigma.compile_rule(rule_yaml(det))
                self.assertIn(reason, str(ctx.exception))

    def test_metadata(self):
        c = sigma.compile_rule(rule_yaml("  sel:\n    user: x\n  condition: sel\n", title="Brute Force IP!",
                                         tags=("attack.t1190", "attack.t9999", "attack.initial_access"),
                                         level="informational"))
        self.assertEqual(c["rule_id"], "sigma_brute_force_ip")  # namespaced: never a built-in id
        self.assertNotIn(c["rule_id"], rules_mod.RULE_FUNCTIONS)
        self.assertEqual(c["severity"], "low")
        self.assertEqual([t["id"] for t in c["techniques"]], ["T1190"])
        self.assertIn("attack.t9999", c["warnings"][0])
        self.assertTrue(any("logsource is informational" in w for w in c["warnings"]))
        self.assertEqual(rules_mod.validate_params(c["rule_id"], c["params"]), c["params"])
        with self.assertRaises(rules_mod.RuleConfigError):
            rules_mod.validate_params(c["rule_id"], {**c["params"], "threshold": 3})

    def test_glob_is_linear(self):
        p = compiled("  sel:\n    message: '*a*a*a*a*a*a*a*a*a*a*b'\n  condition: sel\n")
        started = time.monotonic()
        self.assertFalse(sigma.matches(p, {"message": "a" * 1024}))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_example_rule_compiles(self):
        c = sigma.compile_rule(EXAMPLE.read_text())
        self.assertEqual(c["rule_id"], "sigma_failed_admin_login_from_external_source")
        self.assertEqual([t["id"] for t in c["techniques"]], ["T1110.001"])
        self.assertTrue(sigma.matches(c["params"], {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.5"}))
        self.assertFalse(sigma.matches(c["params"], {"event_type": "auth_failure", "user": "root", "src_ip": "10.1.2.3"}))
        self.assertFalse(sigma.matches(c["params"], {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.5"}))


class SigmaGroupKeyTests(unittest.TestCase):
    def test_host_and_user_keys_fold_ascii_only(self):
        params = compiled("  sel:\n    message: hit\n  condition: sel\n")
        # The matcher still casefolds the whole string. Grouping does not.
        folded = compiled("  sel:\n    user: érin\n  condition: sel\n")
        self.assertTrue(sigma.matches(folded, {"user": "ÉRIN"}))
        self.assertTrue(sigma.matches(folded, {"user": "érin"}))

        def event(i, **fields):
            return {"id": i, "ts": "2026-09-15T12:00:00+00:00", "message": "hit", **fields}

        events = [
            event(1, host="WEB01"),
            event(2, host="web01"),
            event(3, host="Érin-host"),
            event(4, host="érin-host"),
            event(5, user="Alice"),
            event(6, user="alice"),
            event(7, user="ALICE"),
            event(8, user="ÉRIN"),
            event(9, user="érin"),
            event(10, src_ip="2001:DB8::1", host="WEB01", user="Alice"),
            event(11, src_ip="2001:db8::1", host="web01", user="alice"),
            event(12, src_ip="", host="WEB01"),
            event(13),
        ]
        findings = sigma.run(events, params)
        found = {f["group_key"]: f["event_ids"] for f in findings}
        self.assertEqual(found["web01"], [1, 2, 12])
        self.assertEqual(found["Érin-host"], [3])
        self.assertEqual(found["érin-host"], [4])
        self.assertEqual(found["alice"], [5, 6, 7])
        self.assertEqual(found["Érin"], [8])
        self.assertEqual(found["érin"], [9])
        self.assertEqual(found["2001:DB8::1"], [10])
        self.assertEqual(found["2001:db8::1"], [11])
        self.assertEqual(found["unknown"], [13])
        self.assertIn("for web01", next(f["title"] for f in findings if f["group_key"] == "web01"))


WEB_RULE = rule_yaml("  sel:\n    event_type: web_request\n    message|contains: /cgi-bin/.%2e/\n  condition: sel\n",
                     title="Path Traversal Probe")
WEB_ID = "sigma_path_traversal_probe"
GOOD_SAMPLE = {"malicious": [{"event_type": "web_request", "message": "GET /cgi-bin/.%2e/.%2e/bin/sh"}],
               "benign": [{"event_type": "web_request", "message": "GET /cgi-bin/status"}]}
BAD_SAMPLE = {"malicious": [{"event_type": "web_request", "message": "GET /cgi-bin/../bin/sh"}],
              "benign": [{"event_type": "web_request", "message": "GET /cgi-bin/status"}]}


class ImportWorkflowTests(ServerTestCase):
    def import_rule(self, client, source=WEB_RULE, sample=None, dry_run=False):
        body = {"source": source, **({"sample": sample} if sample else {})}
        return client.post("/api/rules/sigma" + ("?dry_run=1" if dry_run else ""), body)

    def approve(self, admin, change):
        status, data, _ = admin.post(f"/api/changes/{change['id']}/review",
                                     {"decision": "approve", "evidence_digest": change["evidence_digest"]})
        self.assertEqual(status, 200, data)
        return data

    def rule(self, client, rule_id=WEB_ID):
        return next((r for r in client.get("/api/rules")[1] if r["id"] == rule_id), None)

    def technique(self, client, tid):
        return next(t for t in client.get("/api/attack/coverage")[1]["techniques"] if t["id"] == tid)

    def test_viewer_cannot_import(self):
        viewer = self.client("viewer")
        self.assertEqual(self.import_rule(viewer)[0], 403)
        self.assertEqual(self.import_rule(viewer, dry_run=True)[0], 403)
        self.assertEqual(viewer.post(f"/api/rules/{WEB_ID}/sigma-sample", {"sample": GOOD_SAMPLE})[0], 403)

    def test_dry_run_compiles_and_creates_nothing(self):
        analyst = self.client("analyst")
        status, data, _ = self.import_rule(analyst, sample=GOOD_SAMPLE, dry_run=True)
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["compiled"]["rule_id"], WEB_ID)
        self.assertIn("message contains '/cgi-bin/.%2e/'", data["compiled"]["conditions"])
        self.assertTrue(data["sample"]["passes"])
        self.assertIn("matched_events", data["backtest"])
        status, data, _ = self.import_rule(analyst, rule_yaml("  s:\n    message|re: x\n  condition: s\n"),
                                           dry_run=True)
        self.assertEqual(status, 200, data)
        self.assertFalse(data["ok"])
        self.assertIn("regular expressions are refused", data["refused"])
        self.assertEqual(analyst.get("/api/changes")[1], [])
        self.assertIsNone(self.rule(analyst))
        # A real import of a refused rule is a 400 naming the reason.
        status, data, _ = self.import_rule(analyst, rule_yaml("  s:\n    Image: x\n  condition: s\n"))
        self.assertEqual(status, 400)
        self.assertIn("field 'Image'", data["error"])

    def test_two_person_review_adds_the_rule_disabled(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        status, change, _ = self.import_rule(analyst)
        self.assertEqual(status, 201, change)
        self.assertEqual((change["kind"], change["target"], change["status"]), ("sigma_add", WEB_ID, "pending"))
        self.assertIsNone(change["evaluation"]["sample"])
        self.assertIsNone(self.rule(admin))  # nothing until approved
        # The proposer cannot approve their own import.
        status, own, _ = self.import_rule(admin, rule_yaml("  s:\n    user: x\n  condition: s\n", title="Other"))
        self.assertEqual(status, 201, own)
        status, data, _ = admin.post(f"/api/changes/{own['id']}/review",
                                     {"decision": "approve", "evidence_digest": own["evidence_digest"]})
        self.assertEqual(status, 403, data)
        self.approve(admin, change)
        rule = self.rule(admin)
        self.assertFalse(rule["enabled"])
        self.assertEqual(rule["sigma"]["source"], WEB_RULE)
        self.assertEqual(rule["sigma"]["sha256"], sigma.compile_rule(WEB_RULE)["sha256"])
        self.assertEqual(self.rule(self.client("viewer"))["sigma"]["source"], WEB_RULE)  # read-only for viewers
        # Same title again: refused, the id exists.
        self.assertEqual(self.import_rule(analyst)[0], 409)
        # Imported logic is not tuned in place.
        status, data, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals",
                                       {"params": {"title": "x"}, "reason": "rename it"})
        self.assertEqual(status, 400, data)
        # A tuning export carries it, and importing that export back changes nothing.
        doc = admin.get("/api/rules/export")[1]
        status, result, _ = admin.request("POST", "/api/rules/import?dry_run=1", raw=json.dumps(doc).encode(),
                                          headers={"Content-Type": "application/json"})
        self.assertEqual(next(r for r in result["rules"] if r["id"] == WEB_ID)["outcome"], "unchanged", result)

    def test_enable_needs_a_passing_sample_and_coverage_follows_it(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.approve(admin, self.import_rule(analyst)[1])
        status, data, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 400, data)
        self.assertIn("no sample attached", data["error"])

        # A failing sample still blocks.
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/sigma-sample",
                                         {"sample": BAD_SAMPLE, "reason": "labeled sample"})
        self.assertEqual(status, 201, change)
        self.assertFalse(change["evaluation"]["sample"]["passes"])
        self.approve(admin, change)
        status, data, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 400, data)
        self.assertIn("1 malicious event(s) not matched", data["error"])

        # A passing sample: the rule may be enabled. Before that T1190 is only mapped (web_scanner) and this rule
        # proves nothing.
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/sigma-sample",
                                         {"sample": GOOD_SAMPLE, "reason": "fixed sample"})
        self.approve(admin, change)
        t = self.technique(admin, "T1190")
        self.assertEqual(t["level"], "mapped")
        self.assertEqual(next(r for r in t["rules"] if r["id"] == WEB_ID)["proves"], [])
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 201, change)
        self.approve(admin, change)
        self.assertTrue(self.rule(admin)["enabled"])
        t = self.technique(admin, "T1190")
        self.assertEqual(t["level"], "validated")
        self.assertEqual(t["scenarios"], [f"sigma_sample:{WEB_ID}"])

        # Replacing the sample with one that fails drops it back to mapped: never coverage without proof.
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/sigma-sample",
                                         {"sample": BAD_SAMPLE, "reason": "new sample"})
        self.approve(admin, change)
        self.assertEqual(self.technique(admin, "T1190")["level"], "mapped")
        lab = next(r for r in admin.get("/api/noise-lab")[1]["rules"] if r["rule_id"] == WEB_ID)
        self.assertEqual(lab["verdict"], "blind")

    def test_enabled_rule_alerts_on_ingested_events(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        self.approve(admin, self.import_rule(analyst, sample=GOOD_SAMPLE)[1])
        status, change, _ = analyst.post(f"/api/rules/{WEB_ID}/proposals", {"enabled": True, "reason": "turn it on"})
        self.approve(admin, change)
        base = utcnow() - timedelta(minutes=30)
        analyst.post("/api/ingest", {"source": "web", "events": [
            {"ts": iso(base), "type": "web_request", "src_ip": "198.51.100.7", "message": "GET /cgi-bin/.%2e/x"},
            {"ts": iso(base + timedelta(minutes=1)), "type": "web_request", "src_ip": "198.51.100.7",
             "message": "GET /index.html"}]})
        alerts = [a for a in analyst.get(f"/api/alerts?rule_id={WEB_ID}")[1] if a["rule_id"] == WEB_ID]
        self.assertEqual(len(alerts), 1, alerts)
        self.assertEqual((alerts[0]["group_key"], alerts[0]["event_count"]), ("198.51.100.7", 1))

    def test_example_rule_imports(self):
        analyst, admin = self.client("analyst"), self.client("admin")
        sample = {"malicious": [{"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.5"}],
                  "benign": [{"event_type": "auth_failure", "user": "root", "src_ip": "10.0.0.8"},
                             {"event_type": "auth_failure", "user": "alice", "src_ip": "203.0.113.5"}]}
        status, change, _ = self.import_rule(analyst, EXAMPLE.read_text(), sample)
        self.assertEqual(status, 201, change)
        self.assertTrue(change["evaluation"]["sample"]["passes"])
        self.approve(admin, change)
        rule = self.rule(admin, "sigma_failed_admin_login_from_external_source")
        self.assertEqual((rule["severity"], rule["enabled"]), ("high", False))
        self.assertEqual([t["id"] for t in rule["techniques"]], ["T1110.001"])

    def test_encoded_command_alerts_only_on_the_fragment(self):
        source = rule_yaml("  sel:\n    message|base64offset|contains: 'cmd\\?.exe'\n  condition: sel\n",
                           title="Encoded Command")
        rule_id = sigma.compile_rule(source)["rule_id"]
        malicious = {"message": "prefix Y21kPy5leG suffix"}
        benign = {"message": "the host finished a health check"}
        sample = {"malicious": [malicious], "benign": [benign]}
        analyst, admin = self.client("analyst"), self.client("admin")
        status, change, _ = self.import_rule(analyst, source, sample)
        self.assertEqual(status, 201, change)
        self.assertTrue(change["evaluation"]["sample"]["passes"])
        self.approve(admin, change)
        status, change, _ = analyst.post(f"/api/rules/{rule_id}/proposals",
                                         {"enabled": True, "reason": "turn it on"})
        self.assertEqual(status, 201, change)
        self.approve(admin, change)
        base = utcnow() - timedelta(minutes=30)
        analyst.post("/api/ingest", {"source": "host", "events": [
            {"ts": iso(base), "type": "process", "src_ip": "198.51.100.8", "message": malicious["message"]},
            {"ts": iso(base + timedelta(minutes=1)), "type": "process", "src_ip": "198.51.100.9",
             "message": benign["message"]}]})
        alerts = [a for a in analyst.get(f"/api/alerts?rule_id={rule_id}")[1] if a["rule_id"] == rule_id]
        self.assertEqual(len(alerts), 1, alerts)
        self.assertEqual(alerts[0]["group_key"], "198.51.100.8")

    def test_imports_spend_the_backtest_buckets(self):
        analyst = self.client("analyst")
        codes = [self.import_rule(analyst, dry_run=True)[0] for _ in range(8)]
        self.assertEqual(codes[:6], [200] * 6)  # the preview bucket (burst 6)
        self.assertEqual(codes[-1], 429)
        # A real import spends from the rule-proposal bucket (burst 20), which previews did not touch.
        for i in range(20):
            src = rule_yaml("  s:\n    user: x\n  condition: s\n", title=f"Rule {'abcdefghijklmnopqrstu'[i]}")
            self.assertEqual(self.import_rule(analyst, src)[0], 201)
        status, data, _ = self.import_rule(analyst, rule_yaml("  s:\n    user: x\n  condition: s\n", title="Last"))
        self.assertEqual(status, 429, data)


if __name__ == "__main__":
    unittest.main()
