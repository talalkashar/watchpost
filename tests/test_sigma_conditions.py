"""Sigma condition language against the spec: and/or/not, parentheses, 1 of / all of, them.

Selection patterns are case-sensitive whole-name globs. `?` is not a condition wildcard.
Names starting with `_` stay out of `them` and out of a pattern unless that pattern starts with `_`.
Field values stay case-insensitive; that is not a condition-name rule.
"""

import unittest

from watchpost import sigma


def _params(detection, title="Condition Rule"):
    source = f"title: {title}\nstatus: test\nlevel: high\ndetection:\n{detection}"
    return sigma.compile_rule(source)["params"]


def _hits(detection, events, title="Condition Rule"):
    params = _params(detection, title)
    return {name for name, event in events.items() if sigma.matches(params, event)}


class ConditionTests(unittest.TestCase):
    def _refuse(self, detection, reason):
        source = f"title: Refuse\nstatus: test\nlevel: high\ndetection:\n{detection}"
        with self.assertRaises(sigma.SigmaError) as ctx:
            sigma.compile_rule(source)
        self.assertIn(reason, str(ctx.exception))

    def test_precedence_and_parentheses(self):
        # or binds loosest, then and, then not. Parentheses override.
        # `a or b and c` is a OR (b AND c), not (a OR b) AND c.
        det = ("  a:\n    user: alice\n  b:\n    src_ip: 203.0.113.9\n  c:\n    host: web01\n"
               "  condition: {}\n")
        events = {
            "a": {"user": "alice"},
            "b": {"src_ip": "203.0.113.9"},
            "c": {"host": "web01"},
            "ab": {"user": "alice", "src_ip": "203.0.113.9"},
            "bc": {"src_ip": "203.0.113.9", "host": "web01"},
            "ac": {"user": "alice", "host": "web01"},
            "abc": {"user": "alice", "src_ip": "203.0.113.9", "host": "web01"},
            "none": {},
        }
        cases = {
            "a or b and c": {"a", "ab", "ac", "bc", "abc"},
            "(a or b) and c": {"bc", "ac", "abc"},
            "not a and b": {"b", "bc"},
            "not (a or b)": {"c", "none"},
            # (a AND NOT b) OR c, so an event that is only b+c still matches through c.
            "a and not b or c": {"a", "ac", "c", "abc", "bc"},
            "not a or not b and c": {"b", "c", "bc", "none", "ac"},
            "not not a": {"a", "ab", "ac", "abc"},
            "not not not a": {"b", "c", "bc", "none"},
            "(a)": {"a", "ab", "ac", "abc"},
            "a AND b OR c": {"ab", "abc", "c", "ac", "bc"},
            "NOT a AND b": {"b", "bc"},
        }
        for cond, want in cases.items():
            with self.subTest(condition=cond):
                self.assertEqual(_hits(det.format(cond), events), want)

    def test_not_binds_tighter_than_of_and_of_is_one_atom(self):
        det = ("  sel_a:\n    user: alice\n  sel_b:\n    src_ip: 203.0.113.9\n"
               "  filter_main:\n    host: web01\n  filter_opt:\n    dest_port: 22\n"
               "  condition: {}\n")
        events = {
            "a": {"user": "alice"},
            "af": {"user": "alice", "host": "web01"},
            "ao": {"user": "alice", "dest_port": 22},
            "b": {"src_ip": "203.0.113.9"},
            "f": {"host": "web01"},
            "none": {},
        }
        # not 1 of sel*  ==  NOT (sel_a OR sel_b)
        self.assertEqual(_hits(det.format("not 1 of sel*"), events), {"f", "none"})
        # selection and not 1 of filter*  ==  sel_a AND NOT (filter_main OR filter_opt)
        self.assertEqual(
            _hits(det.format("sel_a and not 1 of filter*"), events), {"a"})
        self.assertEqual(
            _hits(det.format("all of sel*"), events), set())  # no event has both sel_a and sel_b
        both = {"ab": {"user": "alice", "src_ip": "203.0.113.9"}}
        self.assertEqual(_hits(det.format("all of sel*"), {**events, **both}), {"ab"})

    def test_pattern_is_case_sensitive_and_not_a_prefix(self):
        det = ("  sel:\n    user: low\n  SEL:\n    user: up\n  sel_b:\n    src_ip: 203.0.113.9\n"
               "  condition: {}\n")
        events = {
            "low": {"user": "low"},
            "up": {"user": "up"},
            "bee": {"src_ip": "203.0.113.9"},
            # Extra field does not cancel `user: low`, so this still hits selection `sel`.
            "both": {"user": "low", "user_ignored": "up"},
        }
        cases = {
            "sel": {"low", "both"},
            "SEL": {"up"},
            "1 of sel": {"low", "both"},
            "1 of SEL": {"up"},
            "1 of sel*": {"low", "bee", "both"},
            "1 of SEL*": {"up"},
            "1 of sel**": {"low", "bee", "both"},
            "all of sel*": set(),
        }
        for cond, want in cases.items():
            with self.subTest(condition=cond):
                self.assertEqual(_hits(det.format(cond), events), want)
        # `1 of sel*` must not swallow SEL. Negating it therefore still matches the SEL event.
        self.assertIn("up", _hits(det.format("not 1 of sel*"), events))
        self.assertNotIn("low", _hits(det.format("not 1 of sel*"), events))
        self.assertNotIn("both", _hits(det.format("not 1 of sel*"), events))
        self._refuse(det.format("Sel"), "unknown selection 'Sel'")
        self._refuse(det.format("1 of Sel*"), "matches no selection")

    def test_values_stay_case_insensitive(self):
        params = _params("  sel:\n    user: Alice\n  condition: sel\n")
        self.assertTrue(sigma.matches(params, {"user": "alice"}))
        self.assertTrue(sigma.matches(params, {"user": "ALICE"}))
        self.assertFalse(sigma.matches(params, {"user": "bob"}))

    def test_private_names_follow_them(self):
        # `1 of <pattern>` is `them` restricted to the pattern. `_` names are in `them` only when
        # the pattern itself starts with `_`.
        det = ("  sel:\n    user: alice\n  xend:\n    src_ip: 203.0.113.9\n  xpriv:\n    host: web01\n"
               "  _priv:\n    dest_port: 22\n  _end:\n    dest_ip: 198.51.100.8\n"
               "  condition: {}\n")
        events = {
            "sel": {"user": "alice"},
            "end": {"src_ip": "203.0.113.9"},
            "xpriv": {"host": "web01"},
            "priv": {"dest_port": 22},
            "pend": {"dest_ip": "198.51.100.8"},
            "public": {"user": "alice", "src_ip": "203.0.113.9", "host": "web01"},
            "all": {"user": "alice", "src_ip": "203.0.113.9", "host": "web01",
                    "dest_port": 22, "dest_ip": "198.51.100.8"},
        }
        them = {"sel", "end", "xpriv", "public", "all"}
        self.assertEqual(_hits(det.format("1 of them"), events), them)
        self.assertEqual(_hits(det.format("1 OF THEM"), events), them)
        self.assertEqual(_hits(det.format("1 of *"), events), them)
        self.assertEqual(_hits(det.format("all of them"), events), {"public", "all"})
        self.assertEqual(_hits(det.format("all of *"), events), {"public", "all"})
        self.assertEqual(_hits(det.format("1 of *end"), events), {"end", "public", "all"})
        self.assertEqual(_hits(det.format("1 of *priv"), events), {"xpriv", "public", "all"})
        self.assertEqual(_hits(det.format("1 of _*"), events), {"priv", "pend", "all"})
        self.assertEqual(_hits(det.format("1 of _end"), events), {"pend", "all"})
        self.assertEqual(_hits(det.format("_priv"), events), {"priv", "all"})
        self.assertEqual(_hits(det.format("1 of _priv*"), events), {"priv", "all"})

    def test_star_positions_dots_and_hyphens_are_literal(self):
        det = ("  pre_sel:\n    user: pre\n  sel_mid:\n    user: mid\n  sel:\n    user: sel\n"
               "  notsel:\n    user: ns\n  abc:\n    src_ip: 203.0.113.1\n  axbxc:\n    src_ip: 203.0.113.2\n"
               "  ab:\n    src_ip: 203.0.113.3\n  ac:\n    src_ip: 203.0.113.4\n"
               "  foo.bar:\n    host: dot\n  fooXbar:\n    host: ex\n"
               "  sel-a:\n    dest_ip: 198.51.100.1\n  sel_a:\n    dest_ip: 198.51.100.2\n"
               "  sela:\n    dest_ip: 198.51.100.3\n"
               "  condition: {}\n")
        events = {
            "pre": {"user": "pre"}, "mid": {"user": "mid"}, "sel": {"user": "sel"}, "ns": {"user": "ns"},
            "abc": {"src_ip": "203.0.113.1"}, "ax": {"src_ip": "203.0.113.2"},
            "ab": {"src_ip": "203.0.113.3"}, "ac": {"src_ip": "203.0.113.4"},
            "dot": {"host": "dot"}, "ex": {"host": "ex"},
            "hy": {"dest_ip": "198.51.100.1"}, "us": {"dest_ip": "198.51.100.2"},
            "flat": {"dest_ip": "198.51.100.3"},
        }
        cases = {
            "1 of *sel": {"pre", "sel", "ns"},
            # sel* also names sel-a, sel_a, and sela, not only sel and sel_mid.
            "1 of sel*": {"mid", "sel", "hy", "us", "flat"},
            "1 of *sel*": {"pre", "mid", "sel", "ns", "hy", "us", "flat"},
            "1 of s*l": {"sel"},
            "1 of a*b*c": {"abc", "ax"},
            "1 of foo.bar": {"dot"},
            "1 of foo.bar*": {"dot"},
            "1 of foo*": {"dot", "ex"},
            "1 of sel-*": {"hy"},
            "1 of sel-a": {"hy"},
            # sel_* is sel_mid (user mid) and sel_a (dest us), not the hyphenated sel-a.
            "1 of sel_*": {"mid", "us"},
            "1 of sel": {"sel"},
        }
        for cond, want in cases.items():
            with self.subTest(condition=cond):
                self.assertEqual(_hits(det.format(cond), events), want)

    def test_them_keyword_is_exact_and_operators_are_words(self):
        det = ("  theme:\n    user: alice\n  Them_extra:\n    host: web01\n  other:\n    src_ip: 203.0.113.9\n"
               "  _them:\n    dest_port: 22\n  notsel:\n    dest_ip: 198.51.100.8\n"
               "  notepad:\n    event_type: auth_failure\n  near_host:\n    bytes: 9\n"
               "  condition: {}\n")
        events = {
            "theme": {"user": "alice"},
            "Them": {"host": "web01"},
            "other": {"src_ip": "203.0.113.9"},
            "priv": {"dest_port": 22},
            "notsel": {"dest_ip": "198.51.100.8"},
            "note": {"event_type": "auth_failure"},
            "near": {"bytes": 9},
        }
        self.assertEqual(_hits(det.format("1 of them*"), events), {"theme"})
        self.assertEqual(_hits(det.format("1 of Them*"), events), {"Them"})
        self.assertEqual(_hits(det.format("1 of them"), events),
                         {"theme", "Them", "other", "notsel", "note", "near"})
        # `notsel` / `notepad` / `near_host` are one identifier each, not `not` + the rest.
        self.assertEqual(_hits(det.format("notsel"), events), {"notsel"})
        self.assertEqual(_hits(det.format("notepad"), events), {"note"})
        self.assertEqual(_hits(det.format("not sel"), events) if False else
                         _hits(det.format("not notsel"), events),
                         {"theme", "Them", "other", "priv", "note", "near"})
        self.assertEqual(_hits(det.format("1 of near_*"), events), {"near"})
        self.assertEqual(_hits(det.format("notsel and(notepad)"), events), set())
        self.assertEqual(_hits(det.format("not(notsel)"), events),
                         {"theme", "Them", "other", "priv", "note", "near"})

    def test_whitespace_newlines_and_trailing_comment(self):
        det = ("  sel_a:\n    user: alice\n  sel_b:\n    src_ip: 203.0.113.9\n"
               "  condition: |-\n    sel_a\n    and not sel_b\n")
        events = {"a": {"user": "alice"}, "ab": {"user": "alice", "src_ip": "203.0.113.9"},
                  "b": {"src_ip": "203.0.113.9"}}
        self.assertEqual(_hits(det, events), {"a"})
        commented = ("  sel_a:\n    user: alice\n  sel_b:\n    src_ip: 203.0.113.9\n"
                     "  condition: sel_a and not sel_b # note\n")
        self.assertEqual(_hits(commented, events), {"a"})

    def test_refusals(self):
        base = "  sel:\n    user: x\n  other:\n    host: web01\n  condition: {}\n"
        cases = {
            "2 of sel*": "only '1 of' and 'all of'",
            "any of sel*": "only '1 of' and 'all of'",
            "sel near other": "'near' is not supported",
            "nope": "unknown selection 'nope'",
            "1 of missing*": "matches no selection",
            "1 of _*": "matches no selection",
            "(sel": "ends too early",
            "sel and": "ends too early",
            "1 of": "ends too early",
            "sel and or other": "unexpected 'or'",
            "()": "unexpected ')'",
            "sel)": "unexpected ')'",
            "1 of sel?": "unexpected character '?'",
            "sel | count() by user > 1": "aggregations",
        }
        for cond, reason in cases.items():
            with self.subTest(condition=cond):
                self._refuse(base.format(cond), reason)
        self._refuse("  sel:\n    user: x\n  condition:\n    - sel\n", "lists of conditions")

    def test_paren_depth_is_capped(self):
        ok = "(" * 12 + "sel" + ")" * 12
        _params(f"  sel:\n    user: x\n  condition: {ok}\n", title="Deep Ok")
        too_deep = "(" * 13 + "sel" + ")" * 13
        self._refuse(f"  sel:\n    user: x\n  condition: {too_deep}\n", "nested too deeply")


if __name__ == "__main__":
    unittest.main()
