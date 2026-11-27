"""Search-rule samples must use the stored forms the matcher compares, and the window must keep its edges.

A labeled sample is the only way to enable a promoted search. The engine stores synthetic as 0 or 1,
a complete IP in ingest form, and event_type as the catalog spelling. The sample has to do the same or a
rule whose query uses those fields can never pass and can never be enabled.
"""

import json
import unittest
from datetime import timedelta

from watchpost import search_rules
from watchpost.db import iso, parse_iso

T0 = parse_iso("2025-03-01T12:00:00.000Z")
FLAG_ERROR = "synthetic must be 0, 1, true or false"


def definition(**kw):
    return {"group_by": "user", "threshold": 1, "window_minutes": 5, "severity": "high", **kw}


def compiled(name, query, **kw):
    return search_rules.compile_rule(name, query, definition(**kw))


def sample(malicious, benign):
    return search_rules.validate_sample({"malicious": malicious, "benign": benign})


class SyntheticSampleTests(unittest.TestCase):
    def test_words_and_json_flags_store_the_engine_integer(self):
        raw = {"user": "alice", "synthetic": True}
        shared = {"user": "alice", "synthetic": 1}
        out = sample(
            [raw, shared, shared, {"user": "alice", "synthetic": "TRUE"}, {"user": "alice", "synthetic": "1"}],
            [{"user": "bob", "synthetic": False}, {"user": "bob", "synthetic": "false"},
             {"user": "bob", "synthetic": 0}, {"user": "bob", "synthetic": None}],
        )
        self.assertEqual([e["synthetic"] for e in out["malicious"]], [1, 1, 1, 1, 1])
        self.assertTrue(all(type(e["synthetic"]) is int for e in out["malicious"]))
        self.assertEqual([e["synthetic"] for e in out["benign"]], [0, 0, 0, None])
        # The caller's objects stay as submitted. A repeated dict is not rewritten in place.
        self.assertIs(raw["synthetic"], True)
        self.assertEqual(shared["synthetic"], 1)
        self.assertIs(type(shared["synthetic"]), int)

        params = compiled("Labelled logins", "synthetic:TRUE")["params"]
        # The matcher still compares the integer the events table stores, not the hunt word.
        self.assertTrue(search_rules.matches(params, {"user": "alice", "synthetic": 1}))
        self.assertFalse(search_rules.matches(params, {"user": "alice", "synthetic": "1"}))
        self.assertFalse(search_rules.matches(params, {"user": "alice"}))
        result = search_rules.sample_result(params, json.loads(json.dumps(out)))
        self.assertTrue(result["passes"], result["summary"])

    def test_other_synthetic_values_are_refused_with_the_hunt_error(self):
        for value in ("yes", "truİe", "trüe", " 1 ", "", 2, 1.0, "nope"):
            with self.subTest(value=value):
                with self.assertRaises(search_rules.SearchRuleError) as ctx:
                    sample([{"user": "alice", "synthetic": value}], [{"user": "bob", "synthetic": 0}])
                self.assertIn(FLAG_ERROR, str(ctx.exception))
                self.assertIn("sample.malicious[0].synthetic", str(ctx.exception))
        with self.assertRaises(search_rules.SearchRuleError) as ctx:
            search_rules.parse_filter("synthetic:yes")
        self.assertIn(FLAG_ERROR, str(ctx.exception))

    def test_missing_synthetic_does_not_match_a_flag_and_not_keeps_it(self):
        present = compiled("Labelled only", "synthetic:1")["params"]
        missed = search_rules.sample_result(present, sample(
            [{"user": "alice"}], [{"user": "bob", "synthetic": 0}]))
        self.assertFalse(missed["passes"])
        self.assertEqual(missed["missed"], [0])
        self.assertIn("raise no finding", missed["summary"])

        excluded = compiled("Real logins", "NOT synthetic:1")["params"]
        quiet = search_rules.sample_result(excluded, sample(
            [{"user": "alice", "synthetic": 0}], [{"user": "bob", "synthetic": "true"}]))
        self.assertTrue(quiet["passes"], quiet["summary"])
        # Missing is not 1, so NOT synthetic:1 keeps it and a benign look-alike with no flag fires.
        fired = search_rules.sample_result(excluded, sample(
            [{"user": "alice", "synthetic": "false"}], [{"user": "bob"}]))
        self.assertFalse(fired["passes"])
        self.assertEqual(fired["fired"], [0])

    def test_source_stays_allowed_and_unloaded_fields_stay_unknown(self):
        out = sample([{"user": "alice", "source": "Lab", "synthetic": "0"}], [{"user": "bob", "source": "lab"}])
        self.assertEqual(out["malicious"][0]["source"], "Lab")
        with self.assertRaises(search_rules.SearchRuleError) as ctx:
            sample([{"outcome": "failure"}], [{"user": "bob"}])
        self.assertIn("unknown field", str(ctx.exception))


class StoredFormSampleTests(unittest.TestCase):
    def test_ip_spellings_of_one_address_share_a_group_and_match(self):
        params = compiled("v6 burst", "src_ip:2001:DB8::1", group_by="src_ip", threshold=3)["params"]
        spellings = ["2001:DB8::1", "2001:0db8:0:0:0:0:0:1", " 2001:db8::1 "]
        out = sample(
            [{"src_ip": spelling, "user": "alice"} for spelling in spellings],
            [{"src_ip": "192.0.2.1", "user": "alice"}, {"dest_ip": "2001:DB8::1", "user": "alice"}],
        )
        self.assertEqual([e["src_ip"] for e in out["malicious"]], ["2001:db8::1"] * 3)
        self.assertEqual(out["benign"][1]["dest_ip"], "2001:db8::1")
        result = search_rules.sample_result(params, out)
        self.assertTrue(result["passes"], result["summary"])
        # Not an address: kept as typed, and equality does not treat it as the canonical form.
        odd = sample([{"src_ip": "999.1.1.1", "user": "alice"}], [{"src_ip": "10.0.0.1", "user": "bob"}])
        self.assertEqual(odd["malicious"][0]["src_ip"], "999.1.1.1")
        self.assertFalse(search_rules.matches(params, {"src_ip": "2001:DB8::1"}))
        self.assertTrue(search_rules.matches(params, {"src_ip": "2001:db8::1"}))

    def test_event_type_case_binds_the_catalog_and_host_spelling_stays(self):
        params = compiled("Failures", "event_type:Auth_Failure", threshold=2)["params"]
        out = sample(
            [{"event_type": "Auth_Failure", "user": "alice", "host": "WEB01"},
             {"event_type": " AUTH_FAILURE ", "user": "alice", "host": "web01"}],
            [{"event_type": "auth_success", "user": "alice", "host": "WEB01"}],
        )
        self.assertEqual([e["event_type"] for e in out["malicious"]], ["auth_failure", "auth_failure"])
        self.assertEqual([e["host"] for e in out["malicious"]], ["WEB01", "web01"])
        self.assertEqual(out["benign"][0]["event_type"], "auth_success")
        result = search_rules.sample_result(params, out)
        self.assertTrue(result["passes"], result["summary"])
        # A lookalike that is not a catalog name stays typed, so it does not become auth_failure.
        odd = sample([{"event_type": "auth-failure", "user": "alice"}], [{"user": "bob"}])
        self.assertEqual(odd["malicious"][0]["event_type"], "auth-failure")
        self.assertFalse(search_rules.matches(params, {"event_type": "Auth_Failure", "user": "alice"}))
        self.assertTrue(search_rules.matches(params, {"event_type": "auth_failure", "user": "alice"}))


class RunEdgeTests(unittest.TestCase):
    def test_window_is_inclusive_and_same_timestamps_count(self):
        params = compiled("Web burst", "event_type:web_request", group_by="src_ip", threshold=3)["params"]

        def run(offsets, **fields):
            events = [{"id": n + 1, "ts": iso(T0 + timedelta(seconds=s)), "event_type": "web_request",
                       "src_ip": "203.0.113.9", **fields} for n, s in enumerate(offsets)]
            return search_rules.run(events, params)

        self.assertEqual(len(run([0, 150, 300])), 1)
        self.assertEqual(run([0, 150, 300.001]), [])
        finding, = run([0, 0, 0])
        self.assertEqual(finding["event_ids"], [1, 2, 3])

    def test_zero_port_counts_and_a_blank_user_does_not(self):
        by_port = compiled("Closed port", "event_type:web_request", group_by="dest_port", threshold=3)["params"]
        ports = [{"id": n, "ts": iso(T0 + timedelta(seconds=n)), "event_type": "web_request", "dest_port": 0}
                 for n in range(1, 4)]
        finding, = search_rules.run(ports, by_port)
        self.assertEqual((finding["group_key"], finding["event_ids"]), ("0", [1, 2, 3]))

        by_user = compiled("Accounts", "event_type:web_request", group_by="user", threshold=3)["params"]
        blanks = [{"id": n, "ts": iso(T0 + timedelta(seconds=n)), "event_type": "web_request", "user": ""}
                  for n in range(1, 4)]
        self.assertEqual(search_rules.run(blanks, by_user), [])
        folded = [{"id": n, "ts": iso(T0 + timedelta(seconds=n)), "event_type": "web_request", "user": user}
                  for n, user in enumerate(["alice", "Alice", "ALICE"], 1)]
        finding, = search_rules.run(folded, by_user)
        self.assertEqual(finding["group_key"], "alice")
        hosts = [{"id": n, "ts": iso(T0 + timedelta(seconds=n)), "event_type": "web_request", "host": host}
                 for n, host in enumerate(["WEB01", "WEB01", "web01", "web01"], 1)]
        by_host = compiled("Hosts", "event_type:web_request", group_by="host", threshold=3)["params"]
        self.assertEqual(search_rules.run(hosts, by_host), [])
