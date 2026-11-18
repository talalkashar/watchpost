"""Edge cases for ecs.to_ecs that tests/test_portability.py does not assert.

ecs.py exposes one public function. These tests cover empty input, values that
are present but falsy, outcome strings that must not enter the ECS catalog,
category and type list copies, and document key order.
"""

import unittest

from watchpost import ecs
from watchpost.normalize import EVENT_TYPES

# Catalog types the module docstring leaves unmapped. cloud_api_call is already
# asserted in EcsTests, so the category check below skips it.
LEFT_OUT = EVENT_TYPES - ecs.EVENT_TYPE_CATEGORIES.keys()


class ToEcsEdgeTests(unittest.TestCase):
    def test_empty_and_explicit_none_emit_only_event_kind(self):
        kind_only = {"event": {"kind": "event"}}
        self.assertEqual(ecs.to_ecs({}), kind_only)
        blank = {field: None for field in (
            *ecs.FIELD_MAP, "outcome", "synthetic", *ecs.UNMAPPED)}
        self.assertEqual(ecs.to_ecs(blank), kind_only)
        self.assertEqual(blank["bytes"], None)  # the call does not write the input
        for bad in (None, [], "auth_failure", 0):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(AttributeError):
                    ecs.to_ecs(bad)

    def test_zero_and_empty_string_stay_and_unknown_keys_drop(self):
        # None is omitted. 0 and "" are real values, including under watchpost.*.
        # labels.synthetic follows Python truthiness, so the string "false" is true.
        event = {
            "id": 0, "source": "", "src_ip": "", "user": "", "message": "",
            "dest_port": 0, "bytes": 0, "severity": "", "batch_id": "",
            "synthetic": "", "notes": "not-a-field", "technique": "T1110",
        }
        original = dict(event)
        doc = ecs.to_ecs(event)
        self.assertEqual(event, original)
        self.assertEqual(doc["event"]["id"], "0")
        self.assertEqual(doc["event"]["module"], "")
        self.assertEqual(doc["source"], {"ip": ""})
        self.assertEqual(doc["user"], {"name": ""})
        self.assertEqual(doc["message"], "")
        self.assertEqual(doc["destination"], {"port": 0})
        self.assertEqual(doc["watchpost"], {"severity": "", "bytes": 0, "batch_id": ""})
        self.assertEqual(list(doc["watchpost"]), ["severity", "bytes", "batch_id"])
        self.assertEqual(doc["labels"], {"synthetic": "false"})
        self.assertNotIn("labels", ecs.to_ecs({"synthetic": None}))
        self.assertEqual(ecs.to_ecs({"synthetic": "false"})["labels"], {"synthetic": "true"})
        self.assertNotIn("notes", doc)
        self.assertNotIn("technique", doc)
        self.assertNotIn("T1110", str(doc))

    def test_outcome_near_misses_stay_under_watchpost(self):
        # No strip and no prefix match. "Failure" / dotted I / Kelvin are covered elsewhere.
        for spelling in ("", " ", "failure ", " failure", "failures", "success\n", "unknown\t", "FAILURE "):
            with self.subTest(spelling=spelling):
                doc = ecs.to_ecs({"outcome": spelling})
                self.assertNotIn("outcome", doc["event"])
                self.assertEqual(doc["watchpost"], {"outcome": spelling})

    def test_mapped_types_copy_lists_and_unlisted_types_omit_them(self):
        self.assertTrue(set(ecs.EVENT_TYPE_CATEGORIES) <= EVENT_TYPES)
        for event_type, (category, kinds) in ecs.EVENT_TYPE_CATEGORIES.items():
            if event_type == "auth_failure":
                continue  # the sample event already asserts this pair
            with self.subTest(event_type=event_type):
                doc = ecs.to_ecs({"event_type": event_type})
                self.assertEqual(doc["event"]["action"], event_type)
                self.assertEqual(doc["event"]["category"], list(category))
                self.assertEqual(doc["event"]["type"], list(kinds))
                self.assertIsNot(doc["event"]["category"], category)
                self.assertIsNot(doc["event"]["type"], kinds)
        deny = ecs.to_ecs({"event_type": "fw_deny"})
        deny["event"]["category"].append("host")
        deny["event"]["type"].append("end")
        self.assertEqual(ecs.EVENT_TYPE_CATEGORIES["fw_deny"], (["network"], ["denied", "connection"]))
        fresh = ecs.to_ecs({"event_type": "fw_deny"})
        self.assertEqual(fresh["event"]["category"], ["network"])
        self.assertEqual(fresh["event"]["type"], ["denied", "connection"])
        self.assertIsNot(fresh["event"]["category"], deny["event"]["category"])
        for event_type in sorted(LEFT_OUT):
            with self.subTest(event_type=event_type):
                doc = ecs.to_ecs({"event_type": event_type})
                self.assertEqual(doc["event"]["action"], event_type)
                self.assertNotIn("type", doc["event"])
                if event_type != "cloud_api_call":
                    self.assertNotIn("category", doc["event"])
        for event_type in ("", "auth_failure ", "FW_DENY"):
            with self.subTest(event_type=event_type):
                doc = ecs.to_ecs({"event_type": event_type})
                self.assertEqual(doc["event"]["action"], event_type)
                self.assertNotIn("category", doc["event"])
                self.assertNotIn("type", doc["event"])

    def test_key_order_follows_the_map_then_outcome_then_labels(self):
        fields = {
            "raw": "line", "message": "m", "dest_port": 9, "dest_ip": "10.0.0.2",
            "src_ip": "192.0.2.1", "user": "bob", "event_type": "web_error",
            "host": "web01", "source": "nginx", "ingested_at": "t1", "ts": "t0", "id": 4,
            "synthetic": 1, "batch_id": "b", "bytes": 8, "severity": "high",
        }
        custom = ecs.to_ecs({**fields, "outcome": "nope"})
        self.assertEqual(list(custom), [
            "event", "@timestamp", "host", "user", "source", "destination", "message", "watchpost", "labels"])
        self.assertEqual(list(custom["event"]), [
            "kind", "id", "ingested", "module", "action", "original", "category", "type"])
        self.assertEqual(list(custom["destination"]), ["ip", "port"])
        self.assertEqual(list(custom["watchpost"]), ["outcome", "severity", "bytes", "batch_id"])
        mapped = ecs.to_ecs({**fields, "outcome": "unknown"})
        self.assertEqual(list(mapped), [
            "event", "@timestamp", "host", "user", "source", "destination", "message", "labels", "watchpost"])
        self.assertEqual(list(mapped["event"]), [
            "kind", "id", "ingested", "module", "action", "original", "category", "type", "outcome"])
        self.assertEqual(list(mapped["watchpost"]), ["severity", "bytes", "batch_id"])


if __name__ == "__main__":
    unittest.main()
