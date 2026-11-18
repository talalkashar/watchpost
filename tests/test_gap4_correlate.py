"""Edge cases for the public correlation helpers that the other tests do not assert."""

import unittest

from watchpost import correlate


def _at(seconds):
    return f"2026-09-15T10:{seconds // 60:02d}:{seconds % 60:02d}.000Z"


def _alert(aid, seconds, incident_id=None, sightings=None, **entities):
    """One instant alert. Entity values are kept as given, including blanks."""
    ts = _at(seconds)
    row = {
        "id": aid,
        "first_seen": ts,
        "last_seen": ts,
        "severity": "medium",
        "incident_id": incident_id,
        "entities": {kind: list(values) for kind, values in entities.items()},
    }
    if sightings is not None:
        row["sightings"] = sightings
    return row


class EntityKeyTests(unittest.TestCase):
    def test_empty_blank_and_non_strings(self):
        # Blanks stay blanks, and a surrounding space is part of the key.
        self.assertEqual(correlate.entity_key("user", ""), "")
        self.assertEqual(correlate.entity_key("user", " Erin "), " erin ")
        self.assertEqual(correlate.entity_key("src_ip", ""), "")
        # Anything that is not text is str()'d, then account and host still fold ASCII.
        self.assertEqual(correlate.entity_key("src_ip", None), "None")
        self.assertEqual(correlate.entity_key("user", None), "none")
        self.assertEqual(correlate.entity_key("host", 10), "10")
        # Only account and host fold ASCII. Another kind keeps the stored letters.
        self.assertEqual(correlate.entity_key("process", "WEB01"), "WEB01")


class RuleSummaryTests(unittest.TestCase):
    def test_minutes_floor_at_the_minute_boundaries(self):
        def sentence(minutes):
            return (
                "Alerts that share a source IP, account, or host within "
                f"{minutes} minutes are grouped into this incident."
            )

        # The sentence uses whole minutes, rounded down. 59s is still 0; 60s is 1.
        self.assertEqual(correlate.rule_summary(0), sentence(0))
        self.assertEqual(correlate.rule_summary(59), sentence(0))
        self.assertEqual(correlate.rule_summary(60), sentence(1))
        self.assertEqual(correlate.rule_summary(119), sentence(1))
        self.assertEqual(correlate.rule_summary(120), sentence(2))


class CorrelateEdgeTests(unittest.TestCase):
    def test_empty_input_and_missing_entities(self):
        self.assertEqual(correlate.correlate([]), [])

        bare = {"id": 2, "first_seen": _at(0), "last_seen": _at(0), "entities": None}
        missing = {"id": 1, "first_seen": _at(5), "last_seen": _at(5)}
        groups = correlate.correlate([bare, missing], window_seconds=600)
        self.assertEqual(
            [(g["incident_id"], g["alert_ids"], g["new_alert_ids"]) for g in groups],
            [(None, [1], [1]), (None, [2], [2])],
        )

    def test_blank_users_share_a_key_and_a_space_does_not(self):
        blank = [_alert(1, 0, user=[""]), _alert(2, 30, user=[""])]
        self.assertEqual(
            [g["alert_ids"] for g in correlate.correlate(blank, window_seconds=600)],
            [[1, 2]],
        )
        spaced = [_alert(1, 0, user=[""]), _alert(2, 30, user=[" "])]
        self.assertEqual(
            [g["alert_ids"] for g in correlate.correlate(spaced, window_seconds=600)],
            [[1], [2]],
        )

    def test_empty_sightings_fall_back_to_entities(self):
        # An empty sighting list is the same as omitting sightings: the entity lists count.
        alerts = [
            _alert(1, 0, src_ip=["203.0.113.5"], sightings=[]),
            _alert(2, 30, src_ip=["203.0.113.5"]),
        ]
        self.assertEqual(
            [g["alert_ids"] for g in correlate.correlate(alerts, window_seconds=600)],
            [[1, 2]],
        )

    def test_sightings_ignore_entities_and_a_later_sighting_reopens_the_window(self):
        # The shared host is only on the entity lists. Sightings name different accounts,
        # so the alerts stay apart.
        shadowed = [
            _alert(1, 0, host=["web01"], sightings=[("user", "ann", _at(0))]),
            _alert(2, 30, host=["web01"], sightings=[("user", "bob", _at(30))]),
        ]
        self.assertEqual(
            [g["alert_ids"] for g in correlate.correlate(shadowed, window_seconds=600)],
            [[1], [2]],
        )

        # A sighting kind outside source IP, account, and host still links the alerts.
        process = [
            _alert(1, 0, sightings=[("process", "malware.exe", _at(0))]),
            _alert(2, 30, sightings=[("process", "malware.exe", _at(30))]),
        ]
        self.assertEqual(
            [g["alert_ids"] for g in correlate.correlate(process, window_seconds=600)],
            [[1, 2]],
        )

        # Sightings at t=0 and t=2000. The window is 600s, so t=601 and t=1399 sit in the
        # gap, and t=1400 meets the second sighting exactly.
        def pair(at):
            long = _alert(1, 0, src_ip=["203.0.113.5"], sightings=[
                ("src_ip", "203.0.113.5", _at(0)),
                ("src_ip", "203.0.113.5", _at(2000)),
            ])
            other = _alert(2, at, src_ip=["203.0.113.5"], sightings=[
                ("src_ip", "203.0.113.5", _at(at)),
            ])
            return correlate.correlate([long, other], window_seconds=600)

        self.assertEqual([g["alert_ids"] for g in pair(601)], [[1], [2]])
        self.assertEqual([g["alert_ids"] for g in pair(1399)], [[1], [2]])
        self.assertEqual([g["alert_ids"] for g in pair(1400)], [[1, 2]])

    def test_zero_window_links_only_the_same_timestamp(self):
        ip = "203.0.113.9"
        same = [_alert(1, 0, src_ip=[ip]), _alert(2, 0, src_ip=[ip])]
        apart = [_alert(1, 0, src_ip=[ip]), _alert(2, 1, src_ip=[ip])]
        self.assertEqual([g["alert_ids"] for g in correlate.correlate(same, window_seconds=0)], [[1, 2]])
        self.assertEqual([g["alert_ids"] for g in correlate.correlate(apart, window_seconds=0)], [[1], [2]])

    def test_group_order_follows_incident_id_not_input_order(self):
        # Incident 4's alerts share no entity and still stay one group.
        # The new alert touches incident 9 (earlier) and incident 2 (later). The lower id wins.
        alerts = [
            _alert(3, 4, ip=["203.0.113.5"], user=["erin"]),
            _alert(8, 12, host=["db01"], incident_id=4),
            _alert(7, 0, ip=["203.0.113.5"], incident_id=9),
            _alert(6, 2, user=["frank"], incident_id=4),
            _alert(4, 8, user=["erin"], incident_id=2),
        ]
        expected = [
            {"incident_id": 2, "alert_ids": [3, 4], "new_alert_ids": [3]},
            {"incident_id": 4, "alert_ids": [6, 8], "new_alert_ids": []},
            {"incident_id": 9, "alert_ids": [7], "new_alert_ids": []},
        ]
        self.assertEqual(correlate.correlate(alerts), expected)
        self.assertEqual(correlate.correlate(list(reversed(alerts))), expected)


class ShouldOpenTests(unittest.TestCase):
    def test_empty_wrong_case_and_missing_severity(self):
        self.assertFalse(correlate.should_open([]))
        # The check is the exact word critical. A capital C does not open an incident.
        self.assertFalse(correlate.should_open([{"severity": "Critical"}]))
        # Two alerts open an incident before any severity is read.
        self.assertTrue(correlate.should_open([{"id": 1}, {"id": 2}]))
        with self.assertRaises(KeyError):
            correlate.should_open([{}])


class SummarizeEdgeTests(unittest.TestCase):
    def test_empty_alerts_raise(self):
        with self.assertRaises(ValueError):
            correlate.summarize([])

    def test_long_path_uses_the_ends_and_the_span_is_min_and_max(self):
        # Four tactics, scrambled, and no entities. Times are not in input order.
        alerts = [
            {"severity": "low", "first_seen": "2026-09-15T10:40:00.000Z",
             "last_seen": "2026-09-15T10:45:00.000Z", "tactics": ["Exfiltration"],
             "entities": {}, "synthetic": 1},
            {"severity": "medium", "first_seen": "2026-09-15T10:05:00.000Z",
             "last_seen": "2026-09-15T10:50:00.000Z", "tactics": ["Execution", "Reconnaissance"],
             "entities": None, "synthetic": 1},
            {"severity": "high", "first_seen": "2026-09-15T10:20:00.000Z",
             "last_seen": "2026-09-15T10:21:00.000Z", "tactics": ["Initial Access"],
             "synthetic": 1},
        ]
        summary = correlate.summarize(alerts)
        self.assertEqual(summary["title"], "Reconnaissance → … → Exfiltration (4 tactics)")
        self.assertEqual(summary["stages"], [
            "Reconnaissance", "Initial Access", "Execution", "Exfiltration",
        ])
        self.assertEqual((summary["severity"], summary["escalated"]), ("critical", True))
        self.assertEqual(summary["first_seen"], "2026-09-15T10:05:00.000Z")
        self.assertEqual(summary["last_seen"], "2026-09-15T10:50:00.000Z")
        self.assertEqual(summary["entities"], {"src_ip": [], "user": [], "host": []})
        self.assertEqual((summary["alert_count"], summary["synthetic"]), (3, 1))

    def test_critical_does_not_rise_further_and_unknown_severity_bumps_from_info(self):
        capped = correlate.summarize([{
            "severity": "critical",
            "first_seen": "2026-09-15T10:00:00.000Z",
            "last_seen": "2026-09-15T10:01:00.000Z",
            "tactics": ["Reconnaissance", "Initial Access", "Execution"],
            "entities": {"src_ip": ["203.0.113.5"]},
            "synthetic": 0,
        }])
        self.assertEqual((capped["severity"], capped["escalated"]), ("critical", True))

        def row(severity, tactics, minute):
            ts = f"2026-09-15T10:{minute:02d}:00.000Z"
            return {"severity": severity, "first_seen": ts, "last_seen": ts,
                    "tactics": tactics, "entities": {}, "synthetic": 1}

        # An unknown word is kept as written until escalation, which starts from info.
        plain = correlate.summarize([row("severe", ["Initial Access"], 1)])
        self.assertEqual((plain["severity"], plain["escalated"]), ("severe", False))
        raised = correlate.summarize([
            row("severe", ["Reconnaissance"], 1),
            row("severe", ["Initial Access"], 2),
            row("severe", ["Execution"], 3),
        ])
        self.assertEqual((raised["severity"], raised["escalated"]), ("low", True))
        # Tied ranks keep the earlier alert's spelling.
        self.assertEqual(
            correlate.summarize([row("severe", [], 1), row("info", [], 2)])["severity"],
            "severe",
        )
        self.assertEqual(
            correlate.summarize([row("info", [], 1), row("severe", [], 2)])["severity"],
            "info",
        )

    def test_blank_and_non_string_entities_are_stored_as_keys(self):
        ts = "2026-09-15T10:00:00.000Z"
        summary = correlate.summarize([{
            "severity": "low",
            "first_seen": ts,
            "last_seen": ts,
            "tactics": [],
            "synthetic": 1,
            "entities": {"user": ["", 5], "src_ip": [None], "host": [" Web01 "]},
        }])
        self.assertEqual(summary["entities"]["user"], ["", "5"])
        self.assertEqual(summary["entities"]["src_ip"], ["None"])
        self.assertEqual(summary["entities"]["host"], [" web01 "])
        # The title keeps three entities. The blank account still takes a slot, so the host is left out.
        self.assertEqual(summary["title"], "Related alerts: None, , 5")


if __name__ == "__main__":
    unittest.main()
