import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from tests.helpers import ServerTestCase
from watchpost import hunt
from watchpost.db import connect, init_schema

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)

# (ts, event_type, user, src_ip, host, dest_port, message)
EVENTS = [
    ("2026-10-07T11:00:00.000Z", "auth_failure", "alice", "10.0.0.5", "web01", 22, "invalid password"),
    ("2026-10-07T11:05:00.000Z", "auth_failure", "bob", "10.0.0.5", "web01", 22, "invalid password"),
    ("2026-10-07T11:10:00.000Z", "auth_failure", "carol", "10.0.0.5", "web02", 22, "invalid password"),
    ("2026-10-07T10:59:59.999Z", "auth_failure", "alice", "10.0.0.5", "web02", 22, "invalid password"),
    ("2026-10-07T08:30:00.000Z", "auth_failure", "alice", "203.0.113.45", "web01", 22, "pipe a | b here"),
    ("2026-10-07T08:31:00.000Z", "auth_failure", "alice", "203.0.113.45", "web01", 443, "invalid password"),
    ("2026-10-07T11:20:00.000Z", "auth_success", "alice", "198.51.100.7", "db01", None, "accepted"),
    ("2026-10-07T11:30:00.000Z", "auth_failure", "x' OR 1=1 --", "10.0.0.6", "web01", None, "odd user"),
    ("2026-10-07T11:40:00.000Z", "process_start", None, None, "web01", None, "no ip"),
]


def insert(conn, rows):
    for (ts, et, user, src, host, port, msg) in rows:
        conn.execute("INSERT INTO events(ts, ingested_at, source, host, event_type, severity, user, src_ip,"
                     " message, dest_port, synthetic) VALUES (?,?,?,?,?,?,?,?,?,?,0)",
                     (ts, ts, "lab", host, et, "low", user, src, msg, port))


def memory_db(rows=EVENTS):
    conn = connect(":memory:")
    init_schema(conn)
    insert(conn, rows)
    return conn


class StatsTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text}, now=NOW)

    def test_stats_count_by_one_field_sorted_descending(self):
        data = self.run_q("event_type:auth_failure | stats count by src_ip")
        self.assertEqual(data["kind"], "stats")
        self.assertEqual(data["columns"], ["src_ip", "count"])
        self.assertEqual(data["rows"], [["10.0.0.5", 4], ["203.0.113.45", 2], ["10.0.0.6", 1]])
        self.assertEqual((data["truncated"], data["groups_omitted"]), (False, 0))
        self.assertEqual(data["query"], "event_type:auth_failure | stats count by src_ip")
        self.assertEqual(data["filter"], "event_type:auth_failure")
        self.assertEqual([t["text"] for t in data["terms"]], ["event_type = auth_failure"])

    def test_stats_by_two_fields_and_without_by(self):
        data = self.run_q("event_type:auth_failure | stats count by src_ip, host")
        self.assertEqual(data["columns"], ["src_ip", "host", "count"])
        # Ties on the count sort by the group values, so the order is stable.
        self.assertEqual(data["rows"], [["10.0.0.5", "web01", 2], ["10.0.0.5", "web02", 2],
                                        ["203.0.113.45", "web01", 2], ["10.0.0.6", "web01", 1]])
        self.assertEqual(self.run_q("event_type:auth_failure | stats count by src_ip,host")["rows"], data["rows"])
        total = self.run_q("| stats count")
        self.assertEqual((total["columns"], total["rows"]), (["count"], [[len(EVENTS)]]))
        self.assertEqual((total["truncated"], total["groups_omitted"]), (False, 0))

    def test_dc_and_count_distinct(self):
        data = self.run_q("| stats count, dc(user) by src_ip")
        self.assertEqual(data["columns"], ["src_ip", "count", "dc(user)"])
        self.assertEqual(data["rows"][0], ["10.0.0.5", 4, 3])
        self.assertIn(["203.0.113.45", 2, 1], data["rows"])
        same = self.run_q("| stats count, count(distinct user) by src_ip")
        self.assertEqual((same["columns"], same["rows"]), (data["columns"], data["rows"]))
        self.assertEqual(self.run_q("| stats dc(host)")["rows"], [[3]])

    def test_groups_skip_events_without_the_field(self):
        rows = self.run_q("| stats count by src_ip")["rows"]
        self.assertNotIn(None, [r[0] for r in rows])
        self.assertEqual(sum(r[1] for r in rows), len(EVENTS) - 1)

    def test_port_and_flag_group(self):
        self.assertEqual(self.run_q("| stats count by dest_port")["rows"], [[22, 5], [443, 1]])
        self.assertEqual(self.run_q("| stats count by synthetic")["rows"], [[0, len(EVENTS)]])

    def test_group_cap_truncates_at_1000(self):
        rows = [(f"2026-10-07T09:00:{n % 60:02d}.000Z", "fw_deny", None, f"10.9.{n // 250}.{n % 250}", "fw", None, "d")
                for n in range(1003)]
        conn = memory_db(rows)
        self.addCleanup(conn.close)
        data = hunt.run(conn, {"q": "| stats count by src_ip"}, now=NOW)
        self.assertEqual((len(data["rows"]), data["truncated"], data["groups_omitted"]), (1000, True, 3))
        data = hunt.run(conn, {"q": "src_ip:10.9.0.* | stats count by src_ip"}, now=NOW)
        self.assertEqual((len(data["rows"]), data["truncated"], data["groups_omitted"]), (250, False, 0))

    def test_groups_omitted_names_the_group_past_the_cap(self):
        # One event per account, so the order is the folded name. The last name is the one left out.
        # An event with no account is not a group and is not omitted.
        rows = [("2026-10-07T09:00:00.000Z", "auth_failure", f"user-{n:04d}", "203.0.113.10", "web01", None, "d")
                for n in range(1001)]
        rows.append(("2026-10-07T09:00:00.000Z", "auth_failure", None, "203.0.113.10", "web01", None, "blank"))
        conn = memory_db(rows)
        self.addCleanup(conn.close)
        data = hunt.run(conn, {"q": "| stats count by user"}, now=NOW)
        self.assertEqual(len(data["rows"]), 1000)
        self.assertEqual((data["truncated"], data["groups_omitted"]), (True, 1))
        self.assertEqual(data["rows"][0], ["user-0000", 1])
        self.assertEqual(data["rows"][-1], ["user-0999", 1])
        self.assertNotIn("user-1000", [row[0] for row in data["rows"]])
        exact = memory_db(rows[:1000])
        self.addCleanup(exact.close)
        fitted = hunt.run(exact, {"q": "| stats count by user"}, now=NOW)
        self.assertEqual((len(fitted["rows"]), fitted["truncated"], fitted["groups_omitted"]), (1000, False, 0))
        self.assertEqual(fitted["rows"][-1], ["user-0999", 1])
        empty = self.run_q("user:nobody | stats count by src_ip")
        self.assertEqual((empty["rows"], empty["truncated"], empty["groups_omitted"]), ([], False, 0))
        text = (Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md").read_text()
        self.assertIn("`groups_omitted` is how many groups were past that cap", text)


class TopTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text}, now=NOW)

    def test_top_with_count_and_percent_of_matched_events(self):
        data = self.run_q("event_type:auth_failure | top src_ip")
        self.assertEqual(data["kind"], "top")
        self.assertEqual(data["columns"], ["src_ip", "count", "percent"])
        # 7 matched events: 4, 2 and 1 of them.
        self.assertEqual(data["rows"], [["10.0.0.5", 4, 57.14], ["203.0.113.45", 2, 28.57], ["10.0.0.6", 1, 14.29]])
        self.assertFalse(data["truncated"])

    def test_top_n(self):
        data = self.run_q("event_type:auth_failure | top 2 src_ip")
        self.assertEqual([r[0] for r in data["rows"]], ["10.0.0.5", "203.0.113.45"])
        self.assertTrue(data["truncated"])
        self.assertEqual(self.run_q("| top 100 user")["rows"][0], ["alice", 5, 55.56])
        for bad in ["| top 0 user", "| top 101 user", "| top", "| top 5", "| top user host", "| top -1 user"]:
            with self.subTest(bad=bad), self.assertRaises(hunt.HuntError) as ctx:
                self.run_q(bad)
            self.assertIn("top", str(ctx.exception))

    def test_top_on_no_matches(self):
        data = self.run_q("user:nobody | top src_ip")
        self.assertEqual((data["rows"], data["truncated"], data["total"], data["missing"]), ([], False, 0, 0))

    def test_top_names_total_and_events_missing_the_field(self):
        # One stored event has no source IP. Percents stay shares of every match, so they sum under 100.
        data = self.run_q("| top src_ip")
        self.assertEqual((data["total"], data["missing"]), (len(EVENTS), 1))
        self.assertEqual(data["rows"], [["10.0.0.5", 4, 44.44], ["203.0.113.45", 2, 22.22],
                                        ["10.0.0.6", 1, 11.11], ["198.51.100.7", 1, 11.11]])
        self.assertEqual(round(sum(row[2] for row in data["rows"]), 2), 88.88)
        # A filter where every match has the field: missing is 0 and the percents sum to 100.
        complete = self.run_q("event_type:auth_failure | top src_ip")
        self.assertEqual((complete["total"], complete["missing"]), (7, 0))
        self.assertEqual(round(sum(row[2] for row in complete["rows"]), 2), 100.0)
        # A short top still reports the full match count. Shown percents are not renormalized.
        short = self.run_q("event_type:auth_failure | top 2 src_ip")
        self.assertEqual((short["total"], short["missing"], short["truncated"]), (7, 0, True))
        self.assertEqual([row[2] for row in short["rows"]], [57.14, 28.57])
        # Every match lacks the field: no groups, and missing equals total.
        empty_field = self.run_q("event_type:process_start | top user")
        self.assertEqual((empty_field["rows"], empty_field["total"], empty_field["missing"]), ([], 1, 1))


class TimechartTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text}, now=NOW)

    def test_hourly_buckets_with_edges_and_zero_fill(self):
        data = self.run_q("event_type:auth_failure | timechart span=1h count")
        self.assertEqual(data["kind"], "timechart")
        self.assertEqual(data["columns"], ["_time", "count"])
        # 10:59:59.999 is the last instant of the 10:00 bucket; 11:00:00.000 starts the next one; 09:00 is empty.
        self.assertEqual(data["rows"], [["2026-10-07T08:00:00.000Z", 2], ["2026-10-07T09:00:00.000Z", 0],
                                        ["2026-10-07T10:00:00.000Z", 1], ["2026-10-07T11:00:00.000Z", 4]])
        self.assertFalse(data["truncated"])

    def test_time_window_sets_the_range(self):
        data = self.run_q("event_type:auth_failure last:6h | timechart span=1h")
        self.assertEqual([r[0][11:13] for r in data["rows"]], ["06", "07", "08", "09", "10", "11", "12"])
        self.assertEqual([r[1] for r in data["rows"]], [0, 0, 2, 0, 1, 4, 0])
        data = self.run_q("since:2026-10-07T10:00Z until:2026-10-07T10:59:59Z | timechart span=15m")
        self.assertEqual(data["rows"], [["2026-10-07T10:00:00.000Z", 0], ["2026-10-07T10:15:00.000Z", 0],
                                        ["2026-10-07T10:30:00.000Z", 0], ["2026-10-07T10:45:00.000Z", 0]])

    def test_minute_and_day_edges(self):
        rows = [("2026-10-06T23:59:59.999Z", "fw_deny", None, None, "fw", None, "a"),
                ("2026-10-07T00:00:00.000Z", "fw_deny", None, None, "fw", None, "b"),
                ("2026-10-07T00:04:59.999Z", "fw_deny", None, None, "fw", None, "c"),
                ("2026-10-07T00:05:00.000Z", "fw_deny", None, None, "fw", None, "d"),
                ("2026-10-07T05:59:59.000Z", "fw_deny", None, None, "fw", None, "e"),
                ("2026-10-07T06:00:00.000Z", "fw_deny", None, None, "fw", None, "f")]
        conn = memory_db(rows)
        self.addCleanup(conn.close)
        run = lambda q: hunt.run(conn, {"q": q}, now=NOW)["rows"]  # noqa: E731
        self.assertEqual(run("| timechart span=1d"), [["2026-10-06T00:00:00.000Z", 1], ["2026-10-07T00:00:00.000Z", 5]])
        self.assertEqual(run("| timechart span=6h"), [["2026-10-06T18:00:00.000Z", 1], ["2026-10-07T00:00:00.000Z", 4],
                                                       ["2026-10-07T06:00:00.000Z", 1]])
        five = run("until:2026-10-07T00:09:59Z | timechart span=5m")
        self.assertEqual(five[0], ["2026-10-06T23:55:00.000Z", 1])
        self.assertEqual(five[1:], [["2026-10-07T00:00:00.000Z", 2], ["2026-10-07T00:05:00.000Z", 1]])

    def test_by_keeps_top_five_series_plus_other(self):
        rows = []
        for n, user in enumerate(["u1"] * 7 + ["u2"] * 6 + ["u3"] * 5 + ["u4"] * 4 + ["u5"] * 3 + ["u6"] * 2 + ["u7"]):
            rows.append((f"2026-10-07T{10 + n % 2}:{n:02d}:00.000Z", "auth_failure", user, None, "h", None, "m"))
        rows.append(("2026-10-07T10:59:00.000Z", "auth_failure", None, None, "h", None, "no user"))
        conn = memory_db(rows)
        self.addCleanup(conn.close)
        data = hunt.run(conn, {"q": "| timechart span=1h count by user"}, now=NOW)
        self.assertEqual(data["columns"], ["_time", "u1", "u2", "u3", "u4", "u5", "other"])
        self.assertEqual(len(data["rows"]), 2)
        self.assertEqual([sum(r[i] for r in data["rows"]) for i in range(1, 7)], [7, 6, 5, 4, 3, 4])
        self.assertEqual(sum(sum(r[1:]) for r in data["rows"]), len(rows))
        few = hunt.run(conn, {"q": "user:u1 | timechart span=1h by user"}, now=NOW)
        self.assertEqual(few["columns"], ["_time", "u1"])

    def test_bucket_cap_refusal(self):
        for text in ["last:7d | timechart span=5m", "since:2026-09-01 | timechart span=1h"]:
            with self.subTest(text=text), self.assertRaises(hunt.HuntError) as ctx:
                self.run_q(text)
            self.assertIn("at most 500", str(ctx.exception))
            self.assertIn("narrow the time range", str(ctx.exception))
            self.assertIn("wider span", str(ctx.exception))
        self.assertEqual(len(self.run_q("last:7d | timechart span=1h")["rows"]), 169)

    def test_cap_counts_the_data_range_without_a_window(self):
        insert(self.conn, [("2026-09-01T00:00:00.000Z", "fw_deny", None, None, "fw", None, "old")])
        with self.assertRaises(hunt.HuntError):
            self.run_q("| timechart span=5m")
        self.assertEqual(len(self.run_q("| timechart span=1d")["rows"]), 37)

    def test_empty_result(self):
        self.assertEqual(self.run_q("user:nobody | timechart span=1h")["rows"], [])


class RefusalTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def refused(self, text, *messages):
        with self.assertRaises(hunt.HuntError) as ctx:
            hunt.run(self.conn, {"q": text}, now=NOW)
        for message in messages:
            self.assertIn(message, str(ctx.exception))
        return str(ctx.exception)

    def test_fields_that_cannot_be_grouped(self):
        self.refused("| stats count by message", "message", "free text")
        self.refused("| top ip", "src_ip or dest_ip")
        self.refused("| stats dc(message)", "message")
        for field in ["last", "since", "until"]:
            self.refused(f"| top {field}", "time")
        self.refused("| stats count by usr", "unknown field 'usr'", "src_ip")
        self.refused("| timechart span=1h by message", "message")

    def test_unknown_commands_and_shapes(self):
        self.refused("| sort user", "unknown command 'sort'", "stats", "top", "timechart")
        self.refused("user:a |", "followed by a command")
        self.refused("user:a | stats count | top user", "one | stage")
        self.refused("| stats by user", "aggregate")
        self.refused("| stats sum(dest_port) by user", "aggregate")
        self.refused("| stats count by", "field after by")
        self.refused("| stats count by user, host, src_ip", "at most 2")
        self.refused("| stats count by user, user", "more than once")
        self.refused("| timechart", "span=")
        self.refused("| timechart span=2h", "5m, 15m, 1h, 6h, 1d")
        self.refused("| timechart span=1h by user host", "one field")
        self.refused("NOT | stats count", "NOT")

    def test_injection_attempts_in_field_names_are_refused(self):
        for text in ["| stats count by src_ip; DROP TABLE events", "| stats count by src_ip) --",
                     '| stats count by "src_ip"', "| top 10 user--", "| stats count by user OR 1=1",
                     "| stats dc(user)) FROM events --", "| timechart span=1h;DROP by user"]:
            with self.subTest(text=text):
                self.assertRaises(hunt.HuntError, hunt.run, self.conn, {"q": text}, now=NOW)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], len(EVENTS))

    def test_injection_attempts_in_values_are_bound(self):
        data = hunt.run(self.conn, {"q": "user:\"x' OR 1=1 --\" | stats count by user"}, now=NOW)
        # The value stays bound (one account, not every row). The group label folds ASCII case.
        self.assertEqual(data["rows"], [["x' or 1=1 --", 1]])
        data = hunt.run(self.conn, {"q": "user:\"a' UNION SELECT 1 --\" | top user"}, now=NOW)
        self.assertEqual(data["rows"], [])


class PipeParsingTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_db()
        self.addCleanup(self.conn.close)

    def test_quoted_pipe_stays_in_the_value(self):
        data = hunt.run(self.conn, {"q": '"a | b" | stats count by user'}, now=NOW)
        self.assertEqual(data["terms"][0]["text"], 'message contains "a | b"')
        self.assertEqual(data["rows"], [["alice", 1]])
        self.assertEqual(data["filter"], '"a | b"')
        plain = hunt.run(self.conn, {"q": 'message:"a | b"'}, now=NOW)
        self.assertEqual((plain["total"], "kind" in plain), (1, False))
        self.assertEqual(hunt.parse('user:"x|y" host:a|b')[1]["value"], "a|b")

    def test_pipe_inside_an_unquoted_word_is_literal(self):
        self.assertNotIn("kind", hunt.run(self.conn, {"q": "host:web|stats"}, now=NOW))

    def test_compile_query_validates_the_stage(self):
        where, args = hunt.compile_query("user:alice | top src_ip", now=NOW)
        self.assertEqual((where, args), (["user = ? COLLATE NOCASE"], ["alice"]))
        self.assertRaises(hunt.HuntError, hunt.compile_query, "user:alice | top message", now=NOW)

    def test_plain_search_keeps_its_shape(self):
        data = hunt.run(self.conn, {"q": "user:alice"}, now=NOW)
        self.assertEqual(set(data), {"total", "limit", "offset", "events", "query", "terms"})
        self.assertEqual(data["total"], 5)


class UserGroupCaseTests(unittest.TestCase):
    """stats, top, and timechart fold account spellings; other fields stay exact."""

    ROWS = [
        ("2026-10-07T10:00:00.000Z", "auth_failure", "alice", "10.0.0.5", "web01", 22, "a"),
        ("2026-10-07T10:30:00.000Z", "auth_failure", "Alice", "10.0.0.5", "WEB01", 22, "b"),
        ("2026-10-07T11:00:00.000Z", "auth_failure", "ALICE", "10.0.0.5", "web01", 22, "c"),
        ("2026-10-07T11:10:00.000Z", "auth_failure", "bob", "10.0.0.8", "db01", 22, "d"),
        ("2026-10-07T11:20:00.000Z", "auth_failure", "Bob", "10.0.0.8", "db01", 22, "e"),
        ("2026-10-07T11:40:00.000Z", "process_start", None, None, "web01", None, "no user"),
        ("2026-10-07T11:45:00.000Z", "auth_failure", "Érin", "10.0.0.9", "mail01", 22, "accent"),
        ("2026-10-07T11:50:00.000Z", "auth_failure", "érin", "10.0.0.9", "mail01", 22, "accent"),
    ]

    def setUp(self):
        self.conn = memory_db(self.ROWS)
        self.addCleanup(self.conn.close)

    def run_q(self, text):
        return hunt.run(self.conn, {"q": text}, now=NOW)

    def test_stats_top_and_timechart_fold_user_only(self):
        self.assertEqual(self.run_q("| stats count by user")["rows"],
                         [["alice", 3], ["bob", 2], ["Érin", 1], ["érin", 1]])
        self.assertEqual(self.run_q("| stats count by user, host")["rows"],
                         [["alice", "web01", 2], ["bob", "db01", 2], ["alice", "WEB01", 1],
                          ["Érin", "mail01", 1], ["érin", "mail01", 1]])
        self.assertEqual(self.run_q("| stats count by host")["rows"],
                         [["web01", 3], ["db01", 2], ["mail01", 2], ["WEB01", 1]])
        # dc(user) counts the account, not each spelling. dc(host) still sees WEB01.
        self.assertEqual(self.run_q("| stats dc(user)")["rows"], [[4]])
        self.assertEqual(self.run_q("| stats count, dc(user) by src_ip")["rows"],
                         [["10.0.0.5", 3, 1], ["10.0.0.8", 2, 1], ["10.0.0.9", 2, 2]])
        self.assertEqual(self.run_q("| stats dc(host)")["rows"], [[4]])
        top = self.run_q("| top user")
        self.assertEqual(top["rows"], [["alice", 3, 37.5], ["bob", 2, 25.0],
                                       ["Érin", 1, 12.5], ["érin", 1, 12.5]])
        # The event with no account is missing, not its own group. 3/8 is still 37.5.
        self.assertEqual((top["total"], top["missing"]), (len(self.ROWS), 1))
        self.assertNotIn("Alice", [row[0] for row in top["rows"]])
        chart = self.run_q("| timechart span=1h by user")
        self.assertEqual(chart["columns"], ["_time", "alice", "bob", "Érin", "érin", "other"])
        self.assertEqual(chart["rows"], [
            ["2026-10-07T10:00:00.000Z", 2, 0, 0, 0, 0],
            ["2026-10-07T11:00:00.000Z", 1, 2, 1, 1, 1],
        ])

    def test_user_group_sql_folds_with_lower(self):
        statements = []
        self.conn.set_trace_callback(statements.append)
        self.run_q("| stats count by user")
        self.run_q("| top user")
        self.run_q("| timechart span=1h by user")
        self.run_q("| stats dc(user)")
        self.conn.set_trace_callback(None)
        grouped = [s for s in statements if "GROUP BY" in s.upper()]
        self.assertTrue(grouped)
        self.assertTrue(all("lower(user)" in s for s in grouped))
        statements.clear()
        self.conn.set_trace_callback(statements.append)
        self.run_q("| stats count by host")
        self.conn.set_trace_callback(None)
        host_sql = " ".join(s for s in statements if "GROUP BY" in s.upper())
        self.assertIn("GROUP BY host", host_sql)
        self.assertNotIn("lower(", host_sql)

    def test_reference_says_user_groups_fold(self):
        text = (Path(__file__).resolve().parent.parent / "docs" / "REFERENCE.md").read_text()
        self.assertIn("Accounts fold ASCII case", text)
        self.assertNotIn("lists `Alice` and `alice` separately", text)


class IndexTests(unittest.TestCase):
    def test_stats_by_src_ip_reads_the_src_ip_index(self):
        conn = memory_db()
        self.addCleanup(conn.close)
        statements = []
        conn.set_trace_callback(statements.append)
        hunt.run(conn, {"q": "| stats count by src_ip"}, now=NOW)
        conn.set_trace_callback(None)
        selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
        plan = "; ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + selects[-1]))
        self.assertIn("idx_events_src_ip", plan)


class HuntStatsApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        db = sqlite3.connect(self.db_path)
        with db:
            insert(db, EVENTS)
        db.close()

    def test_viewer_runs_aggregations_but_cannot_save(self):
        viewer = self.client("viewer")
        status, data, _ = viewer.get("/api/hunt?q=" + quote("event_type:auth_failure | top src_ip"))
        self.assertEqual(status, 200, data)
        self.assertEqual((data["kind"], data["rows"][0][0]), ("top", "10.0.0.5"))
        status, data, _ = viewer.get("/api/hunt?q=" + quote("| stats count by user, host"))
        self.assertEqual((status, data["kind"]), (200, "stats"))
        self.assertEqual((data["truncated"], data["groups_omitted"]), (False, 0))
        status, plain, _ = viewer.get("/api/hunt?q=" + quote("| stats count"))
        self.assertEqual((status, plain["groups_omitted"], plain["truncated"]), (200, 0, False))
        self.assertEqual(viewer.post("/api/hunt/saved", {"name": "v", "query": "| top user"})[0], 403)

    def test_bad_stage_is_a_400(self):
        status, data, _ = self.client("viewer").get("/api/hunt?q=" + quote("| stats count by message"))
        self.assertEqual(status, 400)
        self.assertIn("message", data["error"])

    def test_saved_search_with_a_pipeline(self):
        analyst = self.client("analyst")
        status, saved, _ = analyst.post("/api/hunt/saved", {"name": "Top failing IPs",
                                                            "query": "event_type:auth_failure | top 5 src_ip"})
        self.assertEqual(status, 201, saved)
        self.assertEqual(saved["query"], "event_type:auth_failure | top 5 src_ip")
        for query, message in [("event_type:auth_failure | top message", "message"),
                               ("| stats count | top user", "one | stage"), ("| chart count", "unknown command")]:
            with self.subTest(query=query):
                status, data, _ = analyst.post("/api/hunt/saved", {"name": "bad", "query": query})
                self.assertEqual(status, 400, data)
                self.assertIn(message, data["error"])


if __name__ == "__main__":
    unittest.main()
