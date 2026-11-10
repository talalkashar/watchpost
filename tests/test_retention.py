"""Tiered retention: events leave the database only after their archive is written and checked."""

import gzip
import json
import os
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from watchpost import engine, health, retention
from watchpost.config import Config
from watchpost.db import connect, init_schema, iso, utcnow

from .helpers import ServerTestCase


def add_events(conn, days_ago, count, user="alice", ip="203.0.113.45", synthetic=0, message="[SYNTHETIC] failed login"):
    """Insert events that arrived `days_ago` days ago (noon UTC). Returns their ids."""
    arrived = (utcnow() - timedelta(days=days_ago)).replace(hour=12, minute=0, second=0, microsecond=0)
    ids = []
    for n in range(count):
        when = iso(arrived + timedelta(seconds=n))
        ids.append(conn.execute(
            "INSERT INTO events(ts, ingested_at, source, host, event_type, outcome, severity, user, src_ip, message, raw, synthetic)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (when, when, "auth01", "web01", "auth_failure", "failure", "low", user, ip, message, "{}", synthetic)).lastrowid)
    return ids


def day(days_ago):
    return (utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d")


class RetentionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "data", "test.db")
        self.conn = connect(self.db_path)
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def policy(self, hot=30, warm=None, total=None, **kw):
        return retention.Policy.from_config(Config.from_env(
            db_path=self.db_path, retention_hot_days=hot, retention_warm_days=warm, retention_total_days=total, **kw))

    def count(self, sql="SELECT COUNT(*) FROM events", *args):
        return self.conn.execute(sql, args).fetchone()[0]

    def archive(self, days_ago):
        row = self.conn.execute("SELECT * FROM archives WHERE day = ?", (day(days_ago),)).fetchone()
        return dict(row) if row else None


class PolicyTests(RetentionCase):
    def test_off_by_default_and_contradictions_are_refused(self):
        self.assertIsNone(retention.Policy.from_config(Config.from_env(db_path=self.db_path)))
        policy = self.policy(hot=90, warm=180, total=365)
        self.assertEqual(policy.describe(), {"hot_days": 90, "warm_days": 180, "total_days": 365})
        self.assertEqual((policy.archive_dir, policy.cold_dir),
                         (Path(self.tmp.name) / "data" / "archive", Path(self.tmp.name) / "data" / "archive" / "cold"))
        elsewhere = self.policy(archive_dir="/srv/archive", cold_dir="/mnt/cold")
        self.assertEqual((str(elsewhere.archive_dir), str(elsewhere.cold_dir)), ("/srv/archive", "/mnt/cold"))
        for bad in (dict(hot=0), dict(hot=30, warm=30), dict(hot=30, warm=20), dict(hot=30, total=30),
                    dict(hot=30, warm=60, total=60), dict(hot=None, warm=60), dict(hot=None, total=365)):
            with self.assertRaises(ValueError, msg=bad):
                self.policy(**bad)
        with self.assertRaises(ValueError):
            retention.Policy.from_config(Config.from_env(db_path=":memory:", retention_hot_days=30))
        with mock.patch.dict(os.environ, {"SIEM_RETENTION_HOT_DAYS": "90", "SIEM_RETENTION_TOTAL_DAYS": "365",
                                          "SIEM_RETENTION_WARM_DAYS": " "}):
            config = Config.from_env(db_path=self.db_path)
        self.assertEqual((config.retention_hot_days, config.retention_warm_days, config.retention_total_days), (90, None, 365))

    def test_the_hot_period_is_never_shorter_than_what_the_rules_read(self):
        policy = self.policy(hot=1)
        in_force = retention.hot_days_in_force(self.conn, policy)
        self.assertGreaterEqual(in_force, 8)   # two built-in rules look back a week
        add_events(self.conn, in_force - 1, 3)
        add_events(self.conn, in_force + 2, 2)
        summary = retention.run(self.conn, policy)
        self.assertEqual((summary["hot_days_in_force"], summary["removed_from_hot"], self.count()), (in_force, 2, 3))


class RunTests(RetentionCase):
    def test_old_days_are_archived_checked_and_only_then_removed(self):
        old = add_events(self.conn, 40, 4) + add_events(self.conn, 40, 1, synthetic=1)
        add_events(self.conn, 35, 3, user="bob")
        add_events(self.conn, 10, 4)
        add_events(self.conn, 0, 2)
        self.conn.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (1, ?)", (old[1],))   # evidence stays
        policy = self.policy()
        summary = retention.run(self.conn, policy)
        self.assertEqual({k: summary[k] for k in ("archived_days", "archived_events", "removed_from_hot", "kept_as_evidence",
                                                   "moved_to_cold", "deleted_archives", "errors")},
                         {"archived_days": 2, "archived_events": 8, "removed_from_hot": 7, "kept_as_evidence": 1,
                          "moved_to_cold": 0, "deleted_archives": 0, "errors": []})
        self.assertEqual(self.count(), 7)                                    # 4 + 2 recent, 1 evidence
        self.assertEqual(self.count("SELECT COUNT(*) FROM events WHERE id = ?", old[1]), 1)
        row = self.archive(40)
        path = policy.archive_dir / row["file"]
        self.assertEqual((row["tier"], row["file"], row["events"], row["synthetic_events"], row["first_id"], row["last_id"]),
                         ("warm", f"events-{day(40)}.jsonl.gz", 5, 1, old[0], old[-1]))
        self.assertEqual(row["sha256"], retention._sha256(path))
        self.assertEqual(row["bytes"], path.stat().st_size)
        with gzip.open(path, "rt") as handle:
            stored = [json.loads(line) for line in handle]
        self.assertEqual([e["id"] for e in stored], old)                     # the evidence event is in the file too
        self.assertEqual((stored[0]["user"], stored[0]["src_ip"], stored[-1]["synthetic"]), ("alice", "203.0.113.45", 1))
        audited = [json.loads(r[0]) for r in self.conn.execute("SELECT detail FROM audit_log WHERE action = 'archive_created' ORDER BY id")]
        self.assertEqual([(a["events"], a["sha256"]) for a in audited],
                         [(5, row["sha256"]), (3, self.archive(35)["sha256"])])
        # A second run finds nothing to do and reports no error.
        again = retention.run(self.conn, policy)
        self.assertEqual((again["archived_days"], again["removed_from_hot"], again["errors"], self.count()), (0, 0, [], 7))
        status = retention.status(self.conn, policy)
        self.assertEqual((status["enabled"], status["hot"]["events"], status["tiers"]["warm"]["archives"],
                          status["tiers"]["warm"]["events"], status["last_run"]["archived_days"]), (True, 7, 2, 8, 0))

    def test_a_failure_before_the_archive_is_recorded_loses_nothing(self):
        add_events(self.conn, 40, 6)
        policy = self.policy()
        with mock.patch.object(retention.os, "replace", side_effect=OSError("disk full")), self.assertLogs("watchpost.retention", "ERROR"):
            summary = retention.run(self.conn, policy)
        self.assertEqual((summary["archived_days"], summary["removed_from_hot"], len(summary["errors"])), (0, 0, 1))
        self.assertIn("disk full", summary["errors"][0])
        self.assertEqual((self.count(), self.archive(40), list(policy.archive_dir.glob("*"))), (6, None, []))
        with mock.patch.object(retention, "_lines", return_value=iter([])), self.assertLogs("watchpost.retention", "ERROR"):
            self.assertIn("does not read back", retention.run(self.conn, policy)["errors"][0])   # the check after writing
        self.assertEqual(self.count(), 6)
        with mock.patch.object(retention, "DELETE_CHUNK", 4):                # three transactions for six rows
            summary = retention.run(self.conn, policy)
        self.assertEqual((summary["archived_events"], summary["removed_from_hot"], summary["errors"], self.count()), (6, 6, [], 0))

    def test_rows_are_not_removed_when_their_archive_is_gone_or_altered(self):
        ids = add_events(self.conn, 40, 3)
        policy = self.policy()
        retention.run(self.conn, policy)
        path = policy.archive_dir / self.archive(40)["file"]
        # Put the rows back, as if the run had stopped between recording the file and deleting them.
        for event_id in ids:
            self.conn.execute("INSERT INTO events(id, ts, ingested_at, source, event_type, severity) VALUES (?,?,?,?,?,?)",
                              (event_id, f"{day(40)}T12:00:00.000Z", f"{day(40)}T12:00:00.000Z", "auth01", "auth_failure", "low"))
        late = add_events(self.conn, 40, 1)[0]                               # not in the file: it has a later id
        path.write_bytes(path.read_bytes() + b"x")
        with self.assertLogs("watchpost.retention", "ERROR"):
            summary = retention.run(self.conn, policy)
        self.assertIn("does not match its recorded hash", summary["errors"][0])
        self.assertEqual(self.count(), 4)
        self.assertEqual(retention.verify(self.conn, policy), [{"day": day(40), "tier": "warm", "problem": "the file does not match its recorded hash"}])
        path.write_bytes(path.read_bytes()[:-1])                             # restored
        self.assertEqual(retention.verify(self.conn, policy), [])
        summary = retention.run(self.conn, policy)
        self.assertEqual((summary["removed_from_hot"], summary["errors"]), (3, []))
        self.assertEqual([r[0] for r in self.conn.execute("SELECT id FROM events")], [late])   # never deleted unarchived
        path.unlink()
        self.assertEqual(retention.verify(self.conn, policy)[0]["problem"], "the file is missing or cannot be read")

    def test_only_one_run_at_a_time(self):
        self.assertTrue(retention._RUNNING.acquire(blocking=False))
        self.addCleanup(lambda: retention._RUNNING.locked() and retention._RUNNING.release())
        with self.assertRaises(retention.RetentionError) as raised:
            retention.run(self.conn, self.policy())
        self.assertEqual(raised.exception.status, 409)
        retention._RUNNING.release()
        self.assertEqual(retention.run(self.conn, self.policy())["errors"], [])
        with self.assertRaises(retention.RetentionError):
            retention.run(self.conn, None)                                   # retention off


class TierTests(RetentionCase):
    def setUp(self):
        super().setUp()
        add_events(self.conn, 100, 2, user="carol")
        add_events(self.conn, 70, 3, user="bob", ip="198.51.100.7", message="[SYNTHETIC] accepted password")
        add_events(self.conn, 70, 2, user="alice")
        add_events(self.conn, 40, 4)
        self.tiers = self.policy(hot=30, warm=60, total=90)

    def test_archives_go_cold_and_are_deleted_at_the_end_of_retention(self):
        summary = retention.run(self.conn, self.tiers)
        self.assertEqual({k: summary[k] for k in ("archived_days", "moved_to_cold", "deleted_archives", "deleted_events", "errors")},
                         {"archived_days": 3, "moved_to_cold": 2, "deleted_archives": 1, "deleted_events": 2, "errors": []})
        gone, cold, warm = self.archive(100), self.archive(70), self.archive(40)
        self.assertEqual((gone["tier"], cold["tier"], warm["tier"]), ("deleted", "cold", "warm"))
        self.assertTrue(gone["deleted_at"] and cold["moved_at"])
        self.assertEqual(sorted(p.name for p in self.tiers.archive_dir.iterdir()), ["cold", warm["file"]])
        self.assertEqual([p.name for p in self.tiers.cold_dir.iterdir()], [cold["file"]])
        self.assertEqual(retention._sha256(self.tiers.cold_dir / cold["file"]), cold["sha256"])
        self.assertEqual(retention.verify(self.conn, self.tiers), [])
        actions = [r[0] for r in self.conn.execute("SELECT action FROM audit_log WHERE action LIKE 'archive_%' ORDER BY id")]
        self.assertEqual(sorted(actions), ["archive_created"] * 3 + ["archive_deleted"] + ["archive_moved_to_cold"] * 2)
        disposed = json.loads(self.conn.execute("SELECT detail FROM audit_log WHERE action = 'archive_deleted'").fetchone()[0])
        self.assertEqual(disposed, {"events": 2, "sha256": gone["sha256"], "retention_days": 90})
        tiers = retention.status(self.conn, self.tiers)["tiers"]
        self.assertEqual({t: (v["archives"], v["events"]) for t, v in tiers.items()}, {"warm": (1, 4), "cold": (1, 5), "deleted": (1, 2)})
        self.assertEqual(tiers["deleted"]["bytes"], 0)

    def test_a_failed_copy_to_cold_leaves_the_warm_file(self):
        with mock.patch.object(retention.shutil, "copyfile", side_effect=OSError("cold storage offline")), \
                self.assertLogs("watchpost.retention", "ERROR"):
            summary = retention.run(self.conn, self.tiers)
        self.assertEqual((summary["moved_to_cold"], len(summary["errors"])), (0, 2))
        self.assertEqual(self.archive(70)["tier"], "warm")
        self.assertIn("cold storage offline", self.archive(70)["problem"])
        self.assertTrue((self.tiers.archive_dir / self.archive(70)["file"]).exists())
        self.assertEqual(retention.run(self.conn, self.tiers)["moved_to_cold"], 1)   # the 100-day file was deleted instead
        self.assertEqual((self.archive(70)["tier"], self.archive(70)["problem"]), ("cold", None))

    def test_a_warm_day_is_searched_and_a_cold_one_brought_back(self):
        retention.run(self.conn, self.tiers)
        found = retention.search(self.conn, self.tiers, day(40), {})
        self.assertEqual((found["scanned"], found["matched"], len(found["events"]), found["truncated"]), (4, 4, 4, False))
        self.assertEqual(set(found["events"][0]), set(retention.SEARCH_FIELDS))
        self.assertEqual(retention.search(self.conn, self.tiers, day(40), {"limit": "1"})["truncated"], True)
        for bad, status in (({"limit": "many"}, 400), ):
            with self.assertRaises(retention.RetentionError) as raised:
                retention.search(self.conn, self.tiers, day(40), bad)
            self.assertEqual(raised.exception.status, status)
        for target, status in ((day(70), 409), (day(100), 409), (day(5), 404)):   # cold, deleted, never archived
            with self.assertRaises(retention.RetentionError) as raised:
                retention.search(self.conn, self.tiers, target, {})
            self.assertEqual(raised.exception.status, status, target)
        with self.assertRaises(retention.RetentionError):
            retention.thaw(self.conn, self.tiers, day(40), "admin")           # already warm

        back = retention.thaw(self.conn, self.tiers, day(70), "admin")
        self.assertEqual(back["tier"], "warm")
        self.assertEqual(list(self.tiers.cold_dir.iterdir()), [])
        search = lambda **params: retention.search(self.conn, self.tiers, day(70), params)["matched"]  # noqa: E731
        self.assertEqual((search(), search(user="BOB"), search(ip="198.51.100.7"), search(q="accepted"),
                          search(user="bob", q="failed"), search(host="web01", event_type="auth_failure")), (5, 3, 3, 3, 0, 5))
        self.assertEqual(retention.run(self.conn, self.tiers)["moved_to_cold"], 0)        # stays warm for a while
        later = utcnow() + timedelta(days=retention.THAW_DAYS + 1)
        with mock.patch.object(retention, "hot_days_in_force", return_value=30):
            self.assertEqual(retention._run(self.conn, self.tiers, later)["moved_to_cold"], 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'archive_brought_back'").fetchone()[0], 1)


class ServiceTests(RetentionCase):
    def test_the_timer_runs_the_policy_and_health_reports_problems(self):
        add_events(self.conn, 40, 3)
        policy = self.policy()
        service = retention.Service(lambda: connect(self.db_path), policy, interval_seconds=0.05).start()
        self.addCleanup(service.stop)
        for _ in range(100):
            if self.archive(40):
                break
            threading.Event().wait(0.05)
        service.stop()
        self.assertEqual((self.archive(40)["events"], self.count()), (3, 0))
        status, message, guidance, details = service.health_check()
        self.assertEqual((status, guidance, details["hot_days"], details["archives_with_problems"]), ("ok", None, 30, 0))
        (policy.archive_dir / self.archive(40)["file"]).unlink()
        retention.verify(self.conn, policy)
        status, message, guidance, details = service.health_check()
        self.assertEqual((status, details["archives_with_problems"]), ("degraded", 1))
        self.assertIn("1 archive(s) with a problem", message)
        self.assertNotIn("retention", health._COMPONENT_CHECKS)            # stop() unregistered it


class ApiTests(ServerTestCase):
    def config_overrides(self):
        return {"retention_hot_days": 30, "retention_warm_days": 60}

    def test_roles_and_the_whole_flow_over_the_api(self):
        admin, analyst, viewer = self.client("admin"), self.client("analyst"), self.client("viewer")
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        add_events(conn, 70, 2, user="bob")
        add_events(conn, 40, 3)
        status, before, _ = viewer.get("/api/retention")
        self.assertEqual((status, before["enabled"], before["policy"]["hot_days"], before["hot"]["events"], before["archives"]),
                         (200, True, 30, 5, []))
        for client in (viewer, analyst):
            self.assertEqual(client.post("/api/retention/run")[0], 403)
            self.assertEqual(client.post("/api/retention/verify")[0], 403)
            self.assertEqual(client.post(f"/api/retention/archives/{day(70)}/thaw")[0], 403)
        status, summary, _ = admin.post("/api/retention/run")
        self.assertEqual((status, summary["archived_days"], summary["removed_from_hot"], summary["moved_to_cold"], summary["errors"]),
                         (200, 2, 5, 1, []))
        after = analyst.get("/api/retention")[1]
        self.assertEqual([(a["day"], a["tier"], a["events"]) for a in after["archives"]], [(day(40), "warm", 3), (day(70), "cold", 2)])
        self.assertEqual(admin.post("/api/retention/verify")[1], {"problems": []})
        self.assertEqual(viewer.get(f"/api/retention/archives/{day(40)}/events")[0], 403)   # names are not masked in files
        status, found, _ = analyst.get(f"/api/retention/archives/{day(40)}/events?user=alice&limit=2")
        self.assertEqual((status, found["matched"], len(found["events"]), found["truncated"]), (200, 3, 2, True))
        self.assertEqual(analyst.get(f"/api/retention/archives/{day(70)}/events")[0], 409)
        self.assertEqual(analyst.get("/api/retention/archives/not-a-day/events")[0], 404)
        self.assertEqual(admin.post(f"/api/retention/archives/{day(70)}/thaw")[1]["tier"], "warm")
        self.assertEqual(analyst.get(f"/api/retention/archives/{day(70)}/events?user=bob")[1]["matched"], 2)
        audit = admin.get("/api/audit?limit=50")[1]
        actions = {e["action"] for e in (audit["entries"] if isinstance(audit, dict) else audit)}
        self.assertLessEqual({"retention_run", "retention_verified", "archive_created", "archive_moved_to_cold", "archive_brought_back"}, actions)
        self.assertTrue(admin.get("/api/audit/verify")[1]["ok"])


class OffTests(ServerTestCase):
    def test_with_retention_off_nothing_is_touched(self):
        admin = self.client("admin")
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        add_events(conn, 400, 3)
        status, data, _ = admin.get("/api/retention")
        self.assertEqual((status, data["enabled"], data["policy"], data["hot"]["events"]), (200, False, None, 3))
        for path in ("/api/retention/run", "/api/retention/verify", f"/api/retention/archives/{day(400)}/thaw"):
            self.assertEqual(admin.post(path)[0], 409, path)
        self.assertEqual(admin.get(f"/api/retention/archives/{day(400)}/events")[0], 409)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)
        self.assertFalse((Path(self.db_path).parent / "archive").exists())


if __name__ == "__main__":
    unittest.main()
