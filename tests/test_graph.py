"""Investigation graph API, evidence boundaries, viewer masking and snapshot limits."""

from unittest.mock import patch

from tests.helpers import ServerTestCase
from watchpost import graph


STAMP = "2026-11-21T00:00:00Z"


class GraphTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.db = self.app.conn()
        self.addCleanup(self.db.close)

    def add_alert(self, name):
        return self.db.execute(
            "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation,"
            " first_seen, last_seen, event_count, created_at, updated_at)"
            " VALUES ('brute_force_ip',1,'key','high',?,'example',?,?,1,?,?)", (name, *([STAMP] * 4))).lastrowid

    def add_event(self, alert, minute, host="WEB", user="source", ip="10.0.0.12"):
        ts = f"2026-11-21T{minute // 60:02}:{minute % 60:02}:00Z"
        event = self.db.execute(
            "INSERT INTO events(ts, ingested_at, source, host, user, src_ip, event_type, severity, message)"
            " VALUES (?,?,'lab',?,?,?,'auth_failure','low','example')", (ts, ts, host, user, ip)).lastrowid
        self.db.execute("INSERT INTO alert_events VALUES (?,?)", (alert, event))

    def populate(self):
        self.db.execute(
            "INSERT INTO incidents(id,title,severity,first_seen,last_seen,entities,stages,created_at,updated_at)"
            " VALUES (1,'Case on 10.0.0.12','high',?,?,'{}','[]',?,?)", [STAMP] * 4)
        for i, minute in enumerate([0, 30, 61, 61]):
            alert = self.add_alert("Finding for source")
            self.add_event(alert, minute, "WEB" if i == 0 else "web", "source" if i else "SOURCE")
            if i < 3:
                self.db.execute("INSERT INTO incident_alerts VALUES (?,1,'t')", (alert,))

    def test_read_requires_session_and_empty_store_is_empty(self):
        self.assertEqual(self.client().get("/api/graph")[0], 401)
        self.assertEqual(self.client("viewer").get("/api/graph")[:2],
                         (200, {"nodes": [], "edges": [], "limited": False}))

    def test_graph_shows_only_evidence_and_time_witnessed_chains(self):
        self.populate()
        code, data, _ = self.client("viewer").get("/api/graph")
        self.assertEqual(code, 200)
        self.assertFalse(data["limited"])
        nodes = data["nodes"]
        self.assertEqual(sorted(n["type"] for n in nodes), ["alert"] * 4 + ["host", "incident", "src_ip", "user"])
        edges = [(nodes[e["source"]], nodes[e["target"]], e["type"]) for e in data["edges"]]
        self.assertEqual([(a["ref"], b["ref"]) for a, b, k in edges if k == "correlation"], [(1, 2)])
        self.assertEqual({a["ref"] for a, b, k in edges if k == "membership" and b["ref"] == 1}, {1, 2, 3})
        for alert in (n for n in nodes if n["type"] == "alert"):
            self.assertIn("T1110.001", alert["techniques"])
            self.assertEqual([b["type"] for a, b, k in edges if k == "evidence" and a == alert],
                             ["src_ip", "user", "host"])

    def test_masked_pivots_and_edges_stay_usable(self):
        self.populate()
        self.db.execute("UPDATE settings SET value='1' WHERE key='viewer_masking'")
        viewer = self.client("viewer")
        data = viewer.get("/api/graph")[1]
        self.assertNotIn("10.0.0.12", str(data))
        user = next(n for n in data["nodes"] if n["type"] == "user")
        self.assertRegex(user["label"], r"^user-[a-f0-9]{8}$")
        ip = next(n for n in data["nodes"] if n["type"] == "src_ip")
        self.assertRegex(ip["label"], r"^internal-[a-f0-9]{8}$")
        for n in (user, ip):
            self.assertEqual(viewer.get(f"/api/entities/{n['type']}/{n['label']}")[0], 200)
            self.assertTrue(any(e["target"] == n["id"] for e in data["edges"]))
        self.assertIn("10.0.0.12", str(self.client("analyst").get("/api/graph")[1]))

    def test_bounds_preserve_endpoints_and_report_sampling(self):
        self.populate()
        for limit, value in [("ALERT_LIMIT", 2), ("NODE_LIMIT", 6), ("EVIDENCE_EDGE_LIMIT", 2)]:
            with self.subTest(limit=limit), patch.object(graph, limit, value):
                data = graph.snapshot(self.db)
                self.assertTrue(data["limited"])
                ids = {n["id"] for n in data["nodes"]}
                self.assertLessEqual(len(ids), graph.NODE_LIMIT)
                for e in data["edges"]:
                    self.assertTrue({e["source"], e["target"]} <= ids)
        self.add_event(1, 1, host="newest")
        with patch.object(graph, "EVIDENCE_LIMIT", 1):
            data = graph.snapshot(self.db)
        self.assertTrue(data["limited"])
        self.assertIn("newest", [n["label"] for n in data["nodes"]])

    def test_snapshot_transaction_ends_and_errors_are_recorded(self):
        self.populate()
        self.db.execute("UPDATE settings SET value='1' WHERE key='viewer_masking'")
        viewer = self.client("viewer")
        first = viewer.get("/api/graph")[1]
        # The masking key survives the read-only snapshot, so pseudonyms stay stable across requests.
        self.assertEqual(first, viewer.get("/api/graph")[1])
        self.db.execute("INSERT INTO meta(key, value) VALUES ('graph_probe', '1')")  # no lingering write lock
        with patch.object(graph, "snapshot", side_effect=RuntimeError("boom")):
            self.assertEqual(viewer.get("/api/graph")[0], 500)
        self.assertTrue(self.db.execute("SELECT 1 FROM error_log WHERE message LIKE '%boom%'").fetchone())
