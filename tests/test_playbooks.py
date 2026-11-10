"""Response playbooks: every alert gets steps, analysts work them, and nothing leaves without a webhook."""

import hashlib
import hmac
import json
import re
import threading
import unittest
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from watchpost import playbooks, rules
from watchpost.config import Config
from watchpost.db import connect, init_schema, iso, utcnow
from watchpost.server import App

from .helpers import ServerTestCase

ATTACKER, SECRET = "203.0.113.45", "test-webhook-secret"


def failures(ip=ATTACKER, n=12, host="web01"):
    """Failed logins that fire brute_force_ip and nothing else: one address, four accounts, three tries each."""
    start = utcnow().replace(microsecond=0) - timedelta(minutes=10)
    return [{"ts": iso(start + timedelta(seconds=5 * i)), "type": "login_failed", "user": f"user{i % 4}", "src_ip": ip,
             "host": host} for i in range(n)]


class Receiver:
    """A webhook endpoint on loopback that records what it is sent and answers as scripted."""

    def __init__(self):
        self.requests, self.answers = [], []   # answers: statuses for the next requests; then 200
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                receiver.requests.append((dict(self.headers), body))
                status = receiver.answers.pop(0) if receiver.answers else 200
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def bodies(self):
        return [json.loads(body) for _, body in self.requests]


class DefinitionTests(unittest.TestCase):
    def test_every_built_in_rule_has_a_playbook_and_every_playbook_is_well_formed(self):
        for rule in rules.DEFAULT_RULES:
            self.assertNotEqual(playbooks.for_rule(rule["id"])["id"], "generic", rule["id"])
        self.assertEqual(playbooks.for_rule("sigma_anything")["id"], "generic")
        claimed = [rule for playbook in playbooks.PLAYBOOKS for rule in playbook["rules"]]
        self.assertEqual(len(claimed), len(set(claimed)))
        for playbook in playbooks.PLAYBOOKS:
            keys = [step["key"] for step in playbook["steps"]]
            self.assertEqual(len(keys), len(set(keys)), playbook["id"])
            self.assertEqual((keys[0], keys[1], keys[-1]), ("context", "notify", "verdict"))
            for step in playbook["steps"]:
                self.assertRegex(step["key"], r"^[a-z_]{1,40}$")   # the route's pattern
                self.assertIn(step["phase"], playbooks.PHASES)
                self.assertIn(step["kind"], ("auto", "manual", "action"))
                self.assertTrue(step["title"] and step["detail"])
                if step["kind"] == "action":
                    self.assertIn(step["action"], playbooks.ACTIONS)
            phases = [playbooks.PHASES.index(step["phase"]) for step in playbook["steps"]]
            self.assertEqual(phases, sorted(phases), playbook["id"])

    def test_webhook_urls(self):
        for good in ("https://hooks.example.internal/watchpost", "http://127.0.0.1:9000/x", "http://localhost/x",
                     "http://[::1]:9000/x"):
            self.assertEqual(playbooks.check_webhook_url(good), good)
        for bad in ("http://hooks.example.internal/x", "ftp://127.0.0.1/x", "hooks.example.internal",
                    "https://user:pw@hooks.example.internal/x", "https://", ""):
            with self.assertRaises(ValueError, msg=bad):
                playbooks.check_webhook_url(bad)

    def test_the_server_refuses_to_start_on_a_webhook_it_would_not_deliver_to(self):
        with self.assertRaisesRegex(ValueError, "must use https"):
            App(Config.from_env(db_path=":memory:", admin_password="admin-test-password-1",
                                analyst_password="analyst-test-password-1",
                                playbook_webhook_url="http://hooks.example.internal/x"))

    def test_webhook_mode_decides_what_is_sent(self):
        conn = connect(":memory:")
        self.addCleanup(conn.close)
        init_schema(conn)
        base = dict(db_path=":memory:", playbook_webhook_url="https://hooks.example.internal/x")
        for config, real, synthetic in (
                (Config.from_env(db_path=":memory:"), "no webhook", "no webhook"),
                (Config.from_env(**base), None, "synthetic"),
                (Config.from_env(**base, playbook_webhook_synthetic=True), None, None)):
            playbooks.configure(conn, config)
            for is_synthetic, expected in ((0, real), (1, synthetic)):
                reason = playbooks._not_sent(conn, is_synthetic)
                self.assertTrue(reason is None if expected is None else expected in reason, (config, is_synthetic, reason))


class PlaybookTests(ServerTestCase):
    """No webhook configured: the default."""

    def setUp(self):
        super().setUp()
        self.admin, self.analyst = self.client("admin"), self.client("analyst")

    def db(self):
        conn = connect(self.db_path, None)
        self.addCleanup(conn.close)
        return conn

    def alert(self, rule_id, group_key=None, client=None):
        """Detail of the first alert of a rule (and group)."""
        client = client or self.analyst
        found = [a for a in client.get("/api/alerts")[1] if a["rule_id"] == rule_id and group_key in (None, a["group_key"])]
        self.assertTrue(found, rule_id)
        return client.get(f"/api/alerts/{found[0]['id']}")[1]

    def step(self, alert, key):
        return next(s for s in alert["playbook"]["steps"] if s["key"] == key)

    def post_step(self, alert_id, key, body, suffix="", client=None):
        return (client or self.analyst).post(f"/api/alerts/{alert_id}/playbook/steps/{key}{suffix}", body)

    def test_a_new_alert_gets_its_playbook_and_the_automatic_steps_run(self):
        self.assertEqual(self.admin.post("/api/demo/load")[0], 200)
        alert = self.alert("brute_force_ip", ATTACKER)
        playbook = alert["playbook"]
        self.assertEqual((playbook["id"], playbook["name"]), ("credential_attack", "Password attack"))
        self.assertEqual([s["key"] for s in playbook["steps"]],
                         ["context", "notify", "check_success", "block_ip", "reset_passwords", "verdict"])
        context, notify = self.step(alert, "context"), self.step(alert, "notify")
        self.assertEqual((context["status"], context["actor"]), ("done", "playbook"))
        self.assertRegex(context["note"], rf"earlier alert|No earlier alerts for {re.escape(ATTACKER)}")
        self.assertEqual((notify["status"], notify["note"]), ("skipped", "Not sent: no webhook is configured."))
        self.assertEqual(playbook["progress"], {"closed": 2, "total": 6})
        self.assertIsNone(playbook["completed_at"])
        self.assertEqual(self.step(alert, "block_ip")["targets"], [ATTACKER])
        # An internal source is never offered for blocking at the edge.
        self.assertEqual(self.step(self.alert("brute_force_ip", "10.0.50.5"), "block_ip")["targets"], [])
        self.assertEqual(self.alert("success_after_failures")["playbook"]["id"], "account_compromise")
        # Every alert of the demo has one, and nothing was queued for sending.
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                         conn.execute("SELECT COUNT(*) FROM playbook_runs").fetchone()[0])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM playbook_outbox").fetchone()[0], 0)

        status, catalogue, _ = self.client("viewer").get("/api/playbooks")
        self.assertEqual(status, 200)
        self.assertEqual(len(catalogue["playbooks"]), len(playbooks.PLAYBOOKS))
        self.assertEqual(catalogue["webhook"], {"mode": "off", "pending": 0, "sent": 0, "failed": 0})
        self.assertTrue(catalogue["automation"])

    def test_an_analyst_works_the_manual_steps(self):
        self.assertEqual(self.analyst.post("/api/ingest", failures())[0], 201)
        alert = self.alert("brute_force_ip")
        aid = alert["id"]
        self.assertEqual(alert["synthetic"], 0)
        self.assertEqual(self.post_step(aid, "check_success", {"status": "done"}, client=self.client("viewer"))[0], 403)
        self.assertEqual(self.post_step(aid, "check_success", {"status": "finished"})[0], 400)
        self.assertEqual(self.post_step(aid, "check_success", {"status": "skipped"})[0], 400)   # a skip needs a reason
        self.assertEqual(self.post_step(aid, "check_success", {"status": "done", "note": "x" * 1001})[0], 400)
        self.assertEqual(self.post_step(aid, "context", {"status": "done"})[0], 400)            # automatic
        self.assertEqual(self.post_step(aid, "block_ip", {"status": "done"})[0], 400)           # an action is requested
        self.assertEqual(self.post_step(aid, "no_such_step", {"status": "done"})[0], 404)
        self.assertEqual(self.post_step(999999, "check_success", {"status": "done"})[0], 404)

        status, playbook, _ = self.post_step(aid, "check_success", {"status": "done", "note": "No login succeeded."})
        self.assertEqual(status, 200)
        done = next(s for s in playbook["steps"] if s["key"] == "check_success")
        self.assertEqual((done["status"], done["actor"], done["note"]), ("done", "analyst", "No login succeeded."))
        self.post_step(aid, "reset_passwords", {"status": "skipped", "note": "No account was guessed."})
        self.post_step(aid, "block_ip", {"target": ATTACKER, "reason": "Password guessing"}, "/request")
        status, playbook, _ = self.post_step(aid, "verdict", {"status": "done"})
        self.assertEqual(playbook["progress"], {"closed": 6, "total": 6})
        self.assertIsNotNone(playbook["completed_at"])
        status, playbook, _ = self.post_step(aid, "verdict", {"status": "pending"})   # reopened
        self.assertEqual((playbook["progress"]["closed"], playbook["completed_at"]), (5, None))

        alert = self.analyst.get(f"/api/alerts/{aid}")[1]
        self.assertIn(("analyst", "playbook_step", "Look for a login that worked: done"),
                      [(a["actor"], a["action"], a["detail"]) for a in alert["activity"]])
        audit = self.admin.get("/api/audit?limit=50")[1]
        entries = audit["entries"] if isinstance(audit, dict) else audit
        self.assertTrue(any(e["action"] == "playbook_step_updated" and e["target"] == str(aid) for e in entries))
        self.assertTrue(self.admin.get("/api/audit/verify")[1]["ok"])

    def test_without_a_webhook_an_action_is_recorded_and_not_sent(self):
        self.assertEqual(self.analyst.post("/api/ingest", failures())[0], 201)
        aid = self.alert("brute_force_ip")["id"]
        request = lambda body: self.post_step(aid, "block_ip", body, "/request")  # noqa: E731
        self.assertEqual(request({"target": ATTACKER})[0], 400)                                 # no reason
        self.assertEqual(request({"target": "198.51.100.99", "reason": "not in the evidence"})[0], 400)
        self.assertEqual(request({"target": ["x"], "reason": "not a string"})[0], 400)
        self.assertEqual(self.post_step(aid, "check_success", {"target": ATTACKER, "reason": "r"}, "/request")[0], 400)
        self.assertEqual(self.post_step(aid, "block_ip", {"target": ATTACKER, "reason": "r"}, "/request",
                                        client=self.client("viewer"))[0], 403)
        status, playbook, _ = request({"target": ATTACKER, "reason": "Password guessing from this address"})
        self.assertEqual(status, 200)
        step = next(s for s in playbook["steps"] if s["key"] == "block_ip")
        self.assertEqual((step["status"], step["target"], step["actor"]), ("skipped", ATTACKER, "analyst"))
        self.assertEqual(step["note"], "Not sent: no webhook is configured. Reason given: Password guessing from this address")
        conn = self.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM playbook_outbox").fetchone()[0], 0)
        detail = json.loads(conn.execute("SELECT detail FROM audit_log WHERE action = 'playbook_action_requested'").fetchone()[0])
        self.assertEqual((detail["action"], detail["target"], detail["sent"]), ("block_ip", ATTACKER, False))
        # A resolved alert takes no more response actions.
        self.analyst.post(f"/api/alerts/{aid}/status", {"status": "resolved", "disposition": "true_positive"})
        self.assertEqual(request({"target": ATTACKER, "reason": "again"})[0], 409)

    def test_an_alert_from_before_playbooks_can_be_given_one(self):
        self.assertEqual(self.analyst.post("/api/ingest", failures())[0], 201)
        aid = self.alert("brute_force_ip")["id"]
        conn = self.db()
        conn.execute("DELETE FROM playbook_steps")
        conn.execute("DELETE FROM playbook_runs")
        self.assertIsNone(self.analyst.get(f"/api/alerts/{aid}")[1]["playbook"])
        self.assertEqual(self.post_step(aid, "verdict", {"status": "done"})[0], 404)
        self.assertEqual(self.client("viewer").post(f"/api/alerts/{aid}/playbook")[0], 403)
        status, playbook, _ = self.analyst.post(f"/api/alerts/{aid}/playbook")
        self.assertEqual((status, playbook["id"]), (201, "credential_attack"))
        self.assertEqual(self.analyst.post(f"/api/alerts/{aid}/playbook")[0], 409)
        self.assertEqual(self.analyst.post("/api/alerts/999999/playbook")[0], 404)

    def test_the_reviewed_setting_turns_the_automatic_steps_off(self):
        settings = {s["key"]: s for s in self.admin.get("/api/settings")[1]}
        self.assertEqual((settings["playbook_automation"]["value"], settings["playbook_automation"]["max"]), ("1", 1))
        self.db().execute("UPDATE settings SET value = '0' WHERE key = 'playbook_automation'")
        self.assertEqual(self.analyst.post("/api/ingest", failures())[0], 201)
        alert = self.alert("brute_force_ip")
        for key in ("context", "notify"):
            self.assertEqual((self.step(alert, key)["status"], self.step(alert, key)["note"]),
                             ("skipped", "Automatic steps are turned off (setting playbook_automation)."))
        self.assertFalse(self.analyst.get("/api/playbooks")[1]["automation"])


class WebhookTests(ServerTestCase):
    def setUp(self):
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)
        super().setUp()
        self.admin, self.analyst = self.client("admin"), self.client("analyst")
        self.dispatcher = playbooks.Dispatcher(lambda: connect(self.db_path, None), self.receiver.url, SECRET, timeout=5)

    def config_overrides(self):
        return {"playbook_webhook_url": self.receiver.url, "playbook_webhook_secret": SECRET}

    def real_alert(self):
        self.assertEqual(self.analyst.post("/api/ingest", failures())[0], 201)
        alerts = [a for a in self.analyst.get("/api/alerts")[1] if a["rule_id"] == "brute_force_ip" and not a["synthetic"]]
        return alerts[0]["id"]

    def step(self, alert_id, key):
        return next(s for s in self.analyst.get(f"/api/alerts/{alert_id}")[1]["playbook"]["steps"] if s["key"] == key)

    def test_synthetic_alerts_are_not_sent(self):
        self.assertEqual(self.admin.post("/api/demo/load")[0], 200)
        alert = next(a for a in self.analyst.get("/api/alerts")[1] if a["rule_id"] == "success_after_failures")
        self.assertEqual(self.step(alert["id"], "notify")["note"], "Not sent: this alert is synthetic.")
        target = self.step(alert["id"], "disable_account")["targets"][0]
        status, playbook, _ = self.analyst.post(f"/api/alerts/{alert['id']}/playbook/steps/disable_account/request",
                                                {"target": target, "reason": "demo"})
        self.assertEqual(status, 200)
        self.assertIn("Not sent: this alert is synthetic.",
                      next(s for s in playbook["steps"] if s["key"] == "disable_account")["note"])
        self.assertEqual(self.dispatcher.drain(), 0)
        self.assertEqual(self.receiver.requests, [])
        self.assertEqual(self.analyst.get("/api/playbooks")[1]["webhook"]["mode"], "real")

    def test_a_real_alert_is_notified_and_an_action_request_is_delivered_signed(self):
        aid = self.real_alert()
        self.assertEqual(self.step(aid, "notify")["status"], "requested")
        self.assertEqual(self.receiver.requests, [])            # detection did not wait on the network
        self.assertEqual(self.dispatcher.drain(), 1)
        headers, body = self.receiver.requests[0]
        self.assertEqual(headers["X-Watchpost-Signature"], "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest())
        self.assertEqual(headers["Content-Type"], "application/json")
        sent = json.loads(body)
        self.assertEqual((sent["type"], sent["alert"]["id"], sent["alert"]["rule_id"], sent["alert"]["group_key"],
                          sent["alert"]["synthetic"], sent["playbook"]["id"]),
                         ("alert", aid, "brute_force_ip", ATTACKER, False, "credential_attack"))
        self.assertNotIn("user0", body.decode())                # the summary, not the events
        self.assertEqual(set(sent), {"type", "created_at", "watchpost_version", "alert", "playbook"})
        notify = self.step(aid, "notify")
        self.assertEqual((notify["status"], notify["note"]), ("done", "Delivered to the webhook (HTTP 200)."))
        self.assertEqual(self.dispatcher.drain(), 0)            # nothing is sent twice

        status, playbook, _ = self.analyst.post(f"/api/alerts/{aid}/playbook/steps/block_ip/request",
                                                {"target": ATTACKER, "reason": "Password guessing"})
        self.assertEqual(status, 200)
        self.assertEqual(next(s for s in playbook["steps"] if s["key"] == "block_ip")["status"], "requested")
        self.assertEqual(self.dispatcher.drain(), 1)
        sent = self.receiver.bodies()[1]
        self.assertEqual({k: sent[k] for k in ("type", "action", "target", "requested_by", "reason", "wanted")},
                         {"type": "response_action", "action": "block_ip", "target": ATTACKER, "requested_by": "analyst",
                          "reason": "Password guessing", "wanted": "block this address at the network edge"})
        block = self.step(aid, "block_ip")
        self.assertEqual((block["status"], block["target"], block["note"]),
                         ("done", ATTACKER, "Delivered to the webhook (HTTP 200). Reason given: Password guessing"))
        self.assertEqual(self.analyst.get("/api/playbooks")[1]["webhook"], {"mode": "real", "pending": 0, "sent": 2, "failed": 0})
        conn = connect(self.db_path, None)
        self.addCleanup(conn.close)
        detail = json.loads(conn.execute("SELECT detail FROM audit_log WHERE action = 'playbook_action_requested'").fetchone()[0])
        self.assertEqual((detail["target"], detail["sent"], detail["reason"]), (ATTACKER, True, "Password guessing"))

    def test_a_failed_delivery_is_retried_then_given_up(self):
        aid = self.real_alert()
        self.receiver.answers = [500, 302, 500, 500, 500]       # a redirect is not followed: it is a failure
        now = utcnow()
        self.assertEqual(self.dispatcher.drain(now), 0)
        self.assertEqual(self.dispatcher.drain(now + timedelta(seconds=1)), 0)   # not due yet
        self.assertEqual(len(self.receiver.requests), 1)
        self.assertEqual(self.step(aid, "notify")["status"], "requested")
        with self.assertLogs("watchpost.playbooks", "WARNING") as logged:
            for wait in playbooks.RETRY_SECONDS:
                now += timedelta(seconds=wait + 1)
                self.assertEqual(self.dispatcher.drain(now), 0)
        self.assertIn("failed after 5 attempts", logged.output[0])
        self.assertEqual(len(self.receiver.requests), 5)
        notify = self.step(aid, "notify")
        self.assertEqual((notify["status"], notify["note"]),
                         ("failed", "Could not be delivered to the webhook after 5 attempts (HTTP 500)."))
        self.assertEqual(self.dispatcher.drain(now + timedelta(days=1)), 0)
        self.assertEqual(len(self.receiver.requests), 5)
        self.assertEqual(self.analyst.get("/api/playbooks")[1]["webhook"]["failed"], 1)

    def test_an_unreachable_webhook_and_the_delivery_thread(self):
        aid = self.real_alert()
        dead = playbooks.Dispatcher(lambda: connect(self.db_path, None), "http://127.0.0.1:9/hook", timeout=2)
        self.assertEqual(dead.drain(), 0)
        conn = connect(self.db_path, None)
        self.addCleanup(conn.close)
        row = conn.execute("SELECT attempts, last_error, status FROM playbook_outbox").fetchone()
        self.assertEqual((row["attempts"], row["status"]), (1, "pending"))
        self.assertTrue(row["last_error"])
        conn.execute("UPDATE playbook_outbox SET next_attempt_at = ?", (iso(utcnow()),))
        self.dispatcher.poll_seconds = 0.05
        self.dispatcher.start()
        self.addCleanup(self.dispatcher.stop)
        for _ in range(100):
            if self.receiver.requests:
                break
            threading.Event().wait(0.05)
        self.dispatcher.stop()
        self.assertEqual(len(self.receiver.requests), 1)
        unsigned = playbooks.Dispatcher(lambda: connect(self.db_path, None), self.receiver.url)
        self.assertEqual(unsigned.send(7, b"{}"), (True, "HTTP 200"))
        self.assertNotIn("X-Watchpost-Signature", self.receiver.requests[-1][0])
        self.assertEqual(self.step(aid, "notify")["status"], "done")


if __name__ == "__main__":
    unittest.main()
