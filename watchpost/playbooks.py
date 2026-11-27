"""Response playbooks: what to do about an alert, step by step, and a record of what was done.

Every rule maps to one playbook (PLAYBOOKS). When detection creates an alert, the alert gets a copy of
its playbook's steps. A step is one of three kinds:

- auto: Watchpost does it when the alert is created. `context` counts earlier alerts for the same
  subject; `notify` posts the alert's summary to a webhook.
- manual: an analyst does it outside Watchpost and marks it done, or skipped with a reason.
- action: a response action (block an address, disable an account, isolate a host). Watchpost never
  carries one out itself. An analyst picks a target from the alert's evidence and gives a reason, and
  Watchpost posts the request to the webhook for whatever automation the operator runs there. "Done"
  on such a step means the request was delivered, not that the address is blocked.

Guard rails:
- Nothing leaves Watchpost unless the operator set SIEM_PLAYBOOK_WEBHOOK_URL. Without it, notify and
  action steps are recorded as not sent.
- Synthetic alerts are never sent, unless SIEM_PLAYBOOK_WEBHOOK_SYNTHETIC=1. Demo data stays in the demo.
- An action's target must be a value in the alert's own evidence, and `block_ip` takes public addresses
  only. A request needs the analyst role and a reason, and is written to the audit log.
- The reviewed setting `playbook_automation` (0 or 1) turns the automatic steps off.
- A webhook body carries the alert's summary, never its events. With SIEM_PLAYBOOK_WEBHOOK_SECRET set it
  is signed: X-Watchpost-Signature is "sha256=" and the HMAC-SHA256 of the body.

Deliveries wait in the playbook_outbox table. Dispatcher sends them from its own thread, so detection
never waits on the network, and retries a failed delivery four times over about 13 minutes.

Playbooks are built in, like the rules. They are guidance for a lab, not an incident response plan.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta

from . import __version__, masking
from .db import audit, iso, now_iso, transaction, utcnow
from .queries import QueryError

log = logging.getLogger("watchpost.playbooks")

SETTING = "playbook_automation"
PHASES = ("triage", "contain", "recover", "close")
STEP_STATUSES = ("pending", "requested", "done", "skipped", "failed")
CONTEXT_DAYS = 30
MAX_TARGETS = 50
MAX_NOTE = 1000
RETRY_SECONDS = (5, 30, 120, 600)   # waits before the second to fifth attempt; then the delivery has failed
# action -> (event field its target comes from, what the request asks for)
ACTIONS = {
    "block_ip": ("src_ip", "block this address at the network edge"),
    "disable_account": ("user", "disable this account and end its sessions"),
    "isolate_host": ("host", "cut this host off from the network"),
}


def _manual(key, phase, title, detail):
    return {"key": key, "phase": phase, "kind": "manual", "action": None, "title": title, "detail": detail}


def _action(action, title, detail):
    return {"key": action, "phase": "contain", "kind": "action", "action": action, "title": title, "detail": detail}


_CONTEXT = {"key": "context", "phase": "triage", "kind": "auto", "action": "context", "title": "Gather context",
            "detail": f"Count the earlier alerts for the same subject in the last {CONTEXT_DAYS} days and how they were resolved."}
_NOTIFY = {"key": "notify", "phase": "triage", "kind": "auto", "action": "notify", "title": "Notify the response channel",
           "detail": "Post the alert's summary to the configured webhook."}
_VERDICT = _manual("verdict", "close", "Record the verdict",
                   "Resolve the alert as true positive, false positive or benign, and note what was found and what was done.")
_BLOCK = _action("block_ip", "Block the source address",
                 "Ask for the source address to be blocked at the network edge. Public addresses only.")
_DISABLE = _action("disable_account", "Disable the account",
                   "Ask for the account to be disabled and its sessions ended until its owner is confirmed.")
_ISOLATE = _action("isolate_host", "Isolate the host",
                   "Ask for the host to be cut off from the network while it is examined.")

PLAYBOOKS = [
    {"id": "credential_attack", "name": "Password attack",
     "description": "Many failed logins against one or many accounts.",
     "rules": ("brute_force_ip", "password_spray", "account_repeated_failures"),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("check_success", "triage", "Look for a login that worked",
                 "In the related timeline, check whether any targeted account logged in from the same source during or after the failures. If one did, treat it as a compromised account."),
         _BLOCK,
         _manual("reset_passwords", "recover", "Protect the targeted accounts",
                 "Reset the password of any account that may have been guessed, and check that lockout and multi-factor settings held."),
         _VERDICT)},
    {"id": "account_compromise", "name": "Suspected account compromise",
     "description": "A login or privileged action that does not fit the account's history.",
     "rules": ("success_after_failures", "impossible_geo_login", "off_hours_privileged_login",
               "admin_action_from_new_source", "privilege_escalation_after_login"),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("confirm_owner", "triage", "Ask the account's owner",
                 "Reach the owner through a channel the account does not control and ask whether the activity was theirs."),
         _DISABLE, _BLOCK,
         _manual("review_activity", "recover", "Review what the account did",
                 "Go through the related timeline from the first suspicious login on: privilege changes, new accounts, data read."),
         _manual("restore_access", "recover", "Reset credentials and restore access",
                 "Reset the password, re-enrol multi-factor authentication, then re-enable the account."),
         _VERDICT)},
    {"id": "network_recon", "name": "Scanning",
     "description": "One source probing many ports or web paths.",
     "rules": ("web_scanner", "firewall_port_sweep"),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("classify_source", "triage", "Identify the source",
                 "Decide whether the source is internal, an authorized scanner, or outside. An internal source that scans is a host to examine, not an address to block."),
         _BLOCK, _ISOLATE,
         _manual("check_hits", "recover", "Check what the scan found",
                 "Look for allowed connections or successful requests from the same source, and review any service it reached."),
         _VERDICT)},
    {"id": "data_exfiltration", "name": "Possible data theft",
     "description": "An unusual volume of data leaving, or data going to a service that is not approved.",
     "rules": ("data_exfil_volume", "unsanctioned_cloud_service"),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("identify_data", "triage", "Identify the data and the destination",
                 "Work out which host and account sent the data, where it went, and what it could have contained."),
         _ISOLATE, _DISABLE,
         _manual("preserve", "recover", "Preserve the evidence",
                 "Download the alert report and the incident's case timeline before anything on the host changes."),
         _manual("inform_owner", "recover", "Inform the data's owner",
                 "Tell whoever is responsible for the data. Whether anyone outside must be told is their decision, not this tool's."),
         _VERDICT)},
    {"id": "cloud_control_plane", "name": "Cloud account change",
     "description": "Identity or logging changes in a cloud account.",
     "rules": ("cloud_iam_change_by_new_principal", "cloud_logging_disabled"),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("verify_change", "triage", "Check that the change was approved",
                 "Find the change request or ask the principal's owner. An approved change ends here as benign."),
         _DISABLE,
         _manual("revert", "recover", "Undo the change",
                 "Remove the access that was granted, or turn logging back on, and confirm that events arrive again."),
         _manual("rotate_keys", "recover", "Rotate the principal's credentials",
                 "Rotate the access keys and end the sessions of the principal that made the change."),
         _VERDICT)},
    {"id": "log_source_outage", "name": "Log source went quiet",
     "description": "A source that normally sends events has stopped.",
     "rules": ("log_source_silent",),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("check_forwarder", "triage", "Check the sender",
                 "Check that the host is up and its forwarder is running. A forwarder stopped on purpose looks the same as a crash."),
         _manual("maintenance", "triage", "Rule out planned work",
                 "If the silence is planned, record a maintenance window for the source so it stops counting as quiet."),
         _manual("restore", "recover", "Restore the flow and check the gap",
                 "Once events arrive again, note the period with no logs: nothing in it could be detected."),
         _VERDICT)},
    {"id": "generic", "name": "General investigation",
     "description": "For rules without a playbook of their own, such as imported Sigma rules and promoted searches.",
     "rules": (),
     "steps": (
         _CONTEXT, _NOTIFY,
         _manual("scope", "triage", "Establish what happened",
                 "Read the evidence and the related timeline, and decide which accounts, hosts and addresses are involved."),
         _BLOCK, _DISABLE, _ISOLATE,
         _manual("recover", "recover", "Remove the cause",
                 "Undo what the activity changed and close the way it got in."),
         _VERDICT)},
]
_BY_ID = {playbook["id"]: playbook for playbook in PLAYBOOKS}
_BY_RULE = {rule: playbook for playbook in PLAYBOOKS for rule in playbook["rules"]}


class PlaybookError(QueryError):
    pass


def for_rule(rule_id):
    return _BY_RULE.get(rule_id, _BY_ID["generic"])


# --- configuration -------------------------------------------------------------------

def check_webhook_url(url):
    """The URL if a delivery may go there: https, or http to this machine. Raises ValueError otherwise."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("SIEM_PLAYBOOK_WEBHOOK_URL must be an http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("SIEM_PLAYBOOK_WEBHOOK_URL must not carry a user name or password; use SIEM_PLAYBOOK_WEBHOOK_SECRET")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise ValueError("SIEM_PLAYBOOK_WEBHOOK_URL must use https unless it points at this machine")
    return url


def configure(conn, config):
    """Record in the database whether deliveries are possible, so every connection that creates alerts knows.

    The value is "off", "real" (real alerts only) or "all". The URL and the secret stay in the configuration.
    """
    mode = "off"
    if config.playbook_webhook_url:
        check_webhook_url(config.playbook_webhook_url)
        mode = "all" if config.playbook_webhook_synthetic else "real"
    conn.execute("INSERT INTO meta(key, value) VALUES ('playbook_webhook', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (mode,))
    return mode


def webhook_mode(conn):
    row = conn.execute("SELECT value FROM meta WHERE key = 'playbook_webhook'").fetchone()
    return row[0] if row else "off"


def _not_sent(conn, synthetic):
    """Why a delivery for this alert would not be sent, or None when it would."""
    mode = webhook_mode(conn)
    if mode == "off":
        return "Not sent: no webhook is configured."
    if synthetic and mode != "all":
        return "Not sent: this alert is synthetic."
    return None


def automation_on(conn):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (SETTING,)).fetchone()
    return row is None or row[0] != "0"


# --- starting a playbook -------------------------------------------------------------

def _summary(alert):
    return {k: alert[k] for k in ("id", "rule_id", "title", "severity", "status", "group_key", "first_seen",
                                  "last_seen", "event_count")} | {"synthetic": bool(alert["synthetic"])}


def _enqueue(conn, alert, step_key, kind, body):
    now = now_iso()
    playbook = for_rule(alert["rule_id"])
    payload = {"type": kind, "created_at": now, "watchpost_version": __version__, "alert": _summary(alert),
               "playbook": {"id": playbook["id"], "name": playbook["name"]}, **body}
    conn.execute("INSERT INTO playbook_outbox(alert_id, step_key, kind, payload, created_at, next_attempt_at)"
                 " VALUES (?,?,?,?,?,?)", (alert["id"], step_key, kind, json.dumps(payload, sort_keys=True), now, now))


def _set(conn, alert_id, step_key, status, actor, note, target=None):
    conn.execute("UPDATE playbook_steps SET status = ?, actor = ?, note = ?, target = ?, updated_at = ?"
                 " WHERE alert_id = ? AND step_key = ?", (status, actor, note, target, now_iso(), alert_id, step_key))


def _context(conn, alert):
    since = iso(utcnow() - timedelta(days=CONTEXT_DAYS))
    rows = conn.execute("SELECT status, disposition FROM alerts WHERE group_key = ? AND id != ? AND created_at >= ?",
                        (alert["group_key"], alert["id"], since)).fetchall()
    if not rows:
        return f"No earlier alerts for {alert['group_key']} in the last {CONTEXT_DAYS} days."
    counts = {}
    for row in rows:
        label = (row["disposition"] or "resolved").replace("_", " ") if row["status"] == "resolved" else "still open"
        counts[label] = counts.get(label, 0) + 1
    parts = ", ".join(f"{count} {label}" for label, count in sorted(counts.items()))
    return f"{len(rows)} earlier alert(s) for {alert['group_key']} in the last {CONTEXT_DAYS} days: {parts}."


def start(conn, alert):
    """Give a new alert its playbook and run the automatic steps. The caller holds the transaction.

    `alert` is the alerts row. Returns the playbook's id, or None if the alert already has one.
    """
    if conn.execute("SELECT 1 FROM playbook_runs WHERE alert_id = ?", (alert["id"],)).fetchone():
        return None
    playbook = for_rule(alert["rule_id"])
    conn.execute("INSERT INTO playbook_runs(alert_id, playbook_id, started_at) VALUES (?,?,?)",
                 (alert["id"], playbook["id"], now_iso()))
    conn.executemany("INSERT INTO playbook_steps(alert_id, position, step_key) VALUES (?,?,?)",
                     [(alert["id"], position, step["key"]) for position, step in enumerate(playbook["steps"])])
    automatic = automation_on(conn)
    for step in playbook["steps"]:
        if step["kind"] != "auto":
            continue
        if not automatic:
            _set(conn, alert["id"], step["key"], "skipped", "playbook", f"Automatic steps are turned off (setting {SETTING}).")
        elif step["action"] == "context":
            _set(conn, alert["id"], step["key"], "done", "playbook", _context(conn, alert))
        else:
            reason = _not_sent(conn, alert["synthetic"])
            if reason:
                _set(conn, alert["id"], step["key"], "skipped", "playbook", reason)
            else:
                _enqueue(conn, alert, step["key"], "alert", {})
                _set(conn, alert["id"], step["key"], "requested", "playbook", "Waiting to be delivered to the webhook.")
    return playbook["id"]


def start_for(conn, alert_id, actor):
    """Start the playbook of an alert that has none (one created before playbooks existed)."""
    with transaction(conn):
        alert = _alert(conn, alert_id)
        if start(conn, alert) is None:
            raise PlaybookError("this alert already has a playbook", 409)
        audit(conn, actor, "playbook_started", str(alert_id), {"playbook": for_rule(alert["rule_id"])["id"]})
    return get(conn, alert_id)


# --- reading -------------------------------------------------------------------------

def _alert(conn, alert_id):
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        raise PlaybookError("alert not found", 404)
    return alert


def targets(conn, alert_id, action):
    """The values an action may be requested for: what the alert's own evidence names, nothing else."""
    field = ACTIONS[action][0]
    rows = conn.execute(f"SELECT DISTINCT e.{field} FROM events e JOIN alert_events ae ON ae.event_id = e.id"
                        f" WHERE ae.alert_id = ? AND e.{field} IS NOT NULL ORDER BY e.{field} LIMIT ?",
                        (alert_id, MAX_TARGETS * 4))
    values = [row[0] for row in rows]
    if action == "block_ip":
        values = [value for value in values if _is_public(value)]
    return values[:MAX_TARGETS]


def _is_public(value):
    """Not one of the internal ranges (the same ones viewer masking treats as internal), and a host address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (masking.is_internal(address) or address.is_multicast or address.is_unspecified)


def get(conn, alert_id):
    """An alert's playbook with the state of every step, or None if it has none."""
    run = conn.execute("SELECT * FROM playbook_runs WHERE alert_id = ?", (alert_id,)).fetchone()
    if run is None:
        return None
    playbook = _BY_ID.get(run["playbook_id"], _BY_ID["generic"])
    definitions = {step["key"]: step for step in playbook["steps"]}
    steps = []
    for row in conn.execute("SELECT * FROM playbook_steps WHERE alert_id = ? ORDER BY position", (alert_id,)):
        # A step this version no longer defines is still shown, under its key.
        step = definitions.get(row["step_key"]) or _manual(row["step_key"], "triage", row["step_key"], "")
        entry = {**step, "status": row["status"], "actor": row["actor"], "note": row["note"], "target": row["target"],
                 "updated_at": row["updated_at"]}
        if step["kind"] == "action":
            entry["targets"] = targets(conn, alert_id, step["action"])
        steps.append(entry)
    return {"id": playbook["id"], "name": playbook["name"], "description": playbook["description"],
            "started_at": run["started_at"], "completed_at": run["completed_at"],
            "progress": {"closed": sum(s["status"] in ("done", "skipped") for s in steps), "total": len(steps)},
            "steps": steps}


def catalogue(conn):
    """Every playbook with its steps and rules, and the state of the webhook."""
    counts = dict(conn.execute("SELECT status, COUNT(*) FROM playbook_outbox GROUP BY status").fetchall())
    return {"playbooks": [{**{k: p[k] for k in ("id", "name", "description")}, "rules": list(p["rules"]),
                           "steps": list(p["steps"])} for p in PLAYBOOKS],
            "actions": {name: wanted for name, (_, wanted) in ACTIONS.items()},
            "automation": automation_on(conn),
            "webhook": {"mode": webhook_mode(conn), "pending": counts.get("pending", 0),
                        "sent": counts.get("sent", 0), "failed": counts.get("failed", 0)}}


# --- an analyst works the steps ------------------------------------------------------

def _step(conn, alert_id, step_key):
    run = conn.execute("SELECT * FROM playbook_runs WHERE alert_id = ?", (alert_id,)).fetchone()
    row = conn.execute("SELECT * FROM playbook_steps WHERE alert_id = ? AND step_key = ?", (alert_id, step_key)).fetchone()
    if run is None or row is None:
        raise PlaybookError("this alert has no such playbook step", 404)
    definition = next((s for s in _BY_ID.get(run["playbook_id"], _BY_ID["generic"])["steps"] if s["key"] == step_key),
                      None) or _manual(step_key, "triage", step_key, "")
    return definition


def _text(value, name, required):
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()):
        raise PlaybookError(f"{name} is required")
    if len(value) > MAX_NOTE:
        raise PlaybookError(f"{name} must be {MAX_NOTE} characters or fewer")
    return value.strip() or None


def _finish(conn, alert_id, actor, definition, outcome):
    """After a step changed: note it on the alert, and close or reopen the run."""
    now = now_iso()
    open_steps = conn.execute("SELECT COUNT(*) FROM playbook_steps WHERE alert_id = ? AND status NOT IN ('done', 'skipped')",
                              (alert_id,)).fetchone()[0]
    conn.execute("UPDATE playbook_runs SET completed_at = CASE WHEN ? = 0 THEN COALESCE(completed_at, ?) END"
                 " WHERE alert_id = ?", (open_steps, now, alert_id))
    conn.execute("INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                 (alert_id, actor, "playbook_step", f"{definition['title']}: {outcome}", now))
    conn.execute("UPDATE alerts SET updated_at = ? WHERE id = ?", (now, alert_id))


def set_step(conn, alert_id, step_key, actor, status, note=None):
    """Mark a manual step done, skipped (a reason is required) or pending again."""
    if status not in ("done", "skipped", "pending"):
        raise PlaybookError("status must be done, skipped or pending")
    note = _text(note, "a note saying why the step is skipped" if status == "skipped" else "note", status == "skipped")
    with transaction(conn):
        _alert(conn, alert_id)
        definition = _step(conn, alert_id, step_key)
        if definition["kind"] != "manual":
            raise PlaybookError("only a manual step can be marked by hand; an action step is requested, an automatic one runs itself")
        _set(conn, alert_id, step_key, status, actor, note)
        _finish(conn, alert_id, actor, definition, status)
        audit(conn, actor, "playbook_step_updated", str(alert_id), {"step": step_key, "status": status})
    return get(conn, alert_id)


def request_action(conn, alert_id, step_key, actor, target, reason):
    """Ask the operator's automation to carry out a response action on one target from the alert's evidence."""
    reason = _text(reason, "a reason", True)
    with transaction(conn):
        alert = _alert(conn, alert_id)
        definition = _step(conn, alert_id, step_key)
        if definition["kind"] != "action":
            raise PlaybookError("this step is not a response action")
        if alert["status"] == "resolved":
            raise PlaybookError("the alert is resolved; reopen it before requesting a response action", 409)
        allowed = targets(conn, alert_id, definition["action"])
        if not isinstance(target, str) or target not in allowed:
            raise PlaybookError("the target must be one of the values in this alert's evidence"
                                + (" (public addresses only)" if definition["action"] == "block_ip" else ""))
        not_sent = _not_sent(conn, alert["synthetic"])
        if not_sent:
            _set(conn, alert_id, step_key, "skipped", actor, f"{not_sent} Reason given: {reason}", target)
        else:
            _enqueue(conn, alert, step_key, "response_action",
                     {"action": definition["action"], "target": target, "wanted": ACTIONS[definition["action"]][1],
                      "requested_by": actor, "reason": reason})
            _set(conn, alert_id, step_key, "requested", actor, f"Waiting to be delivered to the webhook. Reason given: {reason}", target)
        _finish(conn, alert_id, actor, definition, f"{'not sent' if not_sent else 'requested'} for {target}")
        audit(conn, actor, "playbook_action_requested", str(alert_id),
              {"step": step_key, "action": definition["action"], "target": target, "sent": not not_sent, "reason": reason})
    return get(conn, alert_id)


# --- delivery ------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None   # a redirect is an answer other than 2xx: the delivery fails and is retried


class Dispatcher:
    """Sends what waits in playbook_outbox to the webhook. One pass is drain(); start() runs passes in a thread."""

    def __init__(self, connect, url, secret=None, cafile=None, timeout=10, poll_seconds=2.0):
        self.connect, self.url, self.secret = connect, check_webhook_url(url), secret
        self.timeout, self.poll_seconds = timeout, poll_seconds
        context = ssl.create_default_context(cafile=cafile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))
        self._stop, self._thread = threading.Event(), None

    def start(self):
        self._thread = threading.Thread(target=self._run, name="playbook-dispatcher", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(self.timeout + 5)

    def _run(self):
        while not self._stop.wait(self.poll_seconds):
            try:
                self.drain()
            except Exception as exc:   # the thread must outlive a locked or missing database
                log.error("playbook delivery pass failed: %s", type(exc).__name__)

    def send(self, delivery_id, body):
        """POST one body. Returns (delivered, what happened)."""
        headers = {"Content-Type": "application/json", "User-Agent": f"Watchpost/{__version__}",
                   "X-Watchpost-Delivery": str(delivery_id)}
        if self.secret:
            headers["X-Watchpost-Signature"] = "sha256=" + hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(self.url, data=body, method="POST", headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                response.read(65536)
                return True, f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            with exc:
                return False, f"HTTP {exc.code}"
        except (OSError, ValueError) as exc:
            return False, type(getattr(exc, "reason", exc)).__name__

    def drain(self, now=None):
        """Send every delivery that is due. Returns how many were delivered."""
        conn, delivered = self.connect(), 0
        try:
            due = conn.execute("SELECT * FROM playbook_outbox WHERE status = 'pending' AND next_attempt_at <= ?"
                               " ORDER BY id LIMIT 50", (iso(now or utcnow()),)).fetchall()
            for row in due:
                ok, outcome = self.send(row["id"], row["payload"].encode())
                attempts = row["attempts"] + 1
                with transaction(conn):
                    if ok:
                        conn.execute("UPDATE playbook_outbox SET status = 'sent', attempts = ?, sent_at = ?, last_error = NULL"
                                     " WHERE id = ?", (attempts, now_iso(), row["id"]))
                        self._settle(conn, row, "done", f"Delivered to the webhook ({outcome}).")
                        delivered += 1
                    elif attempts > len(RETRY_SECONDS):
                        conn.execute("UPDATE playbook_outbox SET status = 'failed', attempts = ?, last_error = ? WHERE id = ?",
                                     (attempts, outcome, row["id"]))
                        self._settle(conn, row, "failed", f"Could not be delivered to the webhook after {attempts} attempts ({outcome}).")
                        log.warning("playbook delivery %s failed after %s attempts: %s", row["id"], attempts, outcome)
                    else:
                        retry_at = iso((now or utcnow()) + timedelta(seconds=RETRY_SECONDS[attempts - 1]))
                        conn.execute("UPDATE playbook_outbox SET attempts = ?, last_error = ?, next_attempt_at = ? WHERE id = ?",
                                     (attempts, outcome, retry_at, row["id"]))
        finally:
            conn.close()
        return delivered

    @staticmethod
    def _settle(conn, row, status, outcome):
        """Write a delivery's result onto its step, keeping the reason the analyst gave."""
        step = conn.execute("SELECT * FROM playbook_steps WHERE alert_id = ? AND step_key = ?",
                            (row["alert_id"], row["step_key"])).fetchone()
        if step is None or step["status"] != "requested":
            return   # the step was requested again or changed since; its newer state stands
        kept = step["note"].split("Reason given: ", 1)[1] if step["note"] and "Reason given: " in step["note"] else None
        note = outcome + (f" Reason given: {kept}" if kept else "")
        conn.execute("UPDATE playbook_steps SET status = ?, note = ?, updated_at = ? WHERE id = ?",
                     (status, note, now_iso(), step["id"]))
        open_steps = conn.execute("SELECT COUNT(*) FROM playbook_steps WHERE alert_id = ? AND status NOT IN ('done', 'skipped')",
                                  (row["alert_id"],)).fetchone()[0]
        if not open_steps:
            conn.execute("UPDATE playbook_runs SET completed_at = COALESCE(completed_at, ?) WHERE alert_id = ?",
                         (now_iso(), row["alert_id"]))


def start_if_enabled(app):
    """Start the delivery thread when a webhook is configured. Returns it (it has stop()), or None."""
    config = app.config
    if not config.playbook_webhook_url:
        return None
    dispatcher = Dispatcher(app.conn, config.playbook_webhook_url, config.playbook_webhook_secret,
                            config.playbook_webhook_cafile).start()
    log.info("Response playbooks deliver to the configured webhook (%s alerts)",
             "all" if config.playbook_webhook_synthetic else "real")
    return dispatcher
