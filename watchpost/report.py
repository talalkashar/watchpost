"""Incident and alert reports: one report model, rendered as Markdown or PDF.

`build(conn, incident_id)` reads a correlated incident (watchpost.incidents) with every member alert's
evidence, notes, and ATT&CK techniques. `build_from_alert(conn, alert_id)` reports on a single alert.
Both return the same model shape.
"""

import json

from . import __version__, assets as assets_mod, attack, incidents
from .db import now_iso
from .pdfwriter import Document
from .queries import QueryError, get_alert

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SYNTHETIC_BANNER = ("SYNTHETIC DATA: this report was generated from simulated events for demonstration. "
                    "It does not describe a real intrusion.")
EVIDENCE_PER_ALERT = 25
TIMELINE_LIMIT = 200

# Recommended response actions by ATT&CK technique id. Sub-techniques fall back to their parent id.
ACTIONS = {
    "T1110": ["Block or rate-limit the source IPs at the edge and on the targeted service.",
              "Enforce account lockout and MFA on every externally reachable login."],
    "T1110.001": ["Block the source IP and confirm the targeted account's password is strong and unexposed."],
    "T1110.003": ["Reset passwords for every sprayed account that later logged in successfully.",
                  "Alert on one source failing across many accounts; check for leaked username lists."],
    "T1110.004": ["Check the attempted credentials against known breach corpora and force resets on matches."],
    "T1078": ["Treat the account as compromised: disable or reset it and revoke its active sessions and tokens.",
              "Review everything the account did after the suspicious login."],
    "T1078.004": ["Rotate the cloud principal's keys and review its recent API activity."],
    "T1595": ["Block the scanning IPs and confirm no scanned path (for example /.env) is actually served."],
    "T1595.002": ["Patch or remove the software the scanner probed for; verify with an authenticated scan."],
    "T1046": ["Close unneeded ports on the swept hosts and confirm the firewall default-deny policy."],
    "T1190": ["Check web server logs for successful exploitation and patch the exposed application."],
    "T1548": ["Review sudoers/admin group membership on the host; remove rights that are not needed."],
    "T1548.003": ["Audit /etc/sudoers and sudo logs on the host; require re-authentication for sudo."],
    "T1562.008": ["Turn cloud audit logging back on (StartLogging, or recreate the trail) and restrict who may stop it.",
                  "Treat the time logging was off as a blind spot and review it from other sources."],
    "T1068": ["Patch the host's kernel and local services; rebuild it if root was obtained."],
    "T1136": ["Disable accounts created during the incident window and confirm who requested them."],
    "T1136.001": ["Remove unauthorized local accounts and check for persistence (cron, SSH keys, services)."],
    "T1098": ["Revert unexpected group, role, or permission changes and review who made them."],
    "T1098.001": ["Revoke credentials or access keys added during the incident and rotate the rest."],
    "T1021": ["Restrict remote access between internal hosts to named jump hosts."],
    "T1021.004": ["Review SSH authorized_keys on reached hosts and restrict SSH to a bastion."],
    "T1530": ["Review object-level access logs for the storage involved and tighten bucket policies."],
    "T1567": ["Block the destination service and estimate the volume of data that left."],
    "T1048": ["Block the outbound destination and review egress rules for the source host."],
    "T1041": ["Isolate the host and inspect outbound connections to the command-and-control address."],
    "T1078.003": ["Disable the local account and check it against the approved local account inventory."],
    "T1133": ["Require MFA on the VPN or remote service and review the sessions opened from the flagged sources."],
}
FALLBACK_ACTIONS = [
    "Confirm whether the activity was authorized by talking to the account owner.",
    "Contain: block the source IPs and disable or reset the affected accounts.",
    "Scope: search for other activity from the same IPs and accounts before and after this window.",
    "Record the verdict on each alert so rule precision stays accurate.",
]


class ReportError(QueryError):
    pass


def _json(value, default):
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _catalog_lookup(technique_id):
    try:
        return attack.technique(technique_id)
    except KeyError:
        return None


def rule_techniques(conn, rule_id):
    """Techniques for a rule: the `rules.techniques` column, else the built-in rule definition."""
    row = conn.execute("SELECT techniques FROM rules WHERE id = ?", (rule_id,)).fetchone()
    techniques = _json(row[0] if row else None, None)
    if techniques is None:
        from .rules import DEFAULT_RULES
        techniques = next((r.get("techniques") for r in DEFAULT_RULES if r.get("id") == rule_id), None) or []
    result = []
    for item in techniques:
        if isinstance(item, str):
            item = _catalog_lookup(item) or {"id": item}
        if isinstance(item, dict) and item.get("id"):
            result.append({"id": str(item["id"]), "name": item.get("name") or "",
                           "tactic": item.get("tactic") or "Unmapped tactic"})
    return result


def actions_for(techniques):
    """Recommended actions keyed by technique, de-duplicated, with a generic fallback."""
    rows, seen = [], set()
    for t in techniques:
        for action in ACTIONS.get(t["id"]) or ACTIONS.get(t["id"].split(".")[0]) or []:
            if action not in seen:
                seen.add(action)
                rows.append({"technique": t["id"], "action": action})
    for action in FALLBACK_ACTIONS if not rows else FALLBACK_ACTIONS[-1:]:
        rows.append({"technique": None, "action": action})
    return rows


def _assemble(conn, kind, ident, title, alerts, extra):
    """Merge full alert details into the shared report model."""
    ips, users, hosts, timeline, notes, techniques = set(), set(), set(), {}, [], {}
    for a in alerts:
        for e in a["evidence"]:
            ips.update(filter(None, (e.get("src_ip"), e.get("dest_ip"))))
            users.update(filter(None, (e.get("user"),)))
            hosts.update(filter(None, (e.get("host"),)))
        for e in a["timeline"]:
            timeline.setdefault(e["id"], {**e, "alert_ids": []})
            if e["is_evidence"]:
                timeline[e["id"]]["alert_ids"].append(a["id"])
                timeline[e["id"]]["is_evidence"] = True
        notes += [{**n, "alert_id": a["id"]} for n in a["notes"]]
        a["techniques"] = rule_techniques(conn, a["rule_id"])
        for t in a["techniques"]:
            techniques.setdefault(t["id"], t)
    by_tactic = {}
    for t in sorted(techniques.values(), key=lambda t: (attack.tactic_rank(t["tactic"]), t["tactic"], t["id"])):
        by_tactic.setdefault(t["tactic"], []).append(t)
    severity = max((a["severity"] for a in alerts), key=lambda s: SEVERITY_ORDER.get(s, -1), default="low")
    first = min((a["first_seen"] for a in alerts), default=None)
    last = max((a["last_seen"] for a in alerts), default=None)
    matched = {}
    for a in alerts:
        for asset in a.get("assets") or []:
            matched.setdefault(asset["name"], asset)
    model = {
        "kind": kind, "id": ident, "title": title, "severity": severity, "status": None,
        "assets": [matched[k] for k in sorted(matched)],
        "synthetic": any(a["synthetic"] for a in alerts), "first_seen": first, "last_seen": last,
        "generated_at": now_iso(), "generator": f"Watchpost {__version__}",
        "entities": {"ips": sorted(ips), "users": sorted(users), "hosts": sorted(hosts)},
        "alerts": [{k: a.get(k) for k in ("id", "title", "rule_id", "rule_version", "severity", "base_severity",
                                          "severity_note", "status", "disposition", "explanation", "first_seen",
                                          "last_seen", "event_count", "techniques", "assets")}
                   | {"evidence": a["evidence"][:EVIDENCE_PER_ALERT]} for a in alerts],
        "timeline": sorted(timeline.values(), key=lambda e: (e["ts"], e["id"]))[:TIMELINE_LIMIT],
        "techniques_by_tactic": by_tactic,
        "notes": sorted(notes, key=lambda n: (n["created_at"], n["id"])),
        "actions": actions_for([t for items in by_tactic.values() for t in items]),
    }
    model.update(extra)
    model["summary"] = _summary(model)
    return model


def _summary(m):
    rules = sorted({a["rule_id"] for a in m["alerts"]})
    events = sum(a["event_count"] or 0 for a in m["alerts"])
    parts = [f"{len(m['alerts'])} alert(s) from {len(rules)} detection rule(s) ({', '.join(rules)}) "
             f"covering {events} event(s) between {m['first_seen']} and {m['last_seen']}."]
    ent = m["entities"]
    if ent["ips"] or ent["users"] or ent["hosts"]:
        bits = [f"{len(ent[k])} {label}" for k, label in (("ips", "IP address(es)"), ("users", "account(s)"),
                                                         ("hosts", "host(s)")) if ent[k]]
        parts.append("Entities involved: " + ", ".join(bits) + ".")
    if m["techniques_by_tactic"]:
        parts.append(f"Mapped to {sum(len(v) for v in m['techniques_by_tactic'].values())} ATT&CK technique(s) "
                     f"across {len(m['techniques_by_tactic'])} tactic(s).")
    if m.get("escalated"):
        parts.append(f"Escalated: the alerts span {len(m['stages'])} ATT&CK tactics.")
    if m.get("assets"):
        sensitive = [a for a in m["assets"] if a.get("data_tags")]
        critical = [a for a in m["assets"] if a.get("criticality") in ("high", "critical")]
        bits = [f"{len(m['assets'])} inventoried asset(s)"]
        if critical:
            bits.append(f"{len(critical)} of high or critical importance ({', '.join(a['name'] for a in critical[:3])})")
        if sensitive:
            bits.append(f"{len(sensitive)} processing sensitive data ({', '.join(a['name'] for a in sensitive[:3])})")
        parts.append("Assets involved: " + ", ".join(bits) + ".")
    parts.append(f"Highest severity: {m['severity']}. Status: {m['status'] or 'unknown'}.")
    return " ".join(parts)


def build_from_alert(conn, alert_id):
    try:
        alert = get_alert(conn, alert_id)
    except QueryError as exc:
        raise ReportError(str(exc), exc.status)
    model = _assemble(conn, "alert", alert["id"], alert["title"], [alert], {})
    model["status"] = alert["status"] + (f" ({alert['disposition']})" if alert.get("disposition") else "")
    model["summary"] = _summary(model)
    return model


def build(conn, incident_id):
    try:
        incident = incidents.get_incident(conn, incident_id)
        alerts = [get_alert(conn, a["id"]) for a in incident["alerts"]]
    except QueryError as exc:
        raise ReportError(str(exc), exc.status)
    model = _assemble(conn, "incident", incident["id"], incident["title"], alerts, {})
    # The incident row is authoritative for status, severity (escalation included), span and kill chain.
    model.update(status=incident["status"], first_seen=incident["first_seen"], last_seen=incident["last_seen"],
                 synthetic=bool(incident["synthetic"]) or model["synthetic"], stages=list(incident["stages"]),
                 escalated=incident["escalated"], assignee=incident.get("assignee"))
    if incident["severity"] in SEVERITY_ORDER:
        model["severity"] = incident["severity"]
    for key, name in (("ips", "src_ip"), ("users", "user"), ("hosts", "host")):
        model["entities"][key] = sorted(set(model["entities"][key]) | set(incident["entities"].get(name) or []))
    known = {a["name"]: a for a in model["assets"]}
    for a in incident.get("assets") or []:
        known.setdefault(a["name"], a)
    model["assets"] = [known[k] for k in sorted(known)]
    # ATT&CK techniques by tactic in kill-chain order, each with the alerts that map to it.
    by_tactic = {}
    for t in incident["techniques"]:
        by_tactic.setdefault(t["tactic"], []).append(
            {"id": t["id"], "name": t.get("name") or "", "tactic": t["tactic"], "alert_ids": t["alert_ids"]})
    model["techniques_by_tactic"] = by_tactic or model["techniques_by_tactic"]
    model["actions"] = actions_for([t for items in model["techniques_by_tactic"].values() for t in items])
    model["summary"] = _summary(model)
    return model


# --- Renderers -----------------------------------------------------------------------------

_MD_SPECIAL = "\\`*_[]<>|#"


def md(text):
    """Escape log-derived text so it cannot inject Markdown or HTML into the report."""
    if text is None:
        return "-"
    text = " ".join(str(text).split())
    return "".join("\\" + c if c in _MD_SPECIAL else c for c in text) or "-"


def _md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(md(c) for c in row) + " |" for row in rows]
    return lines


def _alert_refs(t):
    ids = t.get("alert_ids")
    return f" (alert{'s' if len(ids) > 1 else ''} " + ", ".join(f"#{i}" for i in ids) + ")" if ids else ""


def to_markdown(m):
    label = "Incident" if m["kind"] == "incident" else "Alert"
    out = [f"# {label} report: {md(m['title'])}", ""]
    if m["synthetic"]:
        out += [f"> **{SYNTHETIC_BANNER}**", ""]
    out += [f"- **{label}:** #{m['id']}", f"- **Severity:** {md(m['severity'])}", f"- **Status:** {md(m['status'])}",
            f"- **First seen:** {md(m['first_seen'])}", f"- **Last seen:** {md(m['last_seen'])}",
            f"- **Generated:** {m['generated_at']} by {m['generator']}", "", "## Summary", "", md(m["summary"]), ""]
    if m.get("stages"):
        out += ["**Kill-chain stages:** " + " -> ".join(md(s) for s in m["stages"])
                + (" (escalated: 3 or more tactics)" if m.get("escalated") else ""), ""]
    out += ["## Entities", ""]
    for key, label_ in (("ips", "IP addresses"), ("users", "Accounts"), ("hosts", "Hosts")):
        out.append(f"- **{label_}:** " + (", ".join(f"`{md(v)}`" for v in m["entities"][key]) or "none"))
    out += ["", "## Assets", ""]
    if m.get("assets"):
        out += _md_table(["Asset", "Kind", "Criticality", "Sensitive data"],
                         [[a["name"], a.get("kind"), a.get("criticality"), ", ".join(a.get("data_tags") or []) or "none"]
                          for a in m["assets"]])
    else:
        out.append("No inventoried asset is involved.")
    out += ["", "## MITRE ATT&CK techniques", ""]
    if m["techniques_by_tactic"]:
        for tactic, items in m["techniques_by_tactic"].items():
            out.append(f"- **{md(tactic)}:** " + ", ".join(f"{md(t['id'])} {md(t['name'])}".strip() + _alert_refs(t)
                                                          for t in items))
    else:
        out.append("No ATT&CK mapping is recorded for the rules involved.")
    out += ["", "## Timeline", ""]
    out += _md_table(["Time", "Type", "User", "Source IP", "Host", "Evidence", "Message"],
                     [[e["ts"], e["event_type"], e.get("user"), e.get("src_ip"), e.get("host"),
                       "yes" if e["is_evidence"] else "", e.get("message")] for e in m["timeline"]])
    out += ["", "## Alerts and evidence", ""]
    for a in m["alerts"]:
        techs = ", ".join(t["id"] for t in a["techniques"]) or "none"
        out += [f"### Alert #{a['id']}: {md(a['title'])}", "",
                f"- **Rule:** `{md(a['rule_id'])}` v{a['rule_version']} · **Severity:** {md(a['severity'])} · "
                f"**Status:** {md(a['status'])}" + (f" ({md(a['disposition'])})" if a["disposition"] else ""),
                f"- **Window:** {md(a['first_seen'])} to {md(a['last_seen'])} · **Events:** {a['event_count']}",
                f"- **Techniques:** {md(techs)}"]
        if a.get("severity_note") and a.get("base_severity") and a["base_severity"] != a["severity"]:
            out.append(f"- **Asset weighting:** rule severity {md(a['base_severity'])}; {md(a['severity_note'])}")
        out += ["", f"**Why it fired:** {md(a['explanation'])}", ""]
        shown = len(a["evidence"])
        out += _md_table(["Time", "Type", "User", "Source IP", "Host", "Message"],
                         [[e["ts"], e["event_type"], e.get("user"), e.get("src_ip"), e.get("host"), e.get("message")]
                          for e in a["evidence"]])
        if shown < (a["event_count"] or 0):
            out.append(f"\n_First {shown} of {a['event_count']} evidence events shown._")
        out.append("")
    out += ["## Analyst notes", ""]
    out += [f"- {md(n['created_at'])} **{md(n['author'])}**"
            + (f" (alert #{n['alert_id']})" if n.get("alert_id") else "") + f": {md(n['body'])}"
            for n in m["notes"]] or ["No analyst notes recorded."]
    out += ["", "## Recommended actions", ""]
    out += [f"{i}. " + (f"**{md(r['technique'])}:** " if r["technique"] else "") + md(r["action"])
            for i, r in enumerate(m["actions"], 1)]
    out.append("")
    return "\n".join(out)


def to_pdf_bytes(m):
    label = "Incident" if m["kind"] == "incident" else "Alert"
    doc = Document(title=f"{label} report: {m['title']}",
                   footer=f"Watchpost {label.lower()} report #{m['id']}"
                          + (" - SYNTHETIC DATA" if m["synthetic"] else "") + f" - generated {m['generated_at']}")
    doc.text(f"WATCHPOST {label.upper()} REPORT", size=9, bold=True, color=(0.35, 0.4, 0.5))
    doc.text(m["title"], size=18, bold=True)
    doc.space(4)
    if m["synthetic"]:
        doc.banner(SYNTHETIC_BANNER)
        doc.space(4)
    doc.table(["Field", "Value"], [[f"{label}", f"#{m['id']}"], ["Severity", m["severity"]],
                                   ["Status", m["status"] or "-"], ["First seen", m["first_seen"] or "-"],
                                   ["Last seen", m["last_seen"] or "-"], ["Generated", m["generated_at"]]],
              widths=[1, 4], size=9)
    doc.heading("Summary")
    doc.text(m["summary"])
    if m.get("stages"):
        doc.text("Kill-chain stages: " + " -> ".join(m["stages"])
                 + (" (escalated: 3 or more tactics)" if m.get("escalated") else ""), bold=True)
    doc.heading("Entities")
    for key, name in (("ips", "IP addresses"), ("users", "Accounts"), ("hosts", "Hosts")):
        doc.text(f"{name}: " + (", ".join(m["entities"][key]) or "none"))
    doc.heading("Assets")
    if m.get("assets"):
        doc.table(["Asset", "Kind", "Criticality", "Sensitive data"],
                  [[a["name"], a.get("kind") or "-", a.get("criticality") or "-",
                    ", ".join(a.get("data_tags") or []) or "none"] for a in m["assets"]],
                  widths=[2, 1.5, 1.5, 3], size=9)
    else:
        doc.text("No inventoried asset is involved.")
    doc.heading("MITRE ATT&CK techniques")
    if m["techniques_by_tactic"]:
        doc.table(["Tactic", "Technique", "Name", "Alerts"],
                  [[tactic, t["id"], t["name"], ", ".join(f"#{i}" for i in t.get("alert_ids") or []) or "-"]
                   for tactic, items in m["techniques_by_tactic"].items() for t in items],
                  widths=[2, 1, 3.4, 1], size=9)
    else:
        doc.text("No ATT&CK mapping is recorded for the rules involved.")
    doc.heading("Timeline")
    doc.table(["Time", "Type", "User", "Source IP", "Host", "Ev.", "Message"],
              [[e["ts"], e["event_type"], e.get("user"), e.get("src_ip"), e.get("host"),
                "*" if e["is_evidence"] else "", e.get("message")] for e in m["timeline"]],
              widths=[2.3, 1.5, 1, 1.4, 0.9, 0.4, 3.5], size=7)
    doc.heading("Alerts and evidence")
    for a in m["alerts"]:
        doc.text(f"Alert #{a['id']}: {a['title']}", size=11, bold=True)
        doc.text(f"Rule {a['rule_id']} v{a['rule_version']} | severity {a['severity']} | status {a['status']}"
                 + (f" ({a['disposition']})" if a["disposition"] else "") + f" | {a['event_count']} events | "
                 f"techniques: {', '.join(t['id'] for t in a['techniques']) or 'none'}", size=9)
        if a.get("severity_note") and a.get("base_severity") and a["base_severity"] != a["severity"]:
            doc.text(f"Asset weighting: rule severity {a['base_severity']}; {a['severity_note']}", size=9, indent=8)
        doc.text("Why it fired: " + (a["explanation"] or ""), size=9, indent=8)
        doc.space(3)
        doc.table(["Time", "Type", "User", "Source IP", "Host", "Message"],
                  [[e["ts"], e["event_type"], e.get("user"), e.get("src_ip"), e.get("host"), e.get("message")]
                   for e in a["evidence"]], widths=[2.3, 1.5, 1, 1.4, 0.9, 3.9], size=7)
        if len(a["evidence"]) < (a["event_count"] or 0):
            doc.text(f"First {len(a['evidence'])} of {a['event_count']} evidence events shown.", size=8,
                     color=(0.4, 0.4, 0.4))
    doc.heading("Analyst notes")
    if m["notes"]:
        for n in m["notes"]:
            doc.text(f"{n['created_at']} {n['author']}" + (f" (alert #{n['alert_id']})" if n.get("alert_id") else "")
                     + ":", size=9, bold=True)
            doc.text(n["body"], size=9, indent=8)
    else:
        doc.text("No analyst notes recorded.")
    doc.heading("Recommended actions")
    for i, r in enumerate(m["actions"], 1):
        doc.text(f"{i}. " + (f"[{r['technique']}] " if r["technique"] else "") + r["action"], indent=4)
    return doc.to_bytes()
