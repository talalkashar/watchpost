"""A small, static MITRE ATT&CK (Enterprise) subset: only the techniques Watchpost rules map to.

No network fetch. Names and tactic assignments follow ATT&CK Enterprise; where ATT&CK lists a
technique under several tactics, the tactic here is the one that best describes what the rule sees.
"""

# Enterprise tactics in kill-chain order.
TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

TECHNIQUES = {
    "T1595.001": ("Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Initial Access"),
    "T1098.001": ("Account Manipulation: Additional Cloud Credentials", "Persistence"),
    "T1136.003": ("Create Account: Cloud Account", "Persistence"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
}

_TACTIC_ORDER = {name: i for i, (_, name) in enumerate(TACTICS)}


def technique(technique_id):
    """Return {"id", "name", "tactic"} for a catalog technique. Raises KeyError if unknown."""
    name, tactic = TECHNIQUES[technique_id]
    return {"id": technique_id, "name": name, "tactic": tactic}


def techniques(*ids):
    return [technique(i) for i in ids]


def tactics():
    """All Enterprise tactics in kill-chain order: [{"id", "name"}]."""
    return [{"id": tid, "name": name} for tid, name in TACTICS]


def tactic_rank(name):
    """Kill-chain position of a tactic name; unknown names sort last."""
    return _TACTIC_ORDER.get(name, len(TACTICS))


def tactic_order(names):
    """Sort tactic names into kill-chain order, dropping duplicates; unknown names go last."""
    return sorted(set(names), key=lambda n: (tactic_rank(n), n))


def catalog():
    """Every catalog technique, sorted by kill-chain tactic then id."""
    items = [technique(i) for i in TECHNIQUES]
    return sorted(items, key=lambda t: (tactic_rank(t["tactic"]), t["id"]))


def coverage(rules, hits_by_rule):
    """Map each catalog technique to the rules that cover it and their alert counts.

    `rules`: [{"id", "name", "enabled", "techniques": [...]}]; `hits_by_rule`: {rule_id: alert count}.
    """
    by_technique = {t["id"]: {**t, "rules": [], "hits": 0} for t in catalog()}
    for rule in rules:
        for t in rule.get("techniques") or []:
            entry = by_technique.get(t["id"])
            if entry is None:
                continue
            entry["rules"].append({"id": rule["id"], "name": rule["name"], "enabled": bool(rule["enabled"]),
                                   "hits": hits_by_rule.get(rule["id"], 0)})
            entry["hits"] += hits_by_rule.get(rule["id"], 0)
    items = list(by_technique.values())
    for item in items:
        item["covered"] = any(r["enabled"] for r in item["rules"])
    return {
        "tactics": tactics(),
        "techniques": items,
        "summary": {"techniques": len(items), "covered": sum(i["covered"] for i in items),
                    "with_hits": sum(1 for i in items if i["hits"])},
    }


# Evidence levels, strongest first. Only "validated" counts as covered.
LEVELS = ("validated", "mapped", "disabled", "gap")
LEVEL_MEANING = {
    "validated": "An enabled rule detects a labeled synthetic attack that exercises this technique.",
    "mapped": "An enabled rule maps here, but no labeled scenario proves it detects this technique. "
              "Not counted as covered.",
    "disabled": "Only disabled rules map here, so nothing is watching for it.",
    "gap": "No rule maps here.",
}


def evidence(cov, lab_rules, scenarios):
    """Grade each technique in `coverage()` output by what the labeled scenarios prove.

    `lab_rules`: the noise-lab rows ({"rule_id", "verdict", "detected", "lookalikes_*", ...});
    `scenarios`: {name: {"malicious", "techniques"}} as in simulate.SCENARIOS. A scenario proves a
    technique for a rule when the rule is enabled, detected that malicious scenario, and the scenario
    is tagged with the technique. Inputs are not modified. `covered` now means validated.
    """
    lab = {r["rule_id"]: r for r in lab_rules}
    items = []
    for t in cov["techniques"]:
        rules, proving = [], set()
        for r in t["rules"]:
            row = lab.get(r["id"], {})
            proves = sorted(n for n in row.get("detected", []) if r["enabled"] and n in scenarios
                            and scenarios[n]["malicious"] and t["id"] in scenarios[n].get("techniques", ()))
            proving.update(proves)
            rules.append({**r, "verdict": row.get("verdict"), "lookalikes_tested": row.get("lookalikes_tested", []),
                          "lookalikes_fired": row.get("lookalikes_fired", []) + row.get("other_benign_fired", []),
                          "proves": proves})
        if proving:
            level = "validated"
        elif any(r["enabled"] for r in t["rules"]):
            level = "mapped"
        else:
            level = "disabled" if t["rules"] else "gap"
        items.append({**t, "rules": rules, "level": level, "covered": level == "validated",
                      "scenarios": sorted(proving)})
    levels = {lvl: sum(i["level"] == lvl for i in items) for lvl in LEVELS}
    return {**cov, "techniques": items, "levels": list(LEVELS), "level_meaning": LEVEL_MEANING,
            "summary": {**cov["summary"], "covered": levels["validated"], "levels": levels}}


NAVIGATOR_LAYER_VERSION = "4.5"  # the layer file format; this module states no ATT&CK release, so none is claimed
LEVEL_COLORS = {"validated": "#2e9e6b", "mapped": "#e6b422", "disabled": "#9aa5b1", "gap": "#d9534f"}


def navigator_layer(cov):
    """An ATT&CK Navigator layer from `evidence()` output: every catalog technique, colored by level.

    The score is the number of alerts raised by the rules mapped to the technique; the comment
    starts with the level, so the layer reads the same as the Coverage view.
    """
    def comment(t):
        rules = ", ".join(r["id"] + ("" if r["enabled"] else " (disabled)") for r in t["rules"]) or "none"
        proof = f" Detected on synthetic scenario(s): {', '.join(t['scenarios'])}." if t["scenarios"] else ""
        return f"{t['level'].capitalize()}: {LEVEL_MEANING[t['level']]}{proof} Rules: {rules}"

    return {
        "name": "Watchpost rule coverage",
        "versions": {"layer": NAVIGATOR_LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": "Watchpost's technique catalog colored by evidence level. Validated means an enabled rule "
                       "detects a labeled scenario from the project's own synthetic data, not real-world coverage; "
                       "mapped is not counted as covered. Scores count alerts raised from synthetic demo data; "
                       "they are not observations of real attacks.",
        "techniques": [{
            "techniqueID": t["id"],
            "tactic": t["tactic"].lower().replace(" ", "-"),
            "score": t["hits"],
            "color": LEVEL_COLORS[t["level"]],
            "comment": comment(t),
        } for t in cov["techniques"]],
        "gradient": {"colors": ["#cfe2f3", "#1f4e79"], "minValue": 0,
                     "maxValue": max([t["hits"] for t in cov["techniques"]] + [1])},
        "legendItems": [{"label": lvl.capitalize(), "color": LEVEL_COLORS[lvl]} for lvl in LEVELS],
    }
