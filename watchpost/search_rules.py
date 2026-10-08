"""Saved searches as detections: a hunt filter promoted to a threshold rule (rule id search_<slug>).

    query        a hunt filter (watchpost/hunt.py), no `|` stage and no time terms
    group_by     one hunt field to count per (user, host, source, src_ip, dest_ip, event_type, dest_port)
    threshold    fire when at least N matching events of one group value fall ...
    window       ... within W minutes of each other (a sliding window, inclusive at both ends)

The filter is matched in Python over the event dicts the engine already scans (engine.RULE_EVENT_FIELDS),
with the hunt's SQL semantics: same fields and value checks, a trailing `*` on an unquoted value is a prefix
match, message terms are "contains", NOT keeps events missing the field, and comparisons fold case the way
SQLite does (ASCII only): user equality, every prefix match and message contains ignore ASCII case; other
equality is exact. tests/test_search_rules.py cross-checks this matcher against hunt.compile_query in SQL.

Hunt fields the engine does not load (outcome, severity, batch_id) are refused, and so are time terms: the
window replaces them. The rule's params are the compiled definition; only `threshold` and `window_seconds`
are tunable through a reviewed rule_update. A new query means a new rule. Like an imported Sigma rule, it
is added disabled through a two-person `search_add` change request and can be enabled only once its labeled
sample passes: the malicious events must raise a finding and the benign look-alikes must raise none.
"""

import json
import re
import string
from collections import defaultdict
from datetime import timedelta

from . import attack
from . import hunt
from . import sigma
from .db import iso, parse_iso
from .normalize import EventError, parse_timestamp

RULE_PREFIX = "search_"
SAMPLE_PREFIX = "search_sample:"
NAME_MAX = 80
THRESHOLD_MAX = 100_000
WINDOW_MINUTES_MAX = 1440
MAX_TECHNIQUES = 10
SEVERITIES = ("low", "medium", "high", "critical")
TUNABLE = ("threshold", "window_seconds")
PARAM_KEYS = {"title", "query", "terms", "group_by", "threshold", "window_seconds"}
DEFINITION_KEYS = {"name", "group_by", "threshold", "window_minutes", "severity", "techniques"}
# Hunt fields the engine's event dicts do not carry, so a rule could never match them.
NOT_LOADED = ("outcome", "severity", "batch_id")
TIME_FIELDS = ("last", "since", "until")
GROUP_BY = [f for f in hunt.GROUPABLE if f not in NOT_LOADED and f != "synthetic"]
SAMPLE_FIELDS = sigma.SAMPLE_FIELDS | {"source"}
SAMPLE_BASE = "2024-01-01T00:00:00.000Z"  # sample events without a ts are one second apart from here

_ASCII_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


class SearchRuleError(ValueError):
    """The definition is outside what a search rule supports. The message says why."""


def _fold(text):
    """SQLite's NOCASE and LIKE fold ASCII letters only; so does this."""
    return text.translate(_ASCII_FOLD)


def is_search(rule_id):
    return isinstance(rule_id, str) and rule_id.startswith(RULE_PREFIX)


def slug(name):
    """Rule id for a name: search_<letters and underscores>, to fit the [a-z_]+ rule routes."""
    base = re.sub(r"[^a-z]+", "_", name.lower()).strip("_")[:48].strip("_")
    if not base:
        raise SearchRuleError("the name must contain letters (it names the rule id)")
    return RULE_PREFIX + base


# --- The filter ------------------------------------------------------------------------------

def parse_filter(query):
    """(query, terms) for a rule query, refused with a reason when a rule cannot run it."""
    if not isinstance(query, str) or not query.strip():
        raise SearchRuleError("query is required")
    query = query.strip()
    try:
        terms, stage = hunt._parse(query)
        if stage is not None:
            raise SearchRuleError("a rule query is a filter only: remove the | stage (the rule's group-by, "
                                  "threshold and window do the counting)")
        for term in terms:
            if term["field"] in TIME_FIELDS:
                raise SearchRuleError(f"time terms ({term['field']}:) are refused in a rule query: the rule's "
                                      "window replaces them, and detection reads events as they arrive")
            if term["field"] in NOT_LOADED:
                raise SearchRuleError(f"{term['field']} is not available to detection rules (the engine does not "
                                      "load it); filter on another field")
        if not terms:
            raise SearchRuleError("a rule query needs at least one term (an empty filter matches every event)")
        hunt.compile_query(query)  # the same value checks as a hunt: enums, ports, flags
    except hunt.HuntError as exc:
        raise SearchRuleError(str(exc))
    return query, terms


def _starts(value, prefix):
    return isinstance(value, str) and _fold(value).startswith(prefix)


def _predicate(term):
    """One term as a function of an event dict, mirroring hunt._term_sql. Negation is applied by the caller."""
    field, value = term["field"], term["value"]
    kind, column = hunt.FIELDS[field]
    prefix = value[:-1] if value.endswith("*") and not term["quoted"] else None
    if kind == "message":
        needle = _fold(prefix if prefix else value)  # LIKE '%text%': ASCII case-insensitive contains
        return lambda e: isinstance(e.get("message"), str) and needle in _fold(e["message"])
    if kind == "port":
        port = int(value)
        return lambda e: e.get("dest_port") == port
    if kind == "flag":
        flag = hunt.FLAGS[value.lower()]
        return lambda e: e.get("synthetic") == flag
    if kind == "ip":
        if prefix is not None:
            p = _fold(prefix)
            return lambda e: _starts(e.get("src_ip"), p) or _starts(e.get("dest_ip"), p)
        return lambda e: e.get("src_ip") == value or e.get("dest_ip") == value
    if prefix is not None:
        p = _fold(prefix)
        return lambda e: _starts(e.get(column), p)
    if field == "user":  # COLLATE NOCASE
        folded = _fold(value)
        return lambda e: isinstance(e.get("user"), str) and _fold(e["user"]) == folded
    return lambda e: e.get(column) == value


def matcher(terms):
    """A function event -> bool for a list of parsed terms (all ANDed). A NOT term keeps events missing the
    field, as NOT COALESCE((sql), 0) does in hunt._compile."""
    preds = [(_predicate(t), t["negate"]) for t in terms]
    return lambda e: all(pred(e) != negate for pred, negate in preds)


def matches(params, event):
    return matcher(params["terms"])(event)


# --- Definition and stored params ------------------------------------------------------------

def _int(value, name, low, high):
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise SearchRuleError(f"{name} must be an integer between {low} and {high}")
    return value


def _group_by(value):
    if value not in GROUP_BY:
        raise SearchRuleError(f"group_by must be one of {', '.join(GROUP_BY)}")
    return value


def _window_seconds(value):
    _int(value, "window_seconds", 60, WINDOW_MINUTES_MAX * 60)
    if value % 60:
        raise SearchRuleError("window_seconds must be a whole number of minutes (a multiple of 60)")
    return value


def compile_rule(name, query, definition):
    """Compile a promoted saved search. `definition`: {group_by, threshold, window_minutes, severity,
    techniques (optional), name (optional, defaults to `name`)}. Raises SearchRuleError with a reason."""
    if not isinstance(definition, dict) or not set(definition) <= DEFINITION_KEYS:
        raise SearchRuleError("a search rule is {group_by, threshold, window_minutes, severity, techniques "
                              "(optional), name (optional)}")
    name = definition.get("name") or name
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= NAME_MAX:
        raise SearchRuleError(f"name must be 1-{NAME_MAX} characters")
    name = name.strip()
    query, terms = parse_filter(query)
    minutes = _int(definition.get("window_minutes"), "window_minutes", 1, WINDOW_MINUTES_MAX)
    severity = definition.get("severity")
    if severity not in SEVERITIES:
        raise SearchRuleError(f"severity must be one of {', '.join(SEVERITIES)}")
    ids = definition.get("techniques") or []
    if not isinstance(ids, list) or len(ids) > MAX_TECHNIQUES or not all(isinstance(t, str) for t in ids):
        raise SearchRuleError(f"techniques must be a list of at most {MAX_TECHNIQUES} ATT&CK technique ids")
    techniques = []
    for tid in ids:
        if tid.upper() not in attack.TECHNIQUES:
            raise SearchRuleError(f"technique {tid!r} is not in the ATT&CK catalog")
        if tid.upper() not in [t["id"] for t in techniques]:
            techniques.append(attack.technique(tid.upper()))
    params = {"title": name, "query": query, "terms": terms, "group_by": _group_by(definition.get("group_by")),
              "threshold": _int(definition.get("threshold"), "threshold", 1, THRESHOLD_MAX),
              "window_seconds": minutes * 60}
    return {"rule_id": slug(name), "title": name, "severity": severity, "techniques": techniques,
            "description": f"Promoted saved search: {describe(params)}", "query": query, "params": params,
            "conditions": describe(params)}


def describe(params):
    """One readable line, e.g. at least 5 events matching [event_type = auth_failure] per src_ip within 10 min."""
    labels = []
    for t in params["terms"]:
        _, _, label = hunt._term_sql(t, None)
        labels.append(("NOT " if t["negate"] else "") + label)
    return (f"at least {params['threshold']} event(s) matching [{' AND '.join(labels)}] per {params['group_by']} "
            f"within {params['window_seconds'] // 60} min (sliding window)")


def validate_params(params):
    """Check stored params before they run. The compiled terms must be what the query parses to."""
    if not isinstance(params, dict) or set(params) != PARAM_KEYS:
        raise SearchRuleError(f"search rule params must be {', '.join(sorted(PARAM_KEYS))}; only threshold and "
                              "window_seconds are tunable")
    if not isinstance(params["title"], str) or not 1 <= len(params["title"]) <= NAME_MAX:
        raise SearchRuleError("search rule title is malformed")
    query, terms = parse_filter(params["query"])
    if query != params["query"] or terms != params["terms"]:
        raise SearchRuleError("the compiled terms do not match the query")
    _group_by(params["group_by"])
    _int(params["threshold"], "threshold", 1, THRESHOLD_MAX)
    _window_seconds(params["window_seconds"])
    return params


# --- Evaluation ------------------------------------------------------------------------------

def run(events, params):
    """The rule function: (events, params) -> findings, like the built-in rules.

    Matching events are grouped by the group_by value (events without one are not counted). Within a group,
    a window ending at each event holds the events at most window_seconds older; every event of a window
    with at least `threshold` events is marked, and marked events closer than the window become one finding
    (rules._clusters, the built-in threshold rules' own windowing).
    """
    from . import rules as rules_mod  # rules dispatches to this module

    match = matcher(params["terms"])
    column = hunt.FIELDS[params["group_by"]][1]
    threshold, window = params["threshold"], params["window_seconds"]
    groups = defaultdict(list)
    for e in events:
        key = e.get(column)
        if key is not None and key != "" and match(e):
            # Accounts group case-insensitively, as the user: filter matches them (and entities.py keys them):
            # otherwise "alice", "Alice" and "ALICE" would each stay under the threshold.
            groups[str(key).lower() if params["group_by"] == "user" else str(key)].append(e)
    findings = []
    for key, group in groups.items():
        group.sort(key=lambda e: (rules_mod._epoch(e), e["id"]))
        for cluster in rules_mod._clusters(group, window, None, span=lambda a, b: b - a + 1 >= threshold):
            findings.append({
                "group_key": key,
                "event_ids": [e["id"] for e in cluster],
                "first_seen": cluster[0]["ts"],
                "last_seen": cluster[-1]["ts"],
                "title": f"{params['title']}: {len(cluster)} matching event(s) for {params['group_by']} {key}",
                "explanation": f"{len(cluster)} event(s) for {params['group_by']} {key} between {cluster[0]['ts']} "
                               f"and {cluster[-1]['ts']} matched the promoted saved search {params['query']!r}; "
                               f"the rule fires at {threshold} within {window // 60} min.",
            })
    return findings


# --- Labeled sample --------------------------------------------------------------------------

def validate_sample(sample):
    """Sigma's sample shape and checks (sigma.validate_sample), plus `source`, and every `ts` parsed. Events
    without a ts get one: one second apart, in list order."""
    try:
        out = sigma.validate_sample(sample, SAMPLE_FIELDS)
    except sigma.SigmaError as exc:
        raise SearchRuleError(str(exc))
    for side in ("malicious", "benign"):
        for n, e in enumerate(out[side]):
            if e.get("ts") is not None:
                try:
                    e["ts"] = parse_timestamp(e["ts"])
                except EventError as exc:
                    raise SearchRuleError(f"sample.{side}[{n}].ts: {exc}")
    return out


def _sample_events(events):
    base = parse_iso(SAMPLE_BASE)
    return [{**e, "id": n + 1, "ts": e.get("ts") or iso(base + timedelta(seconds=n))} for n, e in enumerate(events)]


def sample_result(params, sample):
    """Run the rule over each side of its sample. Passes when the malicious events raise at least one finding
    and the benign look-alikes raise none. None when there is no sample. `missed` / `fired` list event indexes,
    as for Sigma: every malicious event when nothing fired, and the benign events inside a finding."""
    if not sample:
        return None
    bad = run(_sample_events(sample["malicious"]), params)
    good = run(_sample_events(sample["benign"]), params)
    missed = [] if bad else list(range(len(sample["malicious"])))
    fired = sorted({i - 1 for f in good for i in f["event_ids"]})
    passes = bool(bad) and not good
    reasons = []
    if not bad:
        reasons.append(f"the {len(sample['malicious'])} malicious event(s) raise no finding")
    if good:
        reasons.append(f"the benign look-alikes raise {len(good)} finding(s) (#{', #'.join(map(str, fired))})")
    return {"malicious": len(sample["malicious"]), "benign": len(sample["benign"]), "missed": missed,
            "fired": fired, "passes": passes, "findings": len(bad),
            "summary": "passes: the malicious events raise a finding and the benign look-alikes raise none"
            if passes else "fails: " + "; ".join(reasons)}


# --- Store (called only from an approved change request) ------------------------------------

def stored(conn, rule_id):
    """The search_rules row for a rule, with the sample decoded, or None."""
    row = conn.execute("SELECT * FROM search_rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["sample"] = json.loads(out["sample"]) if out["sample"] else None
    return out


def stored_result(conn, rule_id):
    """The current sample result of a stored search rule (None without a sample)."""
    rec = stored(conn, rule_id)
    row = conn.execute("SELECT params FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if rec is None or row is None:
        return None
    return sample_result(json.loads(row["params"]), rec["sample"])


def sample_scenarios(conn):
    """Each search rule's sample as a labeled malicious scenario, tagged with the rule's techniques."""
    out = {}
    for row in conn.execute("SELECT r.id, r.techniques FROM rules r JOIN search_rules s ON s.rule_id = r.id"
                            " WHERE s.sample IS NOT NULL"):
        out[SAMPLE_PREFIX + row["id"]] = {"malicious": True,
                                          "techniques": [t["id"] for t in json.loads(row["techniques"] or "[]")]}
    return out


def add_rule(conn, compiled, saved_search_id, sample, proposed_by, approved_by, change_request_id, now):
    """Insert an approved search rule, disabled, with its query provenance and sample."""
    rule_id = compiled["rule_id"]
    params = json.dumps(compiled["params"])
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by,"
        " techniques) VALUES (?,?,?,?,0,?,1,?,?,?)",
        (rule_id, compiled["title"], compiled["description"][:2000], compiled["severity"], params, now, approved_by,
         json.dumps(compiled["techniques"])))
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, 1, 0, params, now, proposed_by, approved_by, change_request_id,
         "promoted from a saved search (disabled)"))
    conn.execute(
        "INSERT INTO search_rules(rule_id, query, saved_search_id, sample, proposed_by, approved_by,"
        " change_request_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (rule_id, compiled["query"], saved_search_id, json.dumps(sample) if sample else None, proposed_by,
         approved_by, change_request_id, now))


def set_sample(conn, rule_id, sample, proposed_by, approved_by, change_request_id, now):
    """Replace a search rule's sample. Bumps the rule version so history (and cached evaluations) see it."""
    rule = conn.execute("SELECT version, enabled, params FROM rules WHERE id = ?", (rule_id,)).fetchone()
    version = rule["version"] + 1
    conn.execute("UPDATE search_rules SET sample = ? WHERE rule_id = ?", (json.dumps(sample), rule_id))
    conn.execute("UPDATE rules SET version = ?, updated_at = ?, updated_by = ? WHERE id = ?",
                 (version, now, approved_by, rule_id))
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, version, rule["enabled"], rule["params"], now, proposed_by, approved_by, change_request_id,
         "labeled sample replaced"))
    return version


def preview(conn, params):
    """The rule's findings on stored events before it exists (backtest.preview_new_rule)."""
    from . import backtest

    return backtest.preview_new_rule(conn, "search_preview", params, matcher(params["terms"]))
