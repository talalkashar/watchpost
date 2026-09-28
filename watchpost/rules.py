"""Detection rule logic.

Each rule is a pure function: (events, params) -> list of findings.
Events are dicts with at least id, ts, event_type, user, src_ip.
A finding is {"group_key", "event_ids", "first_seen", "last_seen", "title", "explanation"}.

Rules are deliberately simple, threshold-based, and explainable. No machine learning.
"""

from collections import Counter, defaultdict, deque

from .db import parse_iso

DEFAULT_RULES = [
    {
        "id": "brute_force_ip",
        "name": "Brute-force login attempts from one IP",
        "description": "Fires when a single source IP produces at least `threshold` failed logins "
                       "within `window_seconds`. Typical of password guessing against one or a few accounts.",
        "severity": "high",
        "params": {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "password_spray",
        "name": "Password spraying across many accounts",
        "description": "Fires when a single source IP fails to log in as at least `distinct_users` "
                       "different accounts within `window_seconds`. Spraying tries a few common passwords "
                       "across many users to stay under per-account lockout limits.",
        "severity": "high",
        "params": {"distinct_users": 5, "window_seconds": 600, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "account_repeated_failures",
        "name": "Repeated failures against one account",
        "description": "Fires when one account has at least `threshold` failed logins within "
                       "`window_seconds`, from any number of IPs. Catches distributed guessing that "
                       "per-IP rules miss.",
        "severity": "medium",
        "params": {"threshold": 8, "window_seconds": 900, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "success_after_failures",
        "name": "Successful login after repeated failures",
        "description": "Fires when an account logs in successfully after at least `failures` failed "
                       "attempts for that account within the preceding `window_seconds`. A likely sign "
                       "that guessing succeeded; treat as possible account compromise.",
        "severity": "critical",
        "params": {"failures": 5, "window_seconds": 600, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "off_hours_privileged_login",
        "name": "Privileged login outside business hours",
        "description": "Fires when an account in `privileged_users` logs in successfully outside "
                       "`business_start_hour`-`business_end_hour` (UTC). Unusual timing for admin "
                       "access deserves a second look.",
        "severity": "medium",
        "params": {
            "privileged_users": ["root", "admin", "administrator"],
            "business_start_hour": 8, "business_end_hour": 18,
            "ignore_ips": [], "ignore_users": [],
        },
    },
]

# Allowed parameters and validators, used to reject malformed rule change proposals.
PARAM_SCHEMA = {
    "threshold": ("int", 2, 10000),
    "distinct_users": ("int", 2, 10000),
    "failures": ("int", 1, 10000),
    "window_seconds": ("int", 10, 86400 * 7),
    "business_start_hour": ("int", 0, 23),
    "business_end_hour": ("int", 1, 24),
    "ignore_ips": ("list", 0, 500),
    "ignore_users": ("list", 0, 500),
    "privileged_users": ("list", 1, 500),
}


class RuleConfigError(ValueError):
    pass


def validate_params(rule_id, params):
    import ipaddress

    defaults = next((r["params"] for r in DEFAULT_RULES if r["id"] == rule_id), None)
    if defaults is None:
        raise RuleConfigError(f"unknown rule {rule_id!r}")
    if not isinstance(params, dict):
        raise RuleConfigError("params must be an object")
    unknown = set(params) - set(defaults)
    if unknown:
        raise RuleConfigError(f"unknown parameter(s) for {rule_id}: {', '.join(sorted(unknown))}")
    merged = dict(defaults)
    for key, value in params.items():
        kind, low, high = PARAM_SCHEMA[key]
        if kind == "int":
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise RuleConfigError(f"{key} must be an integer between {low} and {high}")
        else:
            if not isinstance(value, list) or not low <= len(value) <= high:
                raise RuleConfigError(f"{key} must be a list with {low}-{high} entries")
            if not all(isinstance(v, str) and 0 < len(v) <= 128 for v in value):
                raise RuleConfigError(f"{key} entries must be non-empty strings")
            if key == "ignore_ips":
                for v in value:
                    try:
                        ipaddress.ip_address(v)
                    except ValueError:
                        raise RuleConfigError(f"ignore_ips entry {v!r} is not an IP address")
        merged[key] = value
    if merged.get("business_start_hour", 0) >= merged.get("business_end_hour", 24):
        raise RuleConfigError("business_start_hour must be before business_end_hour")
    return merged


def _epoch(event):
    if "_epoch" not in event:
        event["_epoch"] = parse_iso(event["ts"]).timestamp()
    return event["_epoch"]


def _filtered(events, params, event_type):
    ignore_ips = set(params.get("ignore_ips", []))
    ignore_users = {u.lower() for u in params.get("ignore_users", [])}
    out = [
        e for e in events
        if e["event_type"] == event_type
        and e.get("src_ip") not in ignore_ips
        and (e.get("user") or "").lower() not in ignore_users
    ]
    out.sort(key=lambda e: (_epoch(e), e["id"]))
    return out


def _clusters(events, window, qualifies):
    """Return clusters of events that fall inside at least one qualifying sliding window.

    `qualifies(window_events)` decides whether the window ending at each event meets the rule.
    Qualifying events closer than `window` seconds to each other are merged into one cluster.
    """
    marked = set()
    dq = deque()
    for idx, event in enumerate(events):
        dq.append(idx)
        while _epoch(event) - _epoch(events[dq[0]]) > window:
            dq.popleft()
        if qualifies([events[i] for i in dq]):
            marked.update(dq)
    clusters, current = [], []
    for idx in sorted(marked):
        if current and _epoch(events[idx]) - _epoch(current[-1]) > window:
            clusters.append(current)
            current = []
        current.append(events[idx])
    if current:
        clusters.append(current)
    return clusters


def _finding(group_key, cluster, title, explanation):
    return {
        "group_key": group_key,
        "event_ids": [e["id"] for e in cluster],
        "first_seen": cluster[0]["ts"],
        "last_seen": cluster[-1]["ts"],
        "title": title,
        "explanation": explanation,
    }


def _group(events, key):
    groups = defaultdict(list)
    for event in events:
        value = event.get(key)
        if value:
            groups[value].append(event)
    return groups


def brute_force_ip(events, params):
    threshold, window = params["threshold"], params["window_seconds"]
    findings = []
    for ip, group in _group(_filtered(events, params, "auth_failure"), "src_ip").items():
        for cluster in _clusters(group, window, lambda w: len(w) >= threshold):
            users = Counter(e.get("user") or "?" for e in cluster)
            top = ", ".join(f"{u} ({n})" for u, n in users.most_common(3))
            findings.append(_finding(
                ip, cluster,
                f"Brute force from {ip}: {len(cluster)} failed logins",
                f"{ip} produced {len(cluster)} failed logins between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']}, meeting the threshold of {threshold} within {window}s. "
                f"Most targeted accounts: {top}.",
            ))
    return findings


def password_spray(events, params):
    needed, window = params["distinct_users"], params["window_seconds"]
    findings = []
    for ip, group in _group(_filtered(events, params, "auth_failure"), "src_ip").items():
        qualifies = lambda w: len({e.get("user") for e in w if e.get("user")}) >= needed
        for cluster in _clusters(group, window, qualifies):
            users = sorted({e.get("user") for e in cluster if e.get("user")})
            findings.append(_finding(
                ip, cluster,
                f"Password spray from {ip}: {len(users)} accounts targeted",
                f"{ip} failed to log in as {len(users)} different accounts "
                f"({', '.join(users[:8])}{'…' if len(users) > 8 else ''}) between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']}. Threshold: {needed} distinct accounts within {window}s.",
            ))
    return findings


def account_repeated_failures(events, params):
    threshold, window = params["threshold"], params["window_seconds"]
    findings = []
    for user, group in _group(_filtered(events, params, "auth_failure"), "user").items():
        for cluster in _clusters(group, window, lambda w: len(w) >= threshold):
            ips = sorted({e.get("src_ip") or "unknown" for e in cluster})
            findings.append(_finding(
                user.lower(), cluster,
                f"Repeated failures for account {user}: {len(cluster)} attempts",
                f"Account {user} had {len(cluster)} failed logins from {len(ips)} source IP(s) "
                f"({', '.join(ips[:5])}) between {cluster[0]['ts']} and {cluster[-1]['ts']}. "
                f"Threshold: {threshold} within {window}s.",
            ))
    return findings


def success_after_failures(events, params):
    needed, window = params["failures"], params["window_seconds"]
    failures = _group(_filtered(events, params, "auth_failure"), "user")
    failures = {u.lower(): v for u, v in failures.items()}
    findings = []
    for success in _filtered(events, params, "auth_success"):
        user = (success.get("user") or "").lower()
        if not user or user not in failures:
            continue
        t = _epoch(success)
        prior = [f for f in failures[user] if 0 <= t - _epoch(f) <= window]
        if len(prior) < needed:
            continue
        ips = sorted({f.get("src_ip") or "unknown" for f in prior})
        same_ip = success.get("src_ip") in ips
        cluster = prior + [success]
        findings.append(_finding(
            f"{user}|{success.get('src_ip') or 'unknown'}", cluster,
            f"Possible compromise of {success.get('user')}: login after {len(prior)} failures",
            f"{success.get('user')} logged in successfully from {success.get('src_ip') or 'an unknown IP'} "
            f"at {success['ts']} after {len(prior)} failed attempts in the preceding {window}s "
            f"(threshold {needed}). The failures came from {', '.join(ips[:5])}"
            f"{' — including the same IP as the success' if same_ip else ''}.",
        ))
    return findings


def off_hours_privileged_login(events, params):
    privileged = {u.lower() for u in params["privileged_users"]}
    start, end = params["business_start_hour"], params["business_end_hour"]
    findings = []
    for event in _filtered(events, params, "auth_success"):
        user = (event.get("user") or "").lower()
        if user not in privileged:
            continue
        dt = parse_iso(event["ts"])
        if start <= dt.hour < end and dt.weekday() < 5:
            continue
        when = "on a weekend" if dt.weekday() >= 5 else f"at {dt.strftime('%H:%M')} UTC"
        findings.append(_finding(
            f"{user}|{event.get('src_ip') or 'unknown'}|{dt.date().isoformat()}", [event],
            f"Off-hours privileged login: {event.get('user')}",
            f"Privileged account {event.get('user')} logged in from {event.get('src_ip') or 'an unknown IP'} "
            f"{when}, outside business hours ({start:02d}:00-{end:02d}:00 UTC, Mon-Fri).",
        ))
    return findings


RULE_FUNCTIONS = {
    "brute_force_ip": brute_force_ip,
    "password_spray": password_spray,
    "account_repeated_failures": account_repeated_failures,
    "success_after_failures": success_after_failures,
    "off_hours_privileged_login": off_hours_privileged_login,
}

# The largest time span a rule can look across; used to pick the rescan window after ingest.
def lookback_seconds(rules):
    return max([r["params"].get("window_seconds", 0) for r in rules] + [3600])
