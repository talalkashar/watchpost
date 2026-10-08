"""Asset modeling: give hosts a weight of importance and tag the ones that hold sensitive data.

An asset is a host (or a small set of addresses) with a `criticality` and optional data tags such as
`pii` or `pci`. Detection reads the inventory once per run and raises the severity of any alert whose
evidence touches an important asset. The boost is explainable: the alert keeps its rule severity in
`base_severity`, lists the matched assets in `assets`, and says why in `severity_note`.

Boost rule (capped at two levels, never past `critical`):
    criticality high      +1        criticality critical  +2
    any sensitive-data tag +1
Pure helpers (`match`, `boost`, `weigh`, `review_reasons`) take plain dicts; the rest reads and writes the
database.

Two-person review: an edit that could lower an alert's severity (`review_reasons`) is never applied by one
admin. It becomes a change request (improve.py, kinds asset_add/asset_update/asset_delete) that a different
admin approves; `plan_change` checks it against the inventory at proposal and again at approval.
"""

import ipaddress
import json
import re

from .db import audit, now_iso, row_to_dict, transaction
from .normalize import SEVERITIES

CRITICALITIES = ("low", "medium", "high", "critical")
KINDS = ("server", "workstation", "network", "cloud", "database", "other")
# Controlled vocabulary for "systems that process sensitive data". Any tag makes the asset sensitive.
DATA_TAGS = {
    "pii": "Personal data (names, addresses, identifiers)",
    "pci": "Payment card data (PCI DSS scope)",
    "phi": "Health information (HIPAA scope)",
    "credentials": "Secrets, keys, or identity data",
    "financial": "Financial records or payment systems",
    "confidential": "Confidential business information",
}
CRITICALITY_BOOST = {"low": 0, "medium": 0, "high": 1, "critical": 2}
SENSITIVE_BOOST = 1
MAX_BOOST = 2
_NAME_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
ASSET_COLUMNS = ("name", "kind", "criticality", "data_tags", "addresses", "owner", "description", "synthetic")

# Fictional inventory for the synthetic demo data. Hosts match simulate.py and storyline.py.
DEMO_ASSETS = [
    {"name": "db01", "kind": "database", "criticality": "critical", "data_tags": ["pii", "pci"],
     "addresses": ["10.0.0.10"], "owner": "data-platform", "description": "Customer database (synthetic)"},
    {"name": "files01", "kind": "server", "criticality": "high", "data_tags": ["confidential"],
     "addresses": ["10.0.0.20"], "owner": "it-ops", "description": "Shared file server (synthetic)"},
    {"name": "vpn01", "kind": "network", "criticality": "high", "data_tags": ["credentials"],
     "addresses": [], "owner": "net-ops", "description": "VPN concentrator (synthetic)"},
    {"name": "mail01", "kind": "server", "criticality": "medium", "data_tags": ["pii"],
     "addresses": [], "owner": "it-ops", "description": "Mail server (synthetic)"},
    {"name": "web01", "kind": "server", "criticality": "medium", "data_tags": [],
     "addresses": ["10.0.1.20"], "owner": "web-team", "description": "Public web server (synthetic)"},
    {"name": "fw01", "kind": "network", "criticality": "low", "data_tags": [],
     "addresses": [], "owner": "net-ops", "description": "Perimeter firewall (synthetic)"},
]


class AssetError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class ReviewRequired(AssetError):
    """A direct edit that could lower alert severity: it has to be proposed and approved by a second admin."""

    def __init__(self, reasons):
        super().__init__(f"this edit could lower alert severity ({'; '.join(reasons)}), so a second admin must "
                         "approve it", 409)
        self.reasons = reasons


# --- Validation ----------------------------------------------------------------------------

def validate(data):
    """Return a clean asset dict from user input, or raise AssetError with a precise reason."""
    if not isinstance(data, dict):
        raise AssetError("asset must be a JSON object")
    name = str(data.get("name") or "").strip()
    if not _NAME_RE.match(name):
        raise AssetError("name must be 1-128 chars of letters, digits, _ . : -")
    kind = data.get("kind") or "server"
    if kind not in KINDS:
        raise AssetError(f"kind must be one of {', '.join(KINDS)}")
    criticality = data.get("criticality") or "medium"
    if criticality not in CRITICALITIES:
        raise AssetError(f"criticality must be one of {', '.join(CRITICALITIES)}")
    tags = data.get("data_tags") or []
    if isinstance(tags, str):
        tags = [t for t in re.split(r"[,\s]+", tags) if t]
    if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
        raise AssetError("data_tags must be a list of tags")
    tags = sorted({t.strip().lower() for t in tags if t.strip()})
    unknown = [t for t in tags if t not in DATA_TAGS]
    if unknown:
        raise AssetError(f"unknown data tag(s) {', '.join(unknown)}; use {', '.join(sorted(DATA_TAGS))}")
    addresses = data.get("addresses") or []
    if isinstance(addresses, str):
        addresses = [a for a in re.split(r"[,\s]+", addresses) if a]
    if not isinstance(addresses, list) or len(addresses) > 32:
        raise AssetError("addresses must be a list of at most 32 IP addresses")
    clean = []
    for value in addresses:
        try:
            clean.append(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            raise AssetError(f"invalid IP address {value!r}")
    owner = str(data.get("owner") or "").strip()[:128] or None
    description = str(data.get("description") or "").strip()[:500] or None
    return {"name": name, "kind": kind, "criticality": criticality, "data_tags": tags,
            "addresses": sorted(set(clean)), "owner": owner, "description": description,
            "synthetic": int(bool(data.get("synthetic")))}


# --- Review gate ------------------------------------------------------------------------------

# The asset-side counterpart of the hiding-edit gate on rules (rules.HIDING_EDITS): these are the edits that
# can make an alert lose severity or stop matching an asset. Criticality and data tags feed `boost`; the name
# and the addresses decide what `match` finds. Anything else (a new asset, higher criticality, more tags or
# addresses, owner, kind, description) can only keep or raise severity, so it applies at once and is audited.
def review_reasons(before, after, taken=frozenset()):
    """Why the edit from `before` to `after` (clean asset dicts; None when absent) needs a second admin.

    Returns short phrases, empty when the edit may apply directly. `taken` holds the addresses already on
    other assets: claiming one can take over that asset's matches, since an address matches one asset only.
    """
    if after is None:
        return ["deletes the asset"]
    reasons = []
    if before is not None:
        if CRITICALITIES.index(after["criticality"]) < CRITICALITIES.index(before["criticality"]):
            reasons.append(f"lowers criticality from {before['criticality']} to {after['criticality']}")
        reasons += [f"removes sensitive-data tag {t}" for t in sorted(set(before["data_tags"]) - set(after["data_tags"]))]
        reasons += [f"removes address {a}" for a in sorted(set(before["addresses"]) - set(after["addresses"]))]
        if after["name"].lower() != before["name"].lower():  # matching ignores case, so a re-case is no rename
            reasons.append(f"renames {before['name']} to {after['name']}")
    old = set(before["addresses"]) if before else set()
    reasons += [f"claims address {a}, which another asset already has" for a in after["addresses"]
                if a in taken and a not in old]
    return reasons


# --- Pure weighting --------------------------------------------------------------------------

def _public(asset):
    return {k: asset[k] for k in ("id", "name", "kind", "criticality", "data_tags", "synthetic") if k in asset}


def index(assets):
    """Lookup tables for fast matching: lowercase host name -> asset, IP string -> asset."""
    by_name, by_ip = {}, {}
    for a in assets:
        by_name[a["name"].lower()] = a
        for ip in a.get("addresses") or []:
            by_ip.setdefault(ip, a)
    return {"by_name": by_name, "by_ip": by_ip}


def match(idx, events):
    """Assets touched by these events: by `host` name, or by `dest_ip`/`src_ip` address. Sorted by name."""
    found = {}
    for e in events:
        host = e.get("host")
        if host and host.lower() in idx["by_name"]:
            a = idx["by_name"][host.lower()]
            found[a["name"]] = a
        for field in ("dest_ip", "src_ip"):
            ip = e.get(field)
            if ip and ip in idx["by_ip"]:
                a = idx["by_ip"][ip]
                found[a["name"]] = a
    return [found[k] for k in sorted(found)]


def boost(assets):
    """How many severity levels these assets add, and a one-line reason."""
    if not assets:
        return 0, None
    top = max(assets, key=lambda a: CRITICALITY_BOOST[a["criticality"]])
    levels = CRITICALITY_BOOST[top["criticality"]]
    reasons = []
    if levels:
        reasons.append(f"{top['name']} is a {top['criticality']}-criticality asset")
    sensitive = [a for a in assets if a.get("data_tags")]
    if sensitive:
        levels += SENSITIVE_BOOST
        names = ", ".join(f"{a['name']} ({', '.join(a['data_tags'])})" for a in sensitive[:3])
        reasons.append(f"sensitive data on {names}")
    levels = min(levels, MAX_BOOST)
    if not levels:
        return 0, f"touches known asset(s) {', '.join(a['name'] for a in assets[:3])}; no severity change"
    return levels, f"raised {levels} level(s): " + "; ".join(reasons)


def weigh(base_severity, assets):
    """Final severity for an alert with this rule severity and these matched assets.

    Returns {"severity", "base_severity", "assets": [public dicts], "severity_note"}.
    """
    levels, note = boost(assets)
    rank = SEVERITIES.index(base_severity) if base_severity in SEVERITIES else 0
    severity = SEVERITIES[min(rank + levels, len(SEVERITIES) - 1)]
    if levels and severity == base_severity:
        note = f"already {base_severity}; " + note
    return {"severity": severity, "base_severity": base_severity, "assets": [_public(a) for a in assets],
            "severity_note": note}


# --- Storage -----------------------------------------------------------------------------------

def _row(row):
    return row_to_dict(row, ["data_tags", "addresses"])


def list_assets(conn):
    return [_row(r) for r in conn.execute(
        "SELECT * FROM assets ORDER BY CASE criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        " WHEN 'medium' THEN 2 ELSE 3 END, name")]


def get_asset(conn, asset_id):
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        raise AssetError("asset not found", 404)
    return _row(row)


def _snapshot(asset):
    """The fields a change compares and a reviewer is shown (no timestamps: a no-op save is no change)."""
    return {"id": asset["id"], **{k: asset[k] for k in ASSET_COLUMNS}}


def _current(conn, asset_id):
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return None if row is None else _snapshot(_row(row))


def _taken_addresses(conn, asset_id=None):
    """Addresses inventoried on assets other than this one."""
    return {ip for a in list_assets(conn) if a["id"] != asset_id for ip in a["addresses"]}


def _check_name_free(conn, name, asset_id):
    clash = conn.execute("SELECT id FROM assets WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if clash and clash["id"] != asset_id:
        raise AssetError(f"an asset named {name!r} already exists", 409)


def _write(conn, asset, actor, asset_id=None, detail=None):
    """Insert or update a validated asset inside the caller's transaction; returns its id."""
    now = now_iso()
    _check_name_free(conn, asset["name"], asset_id)
    values = [asset["name"], asset["kind"], asset["criticality"], json.dumps(asset["data_tags"]),
              json.dumps(asset["addresses"]), asset["owner"], asset["description"], asset["synthetic"]]
    if asset_id is None:
        asset_id = conn.execute(
            f"INSERT INTO assets({', '.join(ASSET_COLUMNS)}, created_at, updated_at, updated_by)"
            f" VALUES ({', '.join('?' for _ in ASSET_COLUMNS)}, ?, ?, ?)",
            (*values, now, now, actor)).lastrowid
        action = "asset_created"
    else:
        cur = conn.execute(
            f"UPDATE assets SET {', '.join(c + ' = ?' for c in ASSET_COLUMNS)}, updated_at = ?, updated_by = ?"
            " WHERE id = ?", (*values, now, actor, asset_id))
        if not cur.rowcount:
            raise AssetError("asset not found", 404)
        action = "asset_updated"
    audit(conn, actor, action, asset["name"], {"id": asset_id, "criticality": asset["criticality"],
                                                "data_tags": asset["data_tags"], **(detail or {})})
    return asset_id


def _delete(conn, asset_id, actor, detail=None):
    row = conn.execute("SELECT name FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        raise AssetError("asset not found", 404)
    conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    audit(conn, actor, "asset_deleted", row["name"], {"id": asset_id, **(detail or {})})


def save_asset(conn, data, actor, asset_id=None, gated=False):
    """Create an asset, or update the one with this id. Names are unique, ignoring case.

    With `gated` (the admin API), an edit that `review_reasons` flags raises ReviewRequired and changes
    nothing; the check and the write share one transaction, so the asset cannot change in between.
    """
    asset = validate(data)
    with transaction(conn):
        if gated:
            before = None if asset_id is None else _current(conn, asset_id)
            if asset_id is not None and before is None:
                raise AssetError("asset not found", 404)
            reasons = review_reasons(before, asset, _taken_addresses(conn, asset_id))
            if reasons:
                raise ReviewRequired(reasons)
        asset_id = _write(conn, asset, actor, asset_id)
    return get_asset(conn, asset_id)


def delete_asset(conn, asset_id, actor):
    with transaction(conn):
        _delete(conn, asset_id, actor)
    return {"ok": True}


# --- Reviewed changes (called from improve.py) ---------------------------------------------------

def edit_payload(conn, asset_id, data):
    """The fields an edit to this asset changes, from the full asset the editor submitted."""
    before = get_asset(conn, asset_id)
    after = validate(data)
    return {k: after[k] for k in ASSET_COLUMNS if after[k] != before[k]}


def plan_change(conn, kind, target, payload):
    """Check a proposed inventory change against the inventory as it is now: (before, after) snapshots.

    Runs when the change is proposed and again when it is approved, because the asset may have been
    edited, deleted, or lost its name to another asset in between. A conflict raises AssetError with 409.
    An update stores only the fields it changes and is applied on top of the asset as it is at approval.
    """
    if kind == "asset_add":
        after = validate(payload)
        if after["name"] != target:
            raise AssetError("an asset_add targets the name of the asset it adds")
        _check_name_free(conn, after["name"], None)
        return None, after
    before = _current(conn, int(target)) if str(target).isdigit() else None
    if before is None:
        raise AssetError(f"asset #{target} no longer exists; nothing was applied", 409)
    if kind == "asset_delete":
        if payload:
            raise AssetError("an asset_delete takes an empty payload")
        return before, None
    unknown = set(payload) - set(ASSET_COLUMNS)
    if unknown:
        raise AssetError(f"unknown asset field(s) {', '.join(sorted(unknown))}")
    after = {"id": before["id"], **validate({**before, **payload})}
    _check_name_free(conn, after["name"], before["id"])
    if after == before:
        raise AssetError("the asset already matches this change; nothing to apply", 409)
    return before, after


def change_evidence(conn, before, after, recent=5):
    """What a reviewer is shown for an inventory change, computed from the current database.

    The before/after snapshots, each field that differs, why the change needs review (empty when it would
    apply directly anyway), and the open alerts whose severity it would change, without writing anything.
    """
    fields = ("name", "kind", "criticality", "data_tags", "addresses", "owner", "description")
    changes = [{"field": f, "before": (before or {}).get(f), "after": (after or {}).get(f)}
               for f in fields if (before or {}).get(f) != (after or {}).get(f)]
    inventory = [a for a in list_assets(conn) if before is None or a["id"] != before["id"]] + ([after] if after else [])
    inventory.sort(key=lambda a: (-CRITICALITIES.index(a["criticality"]), a["name"].lower()))  # as list_assets
    shifts = [{"id": alert["id"], "title": alert["title"], "from": alert["severity"], "to": weighed["severity"]}
              for alert, weighed in _reweigh_open(conn, index(inventory)) if weighed["severity"] != alert["severity"]]
    shifts.sort(key=lambda x: -x["id"])
    return {"asset": (after or before)["name"], "before": before, "after": after, "changes": changes,
            "needs_review": review_reasons(before, after, _taken_addresses(conn, before and before["id"])),
            "severity_changes": {"alerts": len(shifts), "recent": shifts[:recent]}}


def apply_change(conn, kind, target, payload, actor, detail):
    """Apply an approved change inside the caller's transaction, re-checked against the current inventory."""
    before, after = plan_change(conn, kind, target, payload)
    if after is None:
        _delete(conn, before["id"], actor, detail)
    else:
        _write(conn, {k: after[k] for k in ASSET_COLUMNS}, actor, before and before["id"], detail)


def seed_demo_assets(conn, actor):
    """Add the fictional demo inventory; existing names are left alone. Returns the number created."""
    created = 0
    for demo in DEMO_ASSETS:
        if conn.execute("SELECT 1 FROM assets WHERE name = ? COLLATE NOCASE", (demo["name"],)).fetchone():
            continue
        save_asset(conn, {**demo, "synthetic": True}, actor)
        created += 1
    return created


def load_index(conn):
    return index(list_assets(conn))


def rescore_open_alerts(conn, idx=None):
    """Re-weigh every unresolved alert against the current inventory. Returns how many changed severity.

    Called after the inventory changes so analysts see the new priorities without waiting for new events.
    Resolved alerts keep the severity they were closed with.
    """
    idx = idx or load_index(conn)
    changed = 0
    with transaction(conn):
        for alert, weighed in _reweigh_open(conn, idx):
            now = now_iso()
            conn.execute("UPDATE alerts SET severity = ?, base_severity = ?, assets = ?, severity_note = ?,"
                         " updated_at = CASE WHEN severity = ? THEN updated_at ELSE ? END WHERE id = ?",
                         (weighed["severity"], weighed["base_severity"], json.dumps(weighed["assets"]),
                          weighed["severity_note"], weighed["severity"], now, alert["id"]))
            if weighed["severity"] != alert["severity"]:
                changed += 1
                conn.execute(
                    "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                    (alert["id"], "assets", "severity_changed",
                     f"{alert['severity']} -> {weighed['severity']} ({weighed['severity_note']})", now))
    return changed


def _reweigh_open(conn, idx):
    """(alert row, weigh() result) for every unresolved alert against this inventory index. Writes nothing."""
    rows = conn.execute("SELECT id, title, severity, base_severity FROM alerts WHERE status != 'resolved'").fetchall()
    for alert in rows:
        events = [dict(r) for r in conn.execute(
            "SELECT e.host, e.src_ip, e.dest_ip FROM events e JOIN alert_events ae ON ae.event_id = e.id"
            " WHERE ae.alert_id = ?", (alert["id"],))]
        yield alert, weigh(alert["base_severity"] or alert["severity"], match(idx, events))


def for_entities(conn, hosts, ips):
    """Assets behind an incident's hosts and addresses, for detail views and reports."""
    idx = load_index(conn)
    events = [{"host": h} for h in hosts or []] + [{"dest_ip": ip} for ip in ips or []]
    return [_public(a) for a in match(idx, events)]
