"""Asset modeling: give hosts a weight of importance and tag the ones that hold sensitive data.

An asset is a host (or a small set of addresses) with a `criticality` and optional data tags such as
`pii` or `pci`. Detection reads the inventory once per run and raises the severity of any alert whose
evidence touches an important asset. The boost is explainable: the alert keeps its rule severity in
`base_severity`, lists the matched assets in `assets`, and says why in `severity_note`.

Boost rule (capped at two levels, never past `critical`):
    criticality high      +1        criticality critical  +2
    any sensitive-data tag +1
Pure helpers (`match`, `boost`, `weigh`) take plain dicts; the rest reads and writes the database.
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


def save_asset(conn, data, actor, asset_id=None):
    """Create an asset, or update the one with this id. Names are unique, ignoring case."""
    asset = validate(data)
    now = now_iso()
    with transaction(conn):
        clash = conn.execute("SELECT id FROM assets WHERE name = ? COLLATE NOCASE", (asset["name"],)).fetchone()
        if clash and clash["id"] != asset_id:
            raise AssetError(f"an asset named {asset['name']!r} already exists", 409)
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
                                                    "data_tags": asset["data_tags"]})
    return get_asset(conn, asset_id)


def delete_asset(conn, asset_id, actor):
    with transaction(conn):
        row = conn.execute("SELECT name FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if row is None:
            raise AssetError("asset not found", 404)
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        audit(conn, actor, "asset_deleted", row["name"], {"id": asset_id})
    return {"ok": True}


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
        rows = conn.execute("SELECT id, severity, base_severity FROM alerts WHERE status != 'resolved'").fetchall()
        for alert in rows:
            events = [dict(r) for r in conn.execute(
                "SELECT e.host, e.src_ip, e.dest_ip FROM events e JOIN alert_events ae ON ae.event_id = e.id"
                " WHERE ae.alert_id = ?", (alert["id"],))]
            weighed = weigh(alert["base_severity"] or alert["severity"], match(idx, events))
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


def for_entities(conn, hosts, ips):
    """Assets behind an incident's hosts and addresses, for detail views and reports."""
    idx = load_index(conn)
    events = [{"host": h} for h in hosts or []] + [{"dest_ip": ip} for ip in ips or []]
    return [_public(a) for a in match(idx, events)]
