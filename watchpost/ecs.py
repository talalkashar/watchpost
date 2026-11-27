"""Elastic Common Schema (ECS) field mapping, for export and interop.

Watchpost stores events in its own flat schema (normalize.py); this module only translates one event into an
ECS-shaped document on the way out. It is not ECS-native storage, and the hunt language keeps Watchpost names.

Only fields with a clean ECS match are mapped. Fields without one are kept under a custom `watchpost` object
(ECS leaves room for custom fields) instead of being given an ECS name they do not fit:

- severity: ECS `event.severity` is a number on the source's own scale; Watchpost's is a word
  (info..critical). Writing a made-up numeric scale into it would claim a meaning it does not have.
- bytes: ECS splits byte counts by direction (`source.bytes`, `destination.bytes`) or totals both
  (`network.bytes`); a Watchpost event carries one count without a direction, and for cloud data access it
  is bytes read from storage, not network traffic.
- batch_id: the Watchpost ingest batch, with no ECS counterpart.
- outcome: mapped to `event.outcome` only when an ASCII fold is one of ECS's allowed values
  (success, failure, unknown). `Failure` becomes `failure`. A dotted capital I is not an ASCII `I`,
  so it is not folded, and the original text stays as `watchpost.outcome`. `str.lower()` is not used:
  it expands that letter into `i` plus a combining dot (not an ECS outcome) and maps the Kelvin sign
  onto `k`, so `unKnown` would collide with `unknown`.
"""

# Watchpost field -> ECS field (dotted path). Every target is a field defined in ECS.
FIELD_MAP = {
    "id": "event.id",
    "ts": "@timestamp",
    "ingested_at": "event.ingested",  # when Watchpost stored it
    "source": "event.module",  # closest fit: a free-form log-source label such as "vpn01" or "cloudtrail"
    "host": "host.name",
    "event_type": "event.action",
    "user": "user.name",
    "src_ip": "source.ip",
    "dest_ip": "destination.ip",
    "dest_port": "destination.port",
    "message": "message",
    "raw": "event.original",  # the redacted original record
}
UNMAPPED = ("severity", "bytes", "batch_id")  # see the module docstring
ECS_OUTCOMES = {"success", "failure", "unknown"}
# A–Z only. Not str.lower(): İ (U+0130) becomes i + combining dot, and K (U+212A) becomes k.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

# The allowed values of ECS event.category, to check EVENT_TYPE_CATEGORIES against.
ECS_CATEGORIES = {"authentication", "configuration", "database", "driver", "email", "file", "host", "iam",
                  "intrusion_detection", "malware", "network", "package", "process", "registry", "session",
                  "threat", "vulnerability", "web"}

# Watchpost event_type -> (ECS event.category, ECS event.type), only where a clear pairing exists.
# Left out on purpose: privilege_use and privilege_escalation (sudo/runas could be process, iam or
# authentication depending on the source), cloud_api_call and cloud_data_access (no single category fits an
# arbitrary cloud API call or object read), syslog and other (no meaning beyond "a log line").
EVENT_TYPE_CATEGORIES = {
    "auth_failure": (["authentication"], ["start"]),
    "auth_success": (["authentication"], ["start"]),
    "vpn_login": (["authentication"], ["start"]),
    "account_lockout": (["iam"], ["user", "change"]),
    "user_created": (["iam"], ["user", "creation"]),
    "cloud_iam_change": (["iam"], ["change"]),
    "process_start": (["process"], ["start"]),
    "file_access": (["file"], ["access"]),
    "network_connection": (["network"], ["connection"]),
    "fw_allow": (["network"], ["allowed", "connection"]),
    "fw_deny": (["network"], ["denied", "connection"]),
    "web_request": (["web"], ["access"]),
    "web_scan": (["web"], ["access"]),
    "web_error": (["web"], ["error"]),
}


def _user_domain(name):
    """DOMAIN\\name or name@domain. The stored spelling of user.name is not rewritten."""
    if not isinstance(name, str):
        return None
    if "\\" in name:
        domain, rest = name.split("\\", 1)
        return domain if domain and rest else None
    if "@" in name:
        rest, domain = name.rsplit("@", 1)
        return domain if rest and domain else None
    return None


def _put(doc, dotted, value):
    *parents, leaf = dotted.split(".")
    for key in parents:
        doc = doc.setdefault(key, {})
    doc[leaf] = value


def to_ecs(event):
    """One Watchpost event dict -> a nested ECS-shaped dict. Empty (None) fields are left out."""
    doc = {}
    _put(doc, "event.kind", "event")
    for field, target in FIELD_MAP.items():
        value = event.get(field)
        if value is not None:
            _put(doc, target, str(value) if field == "id" else value)  # event.id is a keyword in ECS
    # Windows accounts often arrive as DOMAIN\name or a UPN. user.name stays the stored text.
    domain = _user_domain(event.get("user"))
    if domain:
        _put(doc, "user.domain", domain)
    category = EVENT_TYPE_CATEGORIES.get(event.get("event_type"))
    if category:
        _put(doc, "event.category", list(category[0]))
        _put(doc, "event.type", list(category[1]))
    outcome = event.get("outcome")
    if outcome is not None:
        folded = outcome.translate(_ASCII_FOLD) if isinstance(outcome, str) else None
        if folded in ECS_OUTCOMES:
            _put(doc, "event.outcome", folded)
        else:
            _put(doc, "watchpost.outcome", outcome)  # the stored value, not a lowered copy
    if event.get("synthetic") is not None:
        _put(doc, "labels.synthetic", "true" if event["synthetic"] else "false")  # ECS labels are keywords
    for field in UNMAPPED:
        if event.get(field) is not None:
            _put(doc, f"watchpost.{field}", event[field])
    return doc
