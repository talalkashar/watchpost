"""Viewer data masking: usernames and internal IPs become keyed pseudonyms in `viewer` responses.

Applied in one place, the server's response path (server.Handler), and only when the reviewed security
setting `viewer_masking` is 1 and the signed-in account is a viewer. Analyst and admin responses never pass
through here.

- Usernames are matched by exact known value (every distinct events.user plus every account name), up to
  CANDIDATE_LIMIT distinct names; past that a viewer is refused (Unavailable) rather than shown raw names. Matched
  case-insensitively, in structured fields and inside free text alike. Not by guessing what a name looks like.
  An account named after a role ("analyst") is masked in identity fields (USER_FIELDS) but not as a word in
  text, where it is the product's own vocabulary ("Analyst notes"). An event username is masked everywhere.
- IPs are found with an IPv4/IPv6 regex and confirmed with `ipaddress`. Only internal addresses are masked
  (RFC 1918, loopback, link-local, IPv6 ULA); public addresses are the attacker side and stay visible.
- A pseudonym is HMAC-SHA256(key, value), truncated: `user-3f9a2c1b`, `internal-8b21e0d4`. The key is derived
  from SIEM_AUDIT_KEY when that is set, else it is a random per-database secret kept in the `meta` table, so
  the same value gets the same pseudonym on every endpoint and across restarts, and nothing here is a constant.
- Pivots: a pseudonym in a query parameter or path segment is resolved back to the real value server-side by
  hashing candidate values (bounded DISTINCT queries). No reverse map is stored.

This is presentation-layer masking for a low-trust role, not anonymization. See README.
"""

import functools
import hashlib
import hmac
import ipaddress
import re
import secrets
from urllib.parse import quote

from .auth import ROLES

SETTING = "viewer_masking"
CANDIDATE_LIMIT = 10000  # distinct usernames / IPs considered per request
DIGEST_CHARS = 8
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fe80::/10", "fc00::/7")]
# Fields that always hold an account or event username, masked whatever their value.
USER_FIELDS = frozenset(("user", "username", "assignee", "author", "actor", "proposed_by", "reviewed_by",
                         "approved_by", "updated_by", "changed_by", "submitted_by", "created_by"))
IP_RE = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{1,4})?(?![\w:])"
    r"|(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)")
PSEUDONYM_RE = re.compile(r"\b(?:user|internal)-[0-9a-f]{%d}\b" % DIGEST_CHARS)


class Unavailable(Exception):
    """More distinct usernames than masking can match: refuse the viewer rather than leave names in text."""
    status = 503


def is_internal(ip):
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return any(ip.version == n.version and ip in n for n in INTERNAL_NETS)


def key(conn):
    """The pseudonym key: derived from the audit chain key when configured, else a random per-database secret."""
    audit_key = getattr(conn, "audit_key", None)
    if audit_key:
        raw = audit_key.encode() if isinstance(audit_key, str) else audit_key
        return hmac.new(raw, b"watchpost viewer masking key", hashlib.sha256).digest()
    conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('masking_key', ?)", (secrets.token_hex(32),))
    return bytes.fromhex(conn.execute("SELECT value FROM meta WHERE key = 'masking_key'").fetchone()[0])


def enabled(conn):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (SETTING,)).fetchone()
    return row is not None and row["value"] == "1"


def for_user(conn, user):
    """A Masker for this request, or None: only viewers are masked, and only with the setting on."""
    if not user or user.get("role") != "viewer" or not enabled(conn):
        return None
    names = {r[0] for r in conn.execute("SELECT DISTINCT lower(user) FROM events WHERE user IS NOT NULL"
                                        " AND user != '' LIMIT ?", (CANDIDATE_LIMIT + 1,))}
    if len(names) > CANDIDATE_LIMIT:  # fail closed: names past the bound would go out unmasked in free text
        raise Unavailable(f"the masked view is unavailable: more than {CANDIDATE_LIMIT:,} distinct usernames")
    names |= {r[0].lower() for r in conn.execute("SELECT username FROM users")} - set(ROLES)
    return Masker(key(conn), names, self_name=user["username"])


@functools.lru_cache(maxsize=8)
def _names_re(names):
    if not names:
        return None
    return re.compile(r"(?<![\w.@-])(?:" + "|".join(map(re.escape, names)) + r")(?![\w@-])", re.IGNORECASE)


class Masker:
    def __init__(self, secret, names, self_name=None):
        self.secret = secret
        self.self_name = (self_name or "").lower()
        names = {n.lower() for n in names if n} - {self.self_name}
        self.names = tuple(sorted(names, key=lambda n: (-len(n), n)))  # longest first: ops-admin before admin
        self.names_re = _names_re(self.names)

    def _digest(self, kind, value):
        return hmac.new(self.secret, f"{kind}\0{value}".encode(), hashlib.sha256).hexdigest()[:DIGEST_CHARS]

    def user(self, name):
        return "user-" + self._digest("user", name.lower())

    def ip(self, ip):
        return "internal-" + self._digest("ip", str(ip))

    def _ip_sub(self, match):
        try:
            ip = ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return self.ip(ip) if is_internal(ip) else match.group(0)

    def text(self, s):
        s = IP_RE.sub(self._ip_sub, s)  # IPs first, so a numeric username cannot split an address
        return self.names_re.sub(lambda m: self.user(m.group(0)), s) if self.names_re else s

    def mask(self, value, field=None):
        if isinstance(value, str):
            if field in USER_FIELDS and value and value.lower() != self.self_name:
                return self.user(value)
            return self.text(value)
        if isinstance(value, dict):
            return {(self.text(k) if isinstance(k, str) else k): self.mask(v, k) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(self.mask(v) for v in value)
        return value

    # --- pivots: pseudonyms in a viewer's request resolve back to real values ----------------------------

    def unmask(self, conn, s, path=False):
        if not PSEUDONYM_RE.search(s):
            return s
        if not hasattr(self, "_reverse"):
            reverse = {self.user(n): n for n in self.names}
            for (value,) in conn.execute("SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL UNION"
                                         " SELECT DISTINCT dest_ip FROM events WHERE dest_ip IS NOT NULL LIMIT ?",
                                         (CANDIDATE_LIMIT,)):
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if is_internal(ip):
                    reverse[self.ip(ip)] = value
            self._reverse = reverse  # this request only; never kept beyond it
        found = lambda m: self._reverse.get(m.group(0), m.group(0))  # noqa: E731
        return PSEUDONYM_RE.sub((lambda m: quote(found(m), safe="")) if path else found, s)
