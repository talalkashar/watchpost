"""Viewer data masking: usernames and internal IPs become keyed pseudonyms in `viewer` responses.

Applied in one place, the server's response path (server.Handler), and only when the reviewed security
setting `viewer_masking` is 1 and the signed-in account is a viewer. Analyst and admin responses never pass
through here.

- Usernames are matched by exact known value (every distinct events.user plus every account name), up to
  CANDIDATE_LIMIT distinct names; past that a viewer is refused (Unavailable) rather than shown raw names. Matched
  on ASCII case only (A–Z), in structured fields and inside free text alike, so Alice and alice are one name
  and ÉRIN and érin stay two. Not by guessing what a name looks like.
  An account named after a role ("analyst") is masked in identity fields (USER_FIELDS) but not as a word in
  text, where it is the product's own vocabulary ("Analyst notes"). That account's pseudonym still resolves
  on pivot. An event username is masked everywhere.
- IPs are found with an IPv4/IPv6 regex and confirmed with `ipaddress`. Only internal addresses are masked
  (RFC 1918, loopback, link-local, IPv6 ULA). A v4 embedded in a mapped, 6to4, or Teredo address counts when
  that v4 is internal. A leading-zero quad is read as decimal, or as octal when only the octal reading is
  internal. Public addresses, including the documentation ranges, stay visible. A token `ipaddress` rejects
  is still masked when it embeds one of those quads or begins with an internal address.
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
# A–Z only. str.lower() and re.IGNORECASE also fold É/é, which would make two accounts one pseudonym.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fe80::/10", "fc00::/7")]
# Canonical spellings ingest stores (`str(ipaddress)`). Extras are dropped by is_internal.
# 6to4 is only the compressed form of an internal v4 (2002:808:… for 8.8.8.8 stays out).
# Teredo stays out: the client is bit-flipped, so a broad 2001:0: prefix would fill the cap.
_INTERNAL_GLOBS = (
    "10.*.*.*", "127.*.*.*", "169.254.*.*", "192.168.*.*",
    "172.1[6-9].*.*", "172.2[0-9].*.*", "172.3[0-1].*.*",
    "::1", "0:0:0:0:0:0:0:1",
    "fe[89ab]*:*", "f[cd]*:*",
    "::ffff:10.*.*.*", "::ffff:127.*.*.*", "::ffff:169.254.*.*", "::ffff:192.168.*.*",
    "::ffff:172.1[6-9].*.*", "::ffff:172.2[0-9].*.*", "::ffff:172.3[0-1].*.*",
    "2002:a[0-9a-f][0-9a-f]:*", "2002:ac1[0-9a-f]:*", "2002:c0a8:*",
    "2002:7f[0-9a-f][0-9a-f]:*", "2002:a9fe:*",
)
# Fields that always hold an account or event username, masked whatever their value.
USER_FIELDS = frozenset(("user", "username", "assignee", "author", "actor", "proposed_by", "reviewed_by",
                         "approved_by", "updated_by", "changed_by", "submitted_by", "created_by"))
# A dotted octet may be four digits so a zero-padded octal loopback (0177) is one token, not skipped.
IP_RE = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,4}(?:\.\d{1,4}){3}|[0-9A-Fa-f]{1,4})?(?![\w:])"
    r"|(?<![\w.])\d{1,4}(?:\.\d{1,4}){3}(?!\w|\.\d)")
PSEUDONYM_RE = re.compile(r"\b(?:user|internal)-[0-9a-f]{%d}\b" % DIGEST_CHARS)
_QUAD_RE = re.compile(r"\d{1,4}(?:\.\d{1,4}){3}")


class Unavailable(Exception):
    """More distinct usernames than masking can match: refuse the viewer rather than leave names in text."""
    status = 503


def _ascii_fold(value):
    """Fold A–Z and leave every other character, including É, as it is."""
    return value.translate(_ASCII_FOLD)


def _embedded_v4(ip):
    """The IPv4 carried in a mapped, 6to4, or Teredo address, or None."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return mapped
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour is not None:
        return sixtofour
    teredo = getattr(ip, "teredo", None)
    if teredo:
        return teredo[1]  # (server, client); the client is the concealed host
    return None


def is_internal(ip):
    embedded = _embedded_v4(ip)
    if embedded is not None and is_internal(embedded):
        return True
    return any(ip.version == n.version and ip in n for n in INTERNAL_NETS)


def _v4_reading(text):
    """Internal address for a dotted quad: decimal if that is internal, else a zero-padded octal reading.

    10.0.0.01 and 010.0.0.1 are 10.0.0.1. 0177.0.0.1 is four digits, so it is not the public 177.0.0.1;
    the padded octet is octal 127, which is loopback, so that reading is used. 008.008.008.008 stays
    8.8.8.8 (visible): an octet with a digit 8-9 has no octal reading. 0.0.0.0 and the documentation
    ranges are not internal.
    """
    parts = text.split(".")
    if len(parts) != 4:
        return None
    decimal = []
    octal = []
    for part in parts:
        if not part.isdigit() or not 1 <= len(part) <= 4:
            return None
        dec = int(part, 10)
        if dec > 255:
            decimal = None
        elif decimal is not None:
            decimal.append(dec)
        padded = len(part) > 1 and part[0] == "0"
        if padded and any(ch > "7" for ch in part):
            octal = None
        elif octal is not None:
            value = int(part, 8) if padded else dec
            if value > 255:
                octal = None
            else:
                octal.append(value)
    for nums in (decimal, octal):
        if not nums or len(nums) != 4:
            continue
        addr = ipaddress.IPv4Address(".".join(str(n) for n in nums))
        if is_internal(addr):
            return addr
    return None


def _internal_prefix(text):
    """Longest leading slice of an unparsed colon-token that is itself an internal address."""
    ends = {len(text)}
    ends.update(i for i, ch in enumerate(text) if ch == ":")
    for end in sorted(ends, reverse=True):
        if end < 2:
            continue
        try:
            addr = ipaddress.ip_address(text[:end])
        except ValueError:
            continue
        if is_internal(addr):
            return addr, end
    return None


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
    # SQLite lower() folds ASCII only. The count uses that set, so ÉRIN and érin are two names toward the cap.
    names = {r[0] for r in conn.execute("SELECT DISTINCT lower(user) FROM events WHERE user IS NOT NULL"
                                        " AND user != '' LIMIT ?", (CANDIDATE_LIMIT + 1,))}
    if len(names) > CANDIDATE_LIMIT:  # fail closed: names past the bound would go out unmasked in free text
        raise Unavailable(f"the masked view is unavailable: more than {CANDIDATE_LIMIT:,} distinct usernames")
    accounts = {_ascii_fold(r[0]) for r in conn.execute("SELECT username FROM users")}
    names |= accounts - set(ROLES)  # a role word in prose stays visible; an event username is still masked
    return Masker(key(conn), names, self_name=user["username"], reversible=accounts)


@functools.lru_cache(maxsize=8)
def _names_re(names):
    if not names:
        return None
    # Names are already ASCII-folded. The search text is folded the same way, so this stays case-sensitive.
    return re.compile(r"(?<![\w.@-])(?:" + "|".join(map(re.escape, names)) + r")(?![\w@-])")


class Masker:
    def __init__(self, secret, names, self_name=None, *, reversible=()):
        self.secret = secret
        self.self_name = _ascii_fold(self_name or "")
        names = {_ascii_fold(n) for n in names if n} - {self.self_name}
        extra = {_ascii_fold(n) for n in reversible if n} - {self.self_name}
        self.names = tuple(sorted(names, key=lambda n: (-len(n), n)))  # longest first: ops-admin before admin
        self._reversible = names | extra  # role accounts are not in self.names, but their pseudonyms pivot
        self.names_re = _names_re(self.names)

    def _digest(self, kind, value):
        return hmac.new(self.secret, f"{kind}\0{value}".encode(), hashlib.sha256).hexdigest()[:DIGEST_CHARS]

    def user(self, name):
        return "user-" + self._digest("user", _ascii_fold(name))

    def ip(self, ip):
        return "internal-" + self._digest("ip", str(ip))

    def _mask_quads(self, text):
        def sub(match):
            addr = _v4_reading(match.group(0))
            return self.ip(addr) if addr is not None else match.group(0)
        return _QUAD_RE.sub(sub, text)

    def _ip_sub(self, match):
        text = match.group(0)
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            ip = None
        # Digest the address itself. A mapped/6to4/Teredo hit must not collapse onto the embedded v4.
        if ip is not None and is_internal(ip):
            return self.ip(ip)
        masked = self._mask_quads(text)
        if masked != text:
            return masked
        if ip is None and ":" in text:
            found = _internal_prefix(text)
            if found:
                addr, end = found
                return self.ip(addr) + text[end:]
        return text

    def text(self, s):
        s = IP_RE.sub(self._ip_sub, s)  # IPs first, so a numeric username cannot split an address
        if not self.names_re:
            return s
        # ASCII fold keeps the same length, so a match on the folded copy is the same span in s.
        folded = _ascii_fold(s)
        parts = []
        last = 0
        for match in self.names_re.finditer(folded):
            parts.append(s[last:match.start()])
            parts.append(self.user(s[match.start():match.end()]))
            last = match.end()
        parts.append(s[last:])
        return "".join(parts)

    def mask(self, value, field=None):
        if isinstance(value, str):
            if field in USER_FIELDS and value and _ascii_fold(value) != self.self_name:
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
            reverse = {self.user(n): n for n in self._reversible}
            globs = _INTERNAL_GLOBS
            src_clause = " OR ".join("src_ip GLOB ?" for _ in globs)
            dest_clause = " OR ".join("dest_ip GLOB ?" for _ in globs)
            for (value,) in conn.execute(
                    "SELECT src_ip FROM events WHERE src_ip IS NOT NULL AND (" + src_clause + ") UNION"
                    " SELECT dest_ip FROM events WHERE dest_ip IS NOT NULL AND (" + dest_clause + ") LIMIT ?",
                    globs + globs + (CANDIDATE_LIMIT,)):
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if is_internal(ip):
                    reverse[self.ip(ip)] = value
            self._reverse = reverse  # this request only; never kept beyond it
        found = lambda m: self._reverse.get(m.group(0), m.group(0))  # noqa: E731
        return PSEUDONYM_RE.sub((lambda m: quote(found(m), safe="")) if path else found, s)
