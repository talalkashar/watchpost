"""Threat intelligence: lists of addresses known to be hostile, and what in Watchpost touches them.

A feed is a named list of IP addresses and networks. It comes from one of three places:
- an admin, who pastes or posts a list;
- a preset: a well-known open feed (PRESETS) the operator turns on by name in SIEM_THREAT_FEEDS, such as
  `SIEM_THREAT_FEEDS=spamhaus_drop,et_compromised,otx`. OTX needs an API key in SIEM_OTX_API_KEY;
- any other URL: `SIEM_THREAT_FEEDS=mylist=https://intel.example.internal/bad.txt`.
URL feeds are fetched on a timer. Nothing is fetched unless configured, and no feed's data is bundled:
the repository holds synthetic data only, and a list of hostile addresses is stale within days anyway.
The sample in samples/threat_intel.txt is synthetic. Each preset has its own terms of use; read them.

What a feed does:
- Every event is tagged when it is stored: if its source or destination address is on a feed, the
  event's `threat` field names the feed and the entry's note. The tag is searchable (`threat:*` in a
  hunt), shown wherever events are, and kept when the event is archived.
- When a feed changes, the stored events are tagged again, so an address listed today also marks what
  it did last week.
- An alert whose evidence carries a tag is raised one severity level, and says why.
- To alert on every sighting, save the hunt `threat:*` and promote it to a detection: it then goes
  through the same review as any other rule.

What a feed is not allowed to do: list an internal address, or a network broader than a /16 (IPv4) or
a /32 (IPv6). One bad line in a feed would otherwise mark the whole office as hostile. Such lines are
refused and counted, and the rest of the feed is used.

Limits: addresses only, no domains, URLs or file hashes. A feed is as good as whoever maintains it;
a listed address is a reason to look, not a verdict.
"""

import ipaddress
import json
import logging
import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from . import __version__, masking
from .db import audit, iso, now_iso, transaction, utcnow
from .normalize import SEVERITIES
from .queries import QueryError

log = logging.getLogger("watchpost.threat_intel")

MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_INDICATORS = 50_000          # per feed
MAX_NOTE = 120
MAX_RETAG_ADDRESSES = 200_000    # distinct addresses in stored events; above this, only new events are tagged
BROADEST_PREFIX = {4: 16, 6: 32}
FEED_NAME = re.compile(r"^[a-z0-9_-]{1,32}$")
_LINE = re.compile(r"^([0-9A-Fa-f:.]+(?:/\d{1,3})?)\s*(?:[#;,|\s]\s*(.*))?$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ThreatIntelError(QueryError):
    pass


# --- reading a list ------------------------------------------------------------------

def _refusal(network):
    """Why an entry may not be listed, or None."""
    if network.prefixlen < BROADEST_PREFIX[network.version]:
        return f"broader than a /{BROADEST_PREFIX[network.version]}"
    if network.is_multicast or network.is_unspecified or network.network_address.is_unspecified:
        return "not a host address"
    if any(network.version == internal.version and network.overlaps(internal) for internal in masking.INTERNAL_NETS):
        return "an internal address"
    return None


def parse(text):
    """Entries of a feed: one address or network per line, an optional note after `#`, `;`, `,` or a space.

    Returns ({value: note}, [refusals as "line N: reason"]). Blank lines and lines starting with # or ; are
    comments. A single-address network is stored as the address.
    """
    entries, refused = {}, []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        found = _LINE.match(line)
        try:
            network = ipaddress.ip_network(found.group(1), strict=False) if found else None
        except ValueError:
            network = None
        if network is None:
            refused.append(f"line {number}: not an address or network")
            continue
        reason = _refusal(network)
        if reason:
            refused.append(f"line {number}: {reason}")
            continue
        single = network.prefixlen == network.max_prefixlen
        value = str(network.network_address) if single else str(network)
        entries[value] = _CONTROL.sub(" ", found.group(2) or "").strip()[:MAX_NOTE] or None
        if len(entries) > MAX_INDICATORS:
            raise ThreatIntelError(f"a feed holds at most {MAX_INDICATORS} entries")
    return entries, refused


# --- matching ------------------------------------------------------------------------

class Matcher:
    """Answers "is this address listed, and by what" for every feed at once.

    Single addresses are looked up as text. Networks are grouped by prefix length, so a lookup costs one
    probe per length in use, however many networks the feeds list.
    """

    def __init__(self, rows=()):
        self.exact, self.by_prefix = {}, {}
        for feed, value, note in rows:
            label = f"{feed}: {note}" if note else feed
            if "/" in value:
                network = ipaddress.ip_network(value)
                table = self.by_prefix.setdefault((network.version, network.prefixlen), {})
                table.setdefault(int(network.network_address), []).append(label)
            else:
                self.exact.setdefault(value, []).append(label)

    def __bool__(self):
        return bool(self.exact or self.by_prefix)

    def label(self, address):
        """What lists this address ("feed: note", several joined), or None."""
        if not address:
            return None
        labels = list(self.exact.get(address, ()))
        if self.by_prefix:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                return None
            number = int(parsed)
            for (version, length), table in self.by_prefix.items():
                if version == parsed.version:
                    shift = parsed.max_prefixlen - length
                    labels += table.get(number >> shift << shift, ())
        return "; ".join(sorted(set(labels))[:3])[:300] if labels else None


_CACHE = {}   # database file -> (version, Matcher); an in-memory database is never cached
_CACHE_LOCK = threading.Lock()


def _version(conn):
    row = conn.execute("SELECT value FROM meta WHERE key = 'threat_intel_version'").fetchone()
    return row[0] if row else "0"


def load(conn):
    """The matcher for the feeds as they are now. Cheap when nothing changed since the last call."""
    version = _version(conn)
    if version == "0":
        return Matcher()
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    with _CACHE_LOCK:
        cached = _CACHE.get(path) if path else None
        if cached and cached[0] == version:
            return cached[1]
    matcher = Matcher(conn.execute("SELECT feed, value, note FROM threat_indicators"))
    if path:
        with _CACHE_LOCK:
            _CACHE[path] = (version, matcher)
    return matcher


def tag(conn, events):
    """Set `threat` on each event about to be stored: what lists its source or destination address, or None."""
    matcher, seen = load(conn), {}
    for event in events:
        event["threat"] = None
        for address in (event.get("src_ip"), event.get("dest_ip")) if matcher else ():
            if address not in seen:
                seen[address] = matcher.label(address)   # a batch names few addresses, many times each
            if seen[address]:
                event["threat"] = seen[address]
                break


def retag(conn):
    """Tag the stored events again after the feeds changed. Returns how many events are tagged now, or None
    when there are too many distinct addresses to go through (new events are still tagged as they arrive)."""
    matcher = load(conn)
    addresses = [r[0] for r in conn.execute(
        "SELECT src_ip FROM events WHERE src_ip IS NOT NULL UNION SELECT dest_ip FROM events WHERE dest_ip IS NOT NULL"
        " LIMIT ?", (MAX_RETAG_ADDRESSES + 1,))]
    if len(addresses) > MAX_RETAG_ADDRESSES:
        return None
    listed = {address: label for address in addresses if (label := matcher.label(address))} if matcher else {}
    with transaction(conn):
        conn.execute("UPDATE events SET threat = NULL WHERE threat IS NOT NULL")
        for address, label in sorted(listed.items()):
            conn.execute("UPDATE events SET threat = ? WHERE dest_ip = ? AND threat IS NULL", (label, address))
            conn.execute("UPDATE events SET threat = ? WHERE src_ip = ?", (label, address))   # the source wins, as in tag()
    return conn.execute("SELECT COUNT(*) FROM events WHERE threat IS NOT NULL").fetchone()[0]


def raise_severity(weighed, labels):
    """An alert's weighed severity, one level higher because its evidence touches a listed address."""
    rank = SEVERITIES.index(weighed["severity"]) if weighed["severity"] in SEVERITIES else 0
    more = f" and {len(labels) - 1} more" if len(labels) > 1 else ""
    reason = f"evidence touches an address listed by threat intelligence ({labels[0]}{more})"
    if rank == len(SEVERITIES) - 1:
        reason = f"already {weighed['severity']}; {reason}"
    note = f"{weighed['severity_note']}; {reason}" if weighed.get("severity_note") else reason
    return {**weighed, "severity": SEVERITIES[min(rank + 1, len(SEVERITIES) - 1)], "severity_note": note}


# --- feeds ---------------------------------------------------------------------------

def replace_feed(conn, name, text, actor, source="import", synthetic=False):
    """Make `text` the whole content of the feed `name`, then tag the stored events again."""
    if not isinstance(name, str) or not FEED_NAME.match(name):
        raise ThreatIntelError("a feed name is 1 to 32 characters of a-z, 0-9, _ and -")
    if not isinstance(text, str) or not text.strip():
        raise ThreatIntelError("the feed is empty: give one address or network per line")
    if len(text.encode()) > MAX_FEED_BYTES:
        raise ThreatIntelError(f"a feed is at most {MAX_FEED_BYTES // (1024 * 1024)} MB")
    entries, refused = parse(text)
    if not entries:
        raise ThreatIntelError("no usable entry in the feed"
                               + (f" ({len(refused)} refused, first: {refused[0]})" if refused else ""))
    now = now_iso()
    with transaction(conn):
        conn.execute("DELETE FROM threat_indicators WHERE feed = ?", (name,))
        conn.executemany("INSERT INTO threat_indicators(feed, value, note) VALUES (?,?,?)",
                         [(name, value, note) for value, note in entries.items()])
        conn.execute(
            "INSERT INTO threat_feeds(name, source, synthetic, indicators, refused, updated_at, updated_by, last_error)"
            " VALUES (?,?,?,?,?,?,?,NULL) ON CONFLICT(name) DO UPDATE SET source = excluded.source,"
            " synthetic = excluded.synthetic, indicators = excluded.indicators, refused = excluded.refused,"
            " updated_at = excluded.updated_at, updated_by = excluded.updated_by, last_error = NULL",
            (name, source, int(bool(synthetic)), len(entries), len(refused), now, actor))
        _bump(conn)
        audit(conn, actor, "threat_feed_updated", name,
              {"indicators": len(entries), "refused": len(refused), "source": source, "synthetic": bool(synthetic)})
    return {"feed": name, "indicators": len(entries), "refused": len(refused), "refusals": refused[:20],
            "events_tagged": retag(conn)}


def delete_feed(conn, name, actor):
    with transaction(conn):
        if conn.execute("DELETE FROM threat_feeds WHERE name = ?", (name,)).rowcount == 0:
            raise ThreatIntelError("no such feed", 404)
        conn.execute("DELETE FROM threat_indicators WHERE feed = ?", (name,))
        _bump(conn)
        audit(conn, actor, "threat_feed_deleted", name)
    return {"feed": name, "events_tagged": retag(conn)}


def _bump(conn):
    conn.execute("INSERT INTO meta(key, value) VALUES ('threat_intel_version', '1') ON CONFLICT(key)"
                 " DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)")


def overview(conn, configured=()):
    """The feeds, how much they list, and the newest events they tagged."""
    feeds = [dict(r) for r in conn.execute("SELECT * FROM threat_feeds ORDER BY name")]
    known = {feed["name"] for feed in feeds}
    feeds += [{"name": name, "source": "url", "synthetic": 0, "indicators": 0, "refused": 0, "updated_at": None,
               "updated_by": None, "last_error": "not fetched yet"} for name in sorted(set(configured) - known)]
    recent = [dict(r) for r in conn.execute(
        "SELECT id, ts, event_type, src_ip, dest_ip, host, threat, synthetic FROM events WHERE threat IS NOT NULL"
        " ORDER BY id DESC LIMIT 20")]
    return {"feeds": feeds, "indicators": sum(feed["indicators"] for feed in feeds),
            "tagged_events": conn.execute("SELECT COUNT(*) FROM events WHERE threat IS NOT NULL").fetchone()[0],
            "recent": recent, "url_feeds": sorted(configured),
            "presets": [{"name": name, "about": preset["about"], "use": preset["use"], "terms": preset["terms"],
                         "enabled": name in configured}
                        for name, preset in PRESETS.items()]}


def lookup(conn, address):
    """Which feeds list one address."""
    try:
        address = str(ipaddress.ip_address(str(address or "").strip()))
    except ValueError:
        raise ThreatIntelError("ip must be an IP address") from None
    return {"ip": address, "listed": load(conn).label(address)}


# --- feeds fetched from a URL --------------------------------------------------------

# Open feeds an operator can turn on by name. Each was fetched once and read with parse(), and its publisher's
# terms were read, on 2026-11-10. `use` says in a few words what those pages said then; `terms` is where to read
# them now. Whether a feed may be used where you work is between you and its publisher. Nothing here is fetched
# unless its name is in SIEM_THREAT_FEEDS, and no feed is fetched more than once an hour (MIN_FETCH_SECONDS):
# Spamhaus and Emerging Threats both ask for that, and none of the others needs more.
PRESETS = {
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "terms": "https://www.spamhaus.org/blocklists/drop-fair-use-policy/",
        "about": "Spamhaus DROP (Don't Route Or Peer): networks hijacked or leased by professional spam and "
                 "cybercrime operations. Data from The Spamhaus Project.",
        "use": "Free to download and use, with credit to The Spamhaus Project. At most one automated download an hour."},
    "et_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "terms": "https://rules.emergingthreats.net/OPEN_download_instructions.html",
        "about": "Emerging Threats (Proofpoint) compromised hosts: addresses seen attacking others, such as SSH brute forcers.",
        "use": "The file states no licence; the open ruleset it belongs to is BSD-licensed. At most one download an hour."},
    "cins_army": {
        "url": "https://cinsscore.com/list/ci-badguys.txt", "terms": "https://cinsscore.com/#list",
        "about": "CINS Army (Sentinel IPS): up to 15,000 addresses with a very poor reputation across its sensors.",
        "use": "No formal licence; the publisher says to use the list in any way you see fit."},
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt", "terms": "https://www.blocklist.de/en/export.html",
        "about": "blocklist.de: every address that attacked one of its reporting servers in the last 48 hours.",
        "use": "No formal licence; a free, voluntary service, offered as is and at your own risk."},
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "terms": "https://github.com/stamparm/ipsum",
        "about": "IPsum level 3: addresses found on three or more of some thirty public blocklists, rebuilt daily.",
        "use": "The Unlicense. The lists it aggregates keep their own terms."},
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "terms": "https://abuse.ch/terms-of-use/",
        "about": "abuse.ch Feodo Tracker: botnet command-and-control servers. The publisher says the dataset is "
                 "currently almost empty after takedowns; it is here for when that changes.",
        "use": "CC0, for commercial and non-commercial use."},
    "tor_exits": {
        "url": "https://check.torproject.org/torbulkexitlist", "terms": "https://support.torproject.org/abuse/ban-tor/",
        "about": "Tor exit relays. Not hostile in themselves: context for a login or a scan that arrives through Tor.",
        "use": "Published by the Tor Project for this purpose; no licence is stated for the file."},
    "otx": {
        "url": "https://otx.alienvault.com", "terms": "https://www.levelblue.com/legal/otx-eula-terms",
        "about": "AlienVault (LevelBlue) OTX: addresses in the pulses your OTX account subscribes to, changed in the last "
                 "SIEM_OTX_DAYS days. Needs a free account and its API key in SIEM_OTX_API_KEY. Its quality "
                 "depends on whom the account follows.",
        "use": "Free for non-commercial use only, under the OTX terms. Read them before using this at work."},
}
MIN_FETCH_SECONDS = 3600
OTX_TYPES = ("IPv4", "IPv6", "CIDR")
OTX_PAGE_SIZE, OTX_MAX_PAGES = 50, 60


def _check_url(name, url):
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        raise ValueError(f"the threat feed {name} has no usable URL")
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError(f"the threat feed {name} must use https")
    if parsed.username or parsed.password:
        raise ValueError(f"the threat feed {name} must not carry a user name or password in its URL")
    return url


def feeds_from_config(config):
    """The URL feeds to fetch, from SIEM_THREAT_FEEDS: {name: {"kind": "list" or "otx", "url"}}.

    An item is a preset's name, or name=url for any other list (name=url also overrides a preset's URL, for
    a mirror). Raises ValueError on anything else, and on `otx` without an API key.
    """
    feeds = {}
    for part in filter(None, (p.strip() for p in (config.threat_feeds or "").split(","))):
        name, given, url = (piece.strip() for piece in part.partition("="))
        if not FEED_NAME.match(name):
            raise ValueError("SIEM_THREAT_FEEDS takes preset names and name=url pairs separated by commas; "
                             "a name is a-z, 0-9, _ and -")
        if not given and name not in PRESETS:
            raise ValueError(f"SIEM_THREAT_FEEDS: {name} is not a preset ({', '.join(sorted(PRESETS))}); give it as {name}=https://...")
        kind = "otx" if name == "otx" else "list"
        if kind == "otx" and not config.otx_api_key:
            raise ValueError("the otx feed needs SIEM_OTX_API_KEY (the API key of a free OTX account)")
        feeds[name] = {"kind": kind, "url": _check_url(name, url if given else PRESETS[name]["url"])}
    if feeds and config.threat_feed_minutes * 60 < MIN_FETCH_SECONDS:
        raise ValueError("SIEM_THREAT_FEED_MINUTES must be at least 60: feed publishers ask not to be polled more often")
    return feeds


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _get(url, headers=None, timeout=30):
    """The body behind a URL. Raises OSError or ValueError; never follows a redirect, never reads past the cap."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"User-Agent": f"Watchpost/{__version__}", **(headers or {})})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_FEED_BYTES + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            raise OSError(f"HTTP {exc.code}") from None
    if len(body) > MAX_FEED_BYTES:
        raise ValueError(f"larger than {MAX_FEED_BYTES // (1024 * 1024)} MB")
    return body.decode("utf-8", "replace")


def fetch(url, timeout=30):
    """The text of a plain list feed."""
    return _get(url, {"Accept": "text/plain, */*"}, timeout)


def fetch_otx(base, api_key, days=30, timeout=30, now=None):
    """The addresses in an OTX account's subscribed pulses changed in the last `days`, as feed text.

    One line per indicator with the pulse's name as its note. Follows the API's paging, but only to the same
    host: the API key is never sent anywhere else.
    """
    since = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    query = urllib.parse.urlencode({"limit": OTX_PAGE_SIZE, "modified_since": since})
    url, lines = f"{base.rstrip('/')}/api/v1/pulses/subscribed?{query}", []
    for _ in range(OTX_MAX_PAGES):
        try:
            page = json.loads(_get(url, {"X-OTX-API-KEY": api_key, "Accept": "application/json"}, timeout))
            pulses = page["results"]
        except (KeyError, TypeError, ValueError):
            raise ValueError("the OTX answer was not the expected JSON") from None
        for pulse in pulses if isinstance(pulses, list) else ():
            name = _CONTROL.sub(" ", str(pulse.get("name") or "OTX pulse"))[:MAX_NOTE]
            for indicator in pulse.get("indicators") or ():
                if isinstance(indicator, dict) and indicator.get("type") in OTX_TYPES:
                    lines.append(f"{str(indicator.get('indicator') or '').strip()} # {name}")
        url = page.get("next")
        if not url or len(lines) > MAX_INDICATORS * 2:
            break
        following, start = urllib.parse.urlsplit(url), urllib.parse.urlsplit(base)
        if (following.scheme, following.netloc) != (start.scheme, start.netloc):
            raise ValueError("the OTX answer pointed to another host for its next page")
    if not lines:
        raise ValueError(f"no address in the subscribed pulses of the last {days} days")
    return "\n".join(lines)


def refresh(conn, feeds, actor="threat-intel", timeout=30, otx_api_key=None, otx_days=30, min_age_seconds=0):
    """Fetch every configured feed. A feed that fails keeps its last good content and records the error.

    A feed fetched successfully less than `min_age_seconds` ago is left alone: publishers ask not to be polled.
    """
    results = []
    fresh = iso(utcnow() - timedelta(seconds=min_age_seconds))
    for name, feed in sorted(feeds.items()):
        last = conn.execute("SELECT updated_at FROM threat_feeds WHERE name = ? AND source = 'url' AND last_error IS NULL"
                            " AND indicators > 0", (name,)).fetchone()
        if min_age_seconds and last and last[0] > fresh:
            results.append({"feed": name, "skipped": f"fetched at {last[0]}; a feed is fetched at most once an hour"})
            continue
        try:
            text = (fetch_otx(feed["url"], otx_api_key, otx_days, timeout) if feed["kind"] == "otx"
                    else fetch(feed["url"], timeout))
            results.append(replace_feed(conn, name, text, actor, source="url"))
        except (OSError, ValueError) as exc:
            problem = f"{type(exc).__name__}: {exc}"[:200]
            conn.execute(
                "INSERT INTO threat_feeds(name, source, indicators, refused, updated_at, updated_by, last_error)"
                " VALUES (?, 'url', 0, 0, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET last_error = excluded.last_error",
                (name, now_iso(), actor, problem))
            log.warning("threat feed %s could not be refreshed: %s", name, problem)
            results.append({"feed": name, "error": problem})
    return results


class Fetcher:
    """Refreshes the URL feeds on a timer, in its own thread."""

    def __init__(self, connect, feeds, interval_seconds, otx_api_key=None, otx_days=30):
        self.connect, self.feeds, self.interval = connect, feeds, interval_seconds
        self.otx_api_key, self.otx_days = otx_api_key, otx_days
        self._stop, self._thread = threading.Event(), None

    def start(self):
        self._thread = threading.Thread(target=self._loop, name="threat-intel", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(35)

    def _loop(self):
        delay = min(30, self.interval)   # the first fetch comes soon after start
        while not self._stop.wait(delay):
            delay = self.interval
            conn = self.connect()
            try:
                refresh(conn, self.feeds, otx_api_key=self.otx_api_key, otx_days=self.otx_days,
                        min_age_seconds=MIN_FETCH_SECONDS - 60)   # also after a restart
            except Exception as exc:   # the thread must outlive a locked database
                log.error("threat feed refresh failed: %s", type(exc).__name__)
            finally:
                conn.close()


def start_if_enabled(app):
    """Called from main.py. Returns the running fetcher, or None when no URL feed is configured."""
    feeds = feeds_from_config(app.config)
    if not feeds:
        return None
    log.info("Threat intelligence: %s fetched every %s minutes", ", ".join(sorted(feeds)), app.config.threat_feed_minutes)
    return Fetcher(app.conn, feeds, app.config.threat_feed_minutes * 60, app.config.otx_api_key, app.config.otx_days).start()

