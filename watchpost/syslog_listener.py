"""Live syslog receiver over UDP and TCP (RFC 3164 and RFC 5424 messages, RFC 6587 TCP framing).

Each frame first goes through the existing auth.log parser, so sshd, sudo, UFW/iptables
firewall and OpenVPN lines get the same event types as uploaded files. A message the
auth.log parser does not recognize is then tried as an nginx/Apache combined access
line (web_request, web_scan, web_error). Anything else becomes a generic
`syslog` event whose severity comes from the PRI field. Frames are queued and
handed to engine.ingest in one batch every `flush_interval` seconds.

Syslog has no authentication. The listener binds to loopback by default; binding
elsewhere should be paired with SIEM_SYSLOG_ALLOW and a host firewall.
Failures are logged to error_log and reported through the `syslog` health
component. They never stop the web server.
"""

import ipaddress
import re
import socket
import socketserver
import threading
import time
from collections import deque
from datetime import datetime, timezone

from .firewall import ASA_TAG
from . import engine, health
from .db import connect, iso, now_iso, utcnow
from .diagnostics import describe_exception, log, record_error, redact_cut
from .normalize import (MAX_FUTURE, MAX_LEN, EventError, clean_text, normalize_authlog_line,
                        normalize_weblog_line, stored_text)

SOURCE = "syslog"
SUBMITTED_BY = "syslog-listener"
MAX_FRAME_BYTES = 16 * 1024   # longer frames are truncated
MAX_QUEUE = 50000             # frames held between flushes; beyond this they are dropped and counted
TCP_IDLE_TIMEOUT = 300
DEFAULT_PRI = 13              # user.notice, RFC 3164 section 4.3.3
RECENT_SECONDS = 600          # drops or flush failures this recent make the component degraded

# PRI severity (0 emerg .. 7 debug) mapped to Watchpost severities.
PRI_SEVERITY = {0: "critical", 1: "critical", 2: "critical", 3: "high",
                4: "medium", 5: "low", 6: "info", 7: "info"}

_PRI = re.compile(r"^<(\d*)>")
_RFC5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$", re.S)
# Optional Cisco sequence (`123: `), BSD timestamp with an optional year and fraction, or an ISO timestamp.
_RFC3164 = re.compile(
    r"^(?:\d{1,5}:\s+)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)(?:\s+(?P<rest>.*))?$",
    re.S)
_TAG = re.compile(r"^(?P<app>[^\s\[:]{1,48})(?:\[(?P<procid>[^\]\s]{1,32})\])?:\s?(?P<msg>.*)$", re.S)
_FRACTION = re.compile(r"(T\d{2}:\d{2}:\d{2})\.(\d+)")
_COMMA_FRACTION = re.compile(r"(T\d{2}:\d{2}:\d{2}),(\d+)")
_BSD_EXTENDED = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})(?:\s+(?P<year>\d{4}))?\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:[.,](?P<frac>\d+))?$")
_TS_PREFIX = re.compile(r"\d{4}-\d{2}-\d{2}T")
_PROG_UNSAFE = re.compile(r"[^\w\-/.]")
_MAX_HOST, _MAX_APP, _MAX_PROCID = 255, 48, 128


def _nil(value):
    return None if value in (None, "-") else value


def _fix_fraction(ts):
    # RFC 5424 allows 1-6 fractional digits; Python 3.10's fromisoformat wants exactly 3 or 6.
    # Some devices use a comma as the decimal mark.
    if not ts:
        return ts
    ts = _COMMA_FRACTION.sub(lambda m: f"{m.group(1)}.{m.group(2)[:6].ljust(6, '0')}", ts, count=1)
    return _FRACTION.sub(lambda m: f"{m.group(1)}.{m.group(2)[:6].ljust(6, '0')}", ts)


def _cut(value, limit):
    if value is None:
        return None
    return value[:limit]


def _bound(value, limit):
    return _cut(_nil(value), limit)


def _parsed(pri, msg, **fields):
    out = {"pri": pri, "facility": pri >> 3, "level": pri & 7, "format": "raw",
           "ts": None, "host": None, "app": None, "procid": None, "msg": msg}
    out.update(fields)
    return out


def _from_5424(ts, host, app, procid, msg):
    return {"format": "rfc5424", "ts": _fix_fraction(_nil(ts)), "host": _bound(host, _MAX_HOST),
            "app": _bound(app, _MAX_APP), "procid": _bound(procid, _MAX_PROCID),
            "msg": (msg or "").lstrip("﻿")}


def _skip_sd(text):
    """Index just after structured data, or None when the block does not close."""
    i, n = 0, len(text)
    if not text.startswith("["):
        return None
    while i < n and text[i] == "[":
        i += 1
        while i < n and text[i] not in " ]":
            i += 1
        if i >= n:
            return None
        while i < n and text[i] == " ":
            i += 1
            if i >= n or text[i] == "]":
                break
            eq = text.find("=", i)
            if eq <= i or " " in text[i:eq] or "]" in text[i:eq]:
                return None
            i = eq + 1
            if i >= n or text[i] != '"':
                return None
            i += 1
            while i < n:
                if text[i] == "\\":
                    if i + 1 >= n:
                        return None
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            else:
                return None
            if i >= n or text[i] not in " ]":
                return None
        if i >= n or text[i] != "]":
            return None
        i += 1
    return i


def _lenient_5424(text):
    """Header split for a version-1 frame whose structured data is missing or unclosed."""
    if not text.startswith("1 "):
        return None
    rest = text[2:].lstrip(" ")
    fields = []
    for _ in range(5):
        if rest == "":
            break
        sp = rest.find(" ")
        if sp == -1:
            fields.append(rest)
            rest = ""
            break
        fields.append(rest[:sp])
        rest = rest[sp + 1:]
    if len(fields) < 5:
        return None
    ts = fields[0]
    if ts != "-" and not _TS_PREFIX.match(ts):
        return None
    msg = rest
    if msg == "-" or msg.startswith("- "):
        msg = "" if msg == "-" else msg[2:]
    elif msg.startswith("["):
        end = _skip_sd(msg)
        if end is not None:
            msg = msg[end:]
            if msg.startswith(" "):
                msg = msg[1:]
    return _from_5424(ts, fields[1], fields[2], fields[3], msg)


def _match_5424(text):
    match = _RFC5424.match(text)
    if match:
        return _from_5424(match["ts"], match["host"], match["app"], match["procid"], match["msg"])
    return _lenient_5424(text)


def _timestamp_for_auth(ts, now):
    """Timestamp text the auth.log parser accepts. Classic BSD timestamps pass through."""
    if not ts:
        return None
    ts = _fix_fraction(ts)
    match = _BSD_EXTENDED.match(ts)
    if not match or (not match.group("year") and not match.group("frac")):
        return ts
    try:
        year = int(match.group("year")) if match.group("year") else None
        stamp = f"{match.group('mon')} {int(match.group('day')):02d} {match.group('hms')}"
        dt = datetime.strptime(f"{year or now.year} {stamp}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise EventError(f"unparseable timestamp {ts[:40]!r}")
    if year is None and dt > now + MAX_FUTURE:
        dt = dt.replace(year=dt.year - 1)
    frac = match.group("frac")
    if frac:
        dt = dt.replace(microsecond=int(frac[:6].ljust(6, "0")))
    return iso(dt)


def parse_frame(frame):
    """Split one syslog message into PRI, header fields, and message text. Never raises."""
    if isinstance(frame, (bytes, bytearray)):
        text = bytes(frame[:MAX_FRAME_BYTES]).decode("utf-8", "replace")
    elif isinstance(frame, str):
        text = frame[:MAX_FRAME_BYTES]
    else:
        return _parsed(DEFAULT_PRI, "")
    text = text.strip("\r\n\x00").lstrip(" \t\ufeff")
    pri = DEFAULT_PRI
    match = _PRI.match(text)
    if match:
        digits = match.group(1)
        if len(digits) <= 3:
            value = int(digits) if digits else 999
            if value <= 191:
                pri = value
        text = text[match.end():]  # out-of-range PRI still leaves the header to be parsed
    header = _match_5424(text)
    if header:
        return _parsed(pri, header.pop("msg"), **header)

    match = _RFC3164.match(text)
    if not match:
        tag = _TAG.match(text)
        if tag and ASA_TAG.fullmatch(tag["app"]):
            return _parsed(pri, tag["msg"], app=tag["app"])
        return _parsed(pri, text)
    host, rest = match["host"], match["rest"] or ""
    if host.endswith(":") or "[" in host:   # no HOSTNAME field: this is already the TAG
        host, rest = None, f"{host} {rest}".strip()
    out = _parsed(pri, rest, format="rfc3164", ts=_fix_fraction(match["ts"]), host=_cut(host, _MAX_HOST))
    tag = _TAG.match(rest)
    if tag:
        out.update(app=_cut(tag["app"], _MAX_APP), procid=_cut(tag["procid"], _MAX_PROCID), msg=tag["msg"])
    return out


def frame_to_event(frame, peer_ip=None, now=None):
    """Normalize one frame. Raises EventError (e.g. a bad timestamp) so the caller can record a rejection."""
    now = now or utcnow()
    if isinstance(frame, (bytes, bytearray)):
        frame = bytes(frame[:MAX_FRAME_BYTES]).decode("utf-8", "replace")
    elif not isinstance(frame, str):
        raise EventError("malformed syslog frame")
    elif len(frame) > MAX_FRAME_BYTES:
        frame = frame[:MAX_FRAME_BYTES]
    parsed = parse_frame(frame)
    host = parsed["host"] or peer_ip or "unknown"
    app = parsed["app"]
    if app and not ASA_TAG.fullmatch(app):
        app = _PROG_UNSAFE.sub("_", app)[:48]
    msg = parsed["msg"].replace("\r", " ").replace("\n", " ")
    # The auth.log parser only accepts a numeric pid. A string PROCID is valid RFC 5424;
    # splicing it into the tag makes normalize_authlog_line reject the whole frame.
    procid = parsed["procid"]
    if not (procid and procid.isdigit() and len(procid) <= _MAX_PROCID):
        procid = None
    prog = (app or "syslog") + (f"[{procid}]" if procid else "")
    # Rebuild an auth.log-style line so the existing parser (and its timestamp rules) does the work.
    try:
        line = f"{_timestamp_for_auth(parsed['ts'], now) or iso(now)} {host} {prog}: {msg}"
        event = normalize_authlog_line(line, SOURCE, now=now)
    except EventError:
        raise
    except ValueError as exc:
        # An impossible BSD date (Sep 32) raises ValueError from strptime. That must be a
        # rejection of this frame, not an exception that drops the rest of the batch.
        raise EventError(f"unparseable timestamp {str(parsed['ts'])[:40]!r}") from exc
    if event["event_type"] == "other":
        event = _web_event(msg, host, now) or event
    if event["event_type"] == "other":
        event["event_type"] = "syslog"
        event["severity"] = PRI_SEVERITY[parsed["level"]]
        event["message"] = stored_text(f"{app}: {msg}" if app else msg, "message")
    event["raw"] = redact_cut(frame.strip("\r\n\x00"), MAX_LEN["raw"])
    return event


def _web_event(msg, host, now):
    """An access log line forwarded by nginx/Apache (access_log syslog:...), or None."""
    try:
        event = normalize_weblog_line(msg, SOURCE, now=now)
    except EventError:
        return None
    event["host"] = clean_text(host, "host")  # access log lines carry no host; use the syslog header's
    return event


def _pending(rfile):
    return getattr(rfile, "_syslog_pending", b"")


def _unread(rfile, data):
    """Push bytes back. A NUL trailer must not swallow the next frame sitting behind it."""
    if data:
        rfile._syslog_pending = data + _pending(rfile)


def _read1(rfile):
    pending = _pending(rfile)
    if pending:
        rfile._syslog_pending = pending[1:]
        return pending[:1]
    return rfile.read(1)


def _readn(rfile, n):
    if n <= 0:
        return b""
    pending = _pending(rfile)
    if not pending:
        return rfile.read(n)
    take, rfile._syslog_pending = pending[:n], pending[n:]
    if len(take) == n:
        return take
    return take + rfile.read(n - len(take))


def _trailer_at(buf):
    newline, nul = buf.find(b"\n"), buf.find(b"\x00")
    if newline == -1:
        return nul
    if nul == -1:
        return newline
    return min(newline, nul)


def _read_until_trailer(rfile, max_bytes):
    """Read at most max_bytes, stopping at LF, NUL, or EOF.

    BufferedReader.read1 returns available bytes even while the writer is idle.
    Save the bytes after the first delimiter for the next frame.
    """
    buf = bytearray()
    read = getattr(rfile, "read1", None)
    while len(buf) < max_bytes:
        chunk = read(min(8192, max_bytes - len(buf))) if read else rfile.read(1)
        if not chunk:
            break
        cut = _trailer_at(chunk)
        if cut != -1:
            buf.extend(chunk[:cut + 1])
            _unread(rfile, chunk[cut + 1:])
            break
        buf.extend(chunk)
    return bytes(buf)


def _readline_limited(rfile, max_bytes):
    pending = _pending(rfile)
    if not pending:
        return _read_until_trailer(rfile, max_bytes)
    cut = _trailer_at(pending)
    if cut != -1 and cut < max_bytes:
        rfile._syslog_pending = pending[cut + 1:]
        return pending[:cut + 1]
    if len(pending) >= max_bytes:
        rfile._syslog_pending = pending[max_bytes:]
        return pending[:max_bytes]
    rfile._syslog_pending = b""
    return pending + _read_until_trailer(rfile, max_bytes - len(pending))


def read_tcp_frame(rfile, max_bytes=MAX_FRAME_BYTES):
    """Read one RFC 6587 frame: octet-counted ("LEN SP MSG") or LF/NUL-terminated. None at EOF."""
    first = _read1(rfile)
    if not first:
        return None
    if first.isdigit():
        digits = first
        while True:
            char = _read1(rfile)
            if not char:
                return digits[:max_bytes]
            if char == b" ":
                break
            if not char.isdigit() or len(digits) >= 6:
                return _read_line(rfile, digits + char, max_bytes)  # not octet counting after all
            digits += char
        length = int(digits)
        data = _readn(rfile, min(length, max_bytes))
        remaining = length - len(data)
        while remaining > 0:  # discard the truncated tail of an oversized frame
            chunk = _readn(rfile, min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        return data
    return _read_line(rfile, first, max_bytes)


def _read_line(rfile, prefix, max_bytes):
    cut = _trailer_at(prefix)
    if cut != -1:
        _unread(rfile, prefix[cut + 1:])
        return prefix[:cut + 1]
    line = prefix + _readline_limited(rfile, max_bytes)
    cut = _trailer_at(line)
    if cut != -1:
        _unread(rfile, line[cut + 1:])
        return line[:cut + 1]
    if len(line) > max_bytes:
        while True:  # discard the rest of an oversized line, stopping at LF or NUL
            more = _readline_limited(rfile, 65536)
            if not more:
                break
            cut = _trailer_at(more)
            if cut == -1:
                continue
            _unread(rfile, more[cut + 1:])
            break
    return line


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def parse_allow(value):
    """Comma-separated IPs or CIDR networks. Empty means any peer."""
    nets = []
    for part in (value or "").split(","):
        if part.strip():
            nets.append(ipaddress.ip_network(part.strip(), strict=False))
    return nets


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.listener.submit(self.request[0], self.client_address[0])


class _TCPHandler(socketserver.StreamRequestHandler):
    timeout = TCP_IDLE_TIMEOUT

    def handle(self):
        listener = self.server.listener
        peer = self.client_address[0]
        if not listener.allowed(peer):
            listener.count("denied")
            return
        try:
            while not listener.stopping.is_set():
                frame = read_tcp_frame(self.rfile)
                if frame is None:
                    return
                if frame.strip(b" \t\r\n\v\f\x00"):
                    listener.submit(frame, peer, checked=True)
        except (socket.timeout, ConnectionError):
            return


def _server_class(base, bind):
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    return type(base.__name__, (base,), {"address_family": family, "allow_reuse_address": True,
                                         "daemon_threads": True})


class SyslogListener:
    def __init__(self, db_path, bind="127.0.0.1", port=5514, flush_interval=2.0,
                 max_batch=20000, allow="", udp=True, tcp=True):
        self.db_path, self.bind, self.port = db_path, bind, port
        self.flush_interval, self.max_batch = flush_interval, max_batch
        self.error = None
        try:
            self.allow = parse_allow(allow)
        except ValueError as exc:
            self.allow = []
            self.error = f"invalid SIEM_SYSLOG_ALLOW entry: {exc}"  # fail closed: do not listen
        self.want_udp, self.want_tcp = udp, tcp
        self.udp_server = self.tcp_server = None
        self.udp_port = self.tcp_port = None
        self.stopping = threading.Event()
        self._queue = deque()
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._threads = []
        self.flush_error = None
        self.last_drop_at = None
        self.stats = {"frames_received": 0, "events_ingested": 0, "rejected": 0, "dropped": 0,
                      "denied": 0, "lost_on_failure": 0, "batches": 0,
                      "last_frame_at": None, "last_flush_at": None}

    # --- lifecycle -----------------------------------------------------------------

    def start(self):
        """Bind and start threads. Returns False (and reports failing health) instead of raising."""
        health.register_check("syslog", self.health_check)
        if self.error:
            self._record(self.error, "Fix SIEM_SYSLOG_ALLOW (comma-separated IPs or CIDR networks), then restart.")
            return False
        try:
            if self.want_tcp:
                self.tcp_server = _server_class(socketserver.ThreadingTCPServer, self.bind)(
                    (self.bind, self.port), _TCPHandler)
                self.tcp_server.listener = self
                self.tcp_port = self.tcp_server.server_address[1]
            if self.want_udp:
                self.udp_server = _server_class(socketserver.UDPServer, self.bind)(
                    (self.bind, self.port), _UDPHandler)
                self.udp_server.listener = self
                self.udp_port = self.udp_server.server_address[1]
        except OSError as exc:
            self.error = f"could not bind {self.bind}:{self.port}: {describe_exception(exc)}"
            self._record(self.error, "Choose a free SIEM_SYSLOG_PORT (ports below 1024 need root), then restart.")
            self._close_servers()
            return False
        for name, target in (("syslog-udp", self.udp_server and self.udp_server.serve_forever),
                             ("syslog-tcp", self.tcp_server and self.tcp_server.serve_forever),
                             ("syslog-flush", self._flush_loop)):
            if target:
                thread = threading.Thread(target=target, name=name, daemon=True)
                thread.start()
                self._threads.append(thread)
        if not _is_loopback(self.bind) and not self.allow:
            log.warning("Syslog listener bound to %s with no SIEM_SYSLOG_ALLOW list: any host that can "
                        "reach it can inject events. Restrict it with a firewall or SIEM_SYSLOG_ALLOW.", self.bind)
        log.info("Syslog listener on %s (udp %s, tcp %s)", self.bind, self.udp_port, self.tcp_port)
        return True

    def stop(self):
        self.stopping.set()
        for server in (self.udp_server, self.tcp_server):
            if server is not None:
                server.shutdown()
        self._close_servers()
        for thread in self._threads:
            thread.join(timeout=5)
        self.flush()
        health.unregister_check("syslog", self.health_check)

    def _close_servers(self):
        for server in (self.udp_server, self.tcp_server):
            if server is not None:
                server.server_close()

    # --- intake --------------------------------------------------------------------

    def allowed(self, peer):
        if not self.allow:
            return True
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(address in net for net in self.allow)

    def count(self, key, n=1):
        with self._lock:
            self.stats[key] += n

    def submit(self, data, peer, checked=False):
        if not checked and not self.allowed(peer):
            self.count("denied")
            return
        frame = data[:MAX_FRAME_BYTES].decode("utf-8", errors="replace")
        with self._lock:
            self.stats["frames_received"] += 1
            self.stats["last_frame_at"] = now_iso()
            if len(self._queue) >= MAX_QUEUE:
                self.stats["dropped"] += 1
                self.last_drop_at = time.monotonic()
                return
            self._queue.append((frame, peer))

    # --- batching into the engine --------------------------------------------------

    def _flush_loop(self):
        while not self.stopping.wait(self.flush_interval):
            try:
                self.flush()
            except Exception as exc:  # never let the thread die silently
                self.flush_error = describe_exception(exc)
                log.error("[syslog] flush loop error: %s", self.flush_error)

    def flush(self):
        """Ingest everything queued so far. Returns the number of frames processed."""
        with self._flush_lock:
            processed = 0
            while True:
                with self._lock:
                    frames = [self._queue.popleft() for _ in range(min(len(self._queue), self.max_batch))]
                if not frames:
                    return processed
                processed += len(frames)
                self._ingest(frames)

    def _ingest(self, frames):
        events, rejections = [], []
        for index, (frame, peer) in enumerate(frames, start=1):
            try:
                events.append(frame_to_event(frame, peer))
            except EventError as exc:
                rejections.append({"index": index, "reason": str(exc)})
        conn = None
        try:
            conn = connect(self.db_path)
            engine.ingest(conn, events, rejections, SOURCE, "syslog", SUBMITTED_BY)
        except Exception as exc:
            self.flush_error = describe_exception(exc)
            self.count("lost_on_failure", len(frames))
            self._record(exc, "The syslog batch was not stored. Check storage health; senders should "
                              "retry (rsyslog does for TCP with a queue).", conn)
            return
        finally:
            if conn is not None:
                conn.close()
        with self._lock:
            self.flush_error = None
            self.stats["events_ingested"] += len(events)
            self.stats["rejected"] += len(rejections)
            self.stats["batches"] += 1
            self.stats["last_flush_at"] = now_iso()

    def _record(self, exc_or_message, guidance, conn=None):
        own = conn is None
        try:
            if own:
                conn = connect(self.db_path)
            record_error(conn, "syslog", exc_or_message, guidance=guidance)
        except Exception:
            log.error("[syslog] %s", exc_or_message)
        finally:
            if own and conn is not None:
                conn.close()

    # --- health --------------------------------------------------------------------

    def health_check(self):
        with self._lock:
            details = {"bind": self.bind, "udp_port": self.udp_port, "tcp_port": self.tcp_port,
                       "allow": [str(n) for n in self.allow], "queued": len(self._queue), **self.stats}
        if self.error:
            return ("failing", f"syslog listener is not running: {self.error}",
                    "Fix the cause (usually the port is in use or needs root), then restart Watchpost.", details)
        dead = [t.name for t in self._threads if not t.is_alive()]
        if dead and not self.stopping.is_set():
            return ("failing", f"syslog thread(s) stopped: {', '.join(dead)}",
                    "Check the Errors list for the cause and restart Watchpost.", details)
        if self.flush_error:
            return ("degraded", f"last syslog batch failed: {self.flush_error}",
                    "Check storage health. Frames from the failed batch were not stored.", details)
        if self.last_drop_at and time.monotonic() - self.last_drop_at < RECENT_SECONDS:
            return ("degraded", f"{details['dropped']} frame(s) dropped because the queue was full",
                    "Senders are faster than ingestion. Reduce forwarded facilities or rate-limit in rsyslog.",
                    details)
        return ("ok", f"listening on {self.bind} (udp {self.udp_port}, tcp {self.tcp_port})", None, details)


def start_if_enabled(app):
    """Called from main.py. Returns the running listener, or None when SIEM_SYSLOG is not 1."""
    config = app.config
    if not config.syslog_enabled:
        return None
    listener = SyslogListener(config.db_path, config.syslog_bind, config.syslog_port,
                              max_batch=config.max_batch_events, allow=config.syslog_allow)
    listener.start()
    return listener
