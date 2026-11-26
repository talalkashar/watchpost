"""Live syslog receiver over UDP, TCP and TLS (RFC 3164 and RFC 5424 messages, RFC 6587 framing, RFC 5425 TLS).

Each frame first goes through the existing auth.log parser, so sshd, sudo, UFW/iptables
firewall and OpenVPN lines get the same event types as uploaded files. A message the
auth.log parser does not recognize is then tried as an nginx/Apache combined access
line (web_request, web_scan, web_error). Anything else becomes a generic
`syslog` event whose severity comes from the PRI field. Frames are queued and
handed to engine.ingest in one batch every `flush_interval` seconds.

Plain UDP and TCP syslog have no authentication and no encryption. The listener binds to
loopback by default; binding elsewhere should be paired with SIEM_SYSLOG_ALLOW and a host
firewall, or use TLS instead. A server certificate (SIEM_SYSLOG_TLS_CERT, SIEM_SYSLOG_TLS_KEY)
encrypts the stream and proves the listener to the sender. A client CA
(SIEM_SYSLOG_TLS_CLIENT_CA) also makes every sender prove a certificate from that CA before
one frame is read.
Failures are logged to error_log and reported through the `syslog` health
component. They never stop the web server.
"""

import ipaddress
import re
import socket
import socketserver
import ssl
import threading
import time
from collections import deque
from datetime import datetime, timezone

from . import engine, health
from .db import connect, iso, now_iso, utcnow
from .diagnostics import describe_exception, log, record_error, redact_cut
from .normalize import (MAX_FUTURE, MAX_LEN, EventError, clean_text, normalize_authlog_line,
                        normalize_weblog_line, stored_text)

SOURCE = "syslog"
SUBMITTED_BY = "syslog-listener"
MAX_FRAME_BYTES = 16 * 1024   # longer frames are truncated
MAX_OCTET_DIGITS = 9          # bound the declared length before converting it to an integer
MAX_QUEUE = 50000             # frames held between flushes; beyond this they are dropped and counted
TCP_IDLE_TIMEOUT = 300
MAX_TLS_CONNECTIONS = 64
TLS_HANDSHAKE_TIMEOUT = 10    # seconds a peer gets to finish the TLS handshake
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
    app = _PROG_UNSAFE.sub("_", parsed["app"])[:48] if parsed["app"] else None
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
        digits = bytearray(first)
        while True:
            char = _read1(rfile)
            if not char:
                return bytes(digits[:max_bytes])
            if char == b" ":
                break
            if not char.isdigit() or len(digits) == MAX_OCTET_DIGITS:
                return _read_line(rfile, bytes(digits) + char, max_bytes)
            digits.extend(char)
        length = int(digits)
        data = bytearray()
        remaining = length
        while remaining:
            chunk = _readn(rfile, min(remaining, 65536))
            if not chunk:
                return None  # EOF before the declared end, including an orderly TLS close
            if len(data) < max_bytes:
                data.extend(chunk[:max_bytes - len(data)])
            remaining -= len(chunk)
        return bytes(data)
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


def _refuse_passphrase():
    raise ValueError("the private key is passphrase-protected; Watchpost cannot ask for a passphrase, so it "
                     "needs an unencrypted key file that only its own user can read")


def _readable(*paths):
    for path in paths:
        with open(path, "rb"):  # the ssl module's own "No such file or directory" does not name the file
            pass


def tls_context(cert, key, client_ca=None):
    """Server-side context for syslog over TLS (RFC 5425). Raises ValueError when a file cannot be used.

    TLS 1.2 is the floor. With `client_ca`, a handshake completes only for a sender whose certificate
    chains to that CA bundle (mutual TLS). The system trust store is never consulted.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Some Python builds (3.11.2 on Debian 12, for one) turn this on for every new context. It makes a
    # stream that was cut off read like one that ended properly, and _TLSHandler must tell the two apart.
    context.options &= ~getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0)
    # No TLS 1.3 session tickets. A sender only writes, so a ticket stays unread in its socket buffer,
    # and rsyslog then takes a connection this side has closed for a live one (see _TLSHandler). A
    # long-lived syslog connection has no use for session resumption anyway.
    context.num_tickets = 0
    part = "certificate and key"
    try:
        _readable(cert, key)
        context.load_cert_chain(cert, key, password=_refuse_passphrase)
        if client_ca:
            part = "client CA"
            _readable(client_ca)
            context.load_verify_locations(cafile=client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot load the TLS {part}: {describe_exception(exc)}") from exc
    return context


def _read_frames(listener, rfile, peer):
    """Queue frames from one stream. True when the peer ended it cleanly; False on a timeout, a broken
    stream, or shutdown."""
    try:
        while not listener.stopping.is_set():
            frame = read_tcp_frame(rfile)
            if frame is None:
                return True
            if frame.strip(b" \t\r\n\v\f\x00"):
                listener.submit(frame, peer, checked=True)
    except OSError:  # idle timeout, reset, or a TLS stream cut short
        pass
    return False


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
        _read_frames(listener, self.rfile, peer)


class _TLSHandler(socketserver.BaseRequestHandler):
    """Syslog over TLS (RFC 5425): the TCP framing, inside a TLS session.

    The handshake runs here, in the connection's own thread, so a peer that stalls it cannot hold up
    the accept loop. The allow list is checked first, so a denied peer costs no handshake.

    Closing follows RFC 5425 section 4.4 where the sender starts it: its close_notify is answered with
    ours. When this side ends the connection (idle timeout, shutdown) it sends no close_notify, on
    purpose. rsyslog tells a closed connection from a live one by peeking at its socket for unread
    bytes; a close_notify waiting there hides the close, and rsyslog then loses its next message.
    Measured with rsyslog 8.2302 and GnuTLS 3.7: every first message after an idle close was lost
    with close_notify (or with session tickets), none without.
    """

    def handle(self):
        listener = self.server.listener
        peer = self.client_address[0]
        if not listener.allowed(peer):
            listener.count("denied")
            return
        self.request.settimeout(TLS_HANDSHAKE_TIMEOUT)
        try:
            # suppress_ragged_eofs=False: a stream cut off without close_notify raises instead of reading
            # as a normal end, so a half-received last frame is dropped, not stored as if it were whole.
            conn = listener.tls_context.wrap_socket(self.request, server_side=True, suppress_ragged_eofs=False)
        except OSError as exc:  # no or untrusted client certificate, plaintext on this port, a stalled peer
            listener.tls_failed(peer, exc)
            return
        with conn:
            conn.settimeout(TCP_IDLE_TIMEOUT)
            with conn.makefile("rb") as rfile:
                ended_cleanly = _read_frames(listener, rfile, peer)
            if ended_cleanly:  # the sender said close_notify: answer it
                try:
                    conn.settimeout(0)  # one small record: never wait on a peer that is already leaving
                    conn.unwrap()
                except OSError:
                    pass


class _TLSServer(socketserver.ThreadingTCPServer):
    """Reserve a slot before starting a worker, including time spent in the handshake."""

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(MAX_TLS_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.listener.count("tls_busy")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def _server_class(base, bind):
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    return type(base.__name__, (base,), {"address_family": family, "allow_reuse_address": True,
                                         "daemon_threads": True})


class SyslogListener:
    def __init__(self, db_path, bind="127.0.0.1", port=5514, flush_interval=2.0,
                 max_batch=20000, allow="", udp=True, tcp=True,
                 tls_port=6514, tls_cert=None, tls_key=None, tls_client_ca=None):
        self.db_path, self.bind, self.port = db_path, bind, port
        self.flush_interval, self.max_batch = flush_interval, max_batch
        self.error = self.guidance = None
        try:
            self.allow = parse_allow(allow)
        except ValueError as exc:
            self.allow = []
            self._fail(f"invalid SIEM_SYSLOG_ALLOW entry: {exc}",  # fail closed: do not listen
                       "Fix SIEM_SYSLOG_ALLOW (comma-separated IPs or CIDR networks), then restart.")
        self.want_udp, self.want_tcp = udp, tcp
        self.tls_cert, self.tls_key, self.tls_client_ca = tls_cert, tls_key, tls_client_ca
        self._tls_port = tls_port
        self.tls_context = None
        self.udp_server = self.tcp_server = self.tls_server = None
        self.udp_port = self.tcp_port = self.tls_port = None
        self.stopping = threading.Event()
        self._queue = deque()
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._threads = []
        self.flush_error = None
        self.last_drop_at = None
        self.stats = {"frames_received": 0, "events_ingested": 0, "rejected": 0, "dropped": 0,
                      "denied": 0, "tls_busy": 0, "tls_failed": 0, "lost_on_failure": 0, "batches": 0,
                      "last_frame_at": None, "last_flush_at": None, "last_tls_failure": None}

    # --- lifecycle -----------------------------------------------------------------

    def start(self):
        """Bind and start threads. Returns False (and reports failing health) instead of raising."""
        health.register_check("syslog", self.health_check)
        if self.error or not self._load_tls():
            self._record(self.error, self.guidance)
            return False
        port = self.port
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
            if self.tls_context is not None:
                port = self._tls_port
                self.tls_server = _server_class(_TLSServer, self.bind)(
                    (self.bind, port), _TLSHandler)
                self.tls_server.listener = self
                self.tls_port = self.tls_server.server_address[1]
        except OSError as exc:
            self._fail(f"could not bind {self.bind}:{port}: {describe_exception(exc)}",
                       "Choose a free SIEM_SYSLOG_PORT and SIEM_SYSLOG_TLS_PORT (ports below 1024 need root), "
                       "then restart.")
            self._record(self.error, self.guidance)
            self._close_servers()  # all or nothing: a transport that did bind does not stay up alone
            return False
        for name, target in (("syslog-udp", self.udp_server and self.udp_server.serve_forever),
                             ("syslog-tcp", self.tcp_server and self.tcp_server.serve_forever),
                             ("syslog-tls", self.tls_server and self.tls_server.serve_forever),
                             ("syslog-flush", self._flush_loop)):
            if target:
                thread = threading.Thread(target=target, name=name, daemon=True)
                thread.start()
                self._threads.append(thread)
        open_to_any = [name for name, on in (("udp", self.udp_server), ("tcp", self.tcp_server),
                                             ("tls without client certificates",
                                              self.tls_server and not self.tls_client_ca)) if on]
        if open_to_any and not _is_loopback(self.bind) and not self.allow:
            log.warning("Syslog listener bound to %s with no SIEM_SYSLOG_ALLOW list and no sender authentication "
                        "(%s): any host that can reach it can inject events. Restrict it with a firewall, "
                        "SIEM_SYSLOG_ALLOW, or TLS client certificates.", self.bind, ", ".join(open_to_any))
        log.info("Syslog listener on %s (%s)", self.bind, self._transports())
        return True

    def stop(self):
        self.stopping.set()
        for server in (self.udp_server, self.tcp_server, self.tls_server):
            if server is not None:
                server.shutdown()
        self._close_servers()
        for thread in self._threads:
            thread.join(timeout=5)
        self.flush()
        health.unregister_check("syslog", self.health_check)

    def _close_servers(self):
        # The references go too: shutdown() on a server whose loop never started would block stop() forever.
        for server in (self.udp_server, self.tcp_server, self.tls_server):
            if server is not None:
                server.server_close()
        self.udp_server = self.tcp_server = self.tls_server = None
        self.udp_port = self.tcp_port = self.tls_port = None

    def _fail(self, error, guidance):
        self.error, self.guidance = error, guidance
        return False

    def _load_tls(self):
        """Build the TLS context when TLS is configured. False (with self.error set) when the settings
        cannot be honoured: a broken TLS setup stops the listener, it never falls back to plaintext."""
        if not (self.tls_cert or self.tls_key or self.tls_client_ca):
            if self.want_udp or self.want_tcp:
                return True
            return self._fail("plaintext syslog is turned off and no TLS certificate is set, so there is "
                              "nothing to listen on",
                              "Set SIEM_SYSLOG_TLS_CERT and SIEM_SYSLOG_TLS_KEY, or remove "
                              "SIEM_SYSLOG_PLAINTEXT=0, then restart.")
        guidance = ("Point SIEM_SYSLOG_TLS_CERT and SIEM_SYSLOG_TLS_KEY at a PEM certificate and its key (no "
                    "passphrase), and SIEM_SYSLOG_TLS_CLIENT_CA, if set, at the PEM CA that signs sender "
                    "certificates. The Watchpost user must be able to read all of them. Then restart.")
        if not (self.tls_cert and self.tls_key):
            return self._fail("syslog TLS needs both SIEM_SYSLOG_TLS_CERT and SIEM_SYSLOG_TLS_KEY", guidance)
        try:
            self.tls_context = tls_context(self.tls_cert, self.tls_key, self.tls_client_ca)
        except ValueError as exc:
            return self._fail(str(exc), guidance)
        return True

    def _transports(self):
        parts = [f"{name} {port}" for name, port in (("udp", self.udp_port), ("tcp", self.tcp_port))
                 if port is not None]
        if self.tls_port is not None:
            parts.append(f"tls {self.tls_port}" + (", client certificates required" if self.tls_client_ca else ""))
        return ", ".join(parts)

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

    def tls_failed(self, peer, exc):
        """A TLS handshake did not complete. Nothing was read from that peer."""
        with self._lock:
            self.stats["tls_failed"] += 1
            self.stats["last_tls_failure"] = f"{now_iso()} {peer}: {describe_exception(exc)}"

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
                       "tls_port": self.tls_port,
                       "tls_client_certificates": bool(self.tls_port is not None and self.tls_client_ca),
                       "allow": [str(n) for n in self.allow], "queued": len(self._queue), **self.stats}
        if self.error:
            return ("failing", f"syslog listener is not running: {self.error}", self.guidance, details)
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
        return ("ok", f"listening on {self.bind} ({self._transports()})", None, details)


def start_if_enabled(app):
    """Called from main.py. Returns the running listener, or None when SIEM_SYSLOG is not 1."""
    config = app.config
    if not config.syslog_enabled:
        return None
    tls = bool(config.syslog_tls_cert or config.syslog_tls_key or config.syslog_tls_client_ca)
    # TLS replaces the plaintext listeners unless SIEM_SYSLOG_PLAINTEXT=1 asks to keep them next to it.
    plaintext = not tls if config.syslog_plaintext is None else config.syslog_plaintext
    listener = SyslogListener(config.db_path, config.syslog_bind, config.syslog_port,
                              max_batch=config.max_batch_events, allow=config.syslog_allow,
                              udp=plaintext, tcp=plaintext, tls_port=config.syslog_tls_port,
                              tls_cert=config.syslog_tls_cert, tls_key=config.syslog_tls_key,
                              tls_client_ca=config.syslog_tls_client_ca)
    listener.start()
    return listener
