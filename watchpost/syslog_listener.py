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

from . import engine, health
from .db import connect, iso, now_iso, utcnow
from .diagnostics import describe_exception, log, record_error, redact
from .normalize import MAX_LEN, EventError, clean_text, normalize_authlog_line, normalize_weblog_line

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

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$", re.S)
_RFC3164 = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<rest>.*)$",
    re.S)
_TAG = re.compile(r"^(?P<app>[^\s\[:]{1,48})(?:\[(?P<procid>[^\]\s]{1,32})\])?:\s?(?P<msg>.*)$", re.S)
_FRACTION = re.compile(r"(T\d{2}:\d{2}:\d{2})\.(\d+)")
_PROG_UNSAFE = re.compile(r"[^\w\-/.]")


def _nil(value):
    return None if value in (None, "-") else value


def _fix_fraction(ts):
    # RFC 5424 allows 1-6 fractional digits; Python 3.10's fromisoformat wants exactly 3 or 6.
    return _FRACTION.sub(lambda m: f"{m.group(1)}.{m.group(2)[:6].ljust(6, '0')}", ts) if ts else ts


def parse_frame(frame):
    """Split one syslog message into PRI, header fields, and message text. Never raises."""
    text = frame.strip("\r\n\x00")
    pri = DEFAULT_PRI
    match = _PRI.match(text)
    if match and int(match.group(1)) <= 191:
        pri, text = int(match.group(1)), text[match.end():]
    out = {"pri": pri, "facility": pri >> 3, "level": pri & 7, "format": "raw",
           "ts": None, "host": None, "app": None, "procid": None, "msg": text}

    match = _RFC5424.match(text)
    if match:
        out.update(format="rfc5424", ts=_fix_fraction(_nil(match["ts"])), host=_nil(match["host"]),
                   app=_nil(match["app"]), procid=_nil(match["procid"]),
                   msg=(match["msg"] or "").lstrip("﻿"))
        return out

    match = _RFC3164.match(text)
    if match:
        host, rest = match["host"], match["rest"]
        if host.endswith(":") or "[" in host:   # no HOSTNAME field: this is already the TAG
            host, rest = None, f"{host} {rest}"
        out.update(format="rfc3164", ts=_fix_fraction(match["ts"]), host=host, msg=rest)
        tag = _TAG.match(rest)
        if tag:
            out.update(app=tag["app"], procid=tag["procid"], msg=tag["msg"])
    return out


def frame_to_event(frame, peer_ip=None, now=None):
    """Normalize one frame. Raises EventError (e.g. a bad timestamp) so the caller can record a rejection."""
    now = now or utcnow()
    parsed = parse_frame(frame)
    host = parsed["host"] or peer_ip or "unknown"
    app = _PROG_UNSAFE.sub("_", parsed["app"])[:48] if parsed["app"] else None
    msg = parsed["msg"].replace("\r", " ").replace("\n", " ")
    prog = (app or "syslog") + (f"[{parsed['procid']}]" if parsed["procid"] else "")
    # Rebuild an auth.log-style line so the existing parser (and its timestamp rules) does the work.
    line = f"{parsed['ts'] or iso(now)} {host} {prog}: {msg}"
    event = normalize_authlog_line(line, SOURCE, now=now)
    if event["event_type"] == "other":
        event = _web_event(msg, host, now) or event
    if event["event_type"] == "other":
        event["event_type"] = "syslog"
        event["severity"] = PRI_SEVERITY[parsed["level"]]
        event["message"] = redact(clean_text(f"{app}: {msg}" if app else msg, "message"))
    event["raw"] = redact(frame.strip("\r\n\x00"))[: MAX_LEN["raw"]]
    return event


def _web_event(msg, host, now):
    """An access log line forwarded by nginx/Apache (access_log syslog:...), or None."""
    try:
        event = normalize_weblog_line(msg, SOURCE, now=now)
    except EventError:
        return None
    event["host"] = clean_text(host, "host")  # access log lines carry no host; use the syslog header's
    return event


def read_tcp_frame(rfile, max_bytes=MAX_FRAME_BYTES):
    """Read one RFC 6587 frame: octet-counted ("LEN SP MSG") or newline-terminated. None at EOF."""
    first = rfile.read(1)
    if not first:
        return None
    if first.isdigit():
        digits = first
        while True:
            char = rfile.read(1)
            if not char:
                return None
            if char == b" ":
                break
            if not char.isdigit() or len(digits) >= 6:
                return _read_line(rfile, digits + char, max_bytes)  # not octet counting after all
            digits += char
        length = int(digits)
        data = rfile.read(min(length, max_bytes))
        remaining = length - len(data)
        while remaining > 0:  # discard the truncated tail of an oversized frame
            chunk = rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        return data
    return _read_line(rfile, first, max_bytes)


def _read_line(rfile, prefix, max_bytes):
    line = prefix + rfile.readline(max_bytes)
    if not line.endswith(b"\n") and len(line) > max_bytes:
        while True:  # discard the rest of an oversized line
            more = rfile.readline(65536)
            if not more or more.endswith(b"\n"):
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
                if frame.strip():
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
