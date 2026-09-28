#!/usr/bin/env python3
"""Watchpost file shipper: tail log files and post new lines to Watchpost with an ingest token.

Standard library only (Python 3.10+), so it runs as-is on Debian 12 and Ubuntu 22.04+.

    export WATCHPOST_TOKEN=wp_...          # an ingest-only token created by an admin
    python3 shipper.py --url https://siem.example.internal \\
        --file /var/log/auth.log:authlog --state /var/lib/watchpost-shipper/positions.json

Each --file is PATH[:FORMAT[:SOURCE]]. FORMAT is passed to /api/ingest/upload (default
"auto"); SOURCE defaults to "<hostname>-<file stem>". Only complete lines are sent.
The byte offset of every file is saved in the position file after each accepted batch,
so a restart resumes where it stopped. Rotation (rename + new file) is followed: the
old file is drained before switching to the new one.

Network and 5xx errors retry the same batch with exponential backoff. A batch the
server refuses as invalid (400, 413, 415, 422) is logged and skipped so one bad
line cannot block a file forever. The token is read from an environment variable or
a file, never from the command line, and is never logged.
"""

import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_STATE = "watchpost-shipper-positions.json"
SKIP_STATUSES = {400, 413, 415, 422}   # the batch itself is bad; retrying cannot help
MAX_BACKOFF = 60.0


def log(message):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} shipper: {message}", file=sys.stderr, flush=True)


class FatalError(Exception):
    pass


class TailedFile:
    """Follows one path across rotations and yields complete lines as bytes."""

    def __init__(self, path, fmt, source, state, from_start):
        self.path, self.fmt, self.source = path, fmt, source
        self.handle, self.inode, self.offset = None, None, 0
        self.pending = b""
        saved = state.get(path)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return  # opened later when it appears
        if saved and saved.get("inode") == st.st_ino and saved.get("offset", 0) <= st.st_size:
            self._open(saved["offset"])
        else:
            # New file, or rotated while the shipper was down: start over (or at the end if tailing).
            self._open(0 if (saved or from_start) else st.st_size)

    def _open(self, offset):
        self.handle = open(self.path, "rb")
        self.inode = os.fstat(self.handle.fileno()).st_ino
        self.handle.seek(offset)
        self.offset, self.pending = offset, b""

    def read_lines(self, max_lines, max_bytes):
        """Return up to max_lines complete lines (without committing the offset) and the end offset."""
        if self.handle is None:
            if not os.path.exists(self.path):
                return [], self.offset
            self._open(0)
        lines, size = [], 0
        self.handle.seek(self.offset)
        position = self.offset
        while len(lines) < max_lines and size < max_bytes:
            line = self.handle.readline(max_bytes)
            if not line:
                break
            position += len(line)
            if not line.endswith(b"\n"):
                if len(line) < max_bytes:
                    position -= len(line)
                    break  # partial line: wait for the writer to finish it
                line += b"\n"  # an over-long line is sent in pieces rather than blocking the file
            if line.strip():
                lines.append(line)
                size += len(line)
        if not lines and position == self.offset and self._check_rotation():
            return self.read_lines(max_lines, max_bytes)
        return lines, position

    def _check_rotation(self):
        """At EOF: if the path now names a different or truncated file, switch to it. True if switched."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False
        if st.st_ino != self.inode:
            self.handle.close()
            self._open(0)
            return True
        if st.st_size < self.offset:  # truncated in place (copytruncate)
            self.offset = 0
            return True
        return False

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def commit(self, offset):
        self.offset = offset

    def state(self):
        return {"inode": self.inode, "offset": self.offset} if self.inode is not None else None


class Shipper:
    def __init__(self, url, token, files, state_path, batch_lines=500, batch_bytes=1024 * 1024,
                 year=None, from_start=False, cafile=None, timeout=30, sleep=time.sleep):
        self.url, self.token = url.rstrip("/"), token
        self.state_path = Path(state_path)
        self.batch_lines, self.batch_bytes, self.year = batch_lines, batch_bytes, year
        self.timeout, self.sleep = timeout, sleep
        self.context = ssl.create_default_context(cafile=cafile) if url.startswith("https:") else None
        state = self._load_state()
        self.files = [TailedFile(path, fmt, source, state, from_start) for path, fmt, source in files]
        self.stats = {"batches": 0, "lines": 0, "skipped_batches": 0, "retries": 0}

    def _load_state(self):
        try:
            return json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log(f"ignoring unreadable position file {self.state_path}: {type(exc).__name__}")
            return {}

    def save_state(self):
        state = {f.path: f.state() for f in self.files if f.state()}
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
        os.replace(tmp, self.state_path)

    def post(self, tailed, lines):
        """Send one batch. Returns the HTTP status; raises OSError on network failure."""
        query = {"format": tailed.fmt, "source": tailed.source}
        if self.year:
            query["year"] = str(self.year)
        request = urllib.request.Request(
            f"{self.url}/api/ingest/upload?{urllib.parse.urlencode(query)}", data=b"".join(lines),
            method="POST", headers={"Authorization": f"Bearer {self.token}", "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as resp:
                body = json.loads(resp.read() or b"null")
                status = resp.status
        except urllib.error.HTTPError as exc:
            with exc:
                try:
                    body = json.loads(exc.read() or b"null")
                except ValueError:
                    body = None
            status = exc.code
        if status in (201, 207):
            log(f"{tailed.path}: sent {len(lines)} line(s), accepted {body.get('accepted')}, "
                f"rejected {body.get('rejected')}")
        elif status in SKIP_STATUSES:
            reason = body.get("error") if isinstance(body, dict) and body.get("error") else \
                f"{body.get('rejected') if isinstance(body, dict) else '?'} record(s) rejected"
            log(f"{tailed.path}: server refused a batch of {len(lines)} line(s) ({status}: {reason}); skipping it")
        return status

    def ship_once(self, max_retries=None):
        """Send everything currently available. Returns the number of lines sent or skipped."""
        total = 0
        for tailed in self.files:
            while True:
                lines, end = tailed.read_lines(self.batch_lines, self.batch_bytes)
                if not lines:
                    if end != tailed.offset:  # only blank lines: just advance
                        tailed.commit(end)
                        self.save_state()
                    break
                self._send_with_backoff(tailed, lines, max_retries)
                tailed.commit(end)
                self.save_state()
                total += len(lines)
        return total

    def _send_with_backoff(self, tailed, lines, max_retries):
        delay, attempt = 1.0, 0
        while True:
            try:
                status = self.post(tailed, lines)
            except (OSError, ValueError) as exc:  # URLError, timeouts, resets, bad JSON from a proxy
                status, problem = None, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            else:
                problem = f"HTTP {status}"
            if status in (201, 207):
                self.stats["batches"] += 1
                self.stats["lines"] += len(lines)
                return
            if status in SKIP_STATUSES:
                self.stats["skipped_batches"] += 1
                return
            if status in (401, 403):
                problem += " (check the ingest token; it may be revoked)"
            attempt += 1
            if max_retries is not None and attempt > max_retries:
                raise FatalError(f"{tailed.path}: giving up after {max_retries} retries ({problem})")
            self.stats["retries"] += 1
            wait = min(delay, MAX_BACKOFF) * (0.5 + random.random() / 2)
            log(f"{tailed.path}: {problem}; retrying in {wait:.1f}s")
            self.sleep(wait)
            delay *= 2

    def close(self):
        for tailed in self.files:
            tailed.close()

    def run(self, interval=2.0):
        while True:
            self.ship_once()
            self.sleep(interval)


def parse_file_spec(spec, hostname=None):
    path, _, rest = spec.partition(":")
    fmt, _, source = rest.partition(":")
    hostname = (hostname or socket.gethostname().split(".")[0])[:40]
    source = source or f"{hostname}-{Path(path).stem}"
    safe = "".join(c if c.isalnum() or c in "_.:-" else "-" for c in source)[:64]
    return os.path.abspath(path), fmt or "auto", safe


def check_url(url, allow_insecure):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FatalError(f"--url must be an http(s) URL, got {url!r}")
    if parsed.scheme == "http" and not allow_insecure:
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise FatalError("refusing to send the token over plain HTTP to a non-loopback host; "
                             "use https:// or pass --allow-insecure-http")


def read_token(args):
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    else:
        token = os.environ.get(args.token_env, "").strip()
    if not token.startswith("wp_"):
        raise FatalError(f"no ingest token: set ${args.token_env} or pass --token-file (tokens start with wp_)")
    return token


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tail log files and ship them to Watchpost.")
    parser.add_argument("--url", required=True, help="Watchpost base URL, e.g. https://siem.example.internal")
    parser.add_argument("--file", action="append", required=True, metavar="PATH[:FORMAT[:SOURCE]]",
                        help="file to tail; repeat for several (FORMAT: auto, authlog, json, jsonl, csv, ...)")
    parser.add_argument("--state", default=DEFAULT_STATE, help="position file (default: %(default)s)")
    parser.add_argument("--token-env", default="WATCHPOST_TOKEN", help="env var holding the token")
    parser.add_argument("--token-file", help="file holding the token (mode 0600 recommended)")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    parser.add_argument("--batch-lines", type=int, default=500)
    parser.add_argument("--year", type=int, help="year for BSD syslog lines (default: server decides)")
    parser.add_argument("--from-start", action="store_true",
                        help="ship existing content of files seen for the first time (default: only new lines)")
    parser.add_argument("--once", action="store_true", help="ship what is there now, then exit")
    parser.add_argument("--max-retries", type=int, help="with --once: give up after this many retries")
    parser.add_argument("--cafile", help="CA bundle for a self-signed HTTPS certificate")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="allow plain HTTP to a non-loopback host (the token travels in clear text)")
    args = parser.parse_args(argv)
    try:
        check_url(args.url, args.allow_insecure_http)
        token = read_token(args)
        files = [parse_file_spec(spec) for spec in args.file]
        shipper = Shipper(args.url, token, files, args.state, batch_lines=args.batch_lines, year=args.year,
                          from_start=args.from_start, cafile=args.cafile)
        try:
            if args.once:
                sent = shipper.ship_once(max_retries=args.max_retries)
                log(f"done: {sent} line(s) processed, {shipper.stats['skipped_batches']} batch(es) skipped")
                return 0
            log(f"shipping {len(files)} file(s) to {args.url} every {args.interval}s")
            shipper.run(args.interval)
        finally:
            shipper.close()
    except FatalError as exc:
        log(str(exc))
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
