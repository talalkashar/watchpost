#!/usr/bin/env python3
"""Watchpost Windows Event Forwarding collector: Windows hosts push their event logs here, with no agent.

Standard library only (Python 3.10+). Windows has a built-in forwarder (Windows Event Forwarding, WEF).
One Group Policy setting points a host at a collector; the host then asks the collector which events it
wants and pushes them over HTTPS, authenticating with the computer's certificate. Nothing is installed
on the Windows host. This script is that collector: it answers the hosts, turns each event into a JSON
record and posts it to Watchpost's `POST /api/ingest`.

    export WATCHPOST_TOKEN=wp_...          # an ingest-only token created by an admin
    python3 wef_collector.py --url https://siem.example.internal \\
        --hostname wef.example.internal --cert wef.crt --key wef.key --client-ca wef-ca.crt \\
        --state /var/lib/watchpost-wef/state.json

At startup it prints the line to paste into the "Configure target Subscription Manager" policy.

EXPERIMENTAL. This follows Microsoft's published protocol ([MS-WSMV], "source-initiated
subscriptions") and what Windows is documented to send. It is tested against a simulated sender in
tests/test_wef_collector.py. It has not been run against a real Windows host. Expect to correct it.

How it works:
- Every host must present a certificate signed by `--client-ca`. The certificate's name (common name,
  or its first DNS name) is the sender. `--allow-sender` narrows that to named hosts.
- A host first asks for its subscriptions (Enumerate). The answer is one subscription: the event query,
  where to deliver, and the bookmark of the last batch this collector stored for that host.
- The host then delivers batches (Events) and heartbeats. A batch is acknowledged only after Watchpost
  has accepted it, and the bookmark is saved then. If Watchpost cannot be reached the answer is 503
  and the host sends the batch again.
- Each record carries `wef_sender`, the authenticated certificate name, next to the `Computer` name the
  event itself claims. They should agree; a host can only lie about the second.

Limits: one subscription for all hosts. HTTPS with certificates only: no Kerberos, so no plain-HTTP
domain mode. The ingest token is read from the environment or a file, never from the command line, and
is never logged. Event contents are never logged.
"""

import argparse
import base64
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.sax.saxutils import escape

DEFAULT_STATE = "watchpost-wef-state.json"
DEFAULT_PORT = 5986                    # the WS-Management HTTPS port Windows expects
SKIP_STATUSES = {400, 413, 415, 422}   # Watchpost refused the batch itself; resending cannot help
MAX_BODY = 4 * 1024 * 1024             # one request as sent; envelopes are capped at MAX_ENVELOPE characters
MAX_MESSAGE = 8 * 1024 * 1024          # one request after decompression
MAX_ENVELOPE = 512000                  # what Windows' own collector asks for
MAX_CONNECTIONS = 256
MAX_HOSTS = 10000                      # bookmarks kept; a host names itself, so the list needs a ceiling
HANDSHAKE_TIMEOUT = 10
IDLE_TIMEOUT = 300
MAX_DATA_FIELDS, MAX_VALUE, MAX_BOOKMARK = 64, 512, 16384

SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
EVENTING = "http://schemas.xmlsoap.org/ws/2004/08/eventing"
ENUMERATION = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
MS_WSMAN = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
MACHINE_ID = "http://schemas.microsoft.com/wbem/wsman/1/machineid"
ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
EARLIEST = "http://schemas.dmtf.org/wbem/wsman/1/wsman/bookmark/earliest"
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
ACTION_SUBSCRIBE = "http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe"
ACTION_SUBSCRIPTION_END = "http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd"
ACTION_EVENTS = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Events"
ACTION_HEARTBEAT = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat"
ACTION_ACK = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack"
ACTION_END = "http://schemas.microsoft.com/wbem/wsman/1/wsman/End"
_NAMESPACES = (f'xmlns:s="{SOAP}" xmlns:a="{ADDRESSING}" xmlns:e="{EVENTING}" xmlns:n="{ENUMERATION}" '
               f'xmlns:w="{WSMAN}" xmlns:p="{MS_WSMAN}"')

# The Security events Watchpost has an event type for (normalize.WINDOWS_EVENT_IDS).
DEFAULT_EVENT_IDS = (4624, 4625, 4648, 4663, 4672, 4688, 4720, 4740)
# Field names Watchpost reads from a record (normalize.FIELD_ALIASES). Event data under one of these names
# is renamed, so a provider's own "level" or "time" field cannot make Watchpost refuse the event.
RESERVED_FIELDS = frozenset("""ts timestamp @timestamp time TimeCreated event_time source log_source Channel host
    hostname Computer device event_type type action category outcome result status severity level user username
    user_name TargetUserName account src_ip source_ip client_ip ip IpAddress remote_addr dest_ip destination_ip
    server_ip dst_ip dest_port destination_port dst_port dport bytes bytes_out bytes_sent sent_bytes out_bytes
    message msg description EventID event_id raw synthetic""".split())
WINDOWS_FIELDS = frozenset({"TargetUserName", "IpAddress"})   # event data Watchpost is meant to read

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]{0,252}$")
_SOURCE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
_FIELD = re.compile(r"[^A-Za-z0-9_.@-]")
# Characters XML 1.0 does not allow: control characters other than tab and line ends, lone surrogates, FFFE, FFFF.
_NOT_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
_FRACTION = re.compile(r"(\.\d{6})\d+")
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def log(message):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} wef: {message}", file=sys.stderr, flush=True)


class FatalError(Exception):
    pass


class Rejected(Exception):
    """A request that is answered with an HTTP error."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status


# --- SLDC (ECMA-321), the compression Windows may apply to a delivery ----------------

class SldcError(ValueError):
    pass


_MATCH_CLASSES = ((1, 2), (2, 4), (3, 8), (4, 16))   # after 0, 10, 110, 1110: (bits that follow, shortest match)


def sldc_decompress(data, limit=MAX_MESSAGE):
    """The data of a compressed request: one SLDC record, then its uncompressed length in four bytes
    ([MS-WSMV] 2.2.9.2). The length is checked."""
    out = _sldc_record(data, limit)
    if len(data) < 4 or int.from_bytes(data[-4:], "little") != len(out):
        raise SldcError("the decompressed data does not have the length the sender stated")
    return out


def _sldc_record(data, limit):
    bits, left = int.from_bytes(data, "big"), len(data) * 8
    out, history, where, scheme = bytearray(), bytearray(1024), 0, 0

    def take(count):
        nonlocal left
        if count > left:
            raise SldcError("the compressed data ends in the middle of a symbol")
        left -= count
        return (bits >> left) & ((1 << count) - 1)

    def emit(byte):
        nonlocal where
        if len(out) >= limit:
            raise SldcError("the data is larger than allowed once decompressed")
        out.append(byte)
        history[where] = byte
        where = (where + 1) & 1023

    def control(code):
        """True at the end of the record."""
        nonlocal scheme, where
        if code in (1, 2):         # Scheme 1, Scheme 2
            scheme = code
        elif code in (5, 6):       # Reset 1, Reset 2: the history starts over
            scheme, where = code - 4, 0
        elif code != 0:            # 0 is Flush. End Of Record, File Mark, End Marker and the reserved codes end it.
            return True
        return False

    while True:
        if scheme == 1:
            if not take(1):
                emit(take(8))      # a literal byte
                continue
            for extra, shortest in _MATCH_CLASSES:
                if not take(1):
                    count = shortest + take(extra)
                    break
            else:
                high = take(4)
                if high == 15:     # nine ones in a row: a control symbol
                    if control(take(4)):
                        return bytes(out)
                    continue
                count = 32 + (high << 4 | take(4))
            start = take(10)       # a copy of `count` bytes from this place in the history
            for offset in range(count):
                emit(history[(start + offset) & 1023])
        elif scheme == 2:
            byte = take(8)         # bytes as they are; FF is followed by a zero bit
            if byte != 0xFF or not take(1):
                emit(byte)
            elif control(take(4)):
                return bytes(out)
        elif take(9) != 0x1FF or control(take(4)):
            raise SldcError("the compressed data does not start with a reset")


# --- XML -----------------------------------------------------------------------------

def parse_xml(text):
    """Parse one XML document. A DOCTYPE is refused: it is the only place entities can be declared."""
    text, pos = _NOT_XML.sub("�", text), 0
    while True:
        while pos < len(text) and text[pos] in " \t\r\n﻿":
            pos += 1
        if text.startswith("<?", pos):
            end, skip = text.find("?>", pos), 2
        elif text.startswith("<!--", pos):
            end, skip = text.find("-->", pos), 3
        elif text.startswith("<!", pos):
            raise Rejected(400, "a document type declaration is not accepted")
        else:
            break
        if end < 0:
            raise Rejected(400, "malformed XML")
        pos = end + skip
    try:
        return ET.fromstring(text[pos:])
    except ET.ParseError as exc:
        raise Rejected(400, f"malformed XML ({exc})") from None


def decode_body(raw, content_type=""):
    """The text of a request body and its encoding. Windows sends UTF-16 with a byte order mark."""
    for mark, encoding in ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"), (b"\xef\xbb\xbf", "utf-8")):
        if raw.startswith(mark):
            return raw[len(mark):].decode(encoding, "replace"), encoding
    encoding = "utf-16-le" if "utf-16" in content_type.lower() else "utf-8"
    return raw.decode(encoding, "replace"), encoding


def encode_body(text, encoding):
    """An answer in the encoding of its request, as (bytes, Content-Type)."""
    if encoding == "utf-8":
        return text.encode(), "application/soap+xml;charset=UTF-8"
    return (b"\xff\xfe" if encoding == "utf-16-le" else b"\xfe\xff") + text.encode(encoding), "application/soap+xml;charset=UTF-16"


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _text(parent, namespace, name):
    found = parent.find(f"{{{namespace}}}{name}") if parent is not None else None
    return "".join(found.itertext()).strip() if found is not None else ""


class Message:
    """What this collector reads from one SOAP request."""

    def __init__(self, text):
        root = parse_xml(text)
        header = root.find(f"{{{SOAP}}}Header")
        if root.tag != f"{{{SOAP}}}Envelope" or header is None:
            raise Rejected(400, "not a SOAP envelope")
        self.action = _text(header, ADDRESSING, "Action")
        self.message_id = _text(header, ADDRESSING, "MessageID")
        self.reply_to = _text(header.find(f"{{{ADDRESSING}}}ReplyTo"), ADDRESSING, "Address") or ANONYMOUS
        machine = _text(header, MACHINE_ID, "MachineID").lower()
        self.machine_id = machine if _NAME.match(machine) else ""
        if not self.action or not self.message_id:
            raise Rejected(400, "the envelope has no Action or no MessageID")
        self.ack_requested = header.find(f"{{{WSMAN}}}AckRequested") is not None
        self.bookmark = None
        marks = header.find(f"{{{WSMAN}}}Bookmark")
        if marks is not None and len(marks) and marks[0].tag == "BookmarkList":
            marks[0].tail = None
            bookmark = ET.tostring(marks[0], encoding="unicode")
            self.bookmark = bookmark if len(bookmark) <= MAX_BOOKMARK else None
        events = root.find(f"{{{SOAP}}}Body/{{{WSMAN}}}Events")
        self.events = list(events) if events is not None else []


def reply(action, request, body=""):
    """The envelope that answers `request`. RelatesTo repeats its MessageID exactly, case included.

    No OperationID and no SequenceId: [MS-WSMV] 3.1.4.1.39 has a server that does not keep answers for
    retransmission ("robust connections") leave both out, and this one keeps none.
    """
    return (f'<s:Envelope xml:lang="en-US" {_NAMESPACES}><s:Header><a:Action>{action}</a:Action>'
            f'<a:MessageID>uuid:{new_id()}</a:MessageID><a:To>{escape(request.reply_to)}</a:To>'
            f'<a:RelatesTo>{escape(request.message_id)}</a:RelatesTo>'
            f'</s:Header><s:Body>{body}</s:Body></s:Envelope>')


def new_id():
    return str(uuid.uuid4()).upper()


# --- events --------------------------------------------------------------------------

def event_query(event_ids=DEFAULT_EVENT_IDS, channels=()):
    """An event query for whole channels, or for the given Security event IDs."""
    if channels:
        selects = "".join(f'<Select Path="{escape(c, {chr(34): "&quot;"})}">*</Select>' for c in channels)
        path = escape(channels[0], {'"': "&quot;"})
    else:
        wanted = " or ".join(f"EventID={int(event_id)}" for event_id in event_ids)
        selects, path = f'<Select Path="Security">*[System[({wanted})]]</Select>', "Security"
    return f'<QueryList><Query Id="0" Path="{path}">{selects}</Query></QueryList>'


def read_query(text):
    """A query from a file, checked and written back out as one line."""
    try:
        root = parse_xml(text)
    except Rejected as exc:
        raise FatalError(f"the event query is not usable: {exc}") from None
    if root.tag != "QueryList" or not len(root):
        raise FatalError("the event query must be a <QueryList> with at least one <Query>")
    for element in root.iter():
        element.tail = None
        if element.text and not element.text.strip():
            element.text = None
    return ET.tostring(root, encoding="unicode")


def _field_name(name):
    name = _FIELD.sub("_", name)[:64] or "Data"
    return f"win_{name}" if name in RESERVED_FIELDS and name not in WINDOWS_FIELDS else name


def event_record(event, sender, source):
    """One Windows event (the <Event> element) as a flat record for /api/ingest, or None to leave it out."""
    parts = {_local(child.tag): child for child in event}
    system = {_local(child.tag): child for child in parts.get("System", ())}
    if _local(event.tag) != "Event" or "EventID" not in system:
        return None
    event_id = (system["EventID"].text or "").strip()
    provider = system["Provider"].get("Name", "") if "Provider" in system else ""
    if provider == "Microsoft-Windows-EventForwarder" and event_id == "111":
        return None   # Windows' own marker that a subscription started; it describes no log entry
    record = {}
    # EventData holds <Data Name="...">; UserData holds one provider-defined element whose children are the fields.
    named = [(item.get("Name") or f"Data{index}", item) for index, item in enumerate(parts.get("EventData", ()), 1)]
    if "UserData" in parts and len(parts["UserData"]):
        named += [(_local(item.tag), item) for item in parts["UserData"][0]]
    for name, item in named[:MAX_DATA_FIELDS]:
        record[_field_name(name)] = "".join(item.itertext())[:MAX_VALUE]
    address = record.pop("IpAddress", None)
    if address:
        try:
            record["IpAddress"] = str(ipaddress.ip_address(address.strip()))
        except ValueError:   # "-", "LOCAL", a host name: Watchpost would refuse the whole event
            record["win_IpAddress"] = address

    def value(name):
        return (system[name].text or "").strip()[:MAX_VALUE] if name in system else ""

    when = system["TimeCreated"].get("SystemTime", "") if "TimeCreated" in system else ""
    rendered = parts.get("RenderingInfo")
    message = _text(rendered, event.tag[:-len("Event")].strip("{}"), "Message") if rendered is not None else ""
    record.update({
        "source": source, "TimeCreated": _FRACTION.sub(r"\1", when), "Computer": value("Computer"),
        "EventID": int(event_id) if event_id.isdigit() else event_id[:16], "EventChannel": value("Channel"),
        "Provider": provider[:MAX_VALUE], "EventRecordID": value("EventRecordID"), "Level": value("Level"),
        "wef_sender": sender,
        "message": (message.splitlines() or [""])[0].strip()[:300] or f"Windows event {event_id[:16]} ({provider[:100]})",
    })
    return record


def events_of(message, sender, source):
    """Records for the events of one delivery, and how many could not be read."""
    records, unreadable = [], 0
    for wrapper in message.events:
        try:
            # Windows sends each event as text inside the wrapper (CDATA). Accept it as a child element too.
            event = wrapper[0] if len(wrapper) else parse_xml(wrapper.text or "")
            record = event_record(event, sender, source)
        except Rejected:
            record, unreadable = None, unreadable + 1
        if record:
            records.append(record)
    return records, unreadable


# --- certificates --------------------------------------------------------------------

def thumbprint(der):
    """A thumbprint as Windows defines it: the SHA-1 of the DER encoding, in hex. Windows names a CA by this
    value in the policy and in the subscription. It identifies a public document; it protects nothing."""
    return hashlib.sha1(der, usedforsecurity=False).hexdigest()


def read_authorities(path):
    """The CA certificates in a PEM file as [(subject, thumbprint)]; the subject is None if it cannot be read."""
    try:
        blocks = _PEM.findall(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise FatalError(f"cannot read --client-ca {path}: {type(exc).__name__}") from None
    if not blocks:
        raise FatalError(f"--client-ca {path} holds no PEM certificate")
    found = []
    for block in blocks:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.load_verify_locations(cadata=block)
            der = base64.b64decode("".join(block.splitlines()[1:-1]), validate=True)
        except (ssl.SSLError, ValueError) as exc:
            raise FatalError(f"--client-ca {path} holds a certificate that cannot be read: {exc}") from None
        listed = context.get_ca_certs()
        found.append((listed[0].get("subject") if listed else None, thumbprint(der)))
    return found


def tls_context(cert, key, client_ca):
    """TLS 1.2 or newer, and no connection without a certificate signed by client_ca."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    for what, load in (("certificate and key", lambda: context.load_cert_chain(cert, key, password=_no_passphrase)),
                       ("client CA", lambda: context.load_verify_locations(client_ca))):
        try:
            load()
        except (OSError, ValueError) as exc:
            raise FatalError(f"cannot load the TLS {what}: {exc}") from None
    return context


def _no_passphrase():
    raise ValueError("the key is passphrase-protected; this collector needs a key without a passphrase")


def sender_name(certificate):
    """The name a verified client certificate gives its host: the common name, else the first DNS name."""
    names = [value for rdn in certificate.get("subject", ()) for key, value in rdn if key == "commonName"]
    names += [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"]
    name = names[0].lower() if names else ""
    return name if _NAME.match(name) else None


# --- the collector -------------------------------------------------------------------

class Collector:
    def __init__(self, url, token, hostname, authorities, state_path, port=DEFAULT_PORT, query=None,
                 source="wef", allow=(), read_existing=False, compression=False, heartbeat=900, max_time=30,
                 cafile=None, timeout=30):
        self.url, self.token, self.source = url.rstrip("/"), token, source
        self.authorities, self.allow = list(authorities), [pattern.lower() for pattern in allow]
        self.query = query or event_query()
        self.read_existing, self.compression = read_existing, compression
        self.heartbeat, self.max_time, self.timeout = int(heartbeat), int(max_time), timeout
        # The same settings always give the same ID, so a restart does not look like a new subscription.
        settings = json.dumps([self.query, read_existing, compression, self.heartbeat, self.max_time])
        self.identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, f"watchpost-wef:{settings}")).upper()
        self.address = f"https://{hostname}:{port}/wsman/subscriptions/{self.identifier}"
        self.context = ssl.create_default_context(cafile=cafile)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.state_path, self.lock = Path(state_path), threading.Lock()
        self.bookmarks = self._load_state()
        self.seen = {}
        self.stats = {"events": 0, "batches": 0, "skipped_batches": 0, "unreadable_events": 0,
                      "failed_deliveries": 0, "refused_requests": 0, "failed_handshakes": 0}

    # --- state ----------------------------------------------------------------------

    def _load_state(self):
        try:
            state = json.loads(self.state_path.read_text())
            marks = state.get("bookmarks") if isinstance(state, dict) else None
            return {k: v for k, v in marks.items() if isinstance(v, str)} if isinstance(marks, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log(f"ignoring unreadable state file {self.state_path}: {type(exc).__name__}")
            return {}

    def _save_state(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
            json.dump({"bookmarks": self.bookmarks}, handle, indent=1, sort_keys=True)
        os.replace(tmp, self.state_path)

    def bookmark(self, key):
        """The stored bookmark of one host, if it is still a well-formed bookmark."""
        with self.lock:
            stored = self.bookmarks.get(key)
        if stored:
            try:
                if parse_xml(stored).tag == "BookmarkList":
                    return stored
            except Rejected:
                pass
        return None

    # --- answering Windows ----------------------------------------------------------

    def allowed(self, sender):
        return not self.allow or any(fnmatch.fnmatchcase(sender, pattern) for pattern in self.allow)

    def issuer_thumbprint(self, certificate):
        """The thumbprint of the CA that signed this client certificate, which the subscription must name."""
        for subject, mark in self.authorities:
            if subject is not None and subject == certificate.get("issuer"):
                return mark
        return self.authorities[0][1]

    def subscription(self, issuer, bookmark):
        """The subscription as Windows expects it: a Subscribe request for the host to run on itself."""
        options = ['<w:Option Name="SubscriptionName">Watchpost</w:Option>']
        if self.compression:
            options.append('<w:Option Name="Compression">SLDC</w:Option>')
        options += ['<w:Option Name="CDATA" xsi:nil="true"/>', '<w:Option Name="ContentFormat">RenderedText</w:Option>',
                    '<w:Option Name="IgnoreChannelError" xsi:nil="true"/>']
        if bookmark is None and self.read_existing:
            options.append('<w:Option Name="ReadExistingEvents" xsi:nil="true"/>')
            bookmark = EARLIEST
        endpoint = (f'<a:Address>{escape(self.address)}</a:Address><a:ReferenceProperties>'
                    f'<e:Identifier>{self.identifier}</e:Identifier></a:ReferenceProperties>')
        # The namespace of auth: is the one Windows' own collector was captured sending and OpenWEC uses.
        # [MS-WSMV] 2.2.4.1 puts the same elements in the w: namespace instead; if a host ignores this
        # policy, that is the first thing to try.
        policy = ('<c:Policy xmlns:c="http://schemas.xmlsoap.org/ws/2002/12/policy" '
                  'xmlns:auth="http://schemas.microsoft.com/wbem/wsman/1/authentication"><c:ExactlyOne><c:All>'
                  '<auth:Authentication Profile="http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual">'
                  f'<auth:ClientCertificate><auth:Thumbprint Role="issuer">{issuer}</auth:Thumbprint>'
                  '</auth:ClientCertificate></auth:Authentication></c:All></c:ExactlyOne></c:Policy>')
        return (
            '<m:Subscription xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/subscription">'
            f'<m:Version>uuid:{self.identifier}</m:Version><s:Envelope {_NAMESPACES}><s:Header>'
            f'<a:To>{ANONYMOUS}</a:To>'
            '<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</w:ResourceURI>'
            f'<a:ReplyTo><a:Address s:mustUnderstand="true">{ANONYMOUS}</a:Address></a:ReplyTo>'
            f'<a:Action s:mustUnderstand="true">{ACTION_SUBSCRIBE}</a:Action>'
            f'<w:MaxEnvelopeSize s:mustUnderstand="true">{MAX_ENVELOPE}</w:MaxEnvelopeSize>'
            f'<a:MessageID>uuid:{new_id()}</a:MessageID>'
            f'<p:OperationID s:mustUnderstand="false">uuid:{new_id()}</p:OperationID>'
            '<p:SequenceId s:mustUnderstand="false">1</p:SequenceId>'
            f'<w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{"".join(options)}</w:OptionSet>'
            f'</s:Header><s:Body><e:Subscribe><e:EndTo>{endpoint}</e:EndTo>'
            f'<e:Delivery Mode="{ACTION_EVENTS}"><w:Heartbeats>PT{self.heartbeat}.000S</w:Heartbeats>'
            f'<e:NotifyTo>{endpoint}{policy}</e:NotifyTo><w:ConnectionRetry Total="5">PT60.0S</w:ConnectionRetry>'
            f'<w:MaxTime>PT{self.max_time}.000S</w:MaxTime>'
            f'<w:MaxEnvelopeSize Policy="Notify">{MAX_ENVELOPE}</w:MaxEnvelopeSize>'
            '<w:ContentEncoding>UTF-16</w:ContentEncoding></e:Delivery>'
            f'<w:Filter Dialect="http://schemas.microsoft.com/win/2004/08/events/eventquery">{self.query}</w:Filter>'
            + (f'<w:Bookmark>{bookmark}</w:Bookmark>' if bookmark else '')
            + '<w:SendBookmarks/></e:Subscribe></s:Body></s:Envelope></m:Subscription>')

    def respond(self, sender, issuer, path, raw, content_type="", content_encoding=""):
        """Answer one POST from an authenticated host: (HTTP status, body, Content-Type). The body may be empty."""
        if not path.startswith("/wsman"):
            raise Rejected(404, f"unknown path from {sender}")
        if sender is None or not self.allowed(sender):
            raise Rejected(403, f"sender {sender or 'with no usable certificate name'} is not allowed")
        if not raw:
            return 200, b"", None
        if content_encoding.strip().lower() == "sldc":
            try:
                raw = sldc_decompress(raw)
            except SldcError:
                pass   # labelled compressed but is not: read it as it is, and let the XML check decide
        elif content_encoding.strip():
            raise Rejected(415, f"unsupported Content-Encoding from {sender}")
        text, encoding = decode_body(raw, content_type)
        message = Message(text)
        key = f"{sender}|{message.machine_id}"
        self._note(key, sender)
        status, envelope = self._dispatch(key, sender, issuer, message)
        return (status, *encode_body(envelope, encoding)) if envelope else (status, b"", None)

    def _dispatch(self, key, sender, issuer, message):
        if message.action == ACTION_ENUMERATE:
            items = self.subscription(issuer, self.bookmark(key))
            return 200, reply(ACTION_ENUMERATE_RESPONSE, message, '<n:EnumerateResponse><n:EnumerationContext/>'
                              f'<w:Items>{items}</w:Items><w:EndOfSequence/></n:EnumerateResponse>')
        if message.action == ACTION_EVENTS:
            self.deliver(key, sender, message)
            return 200, reply(ACTION_ACK, message)
        if message.action == ACTION_HEARTBEAT:
            return 200, reply(ACTION_ACK, message)
        if message.action == ACTION_END:
            return 204, None
        if message.action == ACTION_SUBSCRIPTION_END:
            log(f"{sender} ended its subscription")
            return 200, reply(ACTION_ACK, message) if message.ack_requested else None
        raise Rejected(400, f"unsupported action from {sender}")

    def _note(self, key, sender):
        with self.lock:
            first = key not in self.seen and len(self.seen) < MAX_HOSTS
            if first or key in self.seen:
                self.seen[key] = time.time()
        if first:
            log(f"first request from {sender}")

    def deliver(self, key, sender, message):
        """Store one batch in Watchpost, then remember its bookmark. Raises Rejected(503) to have it resent."""
        records, unreadable = events_of(message, sender, self.source)
        if records:
            try:
                status = self.post(records)
            except (OSError, ValueError) as exc:   # URLError, timeouts, resets
                status = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            if status in SKIP_STATUSES:
                self.count(skipped_batches=1)
                log(f"Watchpost refused a batch of {len(records)} event(s) from {sender} ({status}); skipping it")
            elif status not in (201, 207):
                self.count(failed_deliveries=1)
                hint = " (check the ingest token; it may be revoked)" if status in (401, 403) else ""
                raise Rejected(503, f"could not store {len(records)} event(s) from {sender}: {status}{hint}")
            else:
                self.count(events=len(records), batches=1)
                log(f"stored {len(records)} event(s) from {sender}")
        if unreadable:
            self.count(unreadable_events=unreadable)
            log(f"{unreadable} event(s) from {sender} could not be read and were left out")
        if message.bookmark:
            with self.lock:
                if key in self.bookmarks or len(self.bookmarks) < MAX_HOSTS:
                    self.bookmarks[key] = message.bookmark
                    self._save_state()

    def count(self, **amounts):
        with self.lock:
            for name, amount in amounts.items():
                self.stats[name] += amount

    # --- Watchpost ------------------------------------------------------------------

    def post(self, records):
        """Send one batch to Watchpost. Returns the HTTP status; raises OSError on network failure."""
        body = json.dumps({"source": self.source, "events": records}).encode()
        request = urllib.request.Request(f"{self.url}/api/ingest", data=body, method="POST", headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        context = self.context if self.url.startswith("https:") else None
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as resp:
                resp.read()
                return resp.status
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code


# --- HTTPS server --------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version, sys_version = "Watchpost-WEF", ""
    timeout = IDLE_TIMEOUT

    def setup(self):
        """Finish the TLS handshake here, in the connection's own thread, so a slow client blocks nobody."""
        collector = self.server.collector
        self.sender = self.issuer = None
        self.verified = False
        try:
            self.request.settimeout(HANDSHAKE_TIMEOUT)
            self.request.do_handshake()
            certificate = self.request.getpeercert()
            self.sender, self.issuer = sender_name(certificate), collector.issuer_thumbprint(certificate)
            self.verified = True
        except (OSError, ValueError) as exc:
            collector.count(failed_handshakes=1)
            reason = getattr(exc, "reason", None) or type(exc).__name__
            log(f"TLS handshake with {self.client_address[0]} failed: {reason}")
        super().setup()

    def handle(self):
        if self.verified:
            super().handle()

    def log_message(self, format, *args):
        pass   # requests are counted, not logged; refusals are logged where they happen

    def do_POST(self):
        collector = self.server.collector
        try:
            answer = collector.respond(self.sender, self.issuer, self.path, self._body(),
                                       self.headers.get("Content-Type", ""), self.headers.get("Content-Encoding", ""))
        except Rejected as exc:
            collector.count(refused_requests=1)
            log(f"{exc.status}: {exc}")
            return self._answer(exc.status, close=True)
        self._answer(*answer)

    def _body(self):
        length = self.headers.get("Content-Length", "")
        if self.headers.get("Transfer-Encoding") or not length.isdigit():
            raise Rejected(411, f"request from {self.sender} without a Content-Length")
        if int(length) > MAX_BODY:
            raise Rejected(413, f"request from {self.sender} larger than {MAX_BODY} bytes")
        body = self.rfile.read(int(length))
        if len(body) != int(length):
            raise Rejected(400, f"request from {self.sender} ended early")
        return body

    def _answer(self, status, body=b"", content_type=None, close=False):
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        if status != 204:
            self.send_header("Content-Length", str(len(body)))
        if close:   # the request body may be unread, so the connection cannot be reused
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, collector, context):
        self.collector, self.context = collector, context
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, Handler)

    def get_request(self):
        connection, address = self.socket.accept()
        try:
            return self.context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), address
        except OSError:
            connection.close()
            raise

    def process_request(self, request, client_address):
        if self.slots.acquire(blocking=False):
            super().process_request(request, client_address)
        else:
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        log(f"connection from {client_address[0]} ended with {type(sys.exc_info()[1]).__name__}")


def subscription_manager(hostname, port, authorities, refresh=60):
    """The value for the "Configure target Subscription Manager" policy on the Windows hosts."""
    return (f"Server=https://{hostname}:{port}/wsman/SubscriptionManager/WEC,Refresh={refresh},"
            f"IssuerCA={authorities[0][1].upper()}")


# --- command line --------------------------------------------------------------------

def _is_loopback(hostname):
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return hostname == "localhost"


def check_url(url, allow_insecure=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FatalError(f"--url must be an http(s) URL, got {url!r}")
    if parsed.scheme == "http" and not allow_insecure and not _is_loopback(parsed.hostname):
        raise FatalError(f"refusing to send the token over plain HTTP to {parsed.hostname}; use https://")
    return url.rstrip("/")


def read_token(args):
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    else:
        token = os.environ.get(args.token_env, "").strip()
    if not token.startswith("wp_"):
        raise FatalError(f"no ingest token: set ${args.token_env} or pass --token-file (tokens start with wp_)")
    return token


def build(args):
    """The collector and its server from parsed arguments."""
    if not _NAME.match(args.hostname):
        raise FatalError(f"--hostname must be the DNS name the Windows hosts use for this collector, got {args.hostname!r}")
    if not _SOURCE.match(args.source):
        raise FatalError("--source must be 1-64 characters of letters, digits, _ . : -")
    if args.query_file and args.channel:
        raise FatalError("give --query-file or --channel, not both")
    query = None
    if args.query_file:
        try:
            query = read_query(Path(args.query_file).read_text())
        except OSError as exc:
            raise FatalError(f"cannot read --query-file: {type(exc).__name__}") from None
    elif args.channel:
        query = event_query(channels=args.channel)
    authorities = read_authorities(args.client_ca)
    context = tls_context(args.cert, args.key, args.client_ca)
    collector = Collector(
        check_url(args.url, args.allow_insecure_http), read_token(args), args.hostname, authorities, args.state,
        port=args.port, query=query, source=args.source, allow=args.allow_sender, read_existing=args.read_existing,
        compression=args.compression, heartbeat=args.heartbeat, cafile=args.cafile)
    try:
        server = Server((args.bind, args.port), collector, context)
    except OSError as exc:
        raise FatalError(f"cannot listen on {args.bind} port {args.port}: {exc}") from None
    return collector, server


def main(argv=None):
    parser = argparse.ArgumentParser(description="Receive Windows Event Forwarding over HTTPS and send it to Watchpost.")
    parser.add_argument("--url", required=True, help="Watchpost base URL, e.g. https://siem.example.internal")
    parser.add_argument("--hostname", required=True,
                        help="DNS name the Windows hosts reach this collector by; it must be a name in --cert")
    parser.add_argument("--cert", required=True, help="this collector's certificate (PEM)")
    parser.add_argument("--key", required=True, help="the certificate's private key (PEM, no passphrase)")
    parser.add_argument("--client-ca", required=True,
                        help="CA certificate(s) that sign the Windows hosts' certificates (PEM)")
    parser.add_argument("--bind", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")  # nosec B104
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--allow-sender", action="append", default=[], metavar="NAME",
                        help="accept only this certificate name; repeatable, * and ? match (default: any from the CA)")
    parser.add_argument("--channel", action="append", default=[], metavar="CHANNEL",
                        help="forward every event of this channel, e.g. Security; repeatable "
                             "(default: the Security events Watchpost has a type for)")
    parser.add_argument("--query-file", help="forward what this event query (a <QueryList>, as Event Viewer exports) selects")
    parser.add_argument("--read-existing", action="store_true",
                        help="a host seen for the first time also sends the events it already holds")
    parser.add_argument("--compression", action="store_true", help="ask the hosts to compress what they send (SLDC)")
    parser.add_argument("--heartbeat", type=int, default=900, metavar="SECONDS",
                        help="a host with nothing to send says so this often (default 900)")
    parser.add_argument("--state", default=DEFAULT_STATE, help=f"state file (default ./{DEFAULT_STATE})")
    parser.add_argument("--source", default="wef", help="source name for the events (default wef)")
    parser.add_argument("--token-env", default="WATCHPOST_TOKEN", help="environment variable holding the ingest token")
    parser.add_argument("--token-file", help="file holding the ingest token (instead of the environment variable)")
    parser.add_argument("--cafile", help="CA bundle for a self-signed Watchpost HTTPS certificate")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="allow sending the Watchpost token over plain HTTP to a non-loopback host")
    args = parser.parse_args(argv)
    try:
        collector, server = build(args)
    except FatalError as exc:
        log(f"fatal: {exc}")
        return 2
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    log(f"listening on {args.bind} port {args.port}; subscription {collector.identifier}")
    log(f"Subscription Manager policy value: {subscription_manager(args.hostname, args.port, collector.authorities)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
