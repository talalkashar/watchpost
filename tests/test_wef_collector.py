"""The Windows Event Forwarding collector against a simulated Windows sender.

No Windows host takes part in these tests. The sender here speaks the way [MS-WSMV] and published
captures say Windows does: SOAP in UTF-16 with a byte order mark, events as CDATA text with
single-quoted attributes, optionally SLDC-compressed. All event data is synthetic.
"""

import http.client
import importlib.util
import io
import json
import os
import re
import ssl
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from tests import certgen
from tests.helpers import ServerTestCase
from watchpost import normalize

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("wef_collector", ROOT / "scripts" / "wef_collector.py")
wef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wef)

CA_NAME, HOST = "Watchpost test WEF CA", "dc01.corp.example"
NS = {"s": wef.SOAP, "a": wef.ADDRESSING, "e": wef.EVENTING, "n": wef.ENUMERATION, "w": wef.WSMAN,
      "m": "http://schemas.microsoft.com/wbem/wsman/1/subscription",
      "auth": "http://schemas.microsoft.com/wbem/wsman/1/authentication"}


# --- a small SLDC encoder, so the decoder is tested on more than literals -------------

class Bits:
    def __init__(self):
        self.value, self.count = 0, 0

    def put(self, value, count):
        self.value, self.count = self.value << count | value, self.count + count

    def control(self, code):
        self.put(0x1FF, 9)
        self.put(code, 4)

    def bytes(self, pad_to=8):
        pad = -self.count % pad_to
        return (self.value << pad).to_bytes((self.count + pad) // 8, "big")


def _count_field(bits, count):
    for prefix, width, extra, shortest in ((0b0, 1, 1, 2), (0b10, 2, 2, 4), (0b110, 3, 3, 8), (0b1110, 4, 4, 16)):
        if count < shortest * 2:
            bits.put(prefix, width)
            return bits.put(count - shortest, extra)
    bits.put(0b1111, 4)
    bits.put(count - 32, 8)


def sldc_compress(data, scheme=1):
    """`data` as Windows frames it: one record, End Of Record, padding, then the length in four bytes."""
    bits, history, where = Bits(), bytearray(1024), 0
    bits.control(5 if scheme == 1 else 6)
    position = 0
    while position < len(data):
        best, start, filled = 0, 0, min(position, 1024)
        for candidate in range(filled if scheme == 1 else 0):
            count = 0
            while count < 271 and position + count < len(data):
                place = (candidate + count) % 1024   # not past what is stored, and not what this copy has rewritten
                if place >= filled or (place - where) % 1024 < count or history[place] != data[position + count]:
                    break
                count += 1
            if count > best:
                best, start = count, candidate
        if best >= 2:
            bits.put(1, 1)
            _count_field(bits, best)
            bits.put(start, 10)
        else:
            best = 1
            if scheme == 1:
                bits.put(data[position], 9)
            else:
                bits.put(data[position], 8)
                if data[position] == 0xFF:
                    bits.put(0, 1)
        for byte in data[position:position + best]:
            history[where], where = byte, (where + 1) % 1024
        position += best
    bits.control(4)
    return bits.bytes(pad_to=16) + len(data).to_bytes(4, "little")


class SldcTests(unittest.TestCase):
    def test_round_trip_of_text_longer_than_the_history(self):
        text = "".join(f"<Data Name='Field{n % 7}'>value {n * n}</Data>" for n in range(220)).encode("utf-16-le")
        self.assertGreater(len(text), 4096)
        packed = sldc_compress(text)
        self.assertLess(len(packed), len(text) // 2)   # so copies were used, across the 1024-byte wrap too
        self.assertEqual(wef.sldc_decompress(packed), text)

    def test_every_match_length_class(self):
        for length in (2, 3, 4, 7, 8, 15, 16, 31, 32, 33, 270, 271):
            unit = bytes(range(1, length + 1)) if length < 256 else bytes(range(256)) + bytes(range(length - 256))
            data = unit + b"\x00" + unit
            self.assertEqual(wef.sldc_decompress(sldc_compress(data)), data, length)

    def test_a_copy_that_overlaps_what_it_writes(self):
        bits = Bits()
        bits.control(5)
        bits.put(ord("A"), 9)        # literal A at history place 0
        bits.put(1, 1)
        _count_field(bits, 50)       # copy 50 bytes from place 0: each byte read was written one step earlier
        bits.put(0, 10)
        bits.control(4)
        self.assertEqual(wef.sldc_decompress(bits.bytes(16) + (51).to_bytes(4, "little")), b"A" * 51)

    def test_scheme_2_and_a_switch_of_scheme(self):
        data = bytes(range(256)) * 2 + b"\xff\xff\xff"
        self.assertEqual(wef.sldc_decompress(sldc_compress(data, scheme=2)), data)
        bits = Bits()
        bits.control(6)              # Reset 2: bytes as they are
        bits.put(0x41, 8)
        bits.control(1)              # Scheme 1, history kept
        bits.put(1, 1)
        _count_field(bits, 2)
        bits.put(0, 10)              # copy "A" twice from place 0
        bits.control(0)              # Flush changes nothing
        bits.control(4)
        self.assertEqual(wef.sldc_decompress(bits.bytes(16) + (3).to_bytes(4, "little")), b"AAA")

    def test_refuses_damaged_and_oversized_data(self):
        good = sldc_compress(b"hello hello hello hello")
        for bad in (b"", b"\x00\x01\x02\x03\x04", good[:6], good[:-4] + (99).to_bytes(4, "little"),
                    b"\xff\xfe<\x00s\x00"):   # plain UTF-16 labelled as compressed
            with self.assertRaises(wef.SldcError, msg=bad):
                wef.sldc_decompress(bad)
        with self.assertRaises(wef.SldcError):
            wef.sldc_decompress(sldc_compress(b"x" * 5000), limit=1000)


# --- XML, events and names ------------------------------------------------------------

def event_xml(event_id=4625, record_id=1001, computer=HOST, user="jsmith", address="198.51.100.60",
              when="2026-09-14T15:10:00.1234567Z", channel="Security", extra=""):
    """One synthetic event the way Windows renders it into a delivery (single quotes, RenderedText)."""
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
            f"<EventID>{event_id}</EventID><Version>0</Version><Level>0</Level><Task>12544</Task>"
            f"<TimeCreated SystemTime='{when}'/><EventRecordID>{record_id}</EventRecordID>"
            f"<Channel>{channel}</Channel><Computer>{computer}</Computer><Security/></System><EventData>"
            f"<Data Name='TargetUserName'>{user}</Data><Data Name='IpAddress'>{address}</Data>"
            f"<Data Name='LogonType'>3</Data>{extra}</EventData><RenderingInfo Culture='en-US'>"
            "<Message>[SYNTHETIC] An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0</Message>"
            "<Level>Information</Level><Keywords><Keyword>Audit Failure</Keyword></Keywords></RenderingInfo></Event>")


class EventTests(unittest.TestCase):
    def record(self, xml, sender=HOST):
        return wef.event_record(wef.parse_xml(xml), sender, "wef")

    def test_an_event_becomes_a_record_watchpost_accepts(self):
        record = self.record(event_xml())
        self.assertEqual(
            {k: record[k] for k in ("EventID", "TimeCreated", "Computer", "TargetUserName", "IpAddress", "source",
                                    "EventChannel", "EventRecordID", "wef_sender", "message", "LogonType")},
            {"EventID": 4625, "TimeCreated": "2026-09-14T15:10:00.123456Z", "Computer": HOST, "TargetUserName": "jsmith",
             "IpAddress": "198.51.100.60", "source": "wef", "EventChannel": "Security", "EventRecordID": "1001",
             "wef_sender": HOST, "message": "[SYNTHETIC] An account failed to log on.", "LogonType": "3"})
        event = normalize.normalize_record(record, "wef")
        self.assertEqual((event["event_type"], event["user"], event["src_ip"], event["host"], event["source"]),
                         ("auth_failure", "jsmith", "198.51.100.60", HOST, "wef"))
        self.assertEqual(event["ts"][:19], "2026-09-14T15:10:00")

    def test_values_that_would_make_watchpost_refuse_the_event_are_moved_aside(self):
        extra = ("<Data Name='level'>Verbose</Data><Data Name='time'>yesterday</Data><Data Name='ip'>n/a</Data>"
                 "<Data Name='dest_port'>none</Data><Data>unnamed</Data><Data Name='a b/c'>x</Data>")
        for address in ("-", "LOCAL", "ws17.corp.example"):
            record = self.record(event_xml(address=address, channel="Microsoft-Windows-Sysmon/Operational", extra=extra))
            self.assertNotIn("IpAddress", record)
            self.assertEqual(record["win_IpAddress"], address)
            self.assertEqual((record["win_level"], record["win_time"], record["win_ip"], record["win_dest_port"]),
                             ("Verbose", "yesterday", "n/a", "none"))
            self.assertEqual((record["Data8"], record["a_b_c"]), ("unnamed", "x"))
            event = normalize.normalize_record(record, "wef")   # accepted: no EventError
            self.assertEqual((event["src_ip"], event["source"], event["severity"]), (None, "wef", "low"))

    def test_reserved_names_cover_every_field_watchpost_reads(self):
        aliases = {alias for names in normalize.FIELD_ALIASES.values() for alias in names}
        self.assertLessEqual(aliases, wef.RESERVED_FIELDS)
        self.assertEqual(set(wef.DEFAULT_EVENT_IDS), set(normalize.WINDOWS_EVENT_IDS))

    def test_user_data_long_values_and_the_forwarder_marker(self):
        cleared = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                   "<Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID>"
                   "<TimeCreated SystemTime='2026-09-14T15:12:00.5Z'/><Computer>dc01</Computer></System><UserData>"
                   "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
                   f"<SubjectUserName>admin</SubjectUserName><Note>{'n' * 5000}</Note></LogFileCleared></UserData></Event>")
        record = self.record(cleared)
        self.assertEqual((record["EventID"], record["SubjectUserName"], len(record["Note"])), (1102, "admin", wef.MAX_VALUE))
        self.assertEqual(record["message"], "Windows event 1102 (Microsoft-Windows-Eventlog)")
        marker = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                  "<Provider Name='Microsoft-Windows-EventForwarder'/><EventID>111</EventID>"
                  "<TimeCreated SystemTime='2026-09-14T15:12:00.5Z'/><Computer>dc01</Computer></System>"
                  "<SubscriptionBookmarkEvent><SubscriptionId></SubscriptionId></SubscriptionBookmarkEvent></Event>")
        self.assertIsNone(self.record(marker))
        self.assertIsNone(self.record("<NotAnEvent/>"))

    def test_xml_with_a_doctype_is_refused_and_bad_characters_are_replaced(self):
        for text in ('<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>', '<?xml version="1.0"?>\n<!-- c -->\n<!DOCTYPE a><a/>',
                     "<a>", "<?xml", "<!-- never closed"):
            with self.assertRaises(wef.Rejected, msg=text):
                wef.parse_xml(text)
        root = wef.parse_xml('﻿<?xml version="1.0" encoding="utf-16"?><!-- ok --><a>bell\x07 and \x05</a>')
        self.assertEqual(root.text, "bell� and �")
        self.assertEqual(wef.parse_xml("<a><![CDATA[<!DOCTYPE inside text is only text>]]></a>").text,
                         "<!DOCTYPE inside text is only text>")

    def test_queries(self):
        default = ET.fromstring(wef.event_query())
        self.assertEqual(default.find("Query/Select").get("Path"), "Security")
        self.assertIn("EventID=4625", default.find("Query/Select").text)
        channels = ET.fromstring(wef.event_query(channels=["Security", 'Odd"Name<']))
        self.assertEqual([s.get("Path") for s in channels.iter("Select")], ["Security", 'Odd"Name<'])
        exported = '<?xml version="1.0"?>\n<QueryList>\n  <Query Id="0" Path="System">\n    <Select Path="System">*[System[(Level=1)]]</Select>\n  </Query>\n</QueryList>\n'
        self.assertEqual(wef.read_query(exported),
                         '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[(Level=1)]]</Select></Query></QueryList>')
        for bad in ("<Query/>", "<QueryList/>", "not xml", '<!DOCTYPE q><QueryList><Query/></QueryList>'):
            with self.assertRaises(wef.FatalError, msg=bad):
                wef.read_query(bad)

    def test_sender_names(self):
        name = wef.sender_name
        self.assertEqual(name({"subject": ((("organizationName", "x"),), (("commonName", "DC01.Corp.Example"),))}), HOST)
        self.assertEqual(name({"subject": (), "subjectAltName": (("IP Address", "192.0.2.1"), ("DNS", "ws17.corp.example"))}),
                         "ws17.corp.example")
        for unusable in ({}, {"subject": ((("commonName", "two words"),),)}, {"subject": ((("commonName", "a|b"),),)},
                         {"subject": ((("commonName", "x" * 300),),)}):
            self.assertIsNone(name(unusable))


# --- the collector end to end ---------------------------------------------------------

class Sender:
    """A stand-in for the Windows forwarder: one HTTPS connection with a client certificate."""

    def __init__(self, port, ca, cert=None, machine=HOST):
        context = ssl.create_default_context(cafile=ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert:
            context.load_cert_chain(cert)
        self.machine, self.to = machine, f"https://localhost:{port}/wsman/SubscriptionManager/WEC"
        self.connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=10)
        self.sent = 0

    def close(self):
        self.connection.close()

    def envelope(self, action, headers="", body=""):
        self.sent += 1
        self.message_id = f"uuid:0000000{self.sent}-AAAA-4BBB-8CCC-DDDDEEEEFFFF"
        return (f'<s:Envelope xmlns:s="{wef.SOAP}" xmlns:a="{wef.ADDRESSING}" xmlns:e="{wef.EVENTING}" '
                f'xmlns:n="{wef.ENUMERATION}" xmlns:w="{wef.WSMAN}" xmlns:p="{wef.MS_WSMAN}"><s:Header>'
                f'<a:To>{self.to}</a:To><m:MachineID xmlns:m="{wef.MACHINE_ID}" s:mustUnderstand="false">{self.machine}'
                f'</m:MachineID><a:ReplyTo><a:Address s:mustUnderstand="true">{wef.ANONYMOUS}</a:Address></a:ReplyTo>'
                f'<a:Action s:mustUnderstand="true">{action}</a:Action>'
                f'<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>'
                f'<a:MessageID>{self.message_id}</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false" />'
                '<p:OperationID s:mustUnderstand="false">uuid:11111111-2222-4333-8444-555555555555</p:OperationID>'
                '<p:SequenceId s:mustUnderstand="false">1</p:SequenceId><w:OperationTimeout>PT60.000S</w:OperationTimeout>'
                f'{headers}</s:Header><s:Body>{body}</s:Body></s:Envelope>')

    def post(self, text, path="/wsman/SubscriptionManager/WEC", compress=False, raw=None, headers=None):
        body = raw if raw is not None else b"\xff\xfe" + text.encode("utf-16-le")
        send = {"Content-Type": "application/soap+xml;charset=UTF-16", "User-Agent": "Microsoft WinRM Client",
                **(headers or {})}
        if compress:
            body, send["Content-Encoding"] = sldc_compress(body), "SLDC"
        self.connection.request("POST", path, body=body, headers=send)
        response = self.connection.getresponse()
        payload = response.read()
        self.content_type = response.getheader("Content-Type")
        if payload:
            assert payload.startswith(b"\xff\xfe"), payload[:20]
            return response.status, ET.fromstring(payload[2:].decode("utf-16-le"))
        return response.status, None

    def enumerate(self):
        return self.post(self.envelope(
            wef.ACTION_ENUMERATE, '<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/'
            'SubscriptionManager/Subscription</w:ResourceURI>',
            "<n:Enumerate><w:OptimizeEnumeration/><w:MaxElements>32000</w:MaxElements></n:Enumerate>"))

    def deliver(self, path, identifier, events, bookmark=None, action=None, **kw):
        headers = f'<e:Identifier xmlns:e="{wef.EVENTING}">{identifier}</e:Identifier>'
        if bookmark is not None:
            headers += (f'<w:Bookmark><BookmarkList><Bookmark Channel="Security" RecordId="{bookmark}" IsCurrent="true"/>'
                        '</BookmarkList></w:Bookmark>')
        wrapped = "".join(f'<w:Event Action="http://schemas.dmtf.org/wbem/wsman/1/wsman/Event"><![CDATA[{event}]]></w:Event>'
                          for event in events)
        return self.post(self.envelope(action or wef.ACTION_EVENTS, headers + "<w:AckRequested/>", f"<w:Events>{wrapped}</w:Events>"),
                         path=path, **kw)


class CollectorTests(ServerTestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        ca_key, server_key, host_key, other_key = (certgen.Key() for _ in range(4))
        cls.ca = certgen.write(tmp.name, "ca.pem", certgen.certificate(CA_NAME, ca_key, ca=True))
        cls.cert = certgen.write(tmp.name, "server.pem", certgen.certificate("localhost", server_key, CA_NAME, ca_key,
                                                                             names=["localhost"]))
        cls.key = certgen.write(tmp.name, "server.key", server_key.pem())
        cls.host = certgen.write(tmp.name, "host.pem", certgen.certificate(HOST, host_key, CA_NAME, ca_key), host_key.pem())
        cls.ws17 = certgen.write(tmp.name, "ws17.pem", certgen.certificate("ws17.corp.example", host_key, CA_NAME, ca_key), host_key.pem())
        cls.stranger = certgen.write(tmp.name, "stranger.pem", certgen.certificate("Another CA", other_key, ca=True),
                                     other_key.pem())
        cls.ca_thumbprint = wef.read_authorities(cls.ca)[0][1]

    def setUp(self):
        super().setUp()
        status, token, _ = self.client("admin").post("/api/tokens", {"name": "wef"})
        self.assertEqual(status, 201)
        self.token = token["token"]
        self.state = Path(self.tmp.name) / "state" / "wef.json"
        self.log = io.StringIO()
        patcher = mock.patch.object(wef.sys, "stderr", self.log)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, url=None, **kw):
        collector = wef.Collector(url or self.base, self.token, "localhost", wef.read_authorities(self.ca), self.state, **kw)
        server = wef.Server(("127.0.0.1", 0), collector, wef.tls_context(self.cert, self.key, self.ca))
        collector.address = collector.address.replace(f":{wef.DEFAULT_PORT}/", f":{server.server_address[1]}/")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return collector, server.server_address[1]

    def sender(self, port, cert="host", **kw):
        sender = Sender(port, self.ca, getattr(self, cert) if cert else None, **kw)
        self.addCleanup(sender.close)
        return sender

    def stored(self):
        status, data, _ = self.client("analyst").get("/api/events?source=wef&limit=100")
        self.assertEqual(status, 200)
        return sorted(data["events"], key=lambda e: e["ts"])

    def subscribe(self, sender):
        """Enumerate, and return (delivery path, identifier, the Subscribe element)."""
        status, answer = sender.enumerate()
        self.assertEqual(status, 200)
        self.assertEqual(answer.findtext("s:Header/a:Action", namespaces=NS), wef.ACTION_ENUMERATE_RESPONSE)
        self.assertEqual(answer.findtext("s:Header/a:RelatesTo", namespaces=NS), sender.message_id)
        subscribe = answer.find("s:Body/n:EnumerateResponse/w:Items/m:Subscription/s:Envelope/s:Body/e:Subscribe", NS)
        address = subscribe.findtext("e:Delivery/e:NotifyTo/a:Address", namespaces=NS)
        identifier = subscribe.findtext("e:Delivery/e:NotifyTo/a:ReferenceProperties/e:Identifier", namespaces=NS)
        return address.split(f":{sender.connection.port}", 1)[1], identifier, subscribe

    def test_a_host_subscribes_delivers_and_resumes_from_its_bookmark(self):
        collector, port = self.start()
        sender = self.sender(port)
        path, identifier, subscribe = self.subscribe(sender)
        self.assertEqual(sender.content_type, "application/soap+xml;charset=UTF-16")
        self.assertEqual(path, f"/wsman/subscriptions/{collector.identifier}")
        self.assertEqual(identifier, collector.identifier)
        self.assertEqual(subscribe.findtext("e:Delivery/e:NotifyTo/c:Policy/c:ExactlyOne/c:All/auth:Authentication/"
                                            "auth:ClientCertificate/auth:Thumbprint",
                                            namespaces={**NS, "c": "http://schemas.xmlsoap.org/ws/2002/12/policy"}),
                         self.ca_thumbprint)
        self.assertRegex(self.ca_thumbprint, r"^[0-9a-f]{40}$")
        self.assertEqual(subscribe.find("e:Delivery", NS).get("Mode"), wef.ACTION_EVENTS)
        self.assertEqual(subscribe.findtext("e:Delivery/w:Heartbeats", namespaces=NS), "PT900.000S")
        self.assertIn("EventID=4625", subscribe.findtext("w:Filter/QueryList/Query/Select", namespaces=NS))
        self.assertIsNone(subscribe.find("w:Bookmark", NS))          # none yet: start at the next event
        self.assertIsNotNone(subscribe.find("w:SendBookmarks", NS))
        self.assertEqual(sender.post(sender.envelope(wef.ACTION_END))[0], 204)

        events = [event_xml(4625, 1001 + n, when=f"2026-09-14T15:10:{n:02d}.1234567Z") for n in range(6)]
        events.append(event_xml(4624, 1007, when="2026-09-14T15:11:40.0000000Z"))
        status, ack = sender.deliver(path, identifier, events, bookmark=1007)
        self.assertEqual(status, 200)
        self.assertEqual(ack.findtext("s:Header/a:Action", namespaces=NS), wef.ACTION_ACK)
        self.assertEqual(ack.findtext("s:Header/a:RelatesTo", namespaces=NS), sender.message_id)
        self.assertEqual(ack.findtext("s:Header/a:To", namespaces=NS), wef.ANONYMOUS)
        stored = self.stored()
        self.assertEqual([e["event_type"] for e in stored], ["auth_failure"] * 6 + ["auth_success"])
        self.assertEqual({(e["host"], e["user"], e["src_ip"]) for e in stored}, {(HOST, "jsmith", "198.51.100.60")})
        self.assertEqual(collector.stats["events"], 7)

        status, ack = sender.deliver(path, identifier, [], action=wef.ACTION_HEARTBEAT)
        self.assertEqual((status, ack.findtext("s:Header/a:Action", namespaces=NS)), (200, wef.ACTION_ACK))
        self.assertEqual(json.loads(self.state.read_text())["bookmarks"][f"{HOST}|{HOST}"].count('RecordId="1007"'), 1)
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)

        # A restarted collector hands the host the same subscription, now with the bookmark it stored.
        again, port = self.start()
        _, identifier_again, subscribe = self.subscribe(self.sender(port))
        self.assertEqual(identifier_again, identifier)
        self.assertEqual(subscribe.find("w:Bookmark/BookmarkList/Bookmark", NS).attrib,
                         {"Channel": "Security", "RecordId": "1007", "IsCurrent": "true"})
        other = self.sender(port, cert="ws17", machine="ws17.corp.example")   # another host has no bookmark
        self.assertIsNone(self.subscribe(other)[2].find("w:Bookmark", NS))
        self.assertNotIn("jsmith", self.log.getvalue())
        self.assertNotIn(self.token, self.log.getvalue())

    def test_compressed_deliveries_and_subscription_options(self):
        collector, port = self.start(compression=True, read_existing=True, heartbeat=60,
                                     query=wef.event_query(channels=["Security", "System"]))
        sender = self.sender(port)
        path, identifier, subscribe = self.subscribe(sender)
        envelope = sender.enumerate()[1].find("s:Body/n:EnumerateResponse/w:Items/m:Subscription/s:Envelope", NS)
        options = {o.get("Name"): o.text for o in envelope.iterfind("s:Header/w:OptionSet/w:Option", NS)}
        self.assertEqual(options, {"SubscriptionName": "Watchpost", "Compression": "SLDC", "CDATA": None,
                                   "ContentFormat": "RenderedText", "IgnoreChannelError": None, "ReadExistingEvents": None})
        self.assertEqual(subscribe.findtext("w:Bookmark", namespaces=NS), wef.EARLIEST)
        self.assertEqual([s.get("Path") for s in subscribe.iterfind("w:Filter/QueryList/Query/Select", NS)],
                         ["Security", "System"])
        self.assertNotEqual(identifier, wef.Collector(self.base, self.token, "localhost", [(None, "00")], self.state).identifier)

        events = [event_xml(4625, 2000 + n, when=f"2026-09-14T16:00:{n:02d}.0000000Z") for n in range(12)]
        status, ack = sender.deliver(path, identifier, events, bookmark=2011, compress=True)
        self.assertEqual((status, ack.findtext("s:Header/a:Action", namespaces=NS)), (200, wef.ACTION_ACK))
        self.assertEqual(len(self.stored()), 12)
        # Labelled compressed but sent as it is: still read.
        status, _ = sender.deliver(path, identifier, [event_xml(4624, 2040, when="2026-09-14T16:01:00.0000000Z")],
                                   bookmark=2040, headers={"Content-Encoding": "SLDC"})
        self.assertEqual((status, len(self.stored())), (200, 13))
        # With a bookmark stored, the host is no longer asked to start from its earliest event.
        self.assertIn('RecordId="2040"', ET.tostring(self.subscribe(sender)[2].find("w:Bookmark", NS), encoding="unicode"))
        status, ack = sender.deliver(path, identifier, [], action=wef.ACTION_SUBSCRIPTION_END)
        self.assertEqual((status, ack.findtext("s:Header/a:Action", namespaces=NS)), (200, wef.ACTION_ACK))
        self.assertIn("ended its subscription", self.log.getvalue())

    def test_only_hosts_with_a_certificate_from_the_ca_get_in(self):
        collector, port = self.start(allow=["DC*.corp.example"])
        for cert in (None, "stranger"):
            with self.assertRaises((ssl.SSLError, OSError), msg=cert):
                self.sender(port, cert=cert).enumerate()
        self.assertEqual(self.sender(port).enumerate()[0], 200)
        refused = self.sender(port, cert="ws17", machine="ws17.corp.example")   # right CA, name not allowed
        self.assertEqual(refused.enumerate()[0], 403)
        deadline = threading.Event()
        for _ in range(50):
            if collector.stats["failed_handshakes"] >= 2:
                break
            deadline.wait(0.1)
        self.assertEqual((collector.stats["failed_handshakes"], collector.stats["refused_requests"]), (2, 1))
        self.assertIn("ws17.corp.example is not allowed", self.log.getvalue())

    def test_requests_that_are_refused(self):
        collector, port = self.start()

        def status(**kw):
            sender = self.sender(port)
            return sender.post(kw.pop("text", sender.envelope(wef.ACTION_ENUMERATE)), **kw)[0]

        self.assertEqual(status(path="/"), 404)
        self.assertEqual(status(text='<!DOCTYPE s [<!ENTITY x "y">]><s/>'), 400)
        self.assertEqual(status(text="<s:Envelope"), 400)
        self.assertEqual(status(text="<Envelope><Header/></Envelope>"), 400)
        self.assertEqual(status(headers={"Content-Encoding": "gzip"}), 415)
        self.assertEqual(status(raw=b""), 200)   # an empty request is answered and ignored
        sender = self.sender(port)
        self.assertEqual(sender.post(sender.envelope("http://example.invalid/Unknown"))[0], 400)
        sender = self.sender(port)
        sender.connection.request("POST", "/wsman", headers={"Content-Length": str(wef.MAX_BODY + 1)})
        self.assertEqual(sender.connection.getresponse().status, 413)
        sender = self.sender(port)
        sender.connection.request("GET", "/wsman")
        self.assertEqual(sender.connection.getresponse().status, 501)
        self.assertEqual(self.stored(), [])

    def test_a_batch_is_acknowledged_only_once_watchpost_has_it(self):
        collector, port = self.start()
        sender = self.sender(port)
        path, identifier, _ = self.subscribe(sender)
        batch = [event_xml(4625, 3001)]
        with mock.patch.object(collector, "post", side_effect=OSError("connection refused")):
            self.assertEqual(sender.deliver(path, identifier, batch, bookmark=3001)[0], 503)
        sender = self.sender(port)   # the refusal closed the connection
        with mock.patch.object(collector, "post", return_value=401):
            self.assertEqual(sender.deliver(path, identifier, batch, bookmark=3001)[0], 503)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.stored(), [])
        self.assertIn("check the ingest token", self.log.getvalue())
        sender = self.sender(port)
        self.assertEqual(sender.deliver(path, identifier, batch, bookmark=3001)[0], 200)   # the host's resend
        self.assertEqual(len(self.stored()), 1)
        self.assertEqual(collector.stats["failed_deliveries"], 2)

        # A batch Watchpost refuses as invalid is skipped, or the host would resend it forever. One unreadable
        # event does not cost the rest of its batch.
        future = event_xml(4625, 3002, when="2999-01-01T00:00:00.0000000Z")
        self.assertEqual(sender.deliver(path, identifier, [future], bookmark=3002)[0], 200)
        mixed = ["<Event><broken", event_xml(4624, 3003, when="2026-09-14T15:20:00.0000000Z")]
        self.assertEqual(sender.deliver(path, identifier, mixed, bookmark=3003)[0], 200)
        self.assertEqual([e["event_type"] for e in self.stored()], ["auth_failure", "auth_success"])
        self.assertEqual((collector.stats["skipped_batches"], collector.stats["unreadable_events"]), (1, 1))
        self.assertIn('RecordId="3003"', json.loads(self.state.read_text())["bookmarks"][f"{HOST}|{HOST}"])

    def test_command_line(self):
        common = ["--url", self.base, "--hostname", "wef.corp.example", "--cert", self.cert, "--key", self.key,
                  "--client-ca", self.ca, "--state", str(self.state), "--bind", "127.0.0.1", "--port", "0"]

        def build(extra=(), env=None, drop=()):
            args = [a for a in common if a not in drop] + list(extra)
            with mock.patch.dict(os.environ, {"WATCHPOST_TOKEN": self.token} if env is None else env), \
                    mock.patch.object(wef, "Server") as server:
                server.return_value.serve_forever.side_effect = KeyboardInterrupt
                return wef.main(args), server

        code, server = build()
        self.assertEqual(code, 0)
        self.assertEqual(server.call_args[0][0], ("127.0.0.1", 0))
        out = self.log.getvalue()
        self.assertRegex(out, r"Subscription Manager policy value: Server=https://wef\.corp\.example:0/wsman/"
                              r"SubscriptionManager/WEC,Refresh=60,IssuerCA=[0-9A-F]{40}\n")
        self.assertIn(self.ca_thumbprint.upper(), out)
        self.assertNotIn(self.token, out)
        for extra, env, problem in (
                ([], {}, "no ingest token"),
                (["--channel", "Security", "--query-file", "q.xml"], None, "not both"),
                (["--query-file", str(self.state)], None, "cannot read --query-file"),
                (["--source", "bad source"], None, "--source must be"),
                (["--url", "http://siem.example.internal"], None, "plain HTTP"),
                (["--hostname", "not a name"], None, "--hostname must be"),
                (["--client-ca", self.key], None, "holds no PEM certificate"),
                (["--cert", self.ca, "--key", self.ca], None, "cannot load the TLS certificate and key")):
            drop = {"--url": (common[0], common[1])}.get(extra[0] if extra else "", ())
            self.assertEqual(build(extra, env, drop)[0], 2, problem)
            self.assertIn(problem, self.log.getvalue())
        self.assertEqual(re.findall(r"wp_[A-Za-z0-9_\-]{8,}", self.log.getvalue()), [])


if __name__ == "__main__":
    unittest.main()
