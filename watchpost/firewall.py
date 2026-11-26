"""Firewall appliances over syslog: pfSense/OPNsense, FortiGate, Cisco ASA/FTD and Palo Alto.

`parse(program, message)` takes the program tag and message of one syslog line and returns the
fields of a firewall or login event, or None when the line is none of these formats. The caller
(normalize.normalize_authlog_line) validates every value afterwards, so nothing here is trusted.

Traffic lines become `fw_deny` / `fw_allow` with source, destination and port, which is what the
port sweep and data transfer rules read. Admin and VPN logins become `auth_failure` / `auth_success`.

The parsers follow the vendors' published log formats and are tested on synthetic lines. They have
not been run against the devices themselves, and they read the default formats only: a custom log
format on the device will not match.
"""

import csv
import ipaddress
import re

_ALLOW, _DENY = "fw_allow", "fw_deny"
_IP = r"[0-9A-Fa-f:.]+"


# --- pfSense / OPNsense filterlog ----------------------------------------------------
# rule,subrule,anchor,tracker,interface,reason,action,direction,ipversion, then per IP version:
#   4: tos,ecn,ttl,id,offset,flags,protoid,proto,length,src,dst[,srcport,dstport,...]
#   6: class,flowlabel,hoplimit,proto,protoid,length,src,dst[,srcport,dstport,...]

_FILTERLOG_ACTIONS = {"block": _DENY, "reject": _DENY, "pass": _ALLOW}
_FILTERLOG_ADDRESS = {"4": (16, 18), "6": (12, 15)}  # ip version -> (protocol name, source address)


def _filterlog(message):
    fields = message.split(",")
    if len(fields) < 9 or fields[6] not in _FILTERLOG_ACTIONS or fields[8] not in _FILTERLOG_ADDRESS:
        return None
    proto, src = _FILTERLOG_ADDRESS[fields[8]]
    if len(fields) <= src + 1:
        return None
    has_ports = fields[proto].lower() in ("tcp", "udp") and len(fields) > src + 3
    return {"event_type": _FILTERLOG_ACTIONS[fields[6]], "src_ip": fields[src], "dest_ip": fields[src + 1],
            "dest_port": fields[src + 3] if has_ports else None}


# --- FortiGate key=value -------------------------------------------------------------

_KEY_VALUE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
_FORTI_DENY = {"deny", "blocked", "dropped"}
_FORTI_ALLOW = {"accept", "allow", "close", "timeout", "client-rst", "server-rst", "ip-conn", "start"}
_FORTI_TZ = re.compile(r"[+-](?:[01][0-9]|2[0-3])[0-5][0-9]")


def _fortigate(program, message):
    if program and program.lower() != "fortigate":
        return None
    if not _KEY_VALUE.match(message.lstrip()):
        return None
    if "logid=" not in message or "type=" not in message:
        return None
    kv = {key: quoted if quoted else bare for key, quoted, bare in _KEY_VALUE.findall(message)}
    out = {"host": kv["devname"]} if kv.get("devname") else {}
    tz = kv.get("tz", "")
    if kv.get("date") and kv.get("time") and tz != "-0000" and _FORTI_TZ.fullmatch(tz):
        out["ts"] = f"{kv['date']}T{kv['time']}{tz[:3]}:{tz[3:]}"
    action = kv.get("action", "").lower()
    if kv.get("type") == "traffic" and (action in _FORTI_DENY or action in _FORTI_ALLOW):
        out.update(event_type=_DENY if action in _FORTI_DENY else _ALLOW, src_ip=kv.get("srcip"),
                   dest_ip=kv.get("dstip"), dest_port=kv.get("dstport"), bytes=kv.get("sentbyte"),
                   user=kv.get("user"))
        return out
    if kv.get("type") == "event" and action == "login" and kv.get("status") in ("success", "failed"):
        out.update(event_type="auth_success" if kv["status"] == "success" else "auth_failure",
                   user=kv.get("user"), src_ip=kv.get("srcip"))
        return out
    return None


# --- Cisco ASA / FTD -----------------------------------------------------------------

ASA_TAG = re.compile(r"%(?:ASA|FTD)-[0-7]-(?P<id>[0-9]{6})", re.I)
_ASA_ADDRESS = rf"(?:[\w.\-]+:)?{_IP}"
_ASA_PEER = rf"(?P<{{0}}>{_ASA_ADDRESS})/(?P<{{0}}_port>\d+)"
_ASA_FROM_TO = re.compile(rf"from {_ASA_PEER.format('src')} to {_ASA_PEER.format('dst')}")
_ASA_SRC_DST = re.compile(rf"\bsrc\s+(?P<src>{_ASA_ADDRESS})(?:/\d+)?\s+"
                          rf"dst\s+(?P<dst>{_ASA_ADDRESS})(?:/(?P<dst_port>\d+))?(?=\s|$)", re.I)
_ASA_BUILT = re.compile(rf"^Built (?P<direction>inbound|outbound) (?:TCP|UDP) connection \d+ "
                        rf"for {_ASA_PEER.format('a')} \([^)]*\) to {_ASA_PEER.format('b')}")
_ASA_ACL = re.compile(rf"^access-list\s+\S+\s+(?P<verdict>permitted|denied|permit|deny)\s+\S+\s+"
                      rf"[\w.\-]+/(?P<src>{_IP})\(\d+\)(?:\([^)]*\))?\s*(?:->|to)\s*[\w.\-]+/(?P<dst>{_IP})\((?P<dst_port>\d+)\)", re.I)
_ASA_AAA = re.compile(rf"^AAA user authentication (?P<verdict>Successful|Rejected) :.*?\buser = (?P<user>[^\s:][^:]*)"
                      rf"(?:.*?\buser IP = (?P<src>{_IP}))?")
_ASA_LOGIN = re.compile(rf"^Login (?P<verdict>permitted|denied) from (?P<src>{_IP})/\d+ to .*? for user \"(?P<user>[^\"]*)\"")
_ASA_DENIES = {"106001": _ASA_FROM_TO, "106006": _ASA_FROM_TO, "106007": _ASA_FROM_TO, "106015": _ASA_FROM_TO,
               "106023": _ASA_SRC_DST, "710003": _ASA_FROM_TO}


def _asa_address(peer, *, interface_expected):
    _, separator, suffix = peer.partition(":")
    if not separator:
        return peer
    # A hex interface name can also be an IPv6 group. Prefer the form used by this message ID.
    preferred, fallback = (suffix, peer) if interface_expected else (peer, suffix)
    try:
        ipaddress.ip_address(preferred)
    except ValueError:
        return fallback
    return preferred


def _asa(program, message):
    if program is None:
        # RFC 5424 relays can put the device tag at the start of MSG and leave APP-NAME empty.
        program, _, message = message.lstrip().partition(":")
    found = ASA_TAG.fullmatch(program)
    if not found:
        return None
    msg_id, text = found["id"], message.lstrip()
    if msg_id in _ASA_DENIES:
        peers = _ASA_DENIES[msg_id].search(text)
        verdict = _DENY
        if msg_id == "106023":
            action = text.split(maxsplit=1)[0].lower() if text else ""
            if action not in ("deny", "denied", "permit", "permitted"):
                return None
            verdict = _ALLOW if action.startswith("permit") else _DENY
        return peers and {"event_type": verdict, "src_ip": _asa_address(peers["src"], interface_expected=msg_id == "106023"),
                          "dest_ip": _asa_address(peers["dst"], interface_expected=msg_id in ("106023", "710003")),
                          "dest_port": peers["dst_port"]}
    if msg_id in ("302013", "302015"):
        built = _ASA_BUILT.match(text)
        if not built:
            return None
        # "for" names the outside peer and "to" the inside one, whichever of them opened the connection.
        src, dst = ("a", "b") if built["direction"] == "inbound" else ("b", "a")
        return {"event_type": _ALLOW, "src_ip": _asa_address(built[src], interface_expected=True),
                "dest_ip": _asa_address(built[dst], interface_expected=True),
                "dest_port": built[f"{dst}_port"]}
    if msg_id == "106100":
        acl = _ASA_ACL.match(text)
        return acl and {"event_type": _ALLOW if acl["verdict"].lower().startswith("permit") else _DENY, "src_ip": acl["src"],
                        "dest_ip": acl["dst"], "dest_port": acl["dst_port"]}
    if msg_id in ("113004", "113005"):
        aaa = _ASA_AAA.match(text)
        return aaa and {"event_type": "auth_success" if aaa["verdict"] == "Successful" else "auth_failure",
                        "user": aaa["user"].rstrip(), "src_ip": aaa["src"]}
    if msg_id in ("605004", "605005"):
        login = _ASA_LOGIN.match(text)
        return login and {"event_type": "auth_success" if login["verdict"] == "permitted" else "auth_failure",
                          "user": login["user"], "src_ip": login["src"]}
    return None


# --- Palo Alto TRAFFIC (default comma-separated format) -------------------------------
# 3 type, 7 source, 8 destination, 12 source user, 25 destination port, 30 action, 32 bytes sent

_PAN_DENY = {"deny", "drop", "drop-icmp", "reset-client", "reset-server", "reset-both"}


def parse_palo_alto(program, message):
    if (program and program.lower() != "pan-os") or ",TRAFFIC," not in message:
        return None
    try:
        fields = next(csv.reader([message]))
    except (csv.Error, StopIteration):
        return None
    if len(fields) < 33 or not re.fullmatch(r"[0-9]+", fields[0]) or fields[3] != "TRAFFIC":
        return None
    if fields[30] not in _PAN_DENY and fields[30] != "allow":
        return None
    return {"event_type": _ALLOW if fields[30] == "allow" else _DENY, "src_ip": fields[7], "dest_ip": fields[8],
            "dest_port": fields[25], "bytes": fields[32], "user": fields[12] or None}


def parse(program, message):
    """Fields of a firewall or login event read from one syslog line, or None."""
    if program == "filterlog":
        return _filterlog(message)
    return _asa(program, message) or _fortigate(program, message) or parse_palo_alto(program, message) or None
