"""Sigma rule import: a small YAML-subset parser, a compiler for a documented Sigma subset, and its evaluator.

Nothing here runs input as code. The parser reads only the YAML Sigma rules use (mappings, block lists,
plain and quoted scalars, simple `[a, b]` lists, `|`/`>` text blocks, comments) and refuses the rest with a
reason. The compiler turns `detection` into a small JSON tree (and/or/not/match), and `matches` walks that
tree over one event dict. Value matching is plain string work: `*` and `?` wildcards are matched by a
linear-time glob routine, never by a regular expression built from the rule.

A compiled rule is stored as a Watchpost rule whose `params` are the compiled tree (not tunable: change the
Sigma source and import again). Its original YAML text and sha256 live in the `sigma_rules` table, with an
optional labeled sample: malicious events that must match and benign look-alikes that must not. The rule
cannot be enabled until its sample passes, and its ATT&CK techniques count as validated only while it does.
"""

import hashlib
import ipaddress
import json
import re
from collections import defaultdict

from . import attack
from . import ecs
from .db import parse_iso

MAX_SOURCE_BYTES = 64 * 1024
MAX_LINES = 2000
MAX_DEPTH = 12
MAX_SELECTIONS = 50
MAX_VALUES = 100
MAX_CONDITION = 1000
MAX_SAMPLE_EVENTS = 50
# A condition can name the same selection many times ("1 of them or 1 of them ..."), and each mention copies it,
# so the source cap alone does not bound the compiled rule. These bound what runs against every event.
MAX_COMPILED_VALUES = 2000
MAX_COMPILED_CHARS = 128 * 1024
SAMPLE_VALUE_LIMIT = 2048
GROUP_GAP_SECONDS = 3600  # matching events of one group key further apart than this become separate findings
RULE_PREFIX = "sigma_"
SAMPLE_PREFIX = "sigma_sample:"


class SigmaError(ValueError):
    """The rule (or YAML) is outside the supported subset. The message says why."""


# --- YAML subset ---------------------------------------------------------------------------

_INT_RE = re.compile(r"[-+]?[0-9]+")
_NULLS = {"", "~", "null", "Null", "NULL"}
_TRUE = {"true", "True", "TRUE"}
_FALSE = {"false", "False", "FALSE"}


class _Yaml:
    def __init__(self, text):
        if "\t" in text:
            raise SigmaError("tabs are not supported in this YAML subset; indent with spaces")
        raw = text.replace("\r\n", "\n").split("\n")
        if len(raw) > MAX_LINES:
            raise SigmaError(f"at most {MAX_LINES} lines")
        self.lines = []  # [lineno, indent, content]; content keeps comments (stripped per scalar)
        started = False
        for n, line in enumerate(raw, 1):
            stripped = line.strip()
            if stripped.startswith("%"):
                raise SigmaError(f"line {n}: YAML directives are not supported")
            if stripped in ("---", "...") or stripped.startswith("--- "):
                if started or stripped != "---":
                    raise SigmaError(f"line {n}: multiple YAML documents are not supported; import one rule at a time")
                continue
            if stripped and not stripped.startswith("#"):
                started = True
            self.lines.append([n, len(line) - len(line.lstrip(" ")), line.strip(" ")])
        self.i = 0

    def _next(self):
        """Index of the next line that is not blank or a whole-line comment, or None."""
        while self.i < len(self.lines):
            content = self.lines[self.i][2]
            if content and not content.startswith("#"):
                return self.i
            self.i += 1
        return None

    def parse(self):
        if self._next() is None:
            raise SigmaError("the rule is empty")
        node = self._node(self.lines[self.i][1], 0)
        if self._next() is not None:
            n = self.lines[self.i][0]
            raise SigmaError(f"line {n}: unexpected indentation or content")
        if not isinstance(node, dict):
            raise SigmaError("a Sigma rule must be a YAML mapping")
        return node

    def _node(self, indent, depth):
        if depth > MAX_DEPTH:
            raise SigmaError(f"nesting deeper than {MAX_DEPTH} levels")
        content = self.lines[self.i][2]
        if content == "-" or content.startswith("- "):
            return self._list(indent, depth)
        return self._map(indent, depth)

    def _map(self, indent, depth):
        out = {}
        while self._next() is not None:
            n, ind, content = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise SigmaError(f"line {n}: unexpected indentation")
            if content == "-" or content.startswith("- "):
                raise SigmaError(f"line {n}: a list item where a key was expected")
            key, rest = _split_key(content, n)
            if key in out:
                raise SigmaError(f"line {n}: duplicate key {key!r}")
            self.i += 1
            out[key] = self._value(rest, indent, depth, n)
        return out

    def _list(self, indent, depth):
        out = []
        while self._next() is not None:
            n, ind, content = self.lines[self.i]
            if ind < indent:
                break
            if ind > indent:
                raise SigmaError(f"line {n}: unexpected indentation")
            if not (content == "-" or content.startswith("- ")):
                break
            item = content[1:].lstrip(" ")
            if not item or item.startswith("#"):
                self.i += 1
                if self._next() is None or self.lines[self.i][1] <= indent:
                    out.append(None)
                else:
                    out.append(self._node(self.lines[self.i][1], depth + 1))
            elif item.startswith("- ") or item == "-":
                raise SigmaError(f"line {n}: nested inline lists are not supported")
            elif _is_key(item):
                # "- key: value" starts a mapping whose keys line up with "key": re-read this line from there.
                self.lines[self.i] = [n, ind + len(content) - len(item), item]
                out.append(self._map(self.lines[self.i][1], depth + 1))
            else:
                self.i += 1
                out.append(_scalar(item, n))
        return out

    def _value(self, rest, indent, depth, n):
        if rest and rest[0] in "|>":
            return self._block(rest, indent, n)
        if rest and not rest.startswith("#"):
            value = _scalar(rest, n)
            if self._next() is not None and self.lines[self.i][1] > indent:
                raise SigmaError(f"line {self.lines[self.i][0]}: unexpected indentation after a value")
            return value
        if self._next() is None:
            return None
        ind, content = self.lines[self.i][1], self.lines[self.i][2]
        if ind > indent:
            return self._node(ind, depth + 1)
        if ind == indent and (content == "-" or content.startswith("- ")):
            return self._list(indent, depth + 1)  # a block list may sit at its key's indentation
        return None

    def _block(self, header, indent, n):
        header = _strip_comment(header)
        if header not in ("|", "|-", "|+", ">", ">-", ">+"):
            raise SigmaError(f"line {n}: block scalar header {header!r} is not supported")
        body = []
        while self.i < len(self.lines):
            ln, ind, content = self.lines[self.i]
            if content and ind <= indent:
                break
            body.append((ind, content))
            self.i += 1
        while body and not body[-1][1]:
            body.pop()
        if not body:
            return ""
        base = min(ind for ind, c in body if c)
        lines = [" " * (ind - base) + c if c else "" for ind, c in body]
        if header[0] == "|":
            text = "\n".join(lines)
        else:  # folded: lines join with a space, a blank line is a line break
            text = ""
            for line in lines:
                text += "\n" if not line else (line if not text or text.endswith("\n") else " " + line)
        return text if header.endswith("-") else text + "\n"


def _is_key(content):
    try:
        _split_key(content, 0)
        return True
    except SigmaError:
        return False


def _split_key(content, n):
    """'key: rest' -> (key, rest). Keys are plain or quoted; complex keys are refused."""
    if content[0] in "'\"":
        key, end = _quoted(content, n)
        rest = content[end:]
        if not (rest == ":" or rest.startswith(": ")):
            raise SigmaError(f"line {n}: expected 'key: value'")
        return key, rest[1:].strip(" ")
    if content[0] in "?[{&*!%@`":
        raise SigmaError(f"line {n}: {content[0]!r} keys (complex keys, flow mappings, anchors, aliases, tags) "
                         "are not supported")
    idx = content.find(": ")
    if idx < 0:
        if not content.endswith(":") or " #" in content:
            raise SigmaError(f"line {n}: expected 'key: value'")
        idx = len(content) - 1
    key = content[:idx].rstrip(" ")
    if not key or " #" in key:
        raise SigmaError(f"line {n}: expected 'key: value'")
    if key == "<<":
        raise SigmaError(f"line {n}: merge keys are not supported")
    return key, content[idx + 1:].strip(" ")


def _strip_comment(text):
    idx = text.find(" #")
    return (text[:idx] if idx >= 0 else text).rstrip(" ")


def _quoted(text, n):
    """Parse a quoted scalar at the start of text. Returns (value, index after the closing quote)."""
    q, out, i = text[0], [], 1
    while i < len(text):
        c = text[i]
        if q == "'" and c == "'":
            if text[i + 1:i + 2] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        if q == '"' and c == "\\":
            esc = text[i + 1:i + 2]
            mapped = {"\\": "\\", '"': '"', "n": "\n", "t": "\t", "/": "/", "'": "'"}.get(esc)
            if mapped is None:
                raise SigmaError(f"line {n}: escape \\{esc} is not supported in double-quoted scalars")
            out.append(mapped)
            i += 2
            continue
        if q == '"' and c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise SigmaError(f"line {n}: unterminated quoted scalar (multi-line quoted scalars are not supported)")


def _scalar(text, n):
    if text[0] in "'\"":
        value, end = _quoted(text, n)
        rest = text[end:].strip(" ")
        if rest and not rest.startswith("#"):
            raise SigmaError(f"line {n}: unexpected text after a quoted scalar")
        return value
    if text[0] == "[":
        return _flow_list(_strip_comment(text), n)
    if text[0] in "&*!{%@`|>":
        what = {"&": "anchors", "*": "aliases", "!": "tags", "{": "flow mappings"}.get(text[0], "this syntax")
        raise SigmaError(f"line {n}: {what} are not supported in this YAML subset")
    text = _strip_comment(text)
    if ": " in text or text.endswith(":"):
        raise SigmaError(f"line {n}: a plain scalar may not contain ': '; quote the value")
    return _plain(text)


def _plain(text):
    if text in _NULLS:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    if _INT_RE.fullmatch(text):
        return int(text)
    return text


def _flow_list(text, n):
    if not text.endswith("]"):
        raise SigmaError(f"line {n}: a flow list must close on the same line")
    inner, items, i = text[1:-1].strip(" "), [], 0
    if not inner:
        return []
    while i <= len(inner):
        while i < len(inner) and inner[i] == " ":
            i += 1
        if i < len(inner) and inner[i] in "'\"":
            value, end = _quoted(inner[i:], n)
            i += end
            items.append(value)
        else:
            j = inner.find(",", i)
            j = len(inner) if j < 0 else j
            token = inner[i:j].strip(" ")
            if not token or token[0] in "[{&*!":
                raise SigmaError(f"line {n}: only simple [a, b] lists of scalars are supported")
            items.append(_plain(token))
            i = j
        while i < len(inner) and inner[i] == " ":
            i += 1
        if i < len(inner) and inner[i] != ",":
            raise SigmaError(f"line {n}: only simple [a, b] lists of scalars are supported")
        i += 1
    return items


def parse_yaml(text):
    """Parse the YAML subset. Returns a dict, or raises SigmaError with a reason."""
    if not isinstance(text, str):
        raise SigmaError("the Sigma rule must be text")
    if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise SigmaError(f"a Sigma rule is at most {MAX_SOURCE_BYTES} bytes")
    return _Yaml(text).parse()


# --- Sigma subset: fields, modifiers, conditions ----------------------------------------------

# The event fields a detection rule can read (engine.RULE_EVENT_FIELDS, minus ids and timestamps).
EVENT_FIELDS = ("event_type", "user", "src_ip", "host", "dest_ip", "dest_port", "bytes", "message")
# Common Sigma field names with a clean Watchpost counterpart. Anything else is refused by name.
SIGMA_FIELDS = {
    "SourceIp": "src_ip", "IpAddress": "src_ip", "src_ip": "src_ip",
    "DestinationIp": "dest_ip", "dst_ip": "dest_ip",
    "DestinationPort": "dest_port", "dst_port": "dest_port",
    "User": "user", "TargetUserName": "user",
    "Computer": "host", "ComputerName": "host", "hostname": "host",
}
FIELD_MAP = {
    **{f: f for f in EVENT_FIELDS},
    **{target: field for field, target in ecs.FIELD_MAP.items() if field in EVENT_FIELDS},  # ECS names
    **SIGMA_FIELDS,
}
MODIFIERS = ("contains", "startswith", "endswith", "all", "cidr")
REFUSED_MODIFIERS = {
    "re": "regular expressions are refused (a pattern from an imported rule could take unbounded time)",
    "base64": "base64 modifiers are not supported", "base64offset": "base64 modifiers are not supported",
    "wide": "encoding modifiers are not supported", "utf16le": "encoding modifiers are not supported",
    "utf16be": "encoding modifiers are not supported", "utf16": "encoding modifiers are not supported",
    "windash": "windash is not supported", "expand": "placeholders are not supported",
    "lt": "numeric comparisons are not supported", "lte": "numeric comparisons are not supported",
    "gt": "numeric comparisons are not supported", "gte": "numeric comparisons are not supported",
    "exists": "exists is not supported; match null instead",
}
LEVELS = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
INFO_KEYS = {"title", "id", "status", "description", "level", "tags", "logsource", "detection", "author", "date",
             "modified", "references", "falsepositives", "fields", "license", "related", "name", "taxonomy"}
_TECHNIQUE_TAG = re.compile(r"attack\.(t[0-9]{4}(?:\.[0-9]{3})?)")


def _field(name):
    if not isinstance(name, str) or name not in FIELD_MAP:
        raise SigmaError(f"field {name!r} does not map to a Watchpost event field "
                         f"(supported: {', '.join(EVENT_FIELDS)}, their ECS names, and common Sigma names)")
    return FIELD_MAP[name]


def _value(v, where):
    if v is None or isinstance(v, (str, int)) and not isinstance(v, bool):
        if isinstance(v, str) and len(v) > 1024:
            raise SigmaError(f"{where}: values are at most 1024 characters")
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    raise SigmaError(f"{where}: values must be strings, numbers or null")


def _field_match(key, value, where):
    """One `field|mod|...: value(s)` entry -> a match node."""
    if not isinstance(key, str) or not key:
        raise SigmaError(f"{where}: field names must be strings")
    field, *mods = key.split("|")
    for mod in mods:
        if mod in REFUSED_MODIFIERS:
            raise SigmaError(f"{where}: modifier {mod!r} refused: {REFUSED_MODIFIERS[mod]}")
        if mod not in MODIFIERS:
            raise SigmaError(f"{where}: modifier {mod!r} is not supported (supported: {', '.join(MODIFIERS)})")
    if len(mods) != len(set(mods)):
        raise SigmaError(f"{where}: a modifier is repeated")
    kinds = [m for m in mods if m != "all"]
    if len(kinds) > 1:
        raise SigmaError(f"{where}: combine at most one of contains/startswith/endswith/cidr with all")
    values = value if isinstance(value, list) else [value]
    if not values or len(values) > MAX_VALUES:
        raise SigmaError(f"{where}: between 1 and {MAX_VALUES} values per field")
    values = [_value(v, where) for v in values]
    kind = kinds[0] if kinds else "eq"
    if kind == "cidr":
        for v in values:
            try:
                ipaddress.ip_network(str(v), strict=False)
            except ValueError:
                raise SigmaError(f"{where}: {v!r} is not a CIDR network")
    elif kind != "eq" and None in values:
        raise SigmaError(f"{where}: null cannot be combined with {kind}")
    return {"op": "match", "field": _field(field), "mod": kind, "all": "all" in mods, "values": values}


def _selection(name, body):
    where = f"selection {name!r}"
    if isinstance(body, dict):
        if not body:
            raise SigmaError(f"{where} is empty")
        args = [_field_match(k, v, where) for k, v in body.items()]
        return args[0] if len(args) == 1 else {"op": "and", "args": args}
    if isinstance(body, list) and body and all(isinstance(b, dict) for b in body):
        args = [_selection(name, b) for b in body]  # a list of maps: any of them
        return args[0] if len(args) == 1 else {"op": "or", "args": args}
    if isinstance(body, (list, str, int)) and not isinstance(body, bool):
        # Keywords: a bare value or list of values, matched as a substring of the event message.
        values = body if isinstance(body, list) else [body]
        if not values or len(values) > MAX_VALUES or not all(isinstance(v, (str, int)) and not isinstance(v, bool)
                                                              for v in values):
            raise SigmaError(f"{where}: keyword lists hold 1-{MAX_VALUES} strings")
        return {"op": "match", "field": "message", "mod": "contains", "all": False,
                "values": [_value(v, where) for v in values]}
    raise SigmaError(f"{where} must be a map of fields, a list of maps, or a keyword list")


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+)")


def _tokens(text):
    out, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = _TOKEN.match(text, i)
        if not m:
            raise SigmaError(f"condition: unexpected character {text[i:].strip()[0]!r}")
        out.append(m.group(1))
        i = m.end()
    return out


def _glob_names(pattern, names):
    """Selection names matching a condition pattern like 'sel*' (a trailing or embedded * only)."""
    return [n for n in names if _glob(_pattern(pattern), n.casefold())]


class _Condition:
    """Recursive descent: or_expr := and_expr ('or' and_expr)*; and_expr := not_expr ('and' not_expr)*;
    not_expr := 'not' not_expr | atom; atom := '(' or_expr ')' | ('1'|'all') 'of' (pattern|'them') | name."""

    def __init__(self, text, selections):
        if not isinstance(text, str) or not text.strip():
            raise SigmaError("condition must be a non-empty string (lists of conditions are not supported)")
        if len(text) > MAX_CONDITION:
            raise SigmaError(f"condition is at most {MAX_CONDITION} characters")
        if "|" in text:
            raise SigmaError("condition: aggregations ('| count() by ...') are not supported")
        if "near" in text.lower().split():
            raise SigmaError("condition: 'near' is not supported")
        self.toks, self.i, self.sel = _tokens(text), 0, selections

    def parse(self):
        node = self._or(0)
        if self.i != len(self.toks):
            raise SigmaError(f"condition: unexpected {self.toks[self.i]!r}")
        return node

    def _peek(self):
        return self.toks[self.i].lower() if self.i < len(self.toks) else None

    def _take(self):
        if self.i >= len(self.toks):
            raise SigmaError("condition: ends too early")
        self.i += 1
        return self.toks[self.i - 1]

    def _or(self, depth):
        args = [self._and(depth)]
        while self._peek() == "or":
            self.i += 1
            args.append(self._and(depth))
        return args[0] if len(args) == 1 else {"op": "or", "args": args}

    def _and(self, depth):
        args = [self._not(depth)]
        while self._peek() == "and":
            self.i += 1
            args.append(self._not(depth))
        return args[0] if len(args) == 1 else {"op": "and", "args": args}

    def _not(self, depth):
        if depth > MAX_DEPTH:
            raise SigmaError("condition: nested too deeply")
        if self._peek() == "not":
            self.i += 1
            return {"op": "not", "arg": self._not(depth + 1)}
        return self._atom(depth)

    def _atom(self, depth):
        tok = self._take()
        low = tok.lower()
        if tok == "(":
            node = self._or(depth + 1)
            if self._take() != ")":
                raise SigmaError("condition: missing ')'")
            return node
        if low in ("and", "or", ")", "of", "them"):
            raise SigmaError(f"condition: unexpected {tok!r}")
        if self._peek() == "of":
            if low not in ("1", "all"):
                raise SigmaError(f"condition: only '1 of' and 'all of' are supported, not '{tok} of'")
            self.i += 1
            target = self._take()
            names = sorted(self.sel) if target.lower() == "them" else _glob_names(target, sorted(self.sel))
            if target.lower() == "them":
                names = [n for n in names if not n.startswith("_")]
            if not names:
                raise SigmaError(f"condition: {target!r} matches no selection")
            args = [self.sel[n] for n in names]
            return args[0] if len(args) == 1 else {"op": "or" if low == "1" else "and", "args": args}
        if tok not in self.sel:
            raise SigmaError(f"condition: unknown selection {tok!r}")
        return self.sel[tok]


def slug(title):
    """Rule id for a Sigma title: sigma_<letters and underscores>. Never collides with a built-in rule id."""
    base = re.sub(r"[^a-z]+", "_", title.lower()).strip("_")[:48].strip("_")
    if not base:
        raise SigmaError("the title must contain letters (it names the rule id)")
    return RULE_PREFIX + base


def compile_rule(source):
    """Parse and compile Sigma YAML. Returns the compiled rule; raises SigmaError with a reason."""
    doc = parse_yaml(source)
    title = doc.get("title")
    if not isinstance(title, str) or not 1 <= len(title.strip()) <= 200:
        raise SigmaError("title is required (1-200 characters)")
    for key in ("id", "status", "description", "level"):
        if doc.get(key) is not None and not isinstance(doc[key], str):
            raise SigmaError(f"{key} must be a string")
    level = (doc.get("level") or "medium").lower()
    if level not in LEVELS:
        raise SigmaError(f"level {level!r} is not one of {', '.join(LEVELS)}")
    tags = doc.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise SigmaError("tags must be a list of strings")
    logsource = doc.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        raise SigmaError("logsource must be a mapping")
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError("detection is required and must be a mapping")
    if "timeframe" in detection:
        raise SigmaError("detection: timeframe is not supported (no time-window aggregation)")
    if "condition" not in detection:
        raise SigmaError("detection: condition is required")
    named = {k: v for k, v in detection.items() if k != "condition"}
    if not named or len(named) > MAX_SELECTIONS:
        raise SigmaError(f"detection needs 1-{MAX_SELECTIONS} named selections")
    for name in named:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.\-]+", name) or \
                name.lower() in ("and", "or", "not", "of", "them", "near", "all", "1"):
            raise SigmaError(f"selection name {name!r} is not usable in a condition")
    selections = {name: _selection(name, body) for name, body in named.items()}
    tree = _Condition(detection["condition"], selections).parse()
    _check_budget(tree)

    techniques, ignored_tags = [], []
    for tag in tags:
        m = _TECHNIQUE_TAG.fullmatch(tag.lower())
        if m and m.group(1).upper() in attack.TECHNIQUES:
            if m.group(1).upper() not in [t["id"] for t in techniques]:
                techniques.append(attack.technique(m.group(1).upper()))
        else:
            ignored_tags.append(tag)
    description = (doc.get("description") or "").strip()
    rule_id = slug(title)
    return {
        "rule_id": rule_id,
        "title": title.strip(),
        "sigma_id": doc.get("id"),
        "status": doc.get("status"),
        "description": description or f"Imported Sigma rule: {title.strip()}",
        "level": level,
        "severity": LEVELS[level],
        "techniques": techniques,
        "logsource": logsource or {},
        "params": {"title": title.strip()[:200], "detection": tree},
        "conditions": describe(tree),
        "warnings": ([f"tags not mapped to the ATT&CK catalog (kept out of coverage): {', '.join(ignored_tags)}"]
                     if ignored_tags else []) +
                    (["logsource is informational only: the rule runs on every stored event"] if logsource else []) +
                    [f"key {k!r} is ignored" for k in sorted(set(doc) - INFO_KEYS)],
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def describe(node):
    """The compiled tree as one readable line, e.g. (event_type = 'auth_failure' AND src_ip in 10.0.0.0/8)."""
    op = node["op"]
    if op == "not":
        return f"NOT {describe(node['arg'])}"
    if op in ("and", "or"):
        return "(" + f" {op.upper()} ".join(describe(a) for a in node["args"]) + ")"
    verb = {"eq": "=", "contains": "contains", "startswith": "starts with", "endswith": "ends with",
            "cidr": "in"}[node["mod"]]
    vals = [("null" if v is None else repr(v)) for v in node["values"]]
    joined = vals[0] if len(vals) == 1 else ("all of " if node["all"] else "any of ") + "[" + ", ".join(vals) + "]"
    return f"{node['field']} {verb} {joined}"


def validate_params(params):
    """Check a stored compiled tree before it runs (it came from compile_rule; this guards edits)."""
    if not isinstance(params, dict) or set(params) != {"title", "detection"} or not isinstance(params["title"], str):
        raise SigmaError("Sigma rule params must be the compiled {title, detection}; they are not tunable")

    def check(node, depth):
        if depth > 4 * MAX_DEPTH or not isinstance(node, dict):
            raise SigmaError("compiled detection is malformed")
        op = node.get("op")
        if op in ("and", "or"):
            if set(node) != {"op", "args"} or not isinstance(node["args"], list) or not node["args"]:
                raise SigmaError("compiled detection is malformed")
            for a in node["args"]:
                check(a, depth + 1)
        elif op == "not":
            if set(node) != {"op", "arg"}:
                raise SigmaError("compiled detection is malformed")
            check(node["arg"], depth + 1)
        elif op == "match":
            if set(node) != {"op", "field", "mod", "all", "values"} or node["field"] not in EVENT_FIELDS \
                    or node["mod"] not in ("eq", "contains", "startswith", "endswith", "cidr") \
                    or not isinstance(node["values"], list) or not node["values"]:
                raise SigmaError("compiled detection is malformed")
        else:
            raise SigmaError("compiled detection is malformed")

    check(params["detection"], 0)
    _check_budget(params["detection"])
    return params


def _check_budget(tree):
    """Refuse a compiled detection that would compare too many values per event (see MAX_COMPILED_VALUES)."""
    values = chars = 0
    stack = [tree]
    while stack:
        node = stack.pop()
        if node["op"] in ("and", "or"):
            stack.extend(node["args"])
        elif node["op"] == "not":
            stack.append(node["arg"])
        else:
            values += len(node["values"])
            chars += sum(len(str(v)) for v in node["values"])
        if values > MAX_COMPILED_VALUES or chars > MAX_COMPILED_CHARS:
            raise SigmaError(f"the compiled detection is too large (at most {MAX_COMPILED_VALUES} values and "
                             f"{MAX_COMPILED_CHARS // 1024} KB once the condition is expanded); a condition that "
                             "names the same selections many times multiplies them")


# --- Evaluation ---------------------------------------------------------------------------------

_STAR, _ONE = object(), object()


def _pattern(value):
    """Sigma value -> list of casefolded chars and wildcard markers. `\\*`, `\\?` and `\\\\` are literals."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and value[i + 1:i + 2] in ("*", "?", "\\"):
            out.extend(value[i + 1].casefold())
            i += 2
            continue
        if c == "*":
            if not out or out[-1] is not _STAR:
                out.append(_STAR)
        elif c == "?":
            out.append(_ONE)
        else:
            out.extend(c.casefold())
        i += 1
    return out


def _glob(pattern, text):
    """Wildcard match in O(len(pattern) * len(text)): backtrack only to the last star."""
    p = t = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] is not _STAR and (pattern[p] is _ONE or pattern[p] == text[t]):
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] is _STAR:
            star, mark = p, t
            p += 1
        elif star >= 0:
            p, mark = star + 1, mark + 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] is _STAR:
        p += 1
    return p == len(pattern)


class _Compiled:
    """Patterns prepared once per run; `matches(event)` then walks the tree."""

    def __init__(self, tree):
        self.tree = tree
        self.cache = {}

    def _patterns(self, node):
        key = id(node)
        if key not in self.cache:
            pats = []
            for v in node["values"]:
                if v is None:
                    pats.append(None)
                elif node["mod"] == "cidr":
                    pats.append(ipaddress.ip_network(str(v), strict=False))
                else:
                    pat = _pattern(str(v))
                    if node["mod"] in ("contains", "endswith") and (not pat or pat[0] is not _STAR):
                        pat = [_STAR] + pat
                    if node["mod"] in ("contains", "startswith") and (not pat or pat[-1] is not _STAR):
                        pat = pat + [_STAR]
                    pats.append(pat)
            self.cache[key] = pats
        return self.cache[key]

    def _one(self, pat, mod, value):
        if pat is None:
            return value is None or value == ""
        if value is None or value == "":
            return False
        if mod == "cidr":
            try:
                return ipaddress.ip_address(str(value)) in pat
            except ValueError:
                return False
        return _glob(pat, str(value).casefold())

    def matches(self, event, node=None):
        node = self.tree if node is None else node
        op = node["op"]
        if op == "and":
            return all(self.matches(event, a) for a in node["args"])
        if op == "or":
            return any(self.matches(event, a) for a in node["args"])
        if op == "not":
            return not self.matches(event, node["arg"])
        value = event.get(node["field"])
        hits = (self._one(p, node["mod"], value) for p in self._patterns(node))
        return all(hits) if node["all"] else any(hits)


def matches(params, event):
    return _Compiled(params["detection"]).matches(event)


def group_key(event):
    """Findings are grouped per source IP; events without one by host, then by user."""
    return event.get("src_ip") or event.get("host") or event.get("user") or "unknown"


def run(events, params):
    """The rule function for a Sigma rule: (events, params) -> findings, like the built-in rules.

    Every matching event counts (there is no threshold). Matching events are grouped by `group_key`, and
    within a group events more than GROUP_GAP_SECONDS apart start a new finding.
    """
    compiled = _Compiled(params["detection"])
    title = params["title"]
    groups = defaultdict(list)
    for e in events:
        if compiled.matches(e):
            groups[group_key(e)].append(e)
    findings = []
    for key, group in groups.items():
        group.sort(key=lambda e: (e["ts"], e["id"]))
        cluster = []
        for e in group:
            if cluster and (parse_iso(e["ts"]) - parse_iso(cluster[-1]["ts"])).total_seconds() > GROUP_GAP_SECONDS:
                findings.append(_finding(key, cluster, title))
                cluster = []
            cluster.append(e)
        findings.append(_finding(key, cluster, title))
    return findings


def _finding(key, cluster, title):
    return {
        "group_key": key,
        "event_ids": [e["id"] for e in cluster],
        "first_seen": cluster[0]["ts"],
        "last_seen": cluster[-1]["ts"],
        "title": f"{title}: {len(cluster)} matching event(s) for {key}",
        "explanation": f"{len(cluster)} event(s) for {key} between {cluster[0]['ts']} and {cluster[-1]['ts']} "
                       f"matched the imported Sigma rule {title!r}.",
    }


# --- Labeled sample (the rule's own noise-lab scenario) -----------------------------------------

SAMPLE_FIELDS = set(EVENT_FIELDS) | {"ts"}


def validate_sample(sample, fields=SAMPLE_FIELDS):
    """{"malicious": [events], "benign": [events]}: at least one of each, Watchpost field names only
    (`fields`: the names a sample event may use; promoted saved searches pass their own)."""
    if not isinstance(sample, dict) or set(sample) != {"malicious", "benign"}:
        raise SigmaError("sample must be an object with 'malicious' and 'benign' event lists")
    out = {}
    for side in ("malicious", "benign"):
        events = sample[side]
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_SAMPLE_EVENTS:
            raise SigmaError(f"sample.{side} must list 1-{MAX_SAMPLE_EVENTS} events")
        out[side] = []
        for n, e in enumerate(events):
            if not isinstance(e, dict) or not e:
                raise SigmaError(f"sample.{side}[{n}] must be a non-empty object")
            unknown = set(e) - set(fields)
            if unknown:
                raise SigmaError(f"sample.{side}[{n}]: unknown field(s) {', '.join(sorted(unknown))} "
                                 f"(use Watchpost names: {', '.join(sorted(fields))})")
            for k, v in e.items():
                ok = v is None or (isinstance(v, int) and not isinstance(v, bool) if k in ("dest_port", "bytes")
                                   else isinstance(v, str) and len(v) <= SAMPLE_VALUE_LIMIT)
                if not ok:
                    raise SigmaError(f"sample.{side}[{n}].{k} has the wrong type")
            out[side].append(dict(e))
    return out


def sample_result(params, sample):
    """Run the rule over its sample, event by event. Passes when every malicious event matches and no benign
    look-alike does. None when there is no sample."""
    if not sample:
        return None
    compiled = _Compiled(params["detection"])
    missed = [i for i, e in enumerate(sample["malicious"]) if not compiled.matches(e)]
    fired = [i for i, e in enumerate(sample["benign"]) if compiled.matches(e)]
    passes = not missed and not fired
    reasons = []
    if missed:
        reasons.append(f"{len(missed)} malicious event(s) not matched (#{', #'.join(map(str, missed))})")
    if fired:
        reasons.append(f"{len(fired)} benign look-alike(s) matched (#{', #'.join(map(str, fired))})")
    return {"malicious": len(sample["malicious"]), "benign": len(sample["benign"]), "missed": missed,
            "fired": fired, "passes": passes,
            "summary": "passes: every malicious event matches and no benign look-alike does" if passes
            else "fails: " + "; ".join(reasons)}


def is_sigma(rule_id):
    return isinstance(rule_id, str) and rule_id.startswith(RULE_PREFIX)


def stored(conn, rule_id):
    """The sigma_rules row for a rule, with the sample decoded, or None."""
    row = conn.execute("SELECT * FROM sigma_rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["sample"] = json.loads(out["sample"]) if out["sample"] else None
    return out


def stored_result(conn, rule_id):
    """The current sample result of a stored Sigma rule (None without a sample)."""
    rec = stored(conn, rule_id)
    row = conn.execute("SELECT params FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if rec is None or row is None:
        return None
    return sample_result(json.loads(row["params"]), rec["sample"])


def sample_scenarios(conn):
    """Each Sigma rule's sample as a labeled malicious scenario, tagged with the rule's techniques
    (shape of simulate.SCENARIOS entries that attack.evidence reads)."""
    out = {}
    for row in conn.execute("SELECT r.id, r.techniques FROM rules r JOIN sigma_rules s ON s.rule_id = r.id"
                            " WHERE s.sample IS NOT NULL"):
        out[SAMPLE_PREFIX + row["id"]] = {"malicious": True,
                                          "techniques": [t["id"] for t in json.loads(row["techniques"] or "[]")]}
    return out


# --- Store (called only from an approved change request) ---------------------------------------

def add_rule(conn, compiled, source, sample, proposed_by, approved_by, change_request_id, now):
    """Insert an approved Sigma rule, disabled, with its source, sha256 and sample."""
    rule_id = compiled["rule_id"]
    params = json.dumps(compiled["params"])
    conn.execute(
        "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by,"
        " techniques) VALUES (?,?,?,?,0,?,1,?,?,?)",
        (rule_id, compiled["title"], compiled["description"][:2000], compiled["severity"], params, now, approved_by,
         json.dumps(compiled["techniques"])))
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, 1, 0, params, now, proposed_by, approved_by, change_request_id, "imported from Sigma (disabled)"))
    conn.execute(
        "INSERT INTO sigma_rules(rule_id, source, sha256, sigma_id, sample, imported_by, approved_by,"
        " change_request_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, source, compiled["sha256"], compiled["sigma_id"], json.dumps(sample) if sample else None,
         proposed_by, approved_by, change_request_id, now))


def set_sample(conn, rule_id, sample, proposed_by, approved_by, change_request_id, now):
    """Replace a Sigma rule's sample. Bumps the rule version so history (and cached evaluations) see it."""
    rule = conn.execute("SELECT version, enabled, params FROM rules WHERE id = ?", (rule_id,)).fetchone()
    version = rule["version"] + 1
    conn.execute("UPDATE sigma_rules SET sample = ? WHERE rule_id = ?", (json.dumps(sample), rule_id))
    conn.execute("UPDATE rules SET version = ?, updated_at = ?, updated_by = ? WHERE id = ?",
                 (version, now, approved_by, rule_id))
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, version, rule["enabled"], rule["params"], now, proposed_by, approved_by, change_request_id,
         "labeled sample replaced"))
    return version


def preview(conn, params, window_days=7, max_events=100_000):
    """What the compiled rule would match among stored events: a backtest of a rule that does not exist yet
    (backtest.preview_new_rule, shared with promoted saved searches)."""
    from . import backtest

    compiled = _Compiled(params["detection"])
    return backtest.preview_new_rule(conn, "sigma_preview", params, compiled.matches, window_days, max_events)
