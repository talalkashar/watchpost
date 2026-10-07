"""Hunting: a one-line query language over events, and saved searches.

    user:alice event_type:auth_failure NOT src_ip:10.0.0.5 host:web* "invalid password" last:24h

Terms are ANDed. `field:value` matches a column (a trailing `*` on an unquoted value is a prefix match),
`field:"quoted value"` matches literally, bare or quoted words search the message, and `NOT term` or `-term`
negates one term. Time is `last:15m|24h|7d`, `since:<ISO>` and `until:<ISO>`. Field names come from a
whitelist and become SQL column names only through FIELDS; every value is a bound parameter.
"""

import re
from datetime import timedelta

from .db import audit, iso, now_iso, transaction, utcnow
from .normalize import EVENT_TYPES, SEVERITIES, EventError, parse_timestamp
from .queries import QueryError, _escape_like, page_events

# Same 400/404/409 handling in the server as every other query error.
HuntError = QueryError

MAX_QUERY_LENGTH = 500
MAX_TERMS = 20
NAME_MAX, DESCRIPTION_MAX = 80, 300

# Query field -> (kind, column). The column text is the only part of a term that reaches the SQL string.
FIELDS = {
    "user": ("text", "user"), "host": ("text", "host"), "source": ("text", "source"),
    "outcome": ("text", "outcome"), "src_ip": ("text", "src_ip"), "dest_ip": ("text", "dest_ip"),
    "batch_id": ("text", "batch_id"), "ip": ("ip", None),
    "event_type": ("enum", "event_type"), "severity": ("enum", "severity"),
    "dest_port": ("port", "dest_port"), "synthetic": ("flag", "synthetic"), "message": ("message", "message"),
    "last": ("time", None), "since": ("time", None), "until": ("time", None),
}
ENUMS = {"event_type": sorted(EVENT_TYPES), "severity": SEVERITIES}
FLAGS = {"1": 1, "true": 1, "0": 0, "false": 0}
LAST_UNITS = {"m": 1, "h": 60, "d": 1440}
LAST_MAX_MINUTES = 365 * 1440

_FIELD = re.compile(r"([A-Za-z_]+):")
_LAST = re.compile(r"(\d{1,6})([mhd])")


def parse(text):
    """Split a query into terms: [{field, value, negate, quoted}]. Raises HuntError on bad syntax."""
    if not isinstance(text, str):
        raise HuntError("query must be text")
    if len(text) > MAX_QUERY_LENGTH:
        raise HuntError(f"query must be at most {MAX_QUERY_LENGTH} characters")
    terms, pos, negate = [], 0, False
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        end = pos
        while end < len(text) and not text[end].isspace():
            end += 1
        word = text[pos:end]
        if word == "NOT" or text[pos] == "-":
            if negate or word == "-":
                raise HuntError("NOT (or -) must be followed by a term")
            negate, pos = True, (end if word == "NOT" else pos + 1)
            continue
        if word == "AND" and not negate:
            pos = end  # terms are ANDed anyway
            continue
        if word == "OR":
            raise HuntError("OR is not supported; terms are always ANDed (run two hunts instead)")
        field, match = "message", _FIELD.match(text, pos)
        if match:
            field = match.group(1).lower()
            if field not in FIELDS:
                raise HuntError(f"unknown field {field!r}; fields are {', '.join(FIELDS)} "
                                "(quote text that contains ':' to search the message)")
            pos = match.end()
        value, quoted, pos = _value(text, pos, field)
        terms.append({"field": field, "value": value, "negate": negate, "quoted": quoted})
        negate = False
        if len(terms) > MAX_TERMS:
            raise HuntError(f"query must have at most {MAX_TERMS} terms")
    if negate:
        raise HuntError("NOT (or -) must be followed by a term")
    return terms


def _value(text, pos, field):
    if pos < len(text) and text[pos] == '"':
        chars, pos = [], pos + 1
        while True:
            if pos >= len(text):
                raise HuntError("unterminated quote")
            ch = text[pos]
            if ch == "\\" and pos + 1 < len(text):
                chars.append(text[pos + 1])
                pos += 2
                continue
            if ch == '"':
                break
            chars.append(ch)
            pos += 1
        pos += 1
        if pos < len(text) and not text[pos].isspace():
            raise HuntError("unexpected text after a closing quote; put a space between terms")
        value, quoted = "".join(chars), True
    else:
        end = pos
        while end < len(text) and not text[end].isspace():
            end += 1
        value, quoted, pos = text[pos:end], False, end
    if value == "":
        raise HuntError(f"{field}: needs a value")
    return value, quoted, pos


def _term_sql(term, now):
    """(sql, args, text) for one term. Column names come from FIELDS, values only from args."""
    field, value = term["field"], term["value"]
    kind, column = FIELDS[field]
    prefix = value[:-1] if value.endswith("*") and not term["quoted"] else None
    if kind == "time":
        if term["negate"]:
            raise HuntError(f"{field} cannot be negated")
        if field == "last":
            match = _LAST.fullmatch(value)
            minutes = int(match.group(1)) * LAST_UNITS[match.group(2)] if match else 0
            if not 1 <= minutes <= LAST_MAX_MINUTES:
                raise HuntError("last must be a number with m, h or d, such as 15m, 24h or 7d (at most 365d)")
            start = iso(now - timedelta(minutes=minutes))
            return "ts >= ?", [start], f"time >= {start} (last {value})"
        try:
            bound = parse_timestamp(value, now)
        except EventError as exc:
            raise HuntError(f"{field}: {exc}")
        op = ">=" if field == "since" else "<="
        return f"ts {op} ?", [bound], f"time {op} {bound}"
    if kind == "message":
        text = prefix if prefix else value  # a trailing * on a word adds nothing to "contains"
        return "message LIKE ? ESCAPE '\\'", ["%" + _escape_like(text) + "%"], f'message contains "{text}"'
    if kind == "port":
        if not value.isdigit() or int(value) > 65535:
            raise HuntError("dest_port must be an integer between 0 and 65535")
        return "dest_port = ?", [int(value)], f"dest_port = {int(value)}"
    if kind == "flag":
        if value.lower() not in FLAGS:
            raise HuntError("synthetic must be 0, 1, true or false")
        return "synthetic = ?", [FLAGS[value.lower()]], f"synthetic = {FLAGS[value.lower()]}"
    if kind == "ip":
        if prefix is not None:
            pattern = _escape_like(prefix) + "%"
            return ("(src_ip LIKE ? ESCAPE '\\' OR dest_ip LIKE ? ESCAPE '\\')", [pattern, pattern],
                    f"src_ip or dest_ip starts with {prefix}")
        return "(src_ip = ? OR dest_ip = ?)", [value, value], f"src_ip or dest_ip = {value}"
    if prefix is not None:
        return f"{column} LIKE ? ESCAPE '\\'", [_escape_like(prefix) + "%"], f"{field} starts with {prefix}"
    if kind == "enum" and value not in ENUMS[field]:
        raise HuntError(f"{field} must be one of {', '.join(ENUMS[field])}")
    # Same matching as the Events filter: user names compare case-insensitively.
    collate = " COLLATE NOCASE" if field == "user" else ""
    return f"{column} = ?{collate}", [value], f"{field} = {value}"


def _compile(text, now=None):
    now = now or utcnow()
    compiled = []
    for term in parse(text):
        sql, args, label = _term_sql(term, now)
        if term["negate"]:
            # NOT of a NULL comparison is NULL, which would also drop events missing the field: keep them.
            sql, label = f"NOT COALESCE(({sql}), 0)", "NOT " + label
        compiled.append((sql, args, {"field": term["field"], "value": term["value"], "negate": term["negate"],
                                     "text": label}))
    return compiled


def compile_query(text, now=None):
    """(where fragments, args) for a query; the fragments are ANDed by queries.page_events."""
    compiled = _compile(text, now)
    return [sql for sql, _, _ in compiled], [a for _, args, _ in compiled for a in args]


def explain(text, now=None):
    """How each term was read, for the UI's "how this was parsed" chips."""
    return [echo for _, _, echo in _compile(text, now)]


def run(conn, params, now=None):
    text = params.get("q") or ""
    compiled = _compile(text, now)
    page = page_events(conn, [sql for sql, _, _ in compiled], [a for _, args, _ in compiled for a in args], params)
    page["query"] = text
    page["terms"] = [echo for _, _, echo in compiled]
    return page


# --- Saved searches ----------------------------------------------------------------------

def _text(value, name, limit, required=False):
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise HuntError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise HuntError(f"{name} must be text")
    value = value.strip()
    if len(value) > limit:
        raise HuntError(f"{name} must be at most {limit} characters")
    return value


def list_saved(conn):
    return [dict(r) for r in conn.execute(
        "SELECT id, name, query, description, owner, created_at FROM saved_searches ORDER BY name COLLATE NOCASE")]


def save_search(conn, data, actor):
    name = _text(data.get("name"), "name", NAME_MAX, required=True)
    query = data.get("query")
    if not isinstance(query, str) or not query.strip():
        raise HuntError("query is required")
    query = query.strip()
    compile_query(query)  # a saved search must run
    description = _text(data.get("description"), "description", DESCRIPTION_MAX)
    with transaction(conn):
        if conn.execute("SELECT 1 FROM saved_searches WHERE name = ?", (name,)).fetchone():
            raise HuntError(f"a saved search named {name!r} already exists", 409)
        cur = conn.execute("INSERT INTO saved_searches(name, query, description, owner, created_at)"
                           " VALUES (?, ?, ?, ?, ?)", (name, query, description, actor, now_iso()))
        audit(conn, actor, "saved_search_created", name, {"id": cur.lastrowid, "query": query})
    return dict(conn.execute("SELECT id, name, query, description, owner, created_at FROM saved_searches"
                             " WHERE id = ?", (cur.lastrowid,)).fetchone())


def delete_saved(conn, search_id, actor, is_admin):
    """Analysts delete their own saved searches; admins can delete any."""
    with transaction(conn):
        row = conn.execute("SELECT name, query, owner FROM saved_searches WHERE id = ?", (search_id,)).fetchone()
        if row is None:
            raise HuntError("saved search not found", 404)
        if row["owner"] != actor and not is_admin:
            raise HuntError("only the owner or an admin can delete this saved search", 403)
        conn.execute("DELETE FROM saved_searches WHERE id = ?", (search_id,))
        audit(conn, actor, "saved_search_deleted", row["name"], {"id": search_id, "query": row["query"]})
    return {"ok": True}
