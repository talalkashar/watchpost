"""Hunting: a one-line query language over events, and saved searches.

    user:alice event_type:auth_failure NOT src_ip:10.0.0.5 host:web* "invalid password" last:24h

Terms are ANDed. `field:value` matches a column (a trailing `*` on an unquoted value is a prefix match),
`field:"quoted value"` matches literally, bare or quoted words search the message, and `NOT term` or `-term`
negates one term. Time is `last:15m|24h|7d`, `since:<ISO>` and `until:<ISO>`. Field names come from a
whitelist and become SQL column names only through FIELDS; every value is a bound parameter.

An optional single pipeline stage after the filter aggregates the matched events in SQL:

    event_type:auth_failure last:24h | stats count, dc(user) by src_ip
    event_type:auth_failure | top 10 src_ip
    host:web* last:24h | timechart span=1h count by user

A `|` starts the stage only at the start of a word; inside a quoted value or an unquoted word it is literal.
"""

import re
from datetime import datetime, timedelta, timezone

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

# Pipeline stage caps. Group columns come from FIELDS like filter terms do.
COMMANDS = ("stats", "top", "timechart")
GROUP_KINDS = ("text", "enum", "port", "flag")
GROUPABLE = [f for f, (kind, _) in FIELDS.items() if kind in GROUP_KINDS]
MAX_GROUPS = 1000
MAX_BY = 2
MAX_AGGREGATES = 3
TOP_DEFAULT, TOP_MAX = 10, 100
SPANS = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "1d": 86400}
MAX_BUCKETS = 500
MAX_SERIES = 5
_STAGE_TOKEN = re.compile(r"\w+\s*\([^()]*\)|[^\s,()]+|[,()]")
_AGGREGATE = re.compile(r"dc\(\s*(\S+?)\s*\)|count\(\s*distinct\s+(\S+?)\s*\)", re.IGNORECASE)
# Bucket start in Unix seconds, computed in SQL from the canonical "YYYY-MM-DDTHH:MM:SS.mmmZ" ts.
_BUCKET = "(CAST(strftime('%s', substr(ts, 1, 19)) AS INTEGER) / ?) * ?"


def parse(text):
    """Split a query into terms: [{field, value, negate, quoted}]. Raises HuntError on bad syntax.
    Any pipeline stage is ignored here; _parse returns it."""
    return _parse(text)[0]


def _parse(text):
    """(terms, stage text after the first word-leading `|` or None)."""
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
        if text[pos] == "|":
            if negate:
                raise HuntError("NOT (or -) must be followed by a term")
            return terms, text[pos + 1:]
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
    return terms, None


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
    """(compiled terms, parsed pipeline stage or None)."""
    now = now or utcnow()
    terms, stage = _parse(text)
    stage = parse_stage(stage) if stage is not None else None
    compiled = []
    for term in terms:
        sql, args, label = _term_sql(term, now)
        if term["negate"]:
            # NOT of a NULL comparison is NULL, which would also drop events missing the field: keep them.
            sql, label = f"NOT COALESCE(({sql}), 0)", "NOT " + label
        compiled.append((sql, args, {"field": term["field"], "value": term["value"], "negate": term["negate"],
                                     "text": label}))
    return compiled, stage


def compile_query(text, now=None):
    """(where fragments, args) for a query's filter; the fragments are ANDed by queries.page_events.
    A pipeline stage is parsed and checked too, so a query that compiles also runs."""
    compiled, _ = _compile(text, now)
    return [sql for sql, _, _ in compiled], [a for _, args, _ in compiled for a in args]


def explain(text, now=None):
    """How each term was read, for the UI's "how this was parsed" chips."""
    return [echo for _, _, echo in _compile(text, now)[0]]


def run(conn, params, now=None):
    text = params.get("q") or ""
    now = now or utcnow()
    compiled, stage = _compile(text, now)
    where, args = [sql for sql, _, _ in compiled], [a for _, args, _ in compiled for a in args]
    terms = [echo for _, _, echo in compiled]
    if stage is None:
        page = page_events(conn, where, args, params)
        page["query"] = text
        page["terms"] = terms
        return page
    if stage["command"] == "stats":
        result = _stats(conn, where, args, stage)
    elif stage["command"] == "top":
        result = _top(conn, where, args, stage)
    else:
        result = _timechart(conn, where, args, stage, _window(compiled, now))
    result.update(kind=stage["command"], terms=terms, query=text, filter=_parse_filter_text(text))
    return result


# --- Pipeline stage: stats, top, timechart ------------------------------------------------

def _parse_filter_text(text):
    """The query text before the pipe (for the UI's pivot links, which add terms to the filter)."""
    _, stage = _parse(text)
    return text[:len(text) - len(stage) - 1].strip() if stage is not None else text.strip()


def _group_field(name):
    """(field, column) for a field a stage may group or count by; refuses the rest with a reason."""
    field = name.lower()
    if field not in FIELDS:
        raise HuntError(f"unknown field {name!r}; group by one of {', '.join(GROUPABLE)}")
    kind, column = FIELDS[field]
    if kind == "message":
        raise HuntError(f"message is free text and cannot be grouped; group by one of {', '.join(GROUPABLE)}")
    if kind == "time":
        raise HuntError(f"{field} is a time filter, not a field; use timechart to count events over time")
    if kind == "ip":
        raise HuntError("ip means src_ip or dest_ip; group by src_ip or dest_ip instead")
    return field, column


def _by_fields(tokens, limit):
    """Fields after `by`, comma separated (commas optional)."""
    names = [t for t in tokens if t != ","]
    if not names:
        raise HuntError("put a field after by")
    if len(names) > limit:
        raise HuntError("timechart by takes one field" if limit == 1 else f"by takes at most {limit} fields")
    fields = [_group_field(n) for n in names]
    if len({f for f, _ in fields}) != len(fields):
        raise HuntError("a field appears more than once after by")
    return fields


def parse_stage(text):
    """Parse the text after `|` into {command, ...}. Raises HuntError with the reason on anything else."""
    if "|" in text:
        raise HuntError("only one | stage is supported (stats, top or timechart)")
    tokens = _STAGE_TOKEN.findall(text)
    if not tokens:
        raise HuntError("| must be followed by a command: stats, top or timechart")
    command, rest = tokens[0].lower(), tokens[1:]
    if command not in COMMANDS:
        raise HuntError(f"unknown command {tokens[0]!r}; supported commands are stats, top and timechart")
    lowered = [t.lower() for t in rest]
    if command == "stats":
        split = lowered.index("by") if "by" in lowered else len(rest)
        aggregates = []
        for token in rest[:split]:
            if token == ",":
                continue
            if token.lower() == "count":
                aggregates.append(("count", None))
                continue
            match = _AGGREGATE.fullmatch(token)
            if not match:
                raise HuntError(f"unknown aggregate {token!r}; stats supports count and dc(<field>)"
                                " (also written count(distinct <field>))")
            field, column = _group_field(match.group(1) or match.group(2))
            aggregates.append((f"dc({field})", column))
        if not aggregates:
            raise HuntError("stats needs an aggregate: count or dc(<field>), e.g. | stats count by src_ip")
        if len(aggregates) > MAX_AGGREGATES or len(set(aggregates)) != len(aggregates):
            raise HuntError(f"stats takes at most {MAX_AGGREGATES} different aggregates")
        by = _by_fields(rest[split + 1:], MAX_BY) if split < len(rest) else []
        return {"command": "stats", "aggregates": aggregates, "by": by}
    if command == "top":
        words = [t for t in rest if t != ","]
        limit = TOP_DEFAULT
        if len(words) == 2 and words[0].isdigit():
            limit = int(words[0])
            if not 1 <= limit <= TOP_MAX:
                raise HuntError(f"top N must be between 1 and {TOP_MAX}")
            words = words[1:]
        if len(words) != 1 or words[0].isdigit():
            raise HuntError("top takes one field, optionally after a count: | top src_ip or | top 10 src_ip")
        return {"command": "top", "limit": limit, "by": [_group_field(words[0])]}
    span, by, pos = None, [], 0
    while pos < len(rest):
        token = lowered[pos]
        if token.startswith("span="):
            if span is not None or token[5:] not in SPANS:
                raise HuntError(f"timechart span must be one of {', '.join(SPANS)} (given once)")
            span = token[5:]
        elif token == "by":
            by = _by_fields(rest[pos + 1:], 1)
            break
        elif token != "count":
            raise HuntError(f"unexpected {rest[pos]!r}; use | timechart span=1h [count] [by <field>]")
        pos += 1
    if span is None:
        raise HuntError(f"timechart needs span=<{'|'.join(SPANS)}>, e.g. | timechart span=1h count")
    return {"command": "timechart", "span": span, "by": by}


def _where(where, extra=()):
    clause = list(where) + list(extra)
    return (" WHERE " + " AND ".join(clause)) if clause else ""


def _stats(conn, where, args, stage):
    by = stage["by"]
    columns = [c for _, c in by]
    selects = columns + ["COUNT(*)" if column is None else f"COUNT(DISTINCT {column})"
                         for _, column in stage["aggregates"]]
    sql = f"SELECT {', '.join(selects)} FROM events{_where(where, [f'{c} IS NOT NULL' for c in columns])}"
    if by:
        order = [f"{len(by) + 1} DESC"] + [str(n + 1) for n in range(len(by))]
        sql += f" GROUP BY {', '.join(columns)} ORDER BY {', '.join(order)} LIMIT ?"
        rows = [list(r) for r in conn.execute(sql, args + [MAX_GROUPS + 1])]
    else:
        rows = [list(conn.execute(sql, args).fetchone())]
    return {"columns": [f for f, _ in by] + [name for name, _ in stage["aggregates"]],
            "rows": rows[:MAX_GROUPS], "truncated": len(rows) > MAX_GROUPS}


def _top(conn, where, args, stage):
    (field, column), = stage["by"]
    total = conn.execute(f"SELECT COUNT(*) FROM events{_where(where)}", args).fetchone()[0]
    rows = conn.execute(f"SELECT {column}, COUNT(*) FROM events{_where(where, [f'{column} IS NOT NULL'])}"
                        f" GROUP BY {column} ORDER BY 2 DESC, 1 LIMIT ?", args + [stage["limit"] + 1]).fetchall()
    return {"columns": [field, "count", "percent"],
            "rows": [[value, count, round(100 * count / total, 2)] for value, count in rows[:stage["limit"]]],
            "truncated": len(rows) > stage["limit"]}


def _window(compiled, now):
    """(start, end) ISO bounds the time terms put on the query; either may be None."""
    starts, ends = [], []
    for _, args, echo in compiled:
        if echo["field"] in ("last", "since"):
            starts.append(args[0])
        if echo["field"] == "last":
            ends.append(iso(now))
        elif echo["field"] == "until":
            ends.append(args[0])
    return (max(starts) if starts else None), (min(ends) if ends else None)


def _epoch(ts):
    return int(datetime.fromisoformat(ts[:19]).replace(tzinfo=timezone.utc).timestamp())


def _timechart(conn, where, args, stage, window):
    """Counts per span bucket, every bucket in range filled (0 when empty), refused past MAX_BUCKETS."""
    span = SPANS[stage["span"]]
    start, end = window
    if start is None or end is None:
        low, high = conn.execute(f"SELECT MIN(ts), MAX(ts) FROM events{_where(where)}", args).fetchone()
        start, end = start or low, end or high
    by = stage["by"]
    columns = ["_time"] + ([] if by else ["count"])
    if start is None or end is None or start > end:
        return {"columns": columns, "rows": [], "truncated": False}
    first, last = _epoch(start) // span * span, _epoch(end) // span * span
    buckets = (last - first) // span + 1
    if buckets > MAX_BUCKETS:
        raise HuntError(f"timechart span={stage['span']} needs {buckets:,} buckets here, and at most "
                        f"{MAX_BUCKETS} are drawn; narrow the time range (last:, since:, until:) or use a wider span")
    series = []
    if by:
        (_, column), = by
        series = [r[0] for r in conn.execute(
            f"SELECT {column} FROM events{_where(where, [f'{column} IS NOT NULL'])}"
            f" GROUP BY {column} ORDER BY COUNT(*) DESC, 1 LIMIT ?", args + [MAX_SERIES])]
        marks = ", ".join("?" for _ in series) or "NULL"
        sql = (f"SELECT {_BUCKET} AS bucket, CASE WHEN {column} IN ({marks}) THEN {column} END AS series, COUNT(*)"
               f" FROM events{_where(where)} GROUP BY bucket, series LIMIT ?")
        params = [span, span] + series + args + [MAX_BUCKETS * (MAX_SERIES + 1)]
    else:
        sql = f"SELECT {_BUCKET} AS bucket, NULL, COUNT(*) FROM events{_where(where)} GROUP BY bucket LIMIT ?"
        params = [span, span] + args + [MAX_BUCKETS]
    counts = {}
    for bucket, value, count in conn.execute(sql, params):
        counts[(bucket, value)] = count
    keys = [None]
    if by:
        # Everything outside the top series (including events without the field) is one "other" series.
        has_other = any(value is None for _, value in counts)
        other = "other" if "other" not in [str(s) for s in series] else "(other)"
        columns += [str(s) for s in series] + ([other] if has_other else [])
        keys = series + ([None] if has_other else [])
    rows = [[iso(datetime.fromtimestamp(t, timezone.utc))] + [counts.get((t, k), 0) for k in keys]
            for t in range(first, last + 1, span)]
    return {"columns": columns, "rows": rows, "truncated": False}


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
    compile_query(query)  # a saved search must run (this checks a pipeline stage too)
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
