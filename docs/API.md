# Watchpost API

Base URL: `http://127.0.0.1:8080`. All request and response bodies are JSON unless noted otherwise. Errors come back as `{"error": "..."}`. A 4xx from the API and the generic 500 send `Cache-Control: no-store`, the same as a successful `/api` response, because the message can repeat a request value. A missing static file is 404 `not found` (`text/plain`) and a non-GET on a static path is 405 `{"error": "method not allowed"}`. Both send `Cache-Control: no-store`. A static file that exists stays `Cache-Control: no-cache`. A query string may name each key once. A repeated key (`severity=low&severity=critical`) is 400 `repeated query key 'severity'`. A query string longer than 8192 bytes is 414 `query string exceeds 8192 bytes`, before the parameters are parsed. A POST with `Transfer-Encoding` set, or with no `Content-Length`, is 400 (`Transfer-Encoding is not supported`, or `Content-Length is required` when that header is the one missing) and the connection closes. The body is not read. A POST whose `Content-Length` appears twice, or whose value is not one token of ASCII digits (`4, 2`, `abc`), is 400 `invalid Content-Length`. That response also closes the connection, and the body is not read. `Content-Length: 0` is an empty body. Where an endpoint accepts several values, send them as one comma list.

## Authentication

| Method | How | Used by |
|---|---|---|
| Session cookie | `POST /api/auth/login` sets `wp_session` (HttpOnly, SameSite=Strict). Every session `POST` must also send `X-CSRF-Token: <csrf_token from login or /api/auth/me>`. | Browser UI, scripts |
| Bearer token | `Authorization: Bearer wp_...`, created by an admin. **Ingest endpoints only**; any other endpoint returns 403. No CSRF header needed. | Log shippers, simulator |

Roles: `viewer` (read) < `analyst` (read, ingest, triage, propose rule changes) < `admin` (everything, plus approvals, tokens, demo data, and audit log).

**Viewer is read-only.** A viewer can call every `GET` route whose role below is `viewer` or `public`: dashboard,
stream, events, hunting and saved searches, alerts, incidents, reports, ATT&CK coverage and the Navigator layer,
entities, metrics, rules, the noise lab, tuning exceptions, settings, change requests, evaluations, the asset
inventory, batches, and health details. Any other method is refused with 403 `viewer accounts are read-only`, except
`POST /api/auth/logout`. The server enforces this in `_authorize`, on top of each route's minimum role, so a new
write route is closed to viewers even if its role is left at the default. Admin-only reads (`/api/tokens`,
`/api/audit`, `/api/audit/verify`) are 403 for viewers. The `viewer` account is created on start from `SIEM_VIEWER_PASSWORD` when set and
no user named `viewer` exists.

Five failed logins lock an account for 15 minutes. Both values are security settings, changed only through reviewed proposals.

### Rate limiting

Every request spends a token from a per-client-IP bucket held in memory:

| Bucket | Applies to | Default | Settings |
|---|---|---|---|
| login | `POST /api/auth/login` | burst 10, then 10 per minute | `SIEM_LOGIN_RATE_BURST`, `SIEM_LOGIN_RATE_PER_MIN` |
| general | every other request, API and static files | burst 300, then 1200 per minute | `SIEM_RATE_BURST`, `SIEM_RATE_PER_MIN` |

An empty bucket answers **429** before authentication, with a `Retry-After: <seconds>` header and
`{"error": "too many login attempts; retry in 6 s", "retry_after": 6}` (or `too many requests`). The two buckets are
independent, so a client locked out of login can still load the page. `SIEM_RATE_LIMIT=0` turns limiting off. The
client IP is the TCP peer. With `SIEM_TRUST_PROXY=1` and a loopback peer (a local reverse proxy), it is the **last**
comma-separated entry of the one `X-Forwarded-For` header, the line the proxy wrote. Earlier entries in that header
are ignored. Two `X-Forwarded-For` headers, or a value that is not an address, stay the peer address.
Account lockout is separate: it is per account, also answers 429, and has no `Retry-After`.

```bash
curl -c jar -H 'Content-Type: application/json' -d '{"username":"analyst","password":"..."}' \
  http://127.0.0.1:8080/api/auth/login          # -> {"user": {...}, "csrf_token": "..."}
```

| Endpoint | Role | Notes |
|---|---|---|
| `POST /api/auth/login` | public | `{username, password}`. A username that is not 3–32 characters is the same 401 `invalid username or password` as an unknown account. Login does not truncate it. A password that is not a string, or is longer than 256 characters, is that same 401. Login does not hash that value and does not look up the account. A disabled account is that same 401. Login checks the stored hash, does not increment `failed_logins`, and does not lock the account. The body does not say the account is disabled. |
| `POST /api/auth/logout` | any | |
| `GET /api/auth/me` | any | current user and CSRF token |

## Ingestion

### `POST /api/ingest` (analyst session or token)

Body: one event object, an array of events, or `{"source": "vpn01", "synthetic": false, "events": [...]}`. `Content-Type` must be `application/json`.

Accepted fields (aliases in parentheses):

| Field | Aliases | Notes |
|---|---|---|
| `ts` | `timestamp`, `@timestamp`, `time`, `TimeCreated`, `event_time` | **Required.** ISO-8601 or epoch seconds/ms. No zone = UTC. Must be ≤ 1 day in the future and ≥ year 2000. |
| `event_type` | `type`, `action`, `category`, or Windows `EventID` | Normalized, e.g. `login_failed` → `auth_failure`; unknown → `other`. `syslog` is also accepted, and `GET /api/events?event_type=syslog` filters on it |
| `user` | `username`, `TargetUserName`, `account`, `user.name` | |
| `src_ip` | `source_ip`, `client_ip`, `ip`, `IpAddress`, `source.ip` | Must be a valid IPv4/IPv6 address |
| `dest_ip` | `destination_ip`, `server_ip`, `dst_ip` | |
| `dest_port` | `destination_port`, `dst_port`, `dport` | Integer 0–65535 (firewall events) |
| `bytes` | `bytes_out`, `bytes_sent`, `sent_bytes`, `out_bytes` | Non-negative integer (outbound volume) |
| `host` | `hostname`, `Computer`, `device`, `host.name` | |
| `severity` | `level` | `info`, `low`, `medium`, `high`, or `critical`; defaults by type |
| `outcome`, `message`, `source` | | Secrets like `password=` are redacted before storage |

Event types: `auth_failure`, `auth_success`, `account_lockout`, `user_created`, `privilege_use`, `process_start`,
`network_connection`, `file_access`, `other`, and (2.0) `web_request`, `web_scan`, `web_error`, `fw_deny`, `fw_allow`,
`vpn_login`, `cloud_api_call`, `cloud_iam_change`, `cloud_data_access`, `privilege_escalation`. Firewall actions map
directly (`deny`/`drop`/`block`/`reject` → `fw_deny`, `allow`/`accept`/`permit` → `fw_allow`), as do `sudo`/`runas`/`su`
→ `privilege_escalation` and `vpn` → `vpn_login`. CloudTrail-style records (`eventName` + `eventSource`, optionally
wrapped in `{"Records": [...]}`) are recognised: IAM write calls become `cloud_iam_change`, object and secret reads
become `cloud_data_access`, everything else `cloud_api_call`; the principal comes from `userIdentity`.

Response:

```json
{"batch_id": "…", "received": 3, "accepted": 2, "rejected": 1,
 "rejections": [{"index": 2, "reason": "src_ip is not a valid IP address"}],
 "rejections_omitted": 0,
 "detection": {"run_id": 7, "status": "ok", "events_scanned": 40, "alerts_created": 1, "alerts_updated": 0,
               "correlation": {"status": "ok", "incidents_created": 1, "incidents_updated": 0}}}
```

`rejections` is the first 100 reasons. `rejections_omitted` is `rejected` minus that array (0 when every reason is listed). The stored batch `errors` field is that same first 100, not the full list.

Status codes: **201** all accepted · **207** some rejected · **422** none accepted · **400** malformed body or bad source name · **413** body too large · **415** wrong content type · **401/403** auth · **429** rate limited (see Rate limiting).
If `detection.status` is `"failed"`, the events **were stored**. Fix the cause, then run `POST /api/detection/run`.
If only `detection.correlation.status` is `"failed"`, alerts were stored and only incident grouping was skipped; the next run retries it.

### `POST /api/ingest/upload?format=&source=&synthetic=&year=` (analyst session or token)

Raw UTF-8 file body (`Content-Type: text/plain`). `format` is `auto` (default), `json`, `jsonl`, `csv`, `authlog`, or `weblog`. `authlog` also understands sudo/su, useradd, auditd `exe=`/`type=PATH` records, UFW/iptables `[BLOCK]`/`[ALLOW]` lines, and OpenVPN "Peer Connection Initiated" lines. `weblog` is the nginx/Apache combined access log; requests for scanner paths (`/.env`, `/wp-login.php`, `.git`, …), injection strings, or scanner user agents become `web_scan`, 5xx responses `web_error`. `year` applies only to BSD syslog lines, which carry no year. `synthetic=1` tags events and prefixes the source with `demo:`.

```bash
curl -X POST "http://127.0.0.1:8080/api/ingest/upload?format=authlog&source=bastion01&year=2026" \
  -H "Authorization: Bearer $SIEM_INGEST_TOKEN" -H "Content-Type: text/plain" --data-binary @/var/log/auth.log
```

### Live ingestion (no new routes)

- **File shipper.** `scripts/shipper.py` tails files and posts complete new lines to `POST /api/ingest/upload` with `Authorization: Bearer wp_...`, using `format` and `source` query parameters. It keeps a position file and retries network errors, 5xx, and 401/403 with backoff. It skips batches refused with 400, 413, 415, or 422.
- **Syslog listener.** With `SIEM_SYSLOG=1`, Watchpost also accepts RFC 3164 and RFC 5424 syslog over UDP and TCP on `SIEM_SYSLOG_BIND:SIEM_SYSLOG_PORT` (default `127.0.0.1:5514`). Frames are stored as batches with `source=syslog`, `format=syslog`, and `submitted_by=syslog-listener`. Lines that no parser recognizes get `event_type=syslog`, with severity taken from PRI.

Setup and rsyslog configuration: [LIVE_INGEST.md](LIVE_INGEST.md).

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/ingest/batches` | viewer | Last 50 batches by `created_at`, with up to 100 rejection reasons each. The body stays a bare array. `X-Watchpost-Omitted` is how many batches were past that cap (0 when the table fits) |
| `POST /api/detection/run` | analyst | Full rescan; processes any backlog |
| `GET /api/demo/scenarios` | viewer | Labeled synthetic scenarios |
| `POST /api/demo/load` | admin | `{seed?, force?}`: loads every scenario (409 if already loaded) |
| `POST /api/demo/simulate` | analyst | `{scenario, seed?}`: replays one scenario into this instance |

## Search and investigation

`GET /api/events` (viewer). All parameters are optional:

| Param | Meaning |
|---|---|
| `start`, `end` | ISO timestamps (inclusive) |
| `source`, `host`, `user`, `outcome`, `batch_id` | Exact match (`user`, `host`, `source`, and `outcome` ignore ASCII case; grouping by source and outcome stays the stored spelling); a trailing `*` makes it a prefix match |
| `ip` | Matches `src_ip` or `dest_ip`. A complete address is the form ingest stores (`2001:DB8::1` matches `2001:db8::1`). Anything that is not one address is 400 |
| `event_type` | One normalized type. ASCII case folds onto the catalog spelling (`Auth_Failure` binds `auth_failure`). An unknown name is 400 listing the catalog. Grouping by `event_type` stays the stored spelling |
| `severity` | Comma list, or a single level with `severity_mode=min` for "at least". Spaces around each name are ignored. ASCII case folds onto the catalog spelling (`High` binds `high`). A blank or unknown piece is 400 listing the catalog. Grouping by `severity` stays the stored spelling |
| `q` | Substring of `message` (`%` and `_` are literal), at most 200 characters. A longer value is 400 naming that maximum |
| `synthetic` | `0` or `1` |
| `limit` (1–1000, default 100), `offset` (0–10000, default 0) | Paging; response includes `total`. An offset above 10000 is 400 naming that maximum |
| `since_id` | Only events stored after that event id, newest stored first (ignores event time). This is how to walk newer events; it does not skip rows with `offset`. Used by the dashboard's polling fallback |

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/events/{id}` | viewer | Includes the redacted `raw` record and linked alerts |
| `GET /api/events/{id}/ecs` | viewer | The event as an ECS-shaped document (field mapping for export; see the README, "ECS field mapping") |
| `GET /api/hunt?q=&limit=&offset=` | viewer | Runs a hunt query (syntax in the README, "Hunting"). `offset` above 10000 is 400 naming that maximum, including when a pipeline stage does not page. Returns the event-search page plus `query` and `terms` (`[{field, value, negate, text}]`, how each term was read). A `| top` result includes `total` (matched events) and `missing` (how many of those lack the grouped field). Each percent is that value's share of `total`, so the shown percents can sum under 100. A `| timechart` returns `series_omitted`, how many distinct non-null series were past the 5 drawn series (0 when every series is drawn, including a chart with no `by`). The rest stay in `other`, `truncated` stays false, and the filled buckets do not change. A `| timechart` with no rows, or with every bucket count 0, also returns `note` (`No events match <query> in <span> buckets.`); the rows stay as they are, and a chart with a count above 0 omits `note`. Bad syntax or an unknown field is 400 with the reason. A `bytes:` term is one of `>=`, `>`, `<=`, `<`, `=` and an integer (`bytes:>=1000000`); the number is a bound parameter, and any other value is 400 listing those operators. Grouping by `bytes` is refused. |
| `GET /api/hunt/saved` | viewer | Saved searches: `[{id, name, query, description, owner, created_at}]` by name |
| `POST /api/hunt/saved` | analyst | `{name (≤ 80), query, description? (≤ 300)}`; the query must parse. 409 on a duplicate name (case-insensitive). Audited as `saved_search_created` |
| `POST /api/hunt/saved/{id}/delete` | analyst | Owner or admin only (403 otherwise). Audited as `saved_search_deleted` |
| `GET /api/alerts?status=open&severity=critical,high&rule_id=&limit=` | viewer | `status` and `severity` each take one value or a comma list. Spaces around each name are ignored. ASCII case folds onto the catalog spelling (`Open` is `open`, `High` is `high`). A blank or unknown piece is 400. The console opens on open critical and high. Sorted by active first, then severity, then recency. `limit` is 1–500, default 100. The body stays a bare array. `X-Watchpost-Omitted` is how many matched alerts were past that cap (0 when the list fits) |
| `GET /api/alerts/{id}` | viewer | Adds `rule`, `evidence` (the first 500 evidence events in `ts, id` order), `evidence_omitted` (how many evidence events were past that cap; 0 when the alert has 500 or fewer), `timeline` (the first 300 events involving the same source IPs, users, or hosts, ±30 min, in `ts, id` order; user names and hosts match case-insensitively for ASCII, the same way event search does, and source IPs stay exact), `timeline_omitted` (how many matching events were past that cap; 0 when the window has 300 or fewer), `notes` (the newest 100 by `id`, returned in `id` order), `notes_omitted` (how many older notes were left out; 0 when the alert has 100 or fewer), `activity` (the newest 100 by `id`, returned in `id` order), `activity_omitted` (how many older activity rows were left out; 0 when the alert has 100 or fewer). A note body is still at most 5000 characters. Every alert also carries `base_severity` (the rule's), `assets` (matched inventory entries, see [Asset inventory](#asset-inventory)), and `severity_note` |
| `POST /api/alerts/{id}/notes` | analyst | `{body}` (≤ 5000 chars) |
| `POST /api/alerts/{id}/status` | analyst | `{status: open\|investigating\|resolved, disposition?, note?}`. `resolved` requires `disposition` (`true_positive`, `false_positive`, or `benign`). ASCII case folds onto that spelling (`False_Positive` stores `false_positive`, `Benign` stores `benign`). A blank, a missing disposition, and a non-ASCII lookalike stay that 400. `Open` stays 400. Reopening clears the disposition |
| `GET /api/incidents?status=open,investigating&severity=critical,high&limit=` | viewer | `status` and `severity` each take one value or a comma list. Spaces around each name are ignored. ASCII case folds onto the catalog spelling (`Open` is `open`, `High` is `high`). A blank or unknown piece is 400. Correlated incidents: `title`, `severity`, `status`, `first_seen`, `last_seen`, `entities` (`{src_ip, user, host}` lists; `user` and `host` fold ASCII letters only, so `WEB01` and `web01` are one host `web01`, and `ÉRIN` and `érin` stay two accounts; a source IP stays the stored address), `stages` (ATT&CK tactics in kill-chain order), `top_technique` (`{id, name, tactic}` or null — the earliest mapped technique, same order as the coverage matrix; id breaks ties), `correlation_rule` (the same plain sentence as the incident detail: shared source IP, account, or host within the correlation window, 30 minutes by default), `alert_count`, `synthetic`. Active first, then severity, then recency. `limit` is 1–500, default 100. The body stays a bare array. `X-Watchpost-Omitted` is how many matched incidents were past that cap (0 when the list fits) |
| `GET /api/incidents/{id}` | viewer | Adds `alerts` (each with `techniques`), `events` (the first 1000 distinct evidence events in `ts, id` order, each with `alert_ids`; an event on two alerts is one row), `events_omitted` (how many distinct evidence events were past that cap; 0 when the incident has 1000 or fewer), `timeline` (one entry per alert with tactics and technique ids), `techniques`, `techniques_by_tactic`, `escalated`, the same `correlation_rule` as the list, `assets` (inventory entries behind the incident's hosts and addresses). 404 if missing |
| `POST /api/incidents/{id}/status` | analyst | `{status: open\|investigating\|resolved, note?}`; audited as `incident_status_changed` |
| `GET /api/incidents/{id}/case.json` | viewer | Chronological case record. `techniques` lists each rule technique with `level` (`validated`, `mapped`, `disabled`, or `gap`), the same grade as coverage. `mapped` is not proof. Audited as `case_exported` |
| `GET /api/incidents/{id}/case.md` | viewer | The same record as Markdown. The technique table prints the evidence level, and says mapped is not proof |
| `GET /api/attack/coverage` | viewer | `{tactics, techniques: [{id, name, tactic, level, scenarios, rules: [{id, name, enabled, hits, verdict, lookalikes_fired, proves}], hits, covered, why}], summary, levels, level_meaning}` over the built-in ATT&CK subset. `level` is `validated`, `mapped`, `disabled`, or `gap` (see the README, "ATT&CK coverage"); `covered` is true only for `validated`. `why` is a one-line reason when `level` is `mapped`, otherwise null. `hits` counts alerts from the mapped rules; `summary.levels` counts techniques per level |
| `GET /api/attack/navigator.json` | viewer | The same coverage as a MITRE ATT&CK Navigator layer, colored by level and scored by alert count |
| `GET /api/entities?kind=&limit=` | viewer | Riskiest entities (`kind` is `user`, `src_ip`, or `host`; `limit` 1–100, default 10). ASCII case folds onto that spelling (`User`, `HOST`, and `SRC_IP` are those three). An unknown kind is 400 naming the three. An empty `kind` lists every kind. Each row has its score and the alerts that contribute to it. A user or host `value` is the ASCII-folded key (`Erin` and `WEB01` are `erin` and `web01`). `Érin` and `érin` stay two rows. `entities` is the highest scores, at most `limit` (ties keep `kind`, then `value`). `entities_omitted` is how many scored entities were past that cap (0 when the scored list fits). A false positive or benign close is not scored and is not part of that count |
| `GET /api/entities/{kind}/{value}` | viewer | One entity (value percent-encoded; `{kind}` stays `user`, `src_ip`, or `host`, and `User` is not a path): score breakdown, `alerts` (the newest 50 by `last_seen`, then `id`), `alerts_omitted` (how many of this entity's alerts were past that cap; 0 when there are 50 or fewer), `incidents` (the newest 50 by `last_seen`, then `id`), `incidents_omitted` (how many were past that cap; 0 when there are 50 or fewer), `recent_events` (the newest 50 matching events by `ts`, then `id`), `recent_events_omitted` (how many matching events were past that cap; 0 when the entity has 50 or fewer; `event_count` stays the full count), and `alerts_by_day` (UTC day of each alert's newest evidence event for this entity, zeros filled, newest 31 days; `omitted` counts alerts older than that). The score and `contributions` still include every alert. A false positive or benign close stays weight 0. A `src_ip` path is the address form ingest stores, so `2001:DB8::1` matches `2001:db8::1` and `value` is that form. Anything that is not one address is 400. A user or host path folds ASCII case onto that same key, so `Erin`, `ERIN`, and `erin` are one account and the returned `value` is `erin`. `Érin` and `érin` stay two accounts |
| `GET /api/metrics?hours=24` | viewer | Counts, severity/rule breakdowns, MTTR, and `window_scope`. `hours` filters only `events_ingested_window`. `top_failure_ips`, `top_failure_users`, and `events_by_type` count every stored event. `top_failure_users` groups with SQLite `lower()` (ASCII letters only): `Alice`, `alice`, and `ALICE` are one row named `alice`. `Érin` and `érin` stay two rows. `top_failure_ips` groups the stored address and does not fold it. Each failure list is the 5 groups with the most failures. `top_failure_ips_omitted` and `top_failure_users_omitted` are how many groups were past that cap (0 when there are 5 or fewer). A success is not a group, and a missing address or account is not a group. See [the metrics window](#get-apimetrics-window) |

### `GET /api/metrics` window

`hours` is an integer from 1 to 2160 (90 days), default 24. `window_hours` repeats that value. It does not scope the rest of the payload.

`window_scope.honors_hours` is `events_ingested_window` only. That count is events whose `ingested_at` falls in the last `hours` hours.

`window_scope.all_stored_events` is `events_total`, `synthetic_events`, `top_failure_ips`, `top_failure_users`, and `events_by_type`. Those count every stored event. A failed login older than `hours` still appears in `top_failure_ips` and `top_failure_users`, and its type still appears in `events_by_type`.

`top_failure_users` groups the account with SQLite `lower()`, which folds ASCII letters only, the same fold hunt user groups use. `Alice`, `alice`, and `ALICE` are one row whose `user` is `alice`. `Érin` and `érin` stay two rows. `top_failure_ips` groups the stored address. `2001:DB8::1` and `2001:db8::1` stay two addresses. A success is not a failure row.

`top_failure_ips` and `top_failure_users` are the 5 groups with the most failures. `top_failure_ips_omitted` and `top_failure_users_omitted` are how many groups were past that cap (0 when there are 5 or fewer). A success is not a group. A missing address or account is not a group. The user fold and the stored address stay as they are.

`window_scope.newest_event_24h` is `activity_last_24h_of_data`: the 24 hours ending at the newest stored event, not the `hours` window. Alert counts, mean time to resolve, dispositions, false-positive rates, and open-alert aging read the current alerts table. `omitted_metrics` still names time to detect and dwell time.

`window_scope.note` says the same thing in one sentence: `hours` filters `events_ingested_window` by `ingested_at`, and `top_failure_ips`, `top_failure_users`, and `events_by_type` count every stored event.

### `GET /api/attack/coverage` example

`covered` is true only when the technique is validated on a labeled scenario, not merely because a rule is enabled. `level` is `validated`, `mapped`, `disabled`, or `gap`. A mapped technique can still list an enabled rule and a non-zero `hits` count; those hits are alerts, not proof. This example is two techniques from the labeled synthetic catalog (the `tactics` array is omitted). `summary.covered` counts `validated` only.

```json
{
  "levels": ["validated", "mapped", "disabled", "gap"],
  "level_meaning": {
    "validated": "An enabled rule detects a labeled synthetic attack that exercises this technique.",
    "mapped": "An enabled rule maps here, but no labeled scenario proves it detects this technique. Not counted as covered."
  },
  "summary": {
    "techniques": 2,
    "covered": 1,
    "with_hits": 2,
    "levels": {"validated": 1, "mapped": 1, "disabled": 0, "gap": 0}
  },
  "techniques": [
    {
      "id": "T1110.003",
      "name": "Brute Force: Password Spraying",
      "tactic": "Credential Access",
      "level": "validated",
      "scenarios": ["password_spray"],
      "hits": 1,
      "covered": true,
      "why": null,
      "rules": [
        {
          "id": "password_spray",
          "name": "Password spraying across many accounts",
          "enabled": true,
          "hits": 1,
          "verdict": "quiet",
          "lookalikes_fired": [],
          "proves": ["password_spray"]
        }
      ]
    },
    {
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "level": "mapped",
      "scenarios": [],
      "hits": 4,
      "covered": false,
      "why": "web_scanner detects web_scan, which probes and injects but never exploits.",
      "rules": [
        {
          "id": "web_scanner",
          "name": "Web vulnerability scanning from one IP",
          "enabled": true,
          "hits": 4,
          "verdict": "quiet",
          "lookalikes_fired": [],
          "proves": []
        }
      ]
    }
  ]
}
```

## Reports

Incident and alert reports are downloads (`Content-Disposition: attachment`), not JSON. Any signed-in role,
viewers included (since 2.0 / F; before that, analyst and admin only). Each download is written to the audit log as
`report_downloaded`.

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/alerts/{id}/report.md` | viewer | Markdown report for one alert. `text/markdown; charset=utf-8` |
| `GET /api/alerts/{id}/report.pdf` | viewer | The same report as PDF 1.4. `application/pdf` |
| `GET /api/incidents/{id}/report.md` | viewer | Markdown report for a correlated incident and all its alerts |
| `GET /api/incidents/{id}/report.pdf` | viewer | The same report as PDF 1.4 |

Both formats carry the same sections: header (id, severity, status, first/last seen, generation time), summary,
kill-chain stages (incidents only), entities (IPs, accounts, hosts), assets (inventory entries with criticality and
sensitive-data tags; each alert also shows its asset weighting when it changed the severity), MITRE ATT&CK techniques grouped
by tactic with the coverage evidence level on each one (the report says mapped is not proof; only validated is a labeled scenario), a merged timeline (the first 200 events by `ts`, then `id`; one row per event even when two alerts share it; evidence events marked; `timeline_omitted` is how many merged events were past that cap, and 0 when the timeline fits; Markdown and PDF name that count when it is not 0), each alert with its explanation and up to 25 evidence events,
analyst notes, and recommended actions keyed by technique (generic actions when no technique is mapped).
Reports built from synthetic data open with a "SYNTHETIC DATA" banner and repeat it in the PDF page footer.
Log-derived text is escaped in Markdown so it cannot inject tables, links, or HTML.

Incident reports are built from the correlated incident (`GET /api/incidents/{id}`): its status, severity
(including escalation), span, kill-chain stages, and entities come from the `incidents` row; ATT&CK techniques
come from the member alerts' rule metadata, grouped by tactic in kill-chain order, each listing the alerts that map
to it. Incidents that span three or more tactics are marked escalated.

Errors are JSON: unknown alert → 404 `alert not found`; unknown incident → 404 `incident not found`.

## Asset inventory

Assets give hosts a weight of importance and tag the systems that process sensitive data. Detection matches each
alert's evidence events to the inventory by `host` name (ASCII case only, the same fold as entity hosts: `WEB01` matches `web01`, and `Érin-host` stays apart from `érin-host`) and by `dest_ip`/`src_ip` against an
asset's `addresses`, then raises the alert's severity:

| Matched asset | Levels added |
|---|---|
| criticality `high` | +1 |
| criticality `critical` | +2 |
| any sensitive-data tag (`pii`, `pci`, `phi`, `credentials`, `financial`, `confidential`) | +1 |

The total is capped at two levels and never passes `critical`. The rule's own severity is kept in the alert's
`base_severity`, the matched assets in `assets`, and the reason in `severity_note`; a `severity_changed` entry is
written to the alert's activity. Incident severity follows the weighted alert severities, so one alert on a critical
asset is enough to open an incident. Changing the inventory re-weighs every unresolved alert at once and refreshes
incident severities; resolved alerts keep the severity they were closed with. **Admin → Load synthetic demo data**
seeds a fictional inventory (marked `synthetic`) for the demo hosts; existing names are never overwritten.

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/assets` | viewer | `{assets: [...], criticalities, kinds, data_tags: {tag: description}}`, most critical first |
| `POST /api/assets` | admin | `{name, kind?, criticality?, data_tags?, addresses?, owner?, description?}` → 201 `{asset, alerts_rescored}`. `name` is unique ignoring case (409 on a clash); `data_tags` and `addresses` accept a list or a comma-separated string. Audited as `asset_created` |
| `POST /api/assets/{id}` | admin | Same body; replaces the asset. Audited as `asset_updated` |
| `POST /api/assets/{id}/delete` | admin | Always 409 `review_required`: a delete needs a second admin, through the proposal route below |
| `POST /api/assets/{id}/proposals` | admin | `{...asset, reason}` for an edit, or `{"delete": true, reason}` → 201 change request, approved through `POST /api/changes/{id}/review` |
| `POST /api/assets/proposals` | admin | `{...asset, reason}`: propose an add for review instead of applying it at once |

`POST /api/assets` and `POST /api/assets/{id}` apply an edit only when it cannot lower alert severity. An edit that
lowers criticality, removes a sensitive-data tag or an address, renames the host, or claims an address another asset
has changes nothing and answers 409 with `{error, review_required: true, reasons, proposal_route}`. The full rules
are in the README, "Asset inventory review".

Asset fields: `id`, `name`, `kind` (`server`, `workstation`, `network`, `cloud`, `database`, `other`), `criticality`
(`low`, `medium`, `high`, `critical`), `data_tags`, `addresses`, `owner`, `description`, `synthetic`, `created_at`,
`updated_at`, `updated_by`.

## Rules, feedback, and reviewed changes

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/rules` | viewer | Params, version, `techniques` (`[{id, name, tactic}]`), `performance` (from verdicts), latest `evaluation` |
| `GET /api/rules/{id}/history` | viewer | Every version, with who proposed and who approved it |
| `GET /api/rules/export` | viewer | Download `watchpost-rules.json`: `{format: "watchpost-rules", format_version: 1, watchpost_version, exported_at, note, rules: [{id, name, version, enabled, severity, params, techniques, description}]}`, sorted. Tuning only; detection logic is code and is not exported |
| `POST /api/rules/import` | analyst | Body: an exported document (max 256 KB). `?dry_run=1` proposes nothing; `?label=` names the file in each reason. Applies nothing: each changed rule becomes a `rule_update` change request. Returns `{dry_run, label, summary, rules: [{id, outcome: proposed\|would_propose\|unchanged\|refused, change_id?, changes?, reason?}]}`. 400 on a bad format, 413 when too large, 429 when the backtest quota cannot cover every changed rule |
| `POST /api/rules/sigma` | analyst | Body: `{source, sample?, reason?}` (max 256 KB). Imports a Sigma rule in the supported subset (README, "Sigma rule import"). `?dry_run=1` returns `{dry_run, ok, refused, compiled: {rule_id, title, severity, techniques, conditions, warnings, sha256, params, logsource}, sample, backtest}` and creates nothing (one preview backtest). Otherwise 201 with a pending `sigma_add` change request; approval adds the rule disabled. 400 with the refusal reason, 409 when the rule id exists, 413 when too large, 429 when the backtest quota is spent |
| `POST /api/rules/<id>/sigma-sample` | analyst | Body: `{sample: {malicious: [events], benign: [events]}, reason}`. 201 with a pending `sigma_sample` change request. A Sigma rule can be enabled only while its sample passes |
| `POST /api/hunt/saved/<id>/promote` | analyst | Body: `{group_by, threshold, window_minutes, severity, techniques?, name?, sample?, reason?}` (max 64 KB). Promotes the saved search's filter to a threshold rule `search_<slug>` (README, "Saved searches as detections"). `?dry_run=1` returns `{dry_run, ok, refused, compiled: {rule_id, title, severity, techniques, conditions, query, params}, sample, backtest}` and creates nothing. Otherwise 201 with a pending `search_add` change request; approval adds the rule disabled. Either spends one rule-proposal backtest. 400 with the refusal reason (time terms, `\|` stages, fields detection does not load), 404 unknown saved search, 409 when the rule id exists, 429 when the quota is spent |
| `POST /api/rules/<id>/search-sample` | analyst | Body: `{sample: {malicious: [events], benign: [events]}, reason}`. 201 with a pending `search_sample` change request. A search rule can be enabled only while its sample passes (the malicious events raise a finding, the benign ones none) |
| `POST /api/rules/{id}/proposals` | analyst | `{params?: {...partial}, enabled?: bool, reason}`; validated, then scored against scenarios |
| `POST /api/rules/suggestions` | analyst | Generates proposals from false-positive feedback (deduplicated) |
| `POST /api/rules/{id}/suppressions` | analyst | `{group_key, days (1–90), reason}`: proposes a tuning exception; nothing is suppressed until an admin approves it |
| `GET /api/suppressions` | viewer | Approved tuning exceptions, newest first, with `active` false once expired or revoked |
| `POST /api/suppressions/{id}/revoke` | admin | Ends an exception early; audited as `suppression_revoked` |
| `POST /api/rules/{id}/suppression-windows` | analyst | `{starts_at, expires_at, reason}` proposes a reviewed, rule-wide pause of at most 30 days; approval must acknowledge labeled detection loss |
| `GET /api/rule-suppression-windows` | viewer | Approved rule-wide windows, including `upcoming`, `active`, `expired`, and `ended` history |
| `POST /api/rule-suppression-windows/{id}/end` | admin | Ends an active or upcoming rule-wide window early; the approved interval remains in history |
| `GET /api/noise-lab` | viewer | Each rule against the labeled scenarios and its benign look-alikes: recall, precision, tp/fn/fp, look-alikes tested and fired, and a `verdict` (`quiet`, `noisy`, `blind`, `untested`, `disabled`). `strip` is the pass/fail line above that list: `scenarios`, `detected_attacks` out of `attacks`, `false_positives` (distinct benign scenarios an enabled rule fired on), `missed`, `false_positive_scenarios`, and `verdict` (`pass` only when every labeled attack is detected and no benign scenario fired) |
| `GET /api/settings` | viewer | Security settings with allowed ranges |
| `POST /api/settings/{key}/proposals` | admin | `{value, reason}` |
| `GET /api/changes?status=pending` | viewer | Change requests |
| `POST /api/changes/{id}/review` | admin | `{decision: approve\|reject, note, evidence_digest?, acknowledge_detection_loss?}`. Approval must send the `evidence_digest` of the evidence the reviewer was shown; if the evidence changed, nothing is applied and the answer is 409. A rule change that loses a labeled detection also needs `acknowledge_detection_loss: true`. Self-review → 403; already reviewed → 409 |
| `GET /api/evaluations` / `POST /api/evaluations` | viewer / analyst | Evaluation history / run one now |

A `rule_update` that sets `grouping` includes `grouping_preview`. It scans the newest 10000 events by `id`. `events_omitted` is how many stored events were past that cap (0 when the table has 10000 or fewer). `capped` is true only when `events_omitted` is not 0. `before` and `after` each keep the first 20 sorted `group_keys`. `group_keys_omitted` is how many keys were past that cap (0 when the set fits).

A new-rule preview (`backtest` on a Sigma import or a saved-search promotion, including `?dry_run=1`) keeps the first 10 sorted `group_keys`. `group_keys_omitted` is how many distinct keys were past that cap (0 when the set fits). `findings` stays the full count. `sample_findings` stays the newest 5. The scan window stays the last 7 days of stored event time.

## SOC dashboard and live stream

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/dashboard` | viewer | One read for the dashboard: counts (`events_total`, `synthetic_events`, `alerts_open`, `alerts_investigating`, `alerts_critical_open`, `alerts_total`), `events_per_minute` (60 one-minute buckets by ingest time, ending now), `alert_timeline` (`bucket_minutes` 60 or 5, and 24 `bins` of `{start, critical, high, medium, low, events}` by event time, ending at the newest alert; 5-minute buckets when all recent alerts fall in the last 2 hours), `attackers` (source IPs in alert evidence: `{ip, events, alerts, open_alerts, max_severity, last_seen}`, the top 40 by alerts, then events). `attackers_omitted` is how many source IPs on alerts were past that cap (0 when there are 40 or fewer). An event that is not alert evidence is not a source IP in that count. `top_rules` (`{rule_id, name, severity, alerts, open}`, the top 10 by alerts). `rules_omitted` is how many rule ids on alerts were past that cap (0 when there are 10 or fewer). A rule with no alerts is not in that count. `alerts` (the board: not resolved first, then severity, then last_seen, the first 60). `board_omitted` is how many alerts were past that cap (0 when there are 60 or fewer). `recent_events` (the newest 60 by `ts`, then `id`, no `raw`). `recent_events_omitted` is how many stored events were past that cap (0 when there are 60 or fewer). `events_total` stays the full count |
| `POST /api/dashboard/views` | analyst | `{name (1–80), visibility: private\|shared, filters: {severities}, layout}`. A name that differs only by ASCII case from one this owner already saved is 409 naming the stored row (`you already have a dashboard view named 'dup'` when `dup` is stored), including when the insert loses that race. Another owner's view of that name is not a conflict. `POST /api/dashboard/views/{id}` updates that owner's view the same way |
| `GET /api/geo?ips=a,b,c` | viewer | Up to 200 IPs. `{label: "synthetic geo", ips: {ip: {city, lat, lon, synthetic: true, internal} \| null}}`. Only RFC 5737 documentation ranges (fictional cities) and RFC 1918 ranges (internal sites) have entries; every other address is `null` ("unknown") and is never guessed. 400 on an invalid address |
| `GET /api/stream` | viewer | Server-Sent Events (`text/event-stream`), see below |

### `GET /api/stream`

Session cookie required (EventSource sends it). One thread per connection; at most 64 concurrent streams (503 after that). The first frame sets `retry: 3000`. Every frame is `id`, `event`, and one JSON `data` line:

| `event` | When | `data` |
|---|---|---|
| `hello` | on connect | `{version, user, heartbeat_seconds}` |
| `health` | on connect (full), after each detection run (partial) | `{partial: false, status, checked_at, checks: {name: status}}` or `{partial: true, checks: {detection: ok\|failing}, error, alerts_omitted, incidents_omitted}`. `alerts_omitted` is how many alerts this run touched past the newest 100 by `id` (0 when the run fits, and 0 on a failing run). `incidents_omitted` is the same count for incidents |
| `event` | after a batch is stored | `{batch_id, count, synthetic, events: [...], events_omitted}`: the newest 50 events of the batch (no `raw`). `events_omitted` is `count` minus the events array (0 when the batch fits). The events stay the newest 50 by `ts`, then `id` |
| `alert` | after detection, per alert created or extended | the newest 100 alerts this run touched, by `id`, frames still in `id` order. Each frame keeps the alert row fields plus `change: created\|updated` |
| `incident` | after detection, per incident touched (once the `incidents` table exists) | the newest 100 incidents this run touched, by `id`, frames still in `id` order. Each frame keeps the incident row |
| `heartbeat` | every 15 s without other traffic | `{ts, subscribers}` |
| `resync` | the client fell behind (its 500-message queue overflowed) | `{reason}`: refetch `/api/dashboard` |

Clients that cannot hold a stream can poll `GET /api/events?since_id=<last id>` every few seconds, which is what the dashboard does when SSE fails.

The dashboard also reads `GET /api/incidents`, `GET /api/attack/coverage`, and `GET /api/storyline/status` when the server has them (workstreams A and C). A 404 shows a "pending" panel.

## Health and administration

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/health` | public | `{status, checks: {name: status}}`; HTTP 503 when failing. `checks` includes `syslog` while the listener is enabled and always includes `storyline` |
| `GET /api/health/details` | viewer | Full checks with guidance, a `means` sentence (what failing or degraded means on this demo). `recent_errors` is the newest 20 `error_log` rows by `id`. `recent_errors_omitted` is how many were past that cap (0 when the table fits). `recent_detection_runs` is the newest 10 detection runs by `id`. `recent_detection_runs_omitted` is how many were past that cap (0 when the table fits) |
| `GET /api/tokens` / `POST /api/tokens` | admin | `{name}` → `{token}` (shown once; only a SHA-256 hash is stored) |
| `POST /api/tokens/{id}/revoke` | admin | |
| `GET /api/audit` | admin | Last 200 audit entries by `id`. The body stays a bare array. `X-Watchpost-Omitted` is how many entries were past that cap (0 when the table fits) |
| `GET /api/audit/verify` | admin | Walks the audit hash chain: `{ok, status (verified\|partial\|broken), entries, keyed, head, chain_started, legacy, first_break}` (README, "Tamper-evident audit log") |

## Attack storyline (synthetic demo)

A scripted six-stage intrusion (recon → credential attack → foothold → escalation → lateral movement and cloud IAM → exfiltration) replayed over wall-clock time so a viewer can watch the dashboard react. Every record is stored with `synthetic=1`, `source=demo:storyline`, and uses RFC 5737 addresses (`203.0.113.80`, `198.51.100.140`) plus fictional hosts and users. One attacker address, one victim account (`dave`), and one rogue cloud principal (`svc-deploy-tmp`) tie the alerts together so correlation builds multi-stage incidents. Baseline traffic from other employees runs alongside so the attack stands out against a living system.

| Endpoint | Role | Notes |
|---|---|---|
| `POST /api/storyline/start` | admin | `{speed?: 0.1–10000 (default 1 = about 2 minutes), seed?: int}` → 202 with the status below. 409 while a run is active. Audited as `storyline_started` |
| `POST /api/storyline/stop` | admin | Stops the current run after the batch in flight; audited as `storyline_stopped` |
| `GET /api/storyline/status` | viewer | `{running, stage, progress (0–1), events_sent, alerts_created, started_at, finished_at, error, speed, seed, started_by, stages: [{name, starts_at, description}], synthetic: true}` |

Only one run per process. Events are fed through the normal ingest path, so the SSE stream, detection, correlation, and reports all see them. With `SIEM_DEMO_LOOP=<minutes>` (and optional `SIEM_DEMO_LOOP_SPEED`) `main.py` restarts the storyline on that interval for unattended public demos.

## Correlation

After every detection run, alerts that are not resolved are grouped into incidents. Two alerts are related when
evidence events of both carry the same source IP, account, or host within 30 minutes of each other; relations chain.
A new incident needs two related alerts or one critical alert. An alert belongs to at most one incident; new related
alerts join an open incident; resolved incidents are never reopened by detection (new activity starts a new one).
Incident severity is the highest alert severity, raised one level when the alerts span three or more ATT&CK tactics.
