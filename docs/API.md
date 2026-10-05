# Watchpost API

Base URL: `http://127.0.0.1:8080`. All request and response bodies are JSON unless noted otherwise. Errors come back as `{"error": "..."}`.

## Authentication

| Method | How | Used by |
|---|---|---|
| Session cookie | `POST /api/auth/login` sets `wp_session` (HttpOnly, SameSite=Strict). Every session `POST` must also send `X-CSRF-Token: <csrf_token from login or /api/auth/me>`. | Browser UI, scripts |
| Bearer token | `Authorization: Bearer wp_...`, created by an admin. **Ingest endpoints only**; any other endpoint returns 403. No CSRF header needed. | Log shippers, simulator |

Roles: `viewer` (read) < `analyst` (read, ingest, triage, propose rule changes) < `admin` (everything, plus approvals, tokens, demo data, and audit log).

**Viewer is read-only.** A viewer can call every `GET` route whose role below is `viewer` or `public`: dashboard,
stream, events, alerts, incidents, reports, ATT&CK coverage, metrics, rules, settings, change requests, evaluations,
batches, and health details. Any other method is refused with 403 `viewer accounts are read-only`, except
`POST /api/auth/logout`. The server enforces this in `_authorize`, on top of each route's minimum role, so a new
write route is closed to viewers even if its role is left at the default. Admin-only reads (`/api/tokens`,
`/api/audit`) are 403 for viewers. The `viewer` account is created on start from `SIEM_VIEWER_PASSWORD` when set and
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
`X-Forwarded-For` entry, the one the proxy wrote, so client-supplied entries earlier in the header are ignored.
Account lockout is separate: it is per account, also answers 429, and has no `Retry-After`.

```bash
curl -c jar -H 'Content-Type: application/json' -d '{"username":"analyst","password":"..."}' \
  http://127.0.0.1:8080/api/auth/login          # -> {"user": {...}, "csrf_token": "..."}
```

| Endpoint | Role | Notes |
|---|---|---|
| `POST /api/auth/login` | public | `{username, password}` |
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
 "detection": {"run_id": 7, "status": "ok", "events_scanned": 40, "alerts_created": 1, "alerts_updated": 0,
               "correlation": {"status": "ok", "incidents_created": 1, "incidents_updated": 0}}}
```

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
| `GET /api/ingest/batches` | viewer | Last 50 batches, with up to 100 rejection reasons each |
| `POST /api/detection/run` | analyst | Full rescan; processes any backlog |
| `GET /api/demo/scenarios` | viewer | Labeled synthetic scenarios |
| `POST /api/demo/load` | admin | `{seed?, force?}`: loads every scenario (409 if already loaded) |
| `POST /api/demo/simulate` | analyst | `{scenario, seed?}`: replays one scenario into this instance |

## Search and investigation

`GET /api/events` (viewer). All parameters are optional:

| Param | Meaning |
|---|---|
| `start`, `end` | ISO timestamps (inclusive) |
| `source`, `host`, `user`, `batch_id` | Exact match (`user` ignores case); a trailing `*` makes it a prefix match |
| `ip` | Matches `src_ip` or `dest_ip` |
| `event_type` | One normalized type |
| `severity` | Comma list, or a single level with `severity_mode=min` for "at least" |
| `q` | Substring of `message` (`%` and `_` are literal) |
| `synthetic` | `0` or `1` |
| `limit` (1–1000, default 100), `offset` | Paging; response includes `total` |
| `since_id` | Only events stored after that event id, newest stored first (ignores event time). Used by the dashboard's polling fallback |

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/events/{id}` | viewer | Includes the redacted `raw` record and linked alerts |
| `GET /api/alerts?status=open,investigating&severity=&rule_id=&limit=` | viewer | Sorted by active first, then severity, then recency |
| `GET /api/alerts/{id}` | viewer | Adds `rule`, `evidence`, `timeline` (events involving the same IPs or users, ±30 min), `notes`, `activity`. Every alert also carries `base_severity` (the rule's), `assets` (matched inventory entries, see [Asset inventory](#asset-inventory)), and `severity_note` |
| `POST /api/alerts/{id}/notes` | analyst | `{body}` (≤ 5000 chars) |
| `POST /api/alerts/{id}/status` | analyst | `{status: open\|investigating\|resolved, disposition?, note?}`. `resolved` requires `disposition` (`true_positive`, `false_positive`, or `benign`); reopening clears it |
| `GET /api/incidents?status=open,investigating&severity=&limit=` | viewer | Correlated incidents: `title`, `severity`, `status`, `first_seen`, `last_seen`, `entities` (`{src_ip, user, host}` lists), `stages` (ATT&CK tactics in kill-chain order), `alert_count`, `synthetic`. Active first, then severity, then recency |
| `GET /api/incidents/{id}` | viewer | Adds `alerts` (each with `techniques`), `events` (evidence, each with `alert_ids`), `timeline` (one entry per alert with tactics and technique ids), `techniques`, `techniques_by_tactic`, `escalated`, `assets` (inventory entries behind the incident's hosts and addresses). 404 if missing |
| `POST /api/incidents/{id}/status` | analyst | `{status: open\|investigating\|resolved, note?}`; audited as `incident_status_changed` |
| `GET /api/attack/coverage` | viewer | `{tactics, techniques: [{id, name, tactic, rules: [{id, name, enabled}], hits, covered}], summary}` over the built-in ATT&CK subset; `hits` counts alerts from the covering rules |
| `GET /api/metrics?hours=24` | viewer | Counts, severity/rule breakdowns, MTTR, top failing IPs/users, and a 24-hour histogram ending at the newest event |

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
by tactic, a merged timeline (evidence events marked), each alert with its explanation and up to 25 evidence events,
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
alert's evidence events to the inventory by `host` name (case-insensitive) and by `dest_ip`/`src_ip` against an
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
| `POST /api/assets/{id}/delete` | admin | → `{ok, alerts_rescored}`. Audited as `asset_deleted` |

Asset fields: `id`, `name`, `kind` (`server`, `workstation`, `network`, `cloud`, `database`, `other`), `criticality`
(`low`, `medium`, `high`, `critical`), `data_tags`, `addresses`, `owner`, `description`, `synthetic`, `created_at`,
`updated_at`, `updated_by`.

## Rules, feedback, and reviewed changes

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/rules` | viewer | Params, version, `techniques` (`[{id, name, tactic}]`), `performance` (from verdicts), latest `evaluation` |
| `GET /api/rules/{id}/history` | viewer | Every version, with who proposed and who approved it |
| `POST /api/rules/{id}/proposals` | analyst | `{params?: {...partial}, enabled?: bool, reason}`; validated, then scored against scenarios |
| `POST /api/rules/suggestions` | analyst | Generates proposals from false-positive feedback (deduplicated) |
| `GET /api/settings` | viewer | Security settings with allowed ranges |
| `POST /api/settings/{key}/proposals` | admin | `{value, reason}` |
| `GET /api/changes?status=pending` | viewer | Change requests |
| `POST /api/changes/{id}/review` | admin | `{decision: approve\|reject, note}`. Self-review → 403; already reviewed → 409 |
| `GET /api/evaluations` / `POST /api/evaluations` | viewer / analyst | Evaluation history / run one now |

## SOC dashboard and live stream

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/dashboard` | viewer | One read for the dashboard: counts (`events_total`, `synthetic_events`, `alerts_open`, `alerts_investigating`, `alerts_critical_open`, `alerts_total`), `events_per_minute` (60 one-minute buckets by ingest time, ending now), `alert_timeline` (`bucket_minutes` 60 or 5, and 24 `bins` of `{start, critical, high, medium, low, events}` by event time, ending at the newest alert; 5-minute buckets when all recent alerts fall in the last 2 hours), `attackers` (source IPs in alert evidence: `{ip, events, alerts, open_alerts, max_severity, last_seen}`, top 40), `top_rules`, `alerts` (up to 60, for the board), `recent_events` (60 newest by event time, no `raw`) |
| `GET /api/geo?ips=a,b,c` | viewer | Up to 200 IPs. `{label: "synthetic geo", ips: {ip: {city, lat, lon, synthetic: true, internal} \| null}}`. Only RFC 5737 documentation ranges (fictional cities) and RFC 1918 ranges (internal sites) have entries; every other address is `null` ("unknown") and is never guessed. 400 on an invalid address |
| `GET /api/stream` | viewer | Server-Sent Events (`text/event-stream`), see below |

### `GET /api/stream`

Session cookie required (EventSource sends it). One thread per connection; at most 64 concurrent streams (503 after that). The first frame sets `retry: 3000`. Every frame is `id`, `event`, and one JSON `data` line:

| `event` | When | `data` |
|---|---|---|
| `hello` | on connect | `{version, user, heartbeat_seconds}` |
| `health` | on connect (full), after each detection run (partial) | `{partial: false, status, checked_at, checks: {name: status}}` or `{partial: true, checks: {detection: ok\|failing}, error}` |
| `event` | after a batch is stored | `{batch_id, count, synthetic, events: [...]}`: the newest 50 events of the batch (no `raw`) |
| `alert` | after detection, per alert created or extended | alert row fields plus `change: created\|updated` |
| `incident` | after detection, per incident touched (once the `incidents` table exists) | the incident row |
| `heartbeat` | every 15 s without other traffic | `{ts, subscribers}` |
| `resync` | the client fell behind (its 500-message queue overflowed) | `{reason}`: refetch `/api/dashboard` |

Clients that cannot hold a stream can poll `GET /api/events?since_id=<last id>` every few seconds, which is what the dashboard does when SSE fails.

The dashboard also reads `GET /api/incidents`, `GET /api/attack/coverage`, and `GET /api/storyline/status` when the server has them (workstreams A and C). A 404 shows a "pending" panel.

## Health and administration

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/health` | public | `{status, checks: {name: status}}`; HTTP 503 when failing. `checks` includes `syslog` while the listener is enabled and always includes `storyline` |
| `GET /api/health/details` | viewer | Full checks with guidance, recent redacted errors, recent detection runs |
| `GET /api/tokens` / `POST /api/tokens` | admin | `{name}` → `{token}` (shown once; only a SHA-256 hash is stored) |
| `POST /api/tokens/{id}/revoke` | admin | |
| `GET /api/audit` | admin | Last 200 audit entries |

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
