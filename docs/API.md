# Watchpost API

Base URL: `http://127.0.0.1:8080`. All request and response bodies are JSON unless noted otherwise. Errors come back as `{"error": "..."}`.

## Authentication

| Method | How | Used by |
|---|---|---|
| Session cookie | `POST /api/auth/login` sets `wp_session` (HttpOnly, SameSite=Strict). Every session `POST` must also send `X-CSRF-Token: <csrf_token from login or /api/auth/me>`. | Browser UI, scripts |
| Bearer token | `Authorization: Bearer wp_...`, created by an admin. **Ingest endpoints only**; any other endpoint returns 403. No CSRF header needed. | Log shippers, simulator |

Roles: `viewer` (read) < `analyst` (read, ingest, triage, propose rule changes) < `admin` (everything, plus approvals, tokens, demo data, and audit log).

Five failed logins lock an account for 15 minutes. Both values are security settings, changed only through reviewed proposals.

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
| `event_type` | `type`, `action`, `category`, or Windows `EventID` | Normalized, e.g. `login_failed` → `auth_failure`; unknown → `other` |
| `user` | `username`, `TargetUserName`, `account`, `user.name` | |
| `src_ip` | `source_ip`, `client_ip`, `ip`, `IpAddress`, `source.ip` | Must be a valid IPv4/IPv6 address |
| `dest_ip` | `destination_ip`, `server_ip` | |
| `host` | `hostname`, `Computer`, `device`, `host.name` | |
| `severity` | `level` | `info`, `low`, `medium`, `high`, or `critical`; defaults by type |
| `outcome`, `message`, `source` | | Secrets like `password=` are redacted before storage |

Response:

```json
{"batch_id": "…", "received": 3, "accepted": 2, "rejected": 1,
 "rejections": [{"index": 2, "reason": "src_ip is not a valid IP address"}],
 "detection": {"run_id": 7, "status": "ok", "events_scanned": 40, "alerts_created": 1, "alerts_updated": 0}}
```

Status codes: **201** all accepted · **207** some rejected · **422** none accepted · **400** malformed body or bad source name · **413** body too large · **415** wrong content type · **401/403** auth.
If `detection.status` is `"failed"`, the events **were stored**. Fix the cause, then run `POST /api/detection/run`.

### `POST /api/ingest/upload?format=&source=&synthetic=&year=` (analyst session or token)

Raw UTF-8 file body (`Content-Type: text/plain`). `format` is `auto` (default), `json`, `jsonl`, `csv`, or `authlog`. `year` applies only to BSD syslog lines, which carry no year. `synthetic=1` tags events and prefixes the source with `demo:`.

```bash
curl -X POST "http://127.0.0.1:8080/api/ingest/upload?format=authlog&source=bastion01&year=2026" \
  -H "Authorization: Bearer $SIEM_INGEST_TOKEN" -H "Content-Type: text/plain" --data-binary @/var/log/auth.log
```

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
| `GET /api/alerts/{id}` | viewer | Adds `rule`, `evidence`, `timeline` (events involving the same IPs or users, ±30 min), `notes`, `activity` |
| `POST /api/alerts/{id}/notes` | analyst | `{body}` (≤ 5000 chars) |
| `POST /api/alerts/{id}/status` | analyst | `{status: open\|investigating\|resolved, disposition?, note?}`. `resolved` requires `disposition` (`true_positive`, `false_positive`, or `benign`); reopening clears it |
| `GET /api/metrics?hours=24` | viewer | Counts, severity/rule breakdowns, MTTR, top failing IPs/users, and a 24-hour histogram ending at the newest event |

## Rules, feedback, and reviewed changes

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/rules` | viewer | Params, version, `performance` (from verdicts), latest `evaluation` |
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
| `GET /api/health` | public | `{status, checks: {name: status}}`; HTTP 503 when failing |
| `GET /api/health/details` | viewer | Full checks with guidance, recent redacted errors, recent detection runs |
| `GET /api/tokens` / `POST /api/tokens` | admin | `{name}` → `{token}` (shown once; only a SHA-256 hash is stored) |
| `POST /api/tokens/{id}/revoke` | admin | |
| `GET /api/audit` | admin | Last 200 audit entries |
