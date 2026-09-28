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

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/events/{id}` | viewer | Includes the redacted `raw` record and linked alerts |
| `GET /api/alerts?status=open,investigating&severity=&rule_id=&limit=` | viewer | Sorted by active first, then severity, then recency |
| `GET /api/alerts/{id}` | viewer | Adds `rule`, `evidence`, `timeline` (events involving the same IPs or users, ±30 min), `notes`, `activity` |
| `POST /api/alerts/{id}/notes` | analyst | `{body}` (≤ 5000 chars) |
| `POST /api/alerts/{id}/status` | analyst | `{status: open\|investigating\|resolved, disposition?, note?}`. `resolved` requires `disposition` (`true_positive`, `false_positive`, or `benign`); reopening clears it |
| `GET /api/metrics?hours=24` | viewer | Counts, severity/rule breakdowns, MTTR, top failing IPs/users, and a 24-hour histogram ending at the newest event |

## Reports

Incident and alert reports are downloads (`Content-Disposition: attachment`), not JSON. Analyst and admin only;
viewers get 403. Each download is written to the audit log as `report_downloaded`.

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/alerts/{id}/report.md` | analyst | Markdown report for one alert. `text/markdown; charset=utf-8` |
| `GET /api/alerts/{id}/report.pdf` | analyst | The same report as PDF 1.4. `application/pdf` |
| `GET /api/incidents/{id}/report.md` | analyst | Markdown report for a correlated incident and all its alerts |
| `GET /api/incidents/{id}/report.pdf` | analyst | The same report as PDF 1.4 |

Both formats carry the same sections: header (id, severity, status, first/last seen, generation time), summary,
kill-chain stages (incidents only, when recorded), entities (IPs, accounts, hosts), MITRE ATT&CK techniques grouped
by tactic, a merged timeline (evidence events marked), each alert with its explanation and up to 25 evidence events,
analyst notes, and recommended actions keyed by technique (generic actions when no technique is mapped).
Reports built from synthetic data open with a "SYNTHETIC DATA" banner and repeat it in the PDF page footer.
Log-derived text is escaped in Markdown so it cannot inject tables, links, or HTML.

Errors are JSON: unknown alert or incident → 404; `/api/incidents/{id}/report.*` on a database without the
`incidents` tables (before the correlation engine is installed) → 404 `incidents are not available on this server yet`.

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

## Health and administration

| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/health` | public | `{status, checks: {name: status}}`; HTTP 503 when failing |
| `GET /api/health/details` | viewer | Full checks with guidance, recent redacted errors, recent detection runs |
| `GET /api/tokens` / `POST /api/tokens` | admin | `{name}` → `{token}` (shown once; only a SHA-256 hash is stored) |
| `POST /api/tokens/{id}/revoke` | admin | |
| `GET /api/audit` | admin | Last 200 audit entries |
