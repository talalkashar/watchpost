# Watchpost: a small, working SIEM

Watchpost is a self-contained Security Information and Event Management (SIEM) lab. It ingests authentication logs, normalizes them into one schema, and stores them in SQLite. It runs explainable detection rules, raises alerts with evidence, and supports an analyst workflow from triage to resolution. It also reports its own health and learns nothing on its own: rule changes come from analyst feedback and need approval from a second person.

It uses only the Python standard library (3.10+). No packages to install, no paid services, no outbound network calls.

> **Honesty note.** This is a portfolio/learning project, not a production SIEM. All bundled data is synthetic. See [What is real vs. synthetic vs. future](#what-is-real-vs-synthetic-vs-future).

---

## Quick start

```bash
cd labs/siem
export SIEM_ADMIN_PASSWORD='choose-a-long-password'      # optional; otherwise generated
export SIEM_ANALYST_PASSWORD='choose-another-long-one'   # optional; otherwise generated
./start.sh                                               # http://127.0.0.1:8080
```

If you don't set the password variables, Watchpost generates random passwords on first start. It writes them to `data/initial_credentials.txt` (mode 0600) and never prints them to the logs.

Then sign in as `admin`, open **Admin → Load synthetic demo data**, and follow [DEMO_SCRIPT.md](DEMO_SCRIPT.md).

### Tests

```bash
./run_tests.sh      # unit/integration tests + a 15-step end-to-end smoke check
```

### Replit

`.replit` is included. Before the first run, add `SIEM_ADMIN_PASSWORD` and `SIEM_ANALYST_PASSWORD` in **Secrets**. The Replit run command binds `0.0.0.0` (needed for the Replit webview) and sets `SIEM_SECURE_COOKIES=1`, because Replit serves over HTTPS. Anywhere else, the app binds to `127.0.0.1` unless you set `SIEM_HOST`. Keep the Repl private, or at least don't share the URL, unless you intend the app to be reachable.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SIEM_DB` | `data/watchpost.db` | SQLite database path |
| `SIEM_HOST` / `SIEM_PORT` (or `PORT`) | `127.0.0.1` / `8080` | Bind address |
| `SIEM_ADMIN_PASSWORD`, `SIEM_ANALYST_PASSWORD` | generated | Initial account passwords (min. 12 chars), used only when the database is empty |
| `SIEM_SECURE_COOKIES` | `0` | Set `1` behind HTTPS |
| `SIEM_SESSION_TTL` | `28800` | Session lifetime in seconds |
| `SIEM_MAX_UPLOAD_BYTES` / `SIEM_MAX_BATCH_EVENTS` | 5 MB / 20000 | Ingestion limits |
| `SIEM_SYSLOG` | `0` | `1` also starts the UDP/TCP syslog listener ([docs/LIVE_INGEST.md](docs/LIVE_INGEST.md)) |
| `SIEM_SYSLOG_BIND` / `SIEM_SYSLOG_PORT` | `127.0.0.1` / `5514` | Syslog listener address (same port for UDP and TCP) |
| `SIEM_SYSLOG_ALLOW` | empty (any) | Comma-separated IPs/CIDRs allowed to send syslog |

---

## Architecture

```
 log files ──► POST /api/ingest/upload ─┐
 shipper.py ─► (same, ingest token) ────┤
 collectors ─► POST /api/ingest (token) ├─► normalize.py ──► events (SQLite) ──► engine.run_detection
 simulator ──► (same API, loopback) ────┤   parse + validate      │                 │  rules.py (pure functions)
 syslog ─────► syslog_listener.py ──────┘   + redact secrets      │                 ▼
                                                                  │            alerts + alert_events
                                                                  ▼                 │
 browser UI (static/) ◄── server.py (auth, CSRF, roles) ◄── queries.py ◄────────────┘
                                   │
                                   ├── health.py   storage / ingestion / detection / dependencies
                                   └── improve.py  feedback → performance → suggestions → reviewed changes
                                                   + evaluation against labeled synthetic scenarios
```

| Module | Responsibility |
|---|---|
| `watchpost/normalize.py` | Parses JSON, JSONL, CSV, Linux `auth.log` (OpenSSH), and Windows Security events (4624/4625/4672/4688/4720/4740). Accepts common field aliases, including ECS-style nesting. Validates timestamps, IPs, severities, and lengths, strips control characters, and redacts secrets. Every rejected record gets a reason and a position. |
| `watchpost/correlate.py`, `watchpost/incidents.py` | Pure alert-to-incident grouping; incident queries, status changes, and ATT&CK coverage. |
| `watchpost/attack.py`, `watchpost/geo.py` | Static ATT&CK subset; synthetic geo table for demo IP ranges (never a real lookup). |
| `watchpost/rules.py` | Eleven threshold rules as pure functions over event lists, each with a plain-English explanation. Also validates rule parameters. |
| `watchpost/engine.py` | Stores each batch atomically, then runs detection over the batch's time range plus the longest rule window. Deduplicates and extends open alerts, and records every detection run. |
| `watchpost/queries.py` | Event search (parameterized SQL), alert detail with evidence and a related-events timeline, notes, status changes, and SOC metrics. |
| `watchpost/auth.py` | PBKDF2-SHA256 password hashing, lockout, and server-side sessions (only token hashes are stored). Also ingest-only API tokens (hashed) and the viewer < analyst < admin roles. |
| `watchpost/health.py` | Component checks, each with a status (`ok`/`degraded`/`failing`), a message, and recovery guidance. |
| `watchpost/improve.py` | Scenario evaluation (TP/FN/FP, recall, precision), rule performance from analyst verdicts, heuristic suggestions, and two-person change review. |
| `watchpost/syslog_listener.py` | Optional UDP/TCP syslog receiver (RFC 3164, RFC 5424, RFC 6587 framing). Runs each line through the auth.log parser, falls back to a generic `syslog` event with severity from PRI, and batches into the engine every 2 seconds. Reports itself as the `syslog` health component. |
| `scripts/shipper.py` | Stdlib-only file tailer for Linux boxes: batches new lines to `/api/ingest/upload` with an ingest token, with backoff, rotation handling, and a position file. |
| `watchpost/simulate.py` | Labeled synthetic scenarios and a CLI that sends only to loopback unless you explicitly allow otherwise. |
| `watchpost/report.py` | Incident and alert reports: one model (summary, timeline, entities, alerts with evidence, ATT&CK techniques by tactic, notes, recommended actions) rendered as Markdown or PDF. |
| `watchpost/pdfwriter.py` | Minimal hand-written PDF 1.4 writer (Helvetica, wrapping, tables, page breaks, xref). |
| `watchpost/server.py` | `http.server` routing, security headers (CSP, frame denial, nosniff), CSRF checks, body limits, and the static UI. |

### Normalized event schema

`id, ts (UTC ISO-8601), ingested_at, source, host, event_type, outcome, severity, user, src_ip, dest_ip, message, raw (redacted, truncated), synthetic, batch_id`

`event_type` is one of `auth_failure, auth_success, account_lockout, user_created, privilege_use, process_start, network_connection, file_access, other`, plus (2.0) `web_request, web_scan, web_error, fw_deny, fw_allow, vpn_login, cloud_api_call, cloud_iam_change, cloud_data_access, privilege_escalation`, and `syslog` (a line received by the syslog listener that no parser recognized). Events also carry `dest_port` and `bytes` when the source has them.

### Detection rules

| Rule | Fires when | Severity |
|---|---|---|
| `brute_force_ip` | ≥ 10 failed logins from one IP within 300 s | high |
| `password_spray` | one IP fails as ≥ 5 different accounts within 600 s | high |
| `account_repeated_failures` | one account has ≥ 8 failures within 900 s, from any IPs | medium |
| `success_after_failures` | a successful login follows ≥ 5 failures for that account within 600 s | critical |
| `off_hours_privileged_login` | `root`/`admin`/`administrator` logs in outside 08:00–18:00 UTC on weekdays, or at any time on weekends | medium |
| `web_scanner` | ≥ 5 scanner-like web requests (`/.env`, `/wp-login.php`, injection strings, scanner agents) from one IP within 300 s | medium |
| `firewall_port_sweep` | the firewall denies one IP on ≥ 10 distinct ports within 300 s | medium |
| `impossible_geo_login` | one account logs in from two places ≥ 500 km apart faster than 900 km/h (synthetic geo table only) | high |
| `privilege_escalation_after_login` | sudo/su/runas within 30 min of a login that followed ≥ 3 failures | critical |
| `cloud_iam_change_by_new_principal` | an IAM change by a cloud principal with no activity in the previous 24 h | high |
| `data_exfil_volume` | one account (or IP) moves ≥ 1 GB out, or makes ≥ 100 cloud data reads, within 1 h | high |

Every rule maps to MITRE ATT&CK techniques from a small static catalog (`watchpost/attack.py`, 17 techniques, no network fetch). `GET /api/attack/coverage` shows which techniques are covered and how often they fired.

### Incidents (correlation)

After each detection run, `watchpost/correlate.py` groups related alerts into incidents: alerts whose evidence shares a source IP, account, or host within 30 minutes. An incident needs two related alerts or one critical alert, lists its kill-chain stages (ATT&CK tactics in order), and is raised one severity level when it spans three or more tactics. Reruns change nothing; new alerts join an open incident.

Every rule accepts `ignore_ips` and `ignore_users`. The engine merges overlapping findings into one open alert instead of creating duplicates, and a rescan never re-alerts on evidence already attached to an alert.

### Self-diagnosis

`GET /api/health` is public and returns statuses only, with HTTP 503 when anything is failing. `GET /api/health/details` requires a login and adds details, recent redacted errors, and recent detection runs.

| Check | Failing / degraded when |
|---|---|
| storage | DB can't be opened, the integrity check fails, or the write probe fails (failing); < 100 MB free disk (degraded) |
| ingestion | server-side ingestion errors in 24 h, or > 25 % of records rejected (degraded) |
| detection | last run failed (failing); batches ingested while detection was failing and not yet reprocessed, no enabled rules, or a run stuck > 5 min (degraded) |
| dependencies | Python < 3.10, SQLite < 3.35, or DB directory not writable (failing); UI files missing (degraded) |
| syslog (only when `SIEM_SYSLOG=1`) | port can't be bound, invalid allow list, or a listener thread stopped (failing); last batch failed to store or frames dropped in the last 10 min (degraded) |

If detection fails, the events stay stored, the ingest response says `"detection": {"status": "failed", ...}`, and the UI shows a banner. A full **Run detection** processes the backlog and marks those batches `recovered`. Tests cover each of these paths.

### Continuous improvement (what it actually does)

1. When analysts resolve an alert, they record a verdict: `true_positive`, `false_positive`, or `benign`.
2. **Rules** shows per-rule alert counts and precision, TP / (TP + FP).
3. **Suggest improvements** applies fixed heuristics. If ≥ 2 false-positive alerts share an IP (or account) that never appears in a true positive, it proposes excluding that IP (or account). Otherwise, if false-positive event counts sit below every true-positive count, it proposes a higher threshold.
4. Each proposal, from the system or a person, is scored against the labeled synthetic scenarios before and after the change.
5. Nothing changes until an admin approves, and that admin can't be the one who proposed it. Approval bumps the rule version, writes `rule_history`, re-runs the evaluation, and records everything in the audit log. Security settings (lockout threshold and duration) follow the same process.

This is **not machine learning**. It is transparent, deterministic tuning support.

---

## SOC dashboard

The landing view is a dark SOC console built for a 1280×800 screen: a status strip (events per minute, open and critical alerts, incidents, stored events, health checks, stream state, UTC clock), an attacker world map, a live event stream, alerts over time, top attacker IPs, the MITRE ATT&CK coverage heat matrix, an incident board, top rules, and health. Live updates arrive over Server-Sent Events (`GET /api/stream`); if the stream fails, the page polls every 3 seconds. Charts and the map are inline SVG drawn by `static/charts.js` and `static/map.js`, with no libraries and no external tiles.

**The map positions are synthetic.** `watchpost/geo.py` maps only the RFC 5737 documentation ranges to fictional city names at fixed coordinates, and the RFC 1918 ranges to internal sites. It is not a geo lookup. Any other address is listed as "unknown" and never guessed. The map is labeled "synthetic geo".

## What is real vs. synthetic vs. future

**Real, working, and tested:** everything in the architecture section. That includes the ingestion API and file upload, normalization, persistence, search, the eleven rules, ATT&CK mapping and coverage, incident correlation, alerts with evidence and timelines, notes, status and verdicts, metrics, health checks and recovery, authentication, roles, CSRF protection, API tokens, redaction, feedback-driven suggestions, two-person review, evaluation history, and the audit log.

**Synthetic:** all bundled data. The demo dataset and simulator scenarios (`watchpost/simulate.py`) and the files in `samples/` are invented. External IPs come from the RFC 5737 documentation ranges. Synthetic events are stored with `synthetic=1`, sourced `demo:*`, and tagged in the UI. The evaluation scores (recall and precision) measure the rules against these hand-labeled scenarios only. They say nothing about real-world accuracy.

**Limitations:**
- Single process with SQLite, sized for thousands to low millions of events, not enterprise volume. No retention or rollup.
- Live ingestion is basic: an optional syslog listener (unauthenticated, no TLS; loopback by default) and a single-file-per-flag shipper script. See [docs/LIVE_INGEST.md](docs/LIVE_INGEST.md) for its limits.
- Timestamps without a zone are treated as UTC. BSD syslog lines carry no year, so you pass one or the current year is assumed.
- Only two seeded accounts; there is no user-management UI or API. Accounts can be added with `watchpost.auth.create_user`.
- No TLS termination; run it behind HTTPS (as Replit does) before exposing it.
- Rules cover authentication, web, firewall/VPN, cloud audit, and host scenarios with fixed thresholds. Geo for impossible travel comes from a synthetic table covering only documentation and private ranges.
- There is no scheduled detection. Detection runs on ingest and on demand.

**Future ideas (not implemented):** Sigma rule import, GeoIP and threat-intel enrichment (both need external data), scheduled runs and retention, user management, MFA, and case grouping across alerts.

---

## Project layout

```
labs/siem/
├── main.py, start.sh, run_tests.sh, .replit
├── watchpost/          application package
├── static/             UI: SOC dashboard (dashboard.js, charts.js, map.js) and views (app.js); no inline scripts
├── samples/            synthetic log files for upload
├── scripts/smoke.py    end-to-end smoke check against a real server process
├── scripts/shipper.py  log file shipper for Linux boxes (stdlib only)
├── tests/              unittest suite
├── docs/API.md         API reference
├── docs/LIVE_INGEST.md syslog listener, rsyslog forwarding, and the file shipper
├── DEMO_SCRIPT.md      5-minute demo walkthrough
├── LINKEDIN.md         project description
└── PROGRESS.md         milestones, verification evidence, next steps
```
