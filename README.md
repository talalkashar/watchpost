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
./run_tests.sh      # 57 unit/integration tests + a 12-step end-to-end smoke check
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

---

## Architecture

```
 log files ──► POST /api/ingest/upload ─┐
 collectors ─► POST /api/ingest (token) ├─► normalize.py ──► events (SQLite) ──► engine.run_detection
 simulator ──► (same API, loopback) ────┘   parse + validate      │                 │  rules.py (pure functions)
                                            + redact secrets      │                 ▼
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
| `watchpost/rules.py` | Five threshold rules as pure functions over event lists, each with a plain-English explanation. Also validates rule parameters. |
| `watchpost/engine.py` | Stores each batch atomically, then runs detection over the batch's time range plus the longest rule window. Deduplicates and extends open alerts, and records every detection run. |
| `watchpost/queries.py` | Event search (parameterized SQL), alert detail with evidence and a related-events timeline, notes, status changes, and SOC metrics. |
| `watchpost/auth.py` | PBKDF2-SHA256 password hashing, lockout, and server-side sessions (only token hashes are stored). Also ingest-only API tokens (hashed) and the viewer < analyst < admin roles. |
| `watchpost/health.py` | Component checks, each with a status (`ok`/`degraded`/`failing`), a message, and recovery guidance. |
| `watchpost/improve.py` | Scenario evaluation (TP/FN/FP, recall, precision), rule performance from analyst verdicts, heuristic suggestions, and two-person change review. |
| `watchpost/simulate.py` | Labeled synthetic scenarios and a CLI that sends only to loopback unless you explicitly allow otherwise. |
| `watchpost/report.py` | Incident and alert reports: one model (summary, timeline, entities, alerts with evidence, ATT&CK techniques by tactic, notes, recommended actions) rendered as Markdown or PDF. |
| `watchpost/pdfwriter.py` | Minimal hand-written PDF 1.4 writer (Helvetica, wrapping, tables, page breaks, xref). |
| `watchpost/server.py` | `http.server` routing, security headers (CSP, frame denial, nosniff), CSRF checks, body limits, and the static UI. |

### Normalized event schema

`id, ts (UTC ISO-8601), ingested_at, source, host, event_type, outcome, severity, user, src_ip, dest_ip, message, raw (redacted, truncated), synthetic, batch_id`

`event_type` is one of `auth_failure, auth_success, account_lockout, user_created, privilege_use, process_start, network_connection, file_access, other`.

### Detection rules

| Rule | Fires when | Severity |
|---|---|---|
| `brute_force_ip` | ≥ 10 failed logins from one IP within 300 s | high |
| `password_spray` | one IP fails as ≥ 5 different accounts within 600 s | high |
| `account_repeated_failures` | one account has ≥ 8 failures within 900 s, from any IPs | medium |
| `success_after_failures` | a successful login follows ≥ 5 failures for that account within 600 s | critical |
| `off_hours_privileged_login` | `root`/`admin`/`administrator` logs in outside 08:00–18:00 UTC on weekdays, or at any time on weekends | medium |

Every rule accepts `ignore_ips` and `ignore_users`. The engine merges overlapping findings into one open alert instead of creating duplicates, and a rescan never re-alerts on evidence already attached to an alert.

### Self-diagnosis

`GET /api/health` is public and returns statuses only, with HTTP 503 when anything is failing. `GET /api/health/details` requires a login and adds details, recent redacted errors, and recent detection runs.

| Check | Failing / degraded when |
|---|---|
| storage | DB can't be opened, the integrity check fails, or the write probe fails (failing); < 100 MB free disk (degraded) |
| ingestion | server-side ingestion errors in 24 h, or > 25 % of records rejected (degraded) |
| detection | last run failed (failing); batches ingested while detection was failing and not yet reprocessed, no enabled rules, or a run stuck > 5 min (degraded) |
| dependencies | Python < 3.10, SQLite < 3.35, or DB directory not writable (failing); UI files missing (degraded) |

If detection fails, the events stay stored, the ingest response says `"detection": {"status": "failed", ...}`, and the UI shows a banner. A full **Run detection** processes the backlog and marks those batches `recovered`. Tests cover each of these paths.

### Continuous improvement (what it actually does)

1. When analysts resolve an alert, they record a verdict: `true_positive`, `false_positive`, or `benign`.
2. **Rules** shows per-rule alert counts and precision, TP / (TP + FP).
3. **Suggest improvements** applies fixed heuristics. If ≥ 2 false-positive alerts share an IP (or account) that never appears in a true positive, it proposes excluding that IP (or account). Otherwise, if false-positive event counts sit below every true-positive count, it proposes a higher threshold.
4. Each proposal, from the system or a person, is scored against the labeled synthetic scenarios before and after the change.
5. Nothing changes until an admin approves, and that admin can't be the one who proposed it. Approval bumps the rule version, writes `rule_history`, re-runs the evaluation, and records everything in the audit log. Security settings (lockout threshold and duration) follow the same process.

This is **not machine learning**. It is transparent, deterministic tuning support.

---

## What is real vs. synthetic vs. future

**Real, working, and tested:** everything in the architecture section. That includes the ingestion API and file upload, normalization, persistence, search, the five rules, alerts with evidence and timelines, notes, status and verdicts, metrics, health checks and recovery, authentication, roles, CSRF protection, API tokens, redaction, feedback-driven suggestions, two-person review, evaluation history, and the audit log.

**Synthetic:** all bundled data. The demo dataset and simulator scenarios (`watchpost/simulate.py`) and the files in `samples/` are invented. External IPs come from the RFC 5737 documentation ranges. Synthetic events are stored with `synthetic=1`, sourced `demo:*`, and tagged in the UI. The evaluation scores (recall and precision) measure the rules against these hand-labeled scenarios only. They say nothing about real-world accuracy.

**Limitations:**
- Single process with SQLite, sized for thousands to low millions of events, not enterprise volume. No retention or rollup.
- No syslog/UDP listener or agents. Logs arrive by HTTP upload or API.
- Timestamps without a zone are treated as UTC. BSD syslog lines carry no year, so you pass one or the current year is assumed.
- Only two seeded accounts; there is no user-management UI or API. Accounts can be added with `watchpost.auth.create_user`.
- No TLS termination; run it behind HTTPS (as Replit does) before exposing it.
- Rules cover authentication scenarios only.
- There is no scheduled detection. Detection runs on ingest and on demand.

**Future ideas (not implemented):** a syslog listener, Sigma rule import, GeoIP and threat-intel enrichment (both need external data), scheduled runs and retention, user management, MFA, and case grouping across alerts.

---

## Project layout

```
labs/siem/
├── main.py, start.sh, run_tests.sh, .replit
├── watchpost/          application package
├── static/             UI (index.html, app.js, style.css; no inline scripts)
├── samples/            synthetic log files for upload
├── scripts/smoke.py    end-to-end smoke check against a real server process
├── tests/              unittest suite
├── docs/API.md         API reference
├── DEMO_SCRIPT.md      5-minute demo walkthrough
├── LINKEDIN.md         project description
└── PROGRESS.md         milestones, verification evidence, next steps
```
