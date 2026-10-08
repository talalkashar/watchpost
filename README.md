# Watchpost: a small, working SIEM

Watchpost is a self-contained Security Information and Event Management (SIEM) lab. It ingests authentication, web, firewall/VPN, cloud audit, and host logs, normalizes them into one schema, and stores them in SQLite. It runs explainable detection rules, raises alerts with evidence, and supports an analyst workflow from triage to resolution. It also reports its own health and learns nothing on its own: rule changes come from analyst feedback and need approval from a second person.

It uses only the Python standard library (3.10+). No packages to install, no paid services, no outbound network calls.

> **Honesty note.** This is a portfolio/learning project, not a production SIEM. All bundled data is synthetic. See [What is real vs. synthetic vs. future](#what-is-real-vs-synthetic-vs-future).

**Live demo:** https://watchpost-nxxu.onrender.com (read-only login `viewer` / `watchpost-viewer-demo`; free tier, first load may take a minute).

![Watchpost SOC dashboard](docs/screenshots/01-dashboard.png)

| Incident board | Alerts and correlated incidents |
|---|---|
| ![Incidents](docs/screenshots/02-incidents.png) | ![Alerts](docs/screenshots/03-alerts.png) |

<!-- Still to capture for 2.0 (1280x800, save under docs/screenshots/):
     incident-detail.png (kill-chain stages, techniques by tactic), incident-report-pdf.png (first page of the PDF),
     storyline-running.png (dashboard mid-storyline with the stage tile). -->

## What's new in 5.0

5.0 collects PRs #21 to #34: rule backtesting, triage metrics, TOTP and session management, rule export/import with ECS mapping, a Sigma subset import, log source health, hunt aggregations, saved searches as detections, and viewer data masking. See [CHANGELOG.md](CHANGELOG.md) for the full list, including the security fixes found by automated review.

## What's new in 4.0

4.0 is about making each claim checkable: every feature has a test, every number comes from a script you can rerun, and the limits are written down next to the feature.

| Change | What it adds |
|---|---|
| **Tamper-evident audit log** | Audit entries form a hash chain (HMAC-SHA256 with `SIEM_AUDIT_KEY`, plain SHA-256 without). `GET /api/audit/verify` (admin) walks it and reports `verified`, `partial`, or `broken` with the first break; **Admin → Audit log** shows a badge. What it does and does not detect is listed under [Tamper-evident audit log](#tamper-evident-audit-log). |
| **ATT&CK coverage graded by evidence** | Each technique is **validated** (an enabled rule detects a labeled scenario that shows it), **mapped**, **disabled**, or a **gap**. With the default rules, 16 of 19 catalog techniques are validated and 3 are only mapped. Validated means detected on the project's own synthetic scenarios, not in real traffic. See [ATT&CK coverage](#attck-coverage). |
| **Hunting** | A one-line query language over events (`field:value`, prefixes, `NOT`, `last:7d`, `since:`/`until:`), compiled from a field whitelist with bound values, plus one `| stats`, `| top` or `| timechart` aggregation stage. Saved searches for analysts and admins; the viewer can run them. See [Hunting](#hunting). |
| **Two new detections** | `cloud_logging_disabled` (T1562.008) and `admin_action_from_new_source` (T1078), fourteen rules in total. Each has a labeled attack and a benign look-alike in the noise lab, and the cold-start limits are documented. |
| **Load test and indexes** | `scripts/loadtest.py` (seeded, stdlib only) ingests 100,000 synthetic events and times the read routes. New indexes and narrower per-batch history reads; one laptop run ingested 5,314 events/s. See [Performance](#performance). |
| **Reviewed asset edits** | Builds on Juan Carlos Munera's asset inventory (PR #9): an edit that could lower alert severity (lower criticality, drop a tag or address, rename, delete, claim another asset's address) needs a second admin, with before/after evidence and the alerts it would move. An address listed on several assets now matches all of them, so inventory order never decides the weighting. See [Asset inventory review](#asset-inventory-review). |
| **Keyboard triage and accessibility** | `j`/`k`/`Enter`/`a`/`r`/`Esc`/`/`/`?` shortcuts, landmarks and labels, native dialogs, AA contrast, and a 390px layout, checked by static tests and a headless browser script (automated checks only, not a screen-reader audit). See [Keyboard shortcuts](#keyboard-shortcuts). |

## What's new in 3.1

A small follow-up round. Nothing here changes how the rules detect.

| Change | What it adds |
|---|---|
| **Revoke a tuning exception** | An admin can end an approved exception before it expires (`POST /api/suppressions/<id>/revoke`, admin only, audited as `suppression_revoked`). It stops applying from the next detection run, for both the skip behaviour and the exfil baseline mode. The row stays in the list as history with who revoked it and when. |
| **Review evidence matches the action** | Every change request carries an `evidence_digest` (SHA-256 of its stored evidence). An approval must send the digest of the evidence the reviewer was shown; the server recomputes the evidence and applies the change only when the digests match, all in one transaction. On a mismatch nothing is applied: the request stays pending with the fresh evidence and the API answers 409, and a retry or a second reviewer has to send the new digest. Exception evidence gains a **live impact** section: existing alerts for that rule and group key by status and verdict, the newest few, whether any labeled scenario contains the key at all, how many were ever closed as a true positive, and the status changes the proposer made on them. For `data_exfil_volume` it states that the exception enables baseline mode instead of hiding findings. Two gates protect labeled detections, and they differ on purpose. An **exception** is refused outright, at propose and at approve, when it would make the rule miss a labeled attack it detects today, or when a matching alert has ever been closed as a true positive (read from the append-only alert history, so re-closing the alert as benign does not lift it). A value that a rule change adds to an ignore list (`ignore_ips`, `ignore_users`, `sanctioned_services`), or removes from `privileged_users`, is a permanent exception with no expiry, so each such edit gets the same live impact in the evidence and the same refusal on true-positive history. The gate decides which alerts an entry touches with the same function the rules use to apply it (`rules.covers`), so the two cannot read an entry differently. A **rule change** that loses a labeled detection (a looser threshold, or disabling the rule) can be a legitimate trade, so it is not refused: the reviewer must send `acknowledge_detection_loss: true`, the UI asks for it with a required checkbox, and the audit entry names the scenarios. |
| **Inventory refresh** | In Admin, the asset inventory card redraws after "Load synthetic demo data", without a page reload. |
| **ATT&CK Navigator export** | `GET /api/attack/navigator.json` (viewer) returns the rule coverage as a MITRE ATT&CK Navigator layer: one entry per catalog technique, colored by its evidence level (validated, mapped, disabled, gap; see ATT&CK coverage below), scored by alert count, with the level and the mapped rules in the comment. The scores come from synthetic demo data and the layer says so. It names no ATT&CK release because the static technique table does not state one. The dashboard coverage panel links to it. |

## What's new in 3.0

3.0 came out of the feedback on the 2.0 post. Each item answers something a reader asked for.

| Feature | Asked by | What it adds |
|---|---|---|
| **Noise lab** | Charles Vosburgh, Issouf D. Dayo | Benign look-alike scenarios for the rules (an authorized scanner, an on-call admin at 03:00, an office NAT after a password-expiry day, a nightly backup, and more). `GET /api/noise-lab` and the **Noise lab** view show, per rule, recall, precision, the look-alikes it was tested against, and the ones that fired. Rules that are noisy are shown as noisy: with default settings in 3.0, 8 of the 12 rules fired on at least one benign scenario (in 4.0 it is 8 of 14; the two new rules stay quiet on their look-alikes). |
| **Baseline-aware exfiltration** | Abderrazak Benarous | `data_exfil_volume` keeps its flat thresholds by default: history and analyst verdicts never quiet it. A principal with an approved, unexpired tuning exception (analyst proposes, admin approves) is not skipped but compared with its own history (`baseline_multiplier`, 7-day window), so an excepted nightly backup that always moves several GB stays quiet and still alerts at 3x its own normal. The alert states which mode applied and, in baseline mode, the baseline and the ratio. |
| **Tuning exceptions** | Issouf D. Dayo | A reviewed, expiring allowlist (rule + group key + reason, 1 to 90 days). An analyst proposes one, an admin approves it through the existing two-person review, and the engine skips matching findings and counts them as suppressed. In 3.0 exceptions ended only by expiring; 3.1 added a revoke route. |
| **Shadow IT rule** | Issouf D. Dayo | A twelfth rule, `unsanctioned_cloud_service`, flags use of a cloud service that is not on the rule's sanctioned list (mapped to T1567). It is not part of the attack storyline. |
| **Entity risk** | (added) | Every user, source IP, and host gets a risk score: each alert adds a severity weight (critical 40, high 20, medium 10, low 5, info 1) that halves every 24 hours, and alerts closed as false positive or benign add nothing. `GET /api/entities` and an entity page list the contributing alerts and their weights, so the score can be checked by hand. Asset criticality counts through severity: an alert on a critical or sensitive asset is raised before it is stored, and the breakdown shows the rule's base severity and the asset note next to the raised one. No ML; every point traces to an alert. The dashboard has a **Riskiest entities** panel. |
| **SOC metrics** | (added) | Time to resolve by severity, false-positive rate by rule, and open-alert aging. Time to detect and dwell time are deliberately left out: the demo replays synthetic events with old timestamps, which would make both numbers meaningless. |

Left for a contributor's pull requests ([issue #8](https://github.com/talalkashar/watchpost/issues/8)): encrypted syslog, more log sources, orchestration, hot/warm/cold retention, stronger correlation, and threat intelligence.

## What's new in 2.0

| Workstream | What it adds |
|---|---|
| **A · Correlation and MITRE ATT&CK** | Parsers for nginx/Apache access logs, firewall/VPN, CloudTrail-style cloud audit, and host sudo/process events. Six new rules (eleven in total), each mapped to techniques from a static 17-technique ATT&CK subset. Alerts that share an IP, account, or host are correlated into **incidents** with kill-chain stages, and severity is escalated at 3+ tactics. Adds `GET /api/attack/coverage`. |
| **B · SOC dashboard** | A dark command-center view with a status strip, an attacker map (inline SVG, **synthetic geo** only), a live event stream over **Server-Sent Events** (`/api/stream`, with a polling fallback), alerts over time, top attacker IPs, an ATT&CK heat matrix, an incident board, and health. No JS libraries. |
| **D · Incident reports** | One-click **Markdown and PDF** reports for incidents and alerts, with a timeline, entities, techniques by tactic, evidence, notes, and recommended actions per technique. The PDF writer is hand-written PDF 1.4. |
| **E · Live ingestion** | A UDP/TCP **syslog listener** (RFC 3164/5424) and `scripts/shipper.py`, a file tailer that posts to the ingest API with a token. See [docs/LIVE_INGEST.md](docs/LIVE_INGEST.md). |
| **F · Demo kit** | A read-only **viewer** role that the server enforces on every route, with a public demo account from `SIEM_VIEWER_PASSWORD`. **Per-IP rate limiting** (strict on login). A **`deploy/`** kit for Debian 12: a hardened systemd unit, an idempotent installer, and Caddy or nginx HTTPS. A LinkedIn kit and demo script. |
| **G · Asset modeling** | An **asset inventory** (Admin → Asset inventory) gives hosts a weight of importance (`low` to `critical`) and tags the systems that process **sensitive data** (`pii`, `pci`, `phi`, `credentials`, `financial`, `confidential`). Alerts whose evidence touches a high or critical asset, or a sensitive-data system, are raised one or two severity levels, with the rule's own severity and the reason kept on the alert; incidents and reports inherit the weighting. Changing the inventory re-weighs open alerts at once. Adds `GET/POST /api/assets`. Built by Juan Carlos Munera (PR #9); edits that could lower severity now go through two-person review (see [Asset inventory review](#asset-inventory-review)). |
| **C · Attack storyline** | **Admin → Start storyline** replays a six-stage synthetic intrusion in real time (recon → credential attack → foothold → escalation → lateral and cloud → exfiltration) over baseline noise; the dashboard shows the current stage. `SIEM_DEMO_LOOP=<minutes>` replays it on a timer for unattended public demos. |

### 2.0 architecture

```
  SOURCES                         INGEST (auth: session+CSRF or ingest token)        STORE / ANALYZE
  ───────                         ───────────────────────────────────────────        ───────────────
  log files ──────────────┐
  shipper.py (E) ─────────┤  POST /api/ingest[/upload] ─┐
  simulator / storyline(C)┤                             ├─► normalize.py ──► events (SQLite, synthetic flag)
  syslog UDP/TCP (E) ─► syslog_listener.py ─────────────┘   parse, validate,        │
                                                            redact secrets          ▼
                                                                         engine.run_detection
                                                                         rules.py: 11 pure rules (A)
                                                                         + attack.py ATT&CK map (A)
                                                                                    │
                                                                                    ▼
                                                                    alerts ──► correlate.py (A) ──► incidents
                                                                      │                               │
                                  ┌───────────── stream.py broker ◄───┴───────────────────────────────┤
                                  ▼                                                                   ▼
  BROWSER ◄── HTTPS ── Caddy / nginx (F) ── server.py on 127.0.0.1 ──────────────────► report.py + pdfwriter.py (D)
  dashboard.js, map.js,        deploy/         • ratelimit.py: per-IP buckets (F)       report.md / report.pdf
  charts.js (B), app.js        systemd unit    • roles viewer < analyst < admin (F)
  GET /api/stream (SSE, B)     (F)             • CSRF, CSP, sessions, ingest tokens
                                               • geo.py synthetic geo (B), health.py, improve.py
```

---

## Quick start

```bash
cd labs/siem
export SIEM_ADMIN_PASSWORD='choose-a-long-password'      # optional; otherwise generated
export SIEM_ANALYST_PASSWORD='choose-another-long-one'   # optional; otherwise generated
export SIEM_VIEWER_PASSWORD='a-read-only-demo-login'     # optional; creates a read-only `viewer` account
./start.sh                                               # http://127.0.0.1:8080
```

If you don't set the password variables, Watchpost generates random passwords on first start. It writes them to `data/initial_credentials.txt` (mode 0600) and never prints them to the logs.

Then sign in as `admin`, open **Admin → Load synthetic demo data**, and follow [DEMO_SCRIPT.md](DEMO_SCRIPT.md).

### Tests

```bash
./run_tests.sh      # 565 unit/integration tests + a 26-step end-to-end smoke check
```

### Replit

`.replit` is included. Before the first run, add `SIEM_ADMIN_PASSWORD` and `SIEM_ANALYST_PASSWORD` in **Secrets**. The Replit run command binds `0.0.0.0` (needed for the Replit webview) and sets `SIEM_SECURE_COOKIES=1`, because Replit serves over HTTPS. Anywhere else, the app binds to `127.0.0.1` unless you set `SIEM_HOST`. Keep the Repl private, or at least don't share the URL, unless you intend the app to be reachable.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SIEM_DB` | `data/watchpost.db` | SQLite database path |
| `SIEM_HOST` / `SIEM_PORT` (or `PORT`) | `127.0.0.1` / `8080` | Bind address |
| `SIEM_ADMIN_PASSWORD`, `SIEM_ANALYST_PASSWORD` | generated | Initial account passwords (min. 12 chars), used only when the database is empty |
| `SIEM_VIEWER_PASSWORD` | unset (no viewer) | Creates a read-only `viewer` account on start if none exists; never generated, never resets an existing viewer |
| `SIEM_SECURE_COOKIES` | `0` | Set `1` behind HTTPS |
| `SIEM_SESSION_TTL` | `28800` | Session lifetime in seconds |
| `SIEM_MAX_UPLOAD_BYTES` / `SIEM_MAX_BATCH_EVENTS` | 5 MB / 20000 | Ingestion limits |
| `SIEM_SYSLOG` | `0` | `1` also starts the UDP/TCP syslog listener ([docs/LIVE_INGEST.md](docs/LIVE_INGEST.md)) |
| `SIEM_SYSLOG_BIND` / `SIEM_SYSLOG_PORT` | `127.0.0.1` / `5514` | Syslog listener address (same port for UDP and TCP) |
| `SIEM_SYSLOG_ALLOW` | empty (any) | Comma-separated IPs/CIDRs allowed to send syslog |
| `SIEM_DEMO_LOOP` / `SIEM_DEMO_LOOP_SPEED` | `0` / `1` | Minutes between automatic replays of the synthetic attack storyline (0 = off) and its speed multiplier |
| `SIEM_RATE_LIMIT` | `1` | `0` turns off per-IP rate limiting |
| `SIEM_LOGIN_RATE_BURST` / `SIEM_LOGIN_RATE_PER_MIN` | `10` / `10` | Token bucket for `POST /api/auth/login`, per client IP |
| `SIEM_RATE_BURST` / `SIEM_RATE_PER_MIN` | `300` / `1200` | Token bucket for every other request (API and static), per client IP |
| `SIEM_TRUST_PROXY` | `0` | `1` behind a local reverse proxy: the client IP is the last `X-Forwarded-For` entry on loopback connections |
| `SIEM_AUDIT_KEY` | unset (unkeyed) | HMAC key for the audit log hash chain; see [Tamper-evident audit log](#tamper-evident-audit-log) |

### Public deployment

[`deploy/`](deploy/README.md) installs Watchpost on a Debian 12 VM as a hardened systemd service on loopback, with
Caddy (Let's Encrypt, for a domain) or nginx (self-signed, for a bare IP) in front:
`sudo ./deploy/install.sh --caddy demo.example.org`. Publish only the `viewer` login.

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
| `watchpost/rules.py` | Fifteen built-in explainable rules as pure functions over event lists, each with a plain-English explanation. Also validates rule parameters. |
| `watchpost/engine.py` | Stores each batch atomically, then runs detection over the batch's time range plus the longest rule window. Rules that compare with earlier activity (`history_seconds`) also get their own history span before that, of only the event types they read. Deduplicates and extends open alerts, and records every detection run. |
| `watchpost/queries.py` | Event search (parameterized SQL), alert detail with evidence and a related-events timeline, notes, status changes, and SOC metrics. |
| `watchpost/hunt.py` | Hunt query parser and compiler (whitelisted fields, bound values), the `\|` stats/top/timechart stage, and saved searches. |
| `watchpost/search_rules.py` | Saved searches promoted to threshold detection rules (`search_<slug>`): the hunt filter matched in Python over the engine's event dicts, the sliding-window count, and their labeled samples. See [Saved searches as detections](#saved-searches-as-detections). |
| `watchpost/auth.py` | PBKDF2-SHA256 password hashing, lockout, and server-side sessions (only token hashes are stored). Also ingest-only API tokens (hashed) and the viewer < analyst < admin roles. Viewers are read-only: the server refuses every non-GET request from them except logout. |
| `watchpost/masking.py` | Viewer data masking: keyed pseudonyms for usernames and internal IPs in viewer responses when `viewer_masking` is on. See [Viewer data masking](#viewer-data-masking). |
| `watchpost/totp.py` | RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s, ±1 step), stdlib only. See [Two-factor sign-in and sessions](#two-factor-sign-in-and-sessions). |
| `watchpost/ratelimit.py` | In-memory per-IP token buckets. `server.py` answers 429 with `Retry-After` when a bucket is empty. |
| `watchpost/health.py` | Component checks, each with a status (`ok`/`degraded`/`failing`), a message, and recovery guidance. |
| `watchpost/improve.py` | Scenario evaluation (TP/FN/FP, recall, precision), rule performance from analyst verdicts, heuristic suggestions, and two-person change review. |
| `watchpost/backtest.py` | Replays a proposed rule change over stored events (kept / new / lost findings, open alerts it would lose) for the review evidence and the preview route. |
| `watchpost/portability.py` | Rule export and import: tuning (params, enabled) out as versioned JSON, and back in as reviewed `rule_update` proposals. |
| `watchpost/ecs.py` | Maps an event to Elastic Common Schema field names for export. |
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
| `unsanctioned_cloud_service` | an account uses a cloud service that is not on the sanctioned list (or a subdomain of one) | medium |
| `cloud_logging_disabled` | a cloud audit event records `StopLogging`, `DeleteTrail` or `DeleteFlowLogs` (the `logging_actions` list) | high |
| `admin_action_from_new_source` | an account makes a privileged action (privilege use/escalation, cloud IAM change) from an IP it used for none of its privileged actions in the previous 7 days, and it made ≥ 3 in that span | medium |
| `log_source_silent` | a source and host with a learned cadence stops sending: quiet for > 6× its median gap between arrivals, > 1 h, and > twice its longest recent gap ([Log source health](#log-source-health)) | medium |

Every rule maps to MITRE ATT&CK techniques from a small static catalog (`watchpost/attack.py`, 20 techniques, no network fetch). `GET /api/attack/coverage` grades each technique by evidence (below) and counts how often its rules fired.

The two newest rules use only fields the schema already carries, and each has a labeled attack and a benign look-alike in the noise lab (both detect their attack, tp 1 / fn 0 / fp 0, and stay quiet on their look-alike):

- **`cloud_logging_disabled`** (T1562.008). Reads the action from cloud audit messages of the form `<action> on <service>`, as the CloudTrail parser writes them. Attack `logging_disabled`: the rogue principal `svc-deploy-tmp` stops and deletes the trail, so in the demo it joins the cloud-intrusion incident as a Defense Evasion stage. Look-alike `trail_maintenance`: an admin creates a trail, changes event selectors, updates it and starts logging. `UpdateTrail` and `PutEventSelectors` are not listed by default because the event names the action but not the new settings, so the rule cannot tell whether such a change turned logging off. A denied `StopLogging` also alerts.
- **`admin_action_from_new_source`** (T1078, T1078.004). Attack `admin_new_source`: `ops-admin` changes IAM from the office each morning, then creates an access key from an outside address at 19:10. Look-alike `admin_known_source`: the same admin's IAM change from the usual address, plus a read-only call from a new one. **Cold start:** an account with fewer than `min_prior_actions` privileged actions in `history_seconds` has no baseline and never alerts. That covers every account on a fresh install until it has made three privileged actions, an account that admins less often than that in a week, and an account whose first privileged action is the attack (`cloud_iam_change_by_new_principal` covers a never-seen cloud principal). Events without a source IP, which includes most local sudo lines, are skipped. A legitimate admin on a new laptop address will alert.

MFA push fatigue (T1621) is not built: no event carries an MFA signal (the auth parsers record only success or failure, and the CloudTrail parser does not keep `MFAUsed`), and the rule would need a new log source.

### ATT&CK coverage

A rule mapping to a technique is a claim, not proof. The **Coverage** view (and `GET /api/attack/coverage`, viewer) puts every catalog technique on one of four levels:

| Level | Meaning |
|---|---|
| **validated** | An enabled rule maps to it and detects a labeled malicious scenario that exercises it. |
| **mapped** | An enabled rule maps to it, but no labeled scenario proves detection. Not counted as covered. |
| **disabled** | Only disabled rules map to it. |
| **gap** | No rule maps to it. |

Each malicious scenario in `watchpost/simulate.py` lists the techniques its events actually show (`SCENARIO_TECHNIQUES`), which is narrower than the rules' own mappings. With the default rules, 17 of 20 techniques are validated. T1595.001 (`firewall_port_sweep`: one outside source sweeping one host's ports is not scanning IP blocks), T1190 (`web_scanner`: the scan probes and sends injection strings but never exploits anything) and T1048 (`data_exfil_volume`: the scenario reads cloud storage but shows no exfiltration channel) are only mapped. Each technique lists its rules with their noise-lab verdict, the proving scenarios, and live alert counts; the Navigator layer is colored by the same levels.

The scenarios are synthetic, so "validated" means a rule detected the project's own labeled data, not that it would catch the technique in real traffic. The catalog holds only techniques a Watchpost rule maps to, so the counts are not a measure against all of ATT&CK.

### Incidents (correlation)

After each detection run, `watchpost/correlate.py` groups related alerts into incidents: alerts whose evidence shares a source IP, account, or host within 30 minutes. An incident needs two related alerts or one critical alert, lists its kill-chain stages (ATT&CK tactics in order), and is raised one severity level when it spans three or more tactics. Reruns change nothing; new alerts join an open incident.

Every rule except `log_source_silent` accepts `ignore_ips` and `ignore_users`. The engine merges overlapping findings into one open alert instead of creating duplicates, and a rescan never re-alerts on evidence already attached to an alert.

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

### Log source health

Silence hides attacks: a log forwarder that stops (crashed, uninstalled, or stopped by an intruder) looks exactly like a quiet network. Watchpost keeps no agent heartbeat; it reads the events it already stores. `GET /api/sources/health` (viewer) lists every (source, host) pair with its first and last arrival, events in the last 24 h, cadence, status and the reason for it, and the Health view shows it as the **Log source health** panel. A late or silent source links to its events in Hunt (`source:<x> host:<y>`). The code is `watchpost/sources.py`.

| Term | Definition (constants in `watchpost/sources.py`) |
|---|---|
| arrival | when Watchpost stored an event (`ingested_at`). Events stored in one batch are one arrival. |
| cadence | the median gap between consecutive arrivals, over the newest 100 gaps inside the 24 h before the pair's last arrival |
| learning | fewer than 10 gaps in that window, or under 2 h between first and last arrival. A burst (40 events in 3 minutes) is not a cadence. Never alerts. |
| healthy | not late or silent |
| late | quiet for more than 3× cadence, more than 15 min, and longer than the longest gap in the sample |
| silent | quiet for more than 6× cadence, more than 1 h, and more than twice the longest gap in the sample. `log_source_silent` alerts. |

The longest-gap terms are what keep bursty sources quiet: a nightly backup or an office-hours badge reader has a short median gap but a long overnight one, and without them it would go "silent" every evening.

**The clock.** Silence runs from the last arrival to the wall clock, not to the newest stored event. Entity scores (`entities.py`) anchor on the newest data so replayed demo data keeps its meaning; here a source going quiet is the very thing to see, so "now" has to be the real now. Arrival time, not event time, because replayed and back-filled data carries old timestamps: the demo dataset is dated on the previous weekday, so by `ts` every demo source would look dead since yesterday, while by arrival it is one upload, and so learning. Arrival time also ignores a host's clock skew. The cost: one upload of a week of logs is one arrival, and a forwarder that buffers and resends looks alive while it resends.

**The rule.** `log_source_silent` maps to T1562.006 (Impair Defenses: Indicator Blocking): stopping or blocking a host's log forwarding is that technique, and ATT&CK's own detection advice for it is to watch for a sensor that stops reporting. It does not read the events of the scanned time range like the other rules: each detection run (after every stored batch, and on **Run detection**) hands it each pair's newest 102 arrivals and the clock. It judges each finished gap against the cadence as of its start, and the current silence against the cadence now. The evidence is the last event before the silence, so one silence is one alert however often detection runs, and a resolved one is not raised again for the same silence. The noise lab judges its scenarios as of the end of the scenario day, where each event arrives at its timestamp: attack `log_source_stops` (dc01's telemetry every 5 min since midnight, forwarder stopped at 13:40) is detected, look-alike `office_badge_reader` (three office days of badge swipes, quiet each evening) is not. Loaded as demo data, `log_source_stops` is one upload and stays learning. The live storyline replayed every 10 minutes never goes silent (a test replays 5 hours of it).

**Maintenance windows.** A window (source, optional host, start, end, at most 30 days) excuses silence: quiet time inside it does not count, and the clock resumes when it ends. Windows are added like tuning exceptions, because they reduce detection: an admin proposes one (`POST /api/sources/maintenance` with `source`, `host`, `start`, `end`, `reason`, or the form on the Health view) as a `maintenance_add` change request, and a different admin approves it under Rules → Change requests. An admin can end a window early (`POST /api/sources/maintenance/{id}/end`), which only makes detection stricter, so it is a direct, audited action. Viewers and analysts can do neither.

**Not in `/api/health`.** That endpoint reports Watchpost's own health and returns 503 when it fails. A silent upstream source is not a fault of this service, so it is an alert and this inventory, not a health check.

**Limits.** Computed per query: nothing runs on a timer, so the rule is evaluated only when some batch arrives or someone runs detection; if every source stops at once, nothing raises the alert until the next run (the inventory still shows it). This is not a replacement for agent heartbeats: it cannot tell a crashed forwarder from a stopped one or from a host that is simply idle, a source that was never seen is not missing, and a source that sends less than ten times in its first day stays learning. Each detection run reads every pair's arrivals, one indexed query per pair, which is cheap for tens of sources and grows with thousands of hosts. A backtest of this rule replays only silences that ended, since it has no clock.

### Continuous improvement (what it actually does)

1. When analysts resolve an alert, they record a verdict: `true_positive`, `false_positive`, or `benign`.
2. **Rules** shows per-rule alert counts and precision, TP / (TP + FP).
3. **Suggest improvements** applies fixed heuristics. If ≥ 2 false-positive alerts share an IP (or account) that never appears in a true positive, it proposes excluding that IP (or account). Otherwise, if false-positive event counts sit below every true-positive count, it proposes a higher threshold.
4. Each proposal, from the system or a person, is scored against the labeled synthetic scenarios before and after the change.
5. Nothing changes until an admin approves, and that admin can't be the one who proposed it. Approval bumps the rule version, writes `rule_history`, re-runs the evaluation, and records everything in the audit log. Security settings (lockout threshold and duration) follow the same process.

This is **not machine learning**. It is transparent, deterministic tuning support.

### Backtesting rule changes

Before a rule change is approved, `watchpost/backtest.py` replays the rule over stored events twice, once with today's params and once with the proposed ones, and compares the findings by group key: **kept**, **new** (fires only with the change) and **lost** (fires only today). Each finding lists its entities (linked to their entity pages), first and last time, event count, and a few evidence event ids. It loads events and applies active tuning exceptions and history context through the same engine functions detection uses (`engine.scan_events`, `engine.rule_findings`), so it reports what detection would really do with those params.

- **Window.** The last 7 days of stored event time, ending at the newest stored event. A preview can ask for 1 to 30 days. If the window holds more than 100,000 events, it starts later until it doesn't, and the result says `capped`. At least one rule window is always scanned. The result also gives the window, the number of events scanned, and how many of them are synthetic (`all`, `some` or `none`).
- **Open alerts.** A lost finding is marked when it reproduces an alert that is still open or under investigation. Reproducing means it shares evidence events with that alert under the same group key. The proposal would never have raised that alert. Approving such a change needs the same explicit `acknowledge_detection_loss: true` as losing a labeled attack, and the audit entry names the alerts (`acknowledged_open_alerts_lost`).
- **Review evidence.** Every `rule_update` proposal carries the backtest counts and up to 10 kept, new and lost findings in its evidence. The evidence is hashed into the `evidence_digest`, and approval must present the same digest. The digest covers the findings (kept, new, lost, and open alerts lost) but not the scan context (window, events scanned), so an unrelated event arriving between viewing and approving does not void the review; a change in what the proposal would keep, add, or lose does, and the reviewer has to look again.
- **Preview.** `GET /api/rules/<id>/backtest?params=<JSON>&days=<1-30>` backtests a draft without proposing it. The params are validated exactly as a `rule_update` proposal is (a bad value is a 400). The route needs the analyst role, like proposing. The viewer gets 403 but can read the backtest in a change request's evidence. Every backtest is rate-limited per account on top of the general request limit: previews get a burst of 6, then 12 a minute; rule proposals and approvals of rule changes, which also replay stored events, share a separate burst of 20, then 12 a minute. In the UI, **Propose change…** has a **Preview backtest** button, and **Rules & review** shows a "Backtest on stored events" block on each rule change.

What it is not: it replays stored events only, so it can't predict traffic you haven't stored or behavior that hasn't happened yet. A finding that is "kept" can still change size within its group key, and an open alert raised under older params, or from events outside the window, isn't counted. On the demo, the stored events are synthetic, and the block says so.

### Rule export and import

`GET /api/rules/export` (viewer) downloads `watchpost-rules.json`: `{format: "watchpost-rules", format_version: 1, watchpost_version, exported_at, note, rules}`, each rule with its `id`, `name`, `version`, `enabled`, `severity`, `params`, ATT&CK technique ids and `description`. Keys and rules are sorted, so two exports of the same state differ only in `exported_at`.

**What moves is tuning, not detection logic.** Rules are Python functions in `watchpost/rules.py`, and that code is not exported. An import can change the `params` and `enabled` of rules the importing instance already has. It cannot add a rule or change how one detects. `severity`, `version`, `name`, `description` and the techniques are carried for reading only and are ignored on import.

`POST /api/rules/import` (analyst and above) takes that document, up to 256 KB and 200 rules. It applies nothing. A wrong `format` or `format_version`, an unknown top-level key, or a malformed document refuses the whole import. Each rule is then checked on its own: an unknown rule id, an unknown key, or params that fail the same validation a `rule_update` proposal uses are refused with a reason. Each rule whose params or enabled state differ from today's becomes an ordinary `rule_update` change request with the reason "imported from <file name>", carrying only the changed keys. The backtest evidence, the detection-loss acknowledgement, the true-positive gate and the two-person review all still apply. Identical rules are reported as `unchanged`. The response lists each rule as `proposed` (with `change_id`), `unchanged` or `refused` (with `reason`). `?dry_run=1` returns the same outcomes (`would_propose` instead of `proposed`) and creates nothing.

Every proposal runs a backtest, so an import spends one token per changed rule from the same per-account bucket as hand-made rule proposals (burst 20). It spends them all up front, or refuses the import with 429 and proposes nothing. A dry run spends nothing. The import is audited as `rules_imported` with the change ids, the unchanged count and the refusal reasons. On the **Rules** page, **Export rules (JSON)** is there for every role; **Import rules…** (analyst and above) previews the dry run, then **Create proposals** sends it.

### Sigma rule import

`watchpost/sigma.py` imports a [Sigma](https://github.com/SigmaHQ/sigma) rule as a new Watchpost rule. It is the only way to add detection logic without code, and it supports a deliberately small subset. Anything outside it is refused with a reason that names the problem; nothing is silently approximated.

**YAML.** A stdlib parser for the YAML that Sigma rules use: mappings, block lists (including lists of mappings), plain, single- and double-quoted scalars, comments, simple one-line `[a, b]` lists of scalars, `|` and `>` text blocks (for `description`), and `|` modifiers in keys. Refused: anchors, aliases, tags (`!`, `!!`), flow mappings, nested flow lists, multiple documents, directives, complex keys, merge keys, tabs, duplicate keys, and multi-line plain or quoted scalars. A rule is at most 64 KB and 2,000 lines, and its compiled detection (after the condition is expanded, since naming a selection twice copies it) at most 2,000 values and 128 KB.

**Rule keys.** `title` (required; it names the rule id), `id`, `status`, `description`, `level` (`informational` and `low` → low, `medium`, `high`, `critical`; default medium), `tags` (`attack.tXXXX[.XXX]` becomes an ATT&CK technique when it is in the catalog; other tags are listed as warnings and kept out of coverage), and `detection`. `logsource` is accepted but **informational only**: the rule runs on every stored event, whatever its source. Other keys (`author`, `references`, `falsepositives`, ...) are ignored.

**Detection.** Named selections and one `condition` string.

- A selection is a map of field → value or list of values: OR within a list, AND across fields. A list of maps is OR of the maps. A bare value or list of values (keywords) matches as a case-insensitive substring of `message`.
- Values match case-insensitively, as in Sigma. `*` and `?` are wildcards (`\*`, `\?`, `\\` are literals); `null` matches an empty field. Numbers compare as text (`dest_port: 22`).
- Modifiers: `contains`, `startswith`, `endswith`, `all` (every value must match, instead of any), and `cidr` (stdlib `ipaddress`). At most one of contains/startswith/endswith/cidr per field, plus `all`.
- Conditions: a selection name, `and`, `or`, `not`, parentheses, `1 of <pattern>`, `all of <pattern>` (`sel*` style), `1 of them`, `all of them`.
- Refused with a reason: the `re` modifier (an imported pattern could take unbounded time), base64 and other encoding modifiers, `windash`, numeric comparisons, `exists`, aggregations (`| count() by ...`), `near`, `timeframe`, `N of` other than 1, lists of conditions, unknown selection names, and any field without a Watchpost counterpart (the reason names the field).
- Fields: Watchpost names (`event_type`, `user`, `src_ip`, `host`, `dest_ip`, `dest_port`, `bytes`, `message`), their ECS names from `ecs.py` (`event.action`, `user.name`, `source.ip`, `host.name`, `destination.ip`, `destination.port`, `message`), and a few Sigma names with a clean mapping: `SourceIp`/`IpAddress`/`src_ip` → src_ip, `DestinationIp`/`dst_ip` → dest_ip, `DestinationPort`/`dst_port` → dest_port, `User`/`TargetUserName` → user, `Computer`/`ComputerName`/`hostname` → host. `EventID`, `Image`, `CommandLine` and the like are refused: Watchpost events do not carry them.

**Compiled form.** The detection compiles to a small JSON tree (`and`/`or`/`not`/`match`), stored as the rule's `params`, and an interpreter walks it over each event. There is no `eval` or `exec`, and no regular expression is built from the rule: wildcards are matched by a linear-time glob routine. The params are not tunable; change the YAML and import it again under a new title. The original YAML and its sha256 are stored with the rule (`sigma_rules` table, schema 9) and shown read-only on the rule card.

**Findings.** Every matching event is evidence (there is no threshold). Matching events are grouped by source IP; events without one by host, then by user. Within a group, events more than an hour apart start a new finding. The rule id is `sigma_<title as lowercase letters and underscores>`, so it never collides with a built-in rule.

**Workflow.** `POST /api/rules/sigma` (analyst and above) takes `{source, sample (optional), reason (optional)}`.

- `?dry_run=1` compiles the rule and returns the compiled conditions, warnings, the sample result, and a preview on stored events (events scanned and matched, findings, group keys over the last 7 days of stored event time, through the engine's own `scan_events`/`rule_findings`). A refusal comes back as `{ok: false, refused: <reason>}`. A dry run spends one token from the per-account preview backtest bucket (burst 6).
- Without `dry_run` it creates a `sigma_add` change request (spending one token from the rule-proposal bucket, burst 20, as its evidence carries the same preview). A different admin approves it with the evidence digest; approval adds the rule **disabled**.

**Labeled sample, and the enable gate.** A Sigma rule has no built-in scenario, so it brings its own: `{"malicious": [events], "benign": [events]}`, 1-50 events each, with Watchpost field names. The sample passes when every malicious event matches and no benign look-alike does. It is part of the import, or attached or replaced later with `POST /api/rules/<id>/sigma-sample` (a `sigma_sample` change request with the same two-person review; it bumps the rule version). Enabling is an ordinary `rule_update` with `enabled: true`, refused at proposal and again at approval unless the stored sample passes. In the noise lab the sample appears as the scenario `sigma_sample:<rule id>`: a passing sample counts as a detected attack and a tested look-alike, a failing one as missed or fired. Its ATT&CK techniques are therefore **mapped** while the rule is enabled without a passing sample (for example after a failing sample replaced a good one) and **validated** only while the sample passes. The built-in scenario labels never count for or against an imported rule.

What it is not: a Sigma backend. The sample is written by the importer and reviewed by a second person; a passing sample proves the rule matches those events, not that it catches the technique in real traffic. A worked example is in `docs/sigma-examples/`.

### Saved searches as detections

Like a scheduled saved search with an alert condition: a hunt that finds something worth watching can be promoted to a threshold rule. It follows the Sigma pattern above (change request, added disabled, labeled sample gate, mapped then validated coverage) and runs inside the engine's normal scan.

**Definition.** `POST /api/hunt/saved/<id>/promote` (analyst and above) with `{group_by, threshold, window_minutes, severity, techniques (optional), name (optional, defaults to the saved search's name), sample (optional), reason (optional)}`.

- **Query:** the saved search's filter, copied into the request when it is promoted (editing or deleting the saved search later changes nothing). Filter only: a `|` stage is refused (the group-by and threshold do the counting), and so are time terms (`last:`, `since:`, `until:`): the window replaces them. `outcome`, `severity` and `batch_id` are refused too, because the engine does not load them into the events rules read. At least one term; the hunt limits apply (500 characters, 20 terms).
- **group_by:** one of `src_ip`, `user`, `host`, `dest_ip`, `source`, `event_type`, `dest_port`. Events without a value are not counted. Values group exactly, except accounts: `user` groups case-insensitively, as the `user:` filter matches, so `alice`, `Alice` and `ALICE` count toward one threshold instead of each staying under it.
- **threshold / window:** fire when at least `threshold` (1-100,000) matching events of one group value fall within `window_minutes` (1-1,440) of each other. It is a **sliding** window, inclusive at both ends: the window ending at each event holds the events at most W minutes older (N events spanning exactly W minutes fire; a millisecond more does not). Every event in a qualifying window is evidence, and evidence events closer than W become one finding, the same windowing as the built-in threshold rules (`rules._clusters`). Stored as `window_seconds` (a multiple of 60).
- **severity:** low, medium, high or critical. **techniques:** up to 10 ATT&CK ids from the catalog.

The rule id is `search_<name as lowercase letters and underscores>`. Its `params` are the compiled definition `{title, query, terms, group_by, threshold, window_seconds}`; `validate_params` re-parses the query and refuses stored terms that disagree with it.

**Matching.** The filter runs in Python over the event dicts the engine already passes (`engine.RULE_EVENT_FIELDS`), with the hunt's SQL semantics: the same fields and value checks, a trailing `*` on an unquoted value is a prefix match, message terms mean "contains", and `NOT` keeps events missing the field. Case follows SQLite, which folds ASCII letters only: `user:` equality, every prefix match and message contains ignore ASCII case; other equality (host, source, IPs, event_type) is exact. `tests/test_search_rules.py` runs some 45 queries through both this matcher and `hunt.compile_query` in SQL over a varied event set (mixed case, non-ASCII, `%`/`_` in values, missing fields) and requires the same events, so the two cannot drift.

**Workflow and the gate.**

- `?dry_run=1` compiles the definition and previews it on stored events (the last 7 days of stored event time, through `scan_events`/`rule_findings`): events matched, findings, group keys and up to 5 sample findings. A refusal comes back as `{ok: false, refused: <reason>}`.
- Without `dry_run` it creates a `search_add` change request whose evidence carries the same preview. A different admin approves it with the evidence digest; approval adds the rule **disabled**.
- Both spend one token from the per-account rule-proposal backtest bucket (burst 20), and so does approving a `search_add`.
- **Labeled sample:** `{"malicious": [events], "benign": [events]}`, 1-50 events each, Watchpost field names plus `source` (Sigma's checks). Because the rule counts, the sample is judged as a run, not event by event: it passes when the malicious events raise at least one finding and the benign look-alikes raise none. Events without a `ts` are one second apart in list order. Attach or replace it with `POST /api/rules/<id>/search-sample` (a `search_sample` change request).
- **Enable:** an ordinary `rule_update` with `enabled: true`, refused at proposal and approval unless the stored sample passes. In the noise lab the sample is the scenario `search_sample:<rule id>`; the rule's ATT&CK techniques count as **validated** only while the rule is enabled and its sample passes, and as **mapped** otherwise.
- **Tuning:** unlike Sigma, `threshold` and `window_seconds` are tunable through a normal `rule_update`, with the usual scenario evaluation and backtest in the evidence. Nothing else in `params` is: a different query, group-by or name means promoting a saved search again as a new rule.

In the UI, each saved search on the Hunt page has **Promote to detection…** for analysts (dry run, then submit); the rule card shows the query read-only, and **Labeled sample…** and **Propose change…** work as for any rule. Viewers see promoted rules and their queries but cannot promote.

What it is not: a scheduled search. It does not re-run SQL on a timer; the filter is evaluated in the detection run over each ingest's time range, like every other rule. It has no `OR`, no `| stats` thresholds beyond count-by-one-field, and no distinct-count condition.

### ECS field mapping

`GET /api/events/<id>/ecs` (viewer) returns one stored event as an Elastic Common Schema (ECS) shaped document, for export and interop with ECS-based tools. This is a field mapping on the way out. Watchpost still stores events in its own flat schema, and the hunt language uses Watchpost names. The mapping lives in `watchpost/ecs.py`.

| Watchpost field | ECS field | Note |
|---|---|---|
| `id` | `event.id` | as a string |
| `ts` | `@timestamp` | |
| `ingested_at` | `event.ingested` | when Watchpost stored it |
| `source` | `event.module` | closest fit; Watchpost's source is a free-form log-source label |
| `host` | `host.name` | |
| `event_type` | `event.action` | also sets `event.category` / `event.type` where a clear pairing exists (below) |
| `outcome` | `event.outcome` | only for `success`, `failure` or `unknown`; any other text stays as `watchpost.outcome` |
| `user` | `user.name` | |
| `src_ip` | `source.ip` | |
| `dest_ip` | `destination.ip` | |
| `dest_port` | `destination.port` | |
| `message` | `message` | |
| `raw` | `event.original` | the redacted original record |
| `synthetic` | `labels.synthetic` | `"true"` / `"false"` (ECS labels are keywords) |
| `severity` | not mapped (`watchpost.severity`) | ECS `event.severity` is a number on the source's own scale; Watchpost's is a word |
| `bytes` | not mapped (`watchpost.bytes`) | ECS byte counts carry a direction (`source.bytes`, `destination.bytes`) or a two-way total (`network.bytes`); Watchpost's has neither, and for cloud reads it is not network traffic |
| `batch_id` | not mapped (`watchpost.batch_id`) | no ECS counterpart |

Every document also has `event.kind: "event"`. Event types with a category: `auth_failure`, `auth_success`, `vpn_login` → authentication / start; `account_lockout` → iam / user, change; `user_created` → iam / user, creation; `cloud_iam_change` → iam / change; `process_start` → process / start; `file_access` → file / access; `network_connection` → network / connection; `fw_allow` and `fw_deny` → network / allowed or denied, connection; `web_request` and `web_scan` → web / access; `web_error` → web / error. `privilege_use`, `privilege_escalation`, `cloud_api_call`, `cloud_data_access`, `syslog` and `other` get no category, because no single ECS category fits them across sources.

### Tamper-evident audit log

Each audit entry stores `prev_hash` and `hash`, where `hash = HMAC-SHA256(key, prev_hash + JSON of id, created_at, actor, action, target, detail)`. The previous hash is read and the new entry written in the same write transaction, so concurrent writers cannot fork the chain. `GET /api/audit/verify` (admin only) walks the log once and returns `{ok, status, entries, keyed, head: {id, hash}, chain_started: {id, created_at}, legacy: {entries, last_id}, first_break: {id, reason, detail} | null}`; **Admin → Audit log** shows the result as a badge.

`status` is `verified` only when every entry in the log is chained and intact, `partial` when the chain is intact but older unverified entries precede it, and `broken` when `first_break` is set. `ok` is `true` only for `verified`, so a script or monitor that checks `ok` never reads a partly unverified log as healthy.

**Where the chain starts.** The server only hashes entries it is writing. When no entry carries a hash (a new database, an upgrade from 3.x, or a log whose hashes were removed), the next start writes an `audit_chain_started` entry that links to a fixed genesis value (64 zeros) and records how many older entries exist, the last id, and an identifier of the key (an HMAC of a fixed label, not the key). Those older entries are **legacy**: they are counted, but nothing vouches for them. The result is `partial`, and the badge reads "Chain intact from entry #X (date), but N earlier entries are not verified". Upgrading a 3.x database therefore stays `partial` for good rather than the server signing whatever the file contains: those entries really are unverified.

**The key must stay the same.** The server refuses to start when `SIEM_AUDIT_KEY` differs from the key the chain was started with (including set versus unset), and it never appends an entry under another key. Verifying with another key reports `key_mismatch` instead of passing under plain SHA-256.

**What it detects:** an entry edited in place, one with its hash cleared, or one changed by a database trigger as it was written (`modified`; the server hashes the values it inserted, never the row read back); entries deleted from the middle or the start of the chain, an emptied log, or a chain start whose id shows earlier entries were removed (`deleted`); an entry rewritten together with its own hash, or a second chain start (`broken_link` at that entry or the one after it); legacy entries added or removed after the chain started (`legacy_mismatch`, checked against the signed count in the chain start).

**What it does not detect:**
- Deleting the newest entries. What remains is still a valid, shorter chain (the next append leaves an id gap, but nothing shows it before then).
- Why a chain restarted. Someone who can write the database file can drop the hash column, or clear every hash, and restart the server. The result is `partial` (not `ok`), with the old entries reported as unverified, but it looks the same as a genuine 3.x upgrade. A chain start dated after your upgrade is the sign.
- A full rewrite without a key. With `SIEM_AUDIT_KEY` unset the chain uses plain SHA-256 and `keyed` is `false`: anyone who can write the database file can recompute every hash, and verification passes. That mode only catches careless edits.
- Anyone who has the key. Set `SIEM_AUDIT_KEY` to a long random value kept outside the database (`python3 -c "import secrets; print(secrets.token_hex(32))"`). Set it before the first start and keep it (see above).

For the first two, record the head and the chain start (`id`, `hash`, `created_at`) somewhere the database cannot reach, such as a ticket, a log shipped off the box, or a daily note, and compare them later.

### Two-factor sign-in and sessions

Analysts and admins can add a TOTP second factor (RFC 6238: HMAC-SHA1, 6 digits, 30-second steps, codes from one step before or after accepted for clock drift). It is opt-in per account. The read-only `viewer` role cannot enroll (403), so the public demo login stays a single password step.

**Enrolling** (**Account → Two-factor sign-in**, or the API): `POST /api/auth/mfa/enroll` returns `{secret, otpauth_uri}` with `otpauth://totp/Watchpost:<user>?secret=...&issuer=Watchpost`. There is no QR code: enter the secret in your authenticator app. The secret stays pending, and sign-in stays one step, until `POST /api/auth/mfa/confirm` with `{"code"}` succeeds. `POST /api/auth/mfa/disable` with a current code turns it off (or cancels an unconfirmed setup). `GET /api/auth/mfa/status` (any role) returns `{enabled, pending, available}`.

**Signing in** with it on: `POST /api/auth/login` checks the password and answers `{"mfa_required": true, "mfa_token": ..., "expires_in": 300}` instead of a session. The token is server-side (only its hash is stored, in `mfa_pending`), lasts 5 minutes, and is consumed by the first successful `POST /api/auth/mfa` with `{mfa_token, code}`, which creates the real session. Both routes share the per-IP login rate limit.

- **Lockout.** A wrong code counts toward the same per-account lockout as a wrong password and is audited as `login_failed` with `{"reason": "mfa"}`. Each code attempt (at sign-in or when turning two-factor off) is counted before its code is checked, in one transaction with the lock check, so parallel guesses cannot get more than the threshold of codes checked per lockout window. A correct password does not reset the count for an enrolled account; only a correct code does, so knowing the password does not buy unlimited guesses. Locking drops the account's pending tokens.
- **Replay.** The last accepted time step is stored per account (`users.totp_last_step`); a code from that step or an earlier one is refused, including the code used to confirm enrollment.
- **Secrets.** The secret and codes are never logged or audited. **The secret is stored in the database as-is, not encrypted at rest**: anyone who can read the database file can generate codes. There is no key management here.
- **Recovery.** There are no recovery codes. If someone loses their authenticator, an admin resets it: `POST /api/users/<username>/mfa/reset` (admin, not for your own account), audited as `mfa_reset`, or **Admin → Sign-in sessions → Reset two-factor**. The user then signs in with the password alone until they enroll again.

**Sessions.** `GET /api/auth/sessions` lists your active sessions: `id` (a random, non-secret session id), `created_at`, `last_seen_at` (refreshed at most once a minute), `expires_at`, and `current`. The session token and its hash are never returned. IP address and user agent are not recorded. `POST /api/auth/sessions/<id>/revoke` ends one of your own sessions (analyst and up; someone else's id answers 404). Admins can list every session (`GET /api/sessions`, optional `?user=`) and revoke any (`POST /api/sessions/<id>/revoke`). Every revoke is audited as `session_revoked` with the owner as target. There is no password-change route yet, so nothing revokes sessions on a password change.

Schema 8 adds `users.totp_secret`, `totp_pending`, `totp_last_step`, `sessions.sid`, `sessions.last_seen_at`, and the `mfa_pending` table; sessions from before the upgrade get an id on the next start.

### Viewer data masking

Real SIEMs restrict sensitive fields by role. With the security setting `viewer_masking` set to 1, every response to a `viewer` account shows usernames and internal IP addresses as pseudonyms: `user-3f9a2c1b`, `internal-8b21e0d4`. Analyst and admin responses are not touched (a test compares them byte for byte with masking on and off). **It is off by default**, so the public demo is unchanged until the owner turns it on.

**Turning it on.** It is a reviewed setting like the lockout ones: one admin proposes, a different admin approves, and both steps are in the audit log (`setting_changed`). In the UI, **Rules & review → Security settings**; or with the API:

```bash
curl -b admin.cookies -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"value": 1, "reason": "mask the public demo"}' http://127.0.0.1:8080/api/settings/viewer_masking/proposals
# then a different admin: POST /api/changes/<id>/review {"decision": "approve"}
```

Send `{"value": 0}` the same way to turn it off. A viewer with masking on gets `"masked": true` from login and `/api/auth/me`, and the header shows a **Masked view** pill.

**What is masked.**
- Usernames: every distinct `events.user` and every account name, matched as exact known values (case-insensitive, bounded to 10,000 distinct names; past that bound a viewer gets 503 instead of a response that could hold unmatched names), in structured fields and inside free text: event `message` and `raw`, alert `title`/`explanation`/`group_key`, incident text, notes, entity ids, change-request evidence, and report text. Identity fields (`assignee`, `author`, `actor`, `proposed_by`, ...) are masked whatever their value. An account named after a role (`analyst`) is masked in those fields but not as a word in text, where it is the product's own vocabulary ("Analyst notes"). The signed-in viewer's own name is not hidden from them.
- Internal IPs: RFC 1918, loopback, link-local and IPv6 ULA (`fc00::/7`), found with an IPv4/IPv6 pattern and confirmed with `ipaddress`, in fields, text and JSON keys.
- **Public IPs stay visible on purpose.** They are the attacker side, which is what the demo is about (the brute-force source, the spray source, the impossible-travel login). The synthetic demo uses documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); Python's `is_private` counts those as private, so masking lists its own internal networks instead.
- Host names are not masked.

**One choke point.** `server.Handler` builds a masker after authorization when the account is a viewer and the setting is on, and masks every JSON response, every error message (an error can echo a pivot's resolved value), every download (Markdown and PDF reports are rendered from a masked model; JSON downloads are masked as data; other text downloads are masked as text; a binary download without a model is refused rather than sent unmasked), and every live-stream frame (a viewer's stream re-reads the setting and the known names per frame, so a stream opened before masking was turned on is masked from then on). Routes do nothing themselves.

**Pseudonyms and the key.** A pseudonym is HMAC-SHA256 of the value, truncated to 8 hex characters. The key is derived from `SIEM_AUDIT_KEY` (HMAC of a fixed label, so the audit key itself is never used directly) when that is set; otherwise it is a random 32-byte secret created in the database's `meta` table on first start. Either way the same value gets the same pseudonym on every endpoint and across restarts, and no viewer route returns the key. Changing `SIEM_AUDIT_KEY` changes every pseudonym.

**Pivots still work.** Consistency is what lets a viewer pivot. A pseudonym in a query parameter or path segment is resolved server-side before the route runs: `user:user-3f9a2c1b` in Hunt, `?user=` and `?ip=` on event search, and `/api/entities/user/user-3f9a2c1b`. Resolution hashes the candidate values (the known usernames and up to 10,000 distinct event IPs) and keeps that map only for the request; no reverse map is stored. Wildcards on a pseudonym (`user:user-3f*`) do not resolve, and an unknown pseudonym simply matches nothing.

**Threat model, honestly.** This is presentation-layer masking for a low-trust, read-only role, not anonymization. It hides names and internal addresses from casual viewing of the public demo. It is not a privacy guarantee:
- Pseudonyms over a small username space can be brute-forced by anyone holding the key. The key never leaves the server, but anyone who can read the database file (or the environment) can reverse them.
- Context still identifies people: timestamps, host names, counts, and patterns in the data remain visible, and a viewer who already knows a username can confirm it by pivoting on it.
- Text that splits a name or address in unusual ways (escaped, encoded, or broken across tokens) can slip past exact matching.
- Static UI text (help strings in `app.js`) is not data and is not masked.

### Hunting

**Hunt** takes a one-line query over stored events. Terms are ANDed (there is no OR). The server echoes how it read each term, and the UI shows that as chips under the query box. The query lives in the URL (`#hunt/<query>`), so a hunt is a link you can share. Entity pages and the event detail have **Hunt** links that open it prefilled, for example `user:alice last:7d`.

| Form | Example | Meaning |
|---|---|---|
| `field:value` | `user:alice` | Exact match (user names ignore case, as in event search) |
| `field:prefix*` | `host:web*` | Starts with; unquoted values only |
| `field:"quoted"` | `user:"svc backup"` | Literal value; spaces and `*` are not special, `\"` escapes a quote |
| word or `"phrase"` | `"invalid password"` | Message contains (`%` and `_` are literal) |
| `NOT term` or `-term` | `NOT src_ip:10.0.0.5` | Excludes; events with no value in that field are kept |
| `last:` | `last:15m`, `last:24h`, `last:7d` | Window up to now, at most 365 days |
| `since:` / `until:` | `since:2026-10-01 until:2026-10-02T06:00Z` | ISO times, UTC unless an offset is given |

Fields: `user`, `host`, `source`, `outcome`, `src_ip`, `dest_ip`, `ip` (source or destination), `batch_id`, `event_type`, `severity`, `dest_port`, `synthetic` (`0`/`1`), `message`. An unknown field is an error that lists these. Queries are capped at 500 characters and 20 terms, and results page and sort like event search (newest first, up to 1000 per page).

```
user:alice event_type:auth_failure NOT src_ip:10.0.0.5 host:web* "invalid password" last:24h
ip:203.0.113.* event_type:fw_deny last:7d
event_type:auth_success -source:demo:* since:2026-10-01
```

#### Aggregations (`|` pipeline)

One stage may follow the filter, after a `|`. The filter picks the events and the stage counts them in SQL (`GROUP BY` with a `LIMIT`), so nothing loads the whole table into Python.

| Stage | Example | Result |
|---|---|---|
| `stats <agg>[, <agg>] [by <f1>[, <f2>]]` | `event_type:auth_failure \| stats count, dc(user) by src_ip` | One row per group, largest first (ties by value). Aggregates: `count`, `dc(<field>)` (also written `count(distinct <field>)`), at most 3. Without `by`, one row for all matched events. |
| `top [N] <field>` | `event_type:auth_failure \| top 10 src_ip` | The N most common values (1 to 100, default 10) with count and percent of all matched events. |
| `timechart span=<5m\|15m\|1h\|6h\|1d> [count] [by <field>]` | `host:web* last:24h \| timechart span=1h by user` | Events per time bucket. Buckets start on UTC boundaries (midnight for `1d`, 00/06/12/18 for `6h`) and are computed in SQL from the stored `ts`. Empty buckets are 0. With `by`, the 5 largest series are kept and everything else (including events without the field) is summed into `other`. |

Caps and rules:

- `stats` returns at most 1000 groups, and `top` at most N values. The response says `"truncated": true` when there were more.
- Groups compare values exactly, so `by user` lists `Alice` and `alice` separately even though the `user:` filter ignores case. A pivot on either one shows both.
- `timechart` covers the query's time window (`last:`, `since:`, `until:`), or the first to last matching event when there is none, and draws at most 500 buckets. A larger range is refused with the bucket count and a hint to narrow the time range or use a wider span, rather than silently trimmed. `last:24h` works with every span, `last:7d` needs `1h` or wider.
- Group-by and `dc()` fields come from the same whitelist as filter terms: any of them except `message` (free text), `ip` (use `src_ip` or `dest_ip`) and the time filters, each refused with the reason. Events with no value in a `by` field are left out of `stats` and `top` groups, but still count toward `top`'s percent.
- Only one stage. A second `|`, an unknown command, an unknown aggregate, or a field name that is not on the whitelist is a 400 that lists what is supported. Field names in the stage become SQL only through the whitelist, and values stay bound parameters.
- A `|` starts the stage only at the start of a word. Inside a quoted value (`"a | b"`) or an unquoted word (`host:a|b`) it is part of the value.

The response is `{"kind": "stats"|"top"|"timechart", "columns": [...], "rows": [[...], ...], "truncated": bool, "terms": [...], "query": "...", "filter": "..."}`, where `filter` is the query text before the `|`. A query without a stage keeps the event page shape. In the UI, `stats` and `top` render as a table where each value is a link that adds `field:value` to the filter and shows the matching events. `timechart` renders as an inline SVG chart (bars, or one line per series with `by`) with the numbers in a data table below it. Saved searches can hold a stage, and it is checked on save. The viewer can run aggregations but still cannot save.

Each term compiles to a fixed SQL fragment chosen from a field whitelist, with the value as a bound parameter, so a value like `user:"x' OR 1=1 --"` matches that literal user name and nothing else. Any role can run a hunt and read saved searches. Analysts and admins can save a search (the query is checked on save) and delete their own; admins can delete any. Each save and delete is written to the audit log.

### Asset inventory review

The asset inventory was contributed by Juan Carlos Munera (PR #9): criticality and sensitive-data tags per host, severity raised on alerts that touch them, and open alerts re-weighed whenever the inventory changes. Because the inventory raises severity, editing it can also lower severity, so one admin alone may not make an edit that could do that. Such an edit goes through the same two-person review as rule and setting changes.

| Needs a second admin | Applies at once (still audited) |
|---|---|
| Lowering criticality | Adding an asset |
| Removing a sensitive-data tag | Raising criticality |
| Removing an IP address (alerts on it stop matching) | Adding tags or addresses |
| Renaming the host (alerts on the old name stop matching; a change of case is not a rename) | Editing owner, kind, or description |
| Deleting the asset | |
| Claiming an address another asset already has | |

An address listed on several assets matches every one of them, so the order of the inventory (which a raise or a change of case can shift) never decides which asset an alert keeps. `assets.review_reasons` is the only definition of this list. The direct routes (`POST /api/assets`, `POST /api/assets/<id>`) apply an edit only when it has no review reasons, checked and written in one transaction. Otherwise they change nothing and answer 409 with `review_required`, the reasons, and `proposal_route`. `POST /api/assets/<id>/delete` always answers 409 that way. Proposals go to `POST /api/assets/<id>/proposals` (the full asset as for a direct edit, or `{"delete": true}`) or `POST /api/assets/proposals` (an add, if you want one reviewed), each with a `reason`. Proposing is admin only, like editing the inventory. Analysts and the viewer get 403, and the viewer can still read the inventory and its pending proposals.

An update stores only the fields it changes. The evidence a reviewer sees has the asset before and after, a before/after line for each changed field, the review reasons, and the open alerts whose severity the change would move, with from and to. Approval works like other change requests: a different admin (`POST /api/changes/<id>/review`), sending the `evidence_digest` they were shown. The server re-checks the change against the inventory as it is at that moment. If the asset was deleted, its new name is taken, or it already matches, the approval is refused with 409 and nothing is applied. If the asset was edited in between, the evidence is refreshed and the old digest is refused. An approved change is applied through the same asset functions as a direct edit, then open alerts are re-weighed and incident severities refreshed. Proposals, approvals, rejections, and the asset change itself are all written to the hash-chained audit log, and the asset entry names the change request. **Admin → Asset inventory** shows pending proposals on each asset (for example "Proposed: lower db01 to low (pending review, change #12)"), and the edit dialog offers **Propose for review** when the server answers 409. **Rules & review** lists them with the other change requests.

### Triage metrics

`GET /api/metrics/triage?window=7d` (any role, viewer included; `window` is `24h`, `7d`, `30d` (default), `90d`, or `all`) reports, per severity, for alerts created in the window: the count, how many are still `open` and unresolved, MTTA, MTTR, and SLA breaches. **Metrics overview** shows them in a table, and the alert list puts an `SLA: ack overdue` / `resolve overdue` badge on unresolved alerts past a target.

- **Acknowledged** (`alerts.acknowledged_at`, schema 7) is the first time an alert leaves `open`: *Start investigating*, or resolving straight from open. It is set once and never overwritten, even across reopens. Assigning an alert (`POST /api/alerts/<id>/assign` with `{"assignee": "<analyst or admin>"}`, analyst and up, audited) changes ownership only, not the status, so it does not count as an acknowledgement. Alerts that left `open` before schema 7 keep a NULL time; they are reported as `ack_unknown` and left out of MTTA and ack breaches rather than backfilled.
- **MTTA** is created → acknowledged; **MTTR** is created → resolved. Each comes as mean, median, and p90 (nearest-rank) in minutes over the alerts that have reached that step. All three timestamps are this instance's wall clock, so replayed event times do not distort them.
- **SLA breach**: the step took longer than its target, or is still pending and has been waiting longer. Late acknowledgements stay counted after the alert moves on; the list badge shows only what is overdue now.

| Severity | Acknowledge within | Resolve within |
|---|---|---|
| critical | 15 minutes | 4 hours |
| high | 1 hour | 24 hours |
| medium | 4 hours | 3 days |
| low, info | 24 hours | 7 days |

The targets are a constant (`watchpost/triage.py`, `SLA_TARGETS`), chosen as common SOC starting points, not taken from any contract. **On the demo every alert comes from synthetic scenarios**, so the numbers measure how quickly someone clicked through demo alerts, not a real team's performance. The response says so: `synthetic` is `none`, `some`, or `all`, with `synthetic_alerts`, and the panel carries the synthetic label.

---

## SOC dashboard

The landing view is a dark SOC console built for a 1280×800 screen: a status strip (events per minute, open and critical alerts, incidents, stored events, health checks, stream state, UTC clock), an attacker world map, a live event stream, alerts over time, top attacker IPs, the MITRE ATT&CK coverage heat matrix, an incident board, top rules, and health. Live updates arrive over Server-Sent Events (`GET /api/stream`); if the stream fails, the page polls every 3 seconds. Charts and the map are inline SVG drawn by `static/charts.js` and `static/map.js`, with no libraries and no external tiles.

**The map positions are synthetic.** `watchpost/geo.py` maps only the RFC 5737 documentation ranges to fictional city names at fixed coordinates, and the RFC 1918 ranges to internal sites. It is not a geo lookup. Any other address is listed as "unknown" and never guessed. The map is labeled "synthetic geo".

### Keyboard shortcuts

| Key | Where | Action |
| --- | --- | --- |
| `j` / `k` | Alerts list, Incidents board | Select the next / previous alert or incident (focus ring shows the selection) |
| `Enter` | Alerts list, Incidents board | Open the selected item |
| `a` | Alert or incident page | Start investigating (analyst and admin only) |
| `r` | Alert page | Open the resolve dialog (analyst and admin only) |
| `Esc` | Alert or incident page | Back to the list, with the item still selected; in a dialog, closes it |
| `/` | Any view | Focus the view's search box, or open Hunt when the view has none |
| `?` | Any view | Show the shortcut help (also the "Keyboard shortcuts" button in the side rail) |

Shortcuts never fire while you type in an input, textarea, or select, while a dialog is open, or with Ctrl, Alt, or Cmd held. The read-only viewer can move and open but gets no action keys.

### Accessibility and small screens

What was done: `nav` and `main` landmarks with a skip link, `aria-current` on the current view, a label or `aria-label` on every form control, clickable table rows reachable with Tab and opened with Enter, dialogs on the native `<dialog>` (focus stays inside, Esc closes, focus returns to the trigger), live regions for toasts and errors, status shown by shape and text as well as color, text alternatives on the charts, and no animation under `prefers-reduced-motion`. Text and badge colors meet WCAG AA (4.5:1) against every panel color of the one dark theme. Below 760px the nav folds behind a Menu button, controls are at least 40px tall, and wide tables scroll inside their card.

How it was checked: automated checks only, not a screen-reader audit. `tests/test_ui_a11y.py` asserts the cheap static parts (landmarks, labels in `index.html`, the shortcut handler ignoring typing and dialogs, color contrast computed from the CSS variables). `scripts/ui_check.js` drives headless Chromium through every view and the main dialogs at 1440px and 390px wide, as admin and as viewer: no horizontal page scroll, no unlabeled control or link (a small in-page audit, not axe), 40px tap targets at 390px, no JS errors, and the `j`/`k`/`Enter`/`a`/`r`/`Esc`/`/`/`?` flow. It needs `playwright-core` and a Chromium outside the repo:

```bash
NODE_PATH=/path/to/node_modules CHROME=/path/to/chrome-headless-shell node scripts/ui_check.js
```

## Attack storyline

Admin → "Attack storyline (synthetic)" replays a scripted six-stage intrusion over about two minutes (or faster): web scanning and a port sweep from `203.0.113.80`, a password spray then brute force against `dave`, a VPN login with the cracked password, sudo to root and a new `svc-deploy-tmp` account, a hop to `db01` and cloud IAM changes by that new principal, then bulk storage reads and large outbound transfers. Ten detection rules fire in order and correlation folds them into one Reconnaissance → Exfiltration incident while the dashboard updates live. Every record is labeled synthetic and uses RFC 5737 documentation addresses; the same replay runs in the test suite (`tests/test_storyline.py`) and the smoke check.

## Performance

One run on a dev laptop with synthetic data, not a benchmark. Your numbers will differ; the script is there so
you can produce your own.

```bash
python3 scripts/loadtest.py                    # 100,000 events into a throwaway DB under /tmp
python3 scripts/loadtest.py --events 250000 --json
```

`scripts/loadtest.py` (stdlib only, seed 7) generates a week of background activity (2,000 users, 200 hosts,
about 3,000 internal and 762 documentation-range IPs, 18 event types, a few very busy accounts) plus the labeled
demo scenarios, all stored as synthetic. It ingests them in time-ordered batches of 1,000 through the
`POST /api/ingest` handler (JSON parse, normalization, storage, and detection on each batch), runs one full
detection, then calls each read route's handler 20 times in-process and reports p50/p95. Read times include
the handler and JSON encoding, not HTTP. `--url http://127.0.0.1:8090 --token wp_... --db <that server's DB>`
ingests over HTTP instead.

Run on 2026-10-08 (UTC) with `python3 scripts/loadtest.py --json` (the same run as the command above, printed
as JSON). Machine: Python 3.14.2, macOS 26.6.2 arm64, 10 CPUs. Database on disk afterwards: 97.3 MB.

| Step | Result |
|---|---|
| Ingest (parse, normalize, store, detect per batch) | 18.8 s, 5,314 events/s |
| of which per-batch detection | 9.2 s |
| Full detection run (100,000 events) | 0.69 s |
| Alerts / incidents after the run | 26 / 7 |

| Read path (route handler + JSON, 20 runs) | p50 ms | p95 ms |
|---|---:|---:|
| events: no filter | 1.3 | 1.4 |
| events: user | 2.0 | 2.1 |
| events: user prefix | 2.3 | 2.4 |
| events: ip (src or dest) | 1.3 | 1.4 |
| events: host | 1.1 | 1.2 |
| events: type + last day | 1.3 | 1.3 |
| events: severity >= high | 0.5 | 0.6 |
| events: message text | 22.1 | 22.6 |
| events: page 50 | 1.4 | 1.5 |
| hunt: user + type | 25.2 | 28.4 |
| hunt: ip | 1.4 | 1.5 |
| hunt: host prefix + NOT | 17.0 | 17.8 |
| hunt: message | 22.1 | 24.1 |
| alerts: list | 0.8 | 0.9 |
| alerts: open | 0.7 | 0.8 |
| alert detail | 0.7 | 0.7 |
| dashboard | 34.6 | 35.3 |
| metrics | 29.4 | 31.0 |
| entities: list | 1.2 | 1.3 |
| entity: user | 18.1 | 20.0 |
| entity: src_ip | 1.1 | 1.4 |
| entity: host | 1.6 | 1.7 |
| attack coverage | 0.9 | 1.0 |
| noise lab | 15.9 | 16.0 |

At 250,000 events over the same week (same machine and day) ingest ran at 2,825 events/s, a full detection
took 2.3 s, and the slowest reads were the dashboard and metrics (about 80 ms p50) and hunting the busiest
account by event type (about 68 ms). The database was 243 MB.

What these numbers do and do not say:
- **Ingest slows as the stored week fills up.** Each batch's detection rereads the history the baseline rules
  need: a week of the transfer and cloud events of the accounts involved. That is most of the per-batch
  detection time, and it grows with event density.
- **Text search scans.** `q=` and hunt message terms are `LIKE '%text%'`, which no index serves, so they cost
  one pass over the table (about 22 ms per 100,000 events here). Prefix searches on `host` scan too.
- **Very busy accounts cost more.** The user filters and entity page use an index, but the generator's busiest
  account has about a quarter of all events, so its entity page and a hunt that pairs it with a rare event type
  read tens of thousands of rows.
- **The dashboard's events-per-minute chart** reads every event ingested in the last hour, which here is all of
  them because the whole load arrived in under a minute.
- **Paging totals are exact.** `total` is a `COUNT(*)` with the same filters; with these indexes it stayed in the
  low milliseconds except for text search, so it is not capped.

## What is real vs. synthetic vs. future

**Real, working, and tested:** everything in the architecture section. That includes the ingestion API and file upload, normalization, persistence, search, the fifteen built-in rules, the noise lab, tuning exceptions, entity risk scores, ATT&CK mapping and coverage, incident correlation, Markdown and PDF reports, the SSE dashboard, the syslog listener and shipper, alerts with evidence and timelines, notes, status and verdicts, metrics, health checks and recovery, authentication, roles (including the read-only viewer), per-IP rate limiting, CSRF protection, API tokens, redaction, feedback-driven suggestions, two-person review (including asset inventory edits), evaluation history, hunting and saved searches, keyboard triage, and the hash-chained audit log.

**Synthetic:** all bundled data. The demo dataset and simulator scenarios (`watchpost/simulate.py`) and the files in `samples/` are invented. External IPs come from the RFC 5737 documentation ranges. Synthetic events are stored with `synthetic=1`, sourced `demo:*`, and tagged in the UI. The evaluation scores (recall and precision) measure the rules against these hand-labeled scenarios only. They say nothing about real-world accuracy.

**Limitations:**
- Single process with SQLite. Measured up to 250,000 events on one laptop (see [Performance](#performance)); larger volumes are untested, and this is not enterprise volume. No retention or rollup.
- Live ingestion is basic: an optional syslog listener (unauthenticated, no TLS; loopback by default) and a single-file-per-flag shipper script. See [docs/LIVE_INGEST.md](docs/LIVE_INGEST.md) for its limits.
- Timestamps without a zone are treated as UTC. BSD syslog lines carry no year, so you pass one or the current year is assumed.
- Seeded accounts only (admin, analyst, and an optional viewer); there is no user-management UI or API. Accounts can be added with `watchpost.auth.create_user`.
- No TLS in the app itself; `deploy/` puts Caddy or nginx in front for HTTPS. Rate limits live in memory and reset on restart.
- Rules cover authentication, web, firewall/VPN, cloud audit, and host scenarios with fixed thresholds. Geo for impossible travel comes from a synthetic table covering only documentation and private ranges.
- There is no scheduled detection. Detection runs on ingest and on demand.

**Future ideas (not implemented):** GeoIP and threat-intel enrichment (both need external data), scheduled runs and retention, user management, and case management beyond incidents.

---

## Project layout

```
labs/siem/
├── main.py, start.sh, run_tests.sh, .replit
├── watchpost/          application package
├── static/             UI: SOC dashboard (dashboard.js, charts.js, map.js) and views (app.js); no inline scripts
├── samples/            synthetic log files for upload
├── scripts/smoke.py    end-to-end smoke check against a real server process
├── scripts/loadtest.py seeded load test: ingest, detection, and read-path latency (stdlib only)
├── scripts/ui_check.js headless browser check: every view at 1440px and 390px, labels, keyboard triage
├── scripts/shipper.py  log file shipper for Linux boxes (stdlib only)
├── tests/              unittest suite
├── docs/API.md         API reference
├── docs/LIVE_INGEST.md syslog listener, rsyslog forwarding, and the file shipper
├── deploy/             Debian 12 kit: systemd unit, install.sh, Caddyfile, nginx self-signed config
├── DEMO_SCRIPT.md      30-second shot list and 2-minute walkthrough
├── LINKEDIN.md         project entry, post, and honest limits
└── PROGRESS.md         milestones, verification evidence, next steps
```
