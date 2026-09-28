# Watchpost 2.0 design

Date: 2026-09-27. Status: approved by the owner in conversation ("go run it all").

## Purpose

Watchpost is a portfolio SIEM. The owner will show it on LinkedIn to SOC and
security hiring managers. Success means a 30-second screen recording of a live
intrusion unfolding on a SOC-style dashboard, the tool chaining the alerts into
one incident tagged with MITRE ATT&CK techniques, and a one-click incident
report. A public read-only demo URL and the GitHub repo go in the post.

Everything the owner said: display the SIEM on LinkedIn, people should be blown
away, it must be "actually crazy", spend the cloud budget freely. Everything
else in this document is the agent's judgment.

## Non-negotiable constraints

- Python standard library only (3.10+). No pip packages. No outbound network
  calls from the app itself.
- The existing 57 tests and the smoke check keep passing. New work adds tests.
- The honesty note stays. Synthetic data is always marked `synthetic=1` and the
  UI says so. No machine-learning claims. Geo positions for synthetic IPs come
  from a labeled synthetic table, never from a real geo lookup.
- Secrets never enter the repo. Passwords come from environment variables or
  are generated on first start, as today.
- Existing API routes keep their contracts. New behavior is additive.
- Match the existing style: small modules under `watchpost/`, pure functions
  for rules, vanilla JS in `static/`, no frameworks.

## Current shape (what exists)

- `watchpost/normalize.py` parses auth.log, Windows Security JSONL, CSV, JSON
  into one events schema (`events` table: ts, source, host, event_type,
  outcome, severity, user, src_ip, dest_ip, message, raw, synthetic).
- `watchpost/rules.py` holds five pure-function auth rules and `DEFAULT_RULES`.
- `watchpost/engine.py` ingests, runs detection, writes `alerts` and
  `alert_events`.
- `watchpost/simulate.py` builds seeded synthetic scenarios and posts them to
  the loopback ingest API.
- `watchpost/server.py` is a stdlib HTTP server with sessions, roles
  (admin, analyst), CSRF, CSP, and JSON routes under `/api/`.
- `static/app.js` renders views into `#view`. Plain CSS in `static/style.css`.
- `watchpost/improve.py` handles feedback, precision, proposals, two-person
  review.

## Workstreams

Each workstream is independent enough to run in its own cloud session on its
own branch. Shared interfaces are fixed below so the branches merge cleanly.
Merge order: A, B, C, D, E, then F.

### A. Correlation engine and MITRE ATT&CK

Goal: alerts become incidents, and every rule speaks ATT&CK.

- Add `techniques` (list of `{"id": "T1110.001", "name": "...", "tactic":
  "Credential Access"}`) to every rule in `DEFAULT_RULES` and to the `rules`
  table as a JSON column `techniques`. Ship a small static ATT&CK subset in
  `watchpost/attack.py` (only the techniques the rules use, roughly 15 to 25
  entries, with tactic names). No network fetch.
- New event types and parsers in `normalize.py`, with samples in `samples/`:
  - Web server access logs (nginx/Apache combined): event types `web_request`
    plus derived `web_scan` (paths like `/.env`, `/wp-login.php`, SQLi
    patterns), `web_error`.
  - Firewall/VPN (CSV and syslog-ish): `fw_deny`, `fw_allow`, `vpn_login`.
  - Cloud audit (CloudTrail-like JSON): `cloud_api_call`, `cloud_iam_change`,
    `cloud_data_access`.
  - Host: `process_start`, `privilege_escalation` (sudo/runas), `file_access`.
- New rules (pure functions, same finding shape) with tests:
  - `web_scanner`: N scan-pattern requests from one IP in a window.
  - `firewall_port_sweep`: one IP denied on M distinct ports.
  - `impossible_geo_login` (synthetic geo table): same user, two locations too
    far apart in too short a time.
  - `privilege_escalation_after_login`: sudo/runas within X minutes of a login
    that followed failures.
  - `cloud_iam_change_by_new_principal`: IAM change by a principal with no
    prior history in the lookback.
  - `data_exfil_volume`: outbound bytes or `cloud_data_access` count from one
    principal above a threshold.
- Correlation layer `watchpost/correlate.py`: after detection, group open
  alerts that share an entity (src_ip, user, host) within a window into an
  `incidents` row (id, title, severity = max, status, first_seen, last_seen,
  entity summary JSON, kill-chain stage list, created_at, updated_at) with
  `incident_alerts` join table. Severity escalates when alerts span three or
  more tactics. Pure function `correlate(alerts, window)` returns groups; the
  engine persists them. Reruns are idempotent (an alert belongs to at most one
  incident; new alerts attach to an existing open incident when entities
  match).
- API: `GET /api/incidents`, `GET /api/incidents/{id}` (alerts, events,
  timeline, techniques), `POST /api/incidents/{id}/status`,
  `GET /api/attack/coverage` (every technique in the catalog with the rules
  that cover it and hit counts).

### B. SOC dashboard

Goal: a dark command-center UI that reads as a real SOC screen.

- Rework `static/` into a dashboard layout: left nav, top status strip (events
  per minute, open alerts, open incidents, health), main grid.
- Panels: live event stream (auto-scrolling, color by severity), alerts over
  time chart, top attacker IPs, top rules, ATT&CK coverage heat matrix (from
  `/api/attack/coverage`), incident board, health.
- Attacker map: inline SVG world map (simplified continent outlines, hand-drawn
  paths, no external tiles) with animated pulses from attacker positions.
  Positions come from `watchpost/geo.py`: a static table mapping the synthetic
  documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC
  1918 ranges to fictional cities with lat/long. Label reads "synthetic geo".
  Real IPs with no table entry render as "unknown" in a side list, never
  guessed.
- Charts are inline SVG drawn by a small `static/charts.js` (bars, lines,
  sparklines). No libraries.
- Live updates: `GET /api/stream` using Server-Sent Events from the stdlib
  server (a thread per connection, heartbeat every 15 seconds, sends
  `event`, `alert`, `incident`, `health` messages). Fallback: poll every 3
  seconds when SSE fails.
- Keep every existing view reachable (rules, review, settings, tokens, audit).
- CSP stays strict. No inline scripts; all JS in files.
- Works at 1280 wide for the recording. Phone layout is best effort.

Interface contract: the dashboard consumes `/api/incidents`,
`/api/attack/coverage`, and `/api/stream`. Until A merges, the panels read from
`/api/alerts` and show an "incidents pending" placeholder; the branch must
not fail without A.

### C. Attack storyline mode

Goal: one button replays a full intrusion in real time for the video.

- `watchpost/storyline.py`: a scripted multi-stage intrusion with wall-clock
  pacing (target about 120 seconds, speed multiplier parameter):
  1. Recon: web scanner hits `/.env`, `/wp-login.php`, port sweep denied by
     firewall.
  2. Credential attack: password spray across ten users, then brute force on
     one.
  3. Foothold: successful VPN login from the attacker IP after failures.
  4. Escalation: sudo to root on `web01`, new admin user created.
  5. Lateral and cloud: login to `db01`, cloud IAM key created by the new
     principal.
  6. Exfil: large `cloud_data_access` burst and outbound firewall allows.
  Baseline noise (normal logins, allowed traffic) runs throughout so the
  attack is visible against a living system.
- Events post to the loopback ingest API in small batches on a background
  thread, and detection runs after each batch so alerts appear within
  seconds. Synthetic flag on. Attacker IPs from the documentation ranges so
  the geo table places them.
- API: `POST /api/storyline/start` (admin, params: speed, seed),
  `POST /api/storyline/stop`, `GET /api/storyline/status` (stage, progress,
  events sent). Only one storyline runs at a time.
- UI hook: a "Run attack storyline" button in the admin area and a stage
  ticker in the dashboard status strip. If B is not merged yet, the button
  goes in the existing admin view.
- Tests: the storyline builder is deterministic for a seed; a fast run
  (speed 100x) through the engine produces alerts from at least four distinct
  rules and, once A is merged, a single incident spanning three or more
  tactics.

### D. Incident reports

Goal: one click gives a report a recruiter can be handed.

- `watchpost/report.py`: build a report model from an incident (summary,
  timeline, entities, alerts with evidence, ATT&CK techniques by tactic,
  analyst notes, recommended actions per technique from a static table).
- Renderers, stdlib only: Markdown, and PDF written by hand (a minimal PDF
  1.4 writer with Helvetica text, page breaks, and simple tables; keep it
  under 300 lines). HTML print view as a third option via the dashboard.
- API: `GET /api/incidents/{id}/report.md`, `GET /api/incidents/{id}/report.pdf`.
  Analyst and admin only. Reports carry the "synthetic data" banner when the
  incident is synthetic.
- Until A merges, the report module accepts an alert id as well
  (`/api/alerts/{id}/report.pdf`) so it is testable standalone.
- Tests: Markdown content checks, PDF starts with `%PDF-1.4`, has the right
  page count, and reopens through a tiny parser in the test that finds the
  incident title in the content stream.

### E. Live ingestion

Goal: real logs from a real machine flow in during the demo.

- `watchpost/syslog_listener.py`: UDP and TCP syslog receiver (RFC 3164 and
  5424 framing), bound to loopback by default, `SIEM_SYSLOG_BIND` and
  `SIEM_SYSLOG_PORT` to change. Each line goes through the existing
  auth.log parser first, then a generic syslog fallback event
  (`event_type=syslog`, severity from PRI). Batches every 2 seconds into the
  engine. Started from `main.py` when `SIEM_SYSLOG=1`.
- `scripts/shipper.py`: tails one or more files (auth.log, nginx access.log)
  and posts to `/api/ingest` with an ingest token, with backoff and a
  position file. Stdlib only. Works on Debian and Ubuntu.
- `docs/LIVE_INGEST.md`: how to point a Linux box at Watchpost, including
  rsyslog forward config.
- Tests: send frames to the listener on a random port and assert events land
  with the right host and type. Shipper tested against a temp file.

### F. Public demo and LinkedIn kit

Goal: a URL and a story the owner can post.

- Deploy to the owner's GCP VM `openclaw` (e2-small, us-central1-a) with a
  systemd unit, `SIEM_HOST=127.0.0.1`, and a reverse proxy for HTTPS. The
  proxy is Caddy from its static binary if the owner provides a domain, or
  nginx with a self-signed cert on the bare IP otherwise. The `deploy/`
  folder holds the unit file, proxy config, and `deploy.sh`.
- New `viewer` role: read-only. Can see the dashboard, alerts, incidents,
  reports, and health. Cannot ingest, resolve, run the storyline, or change
  settings. The demo login in the post is a viewer. Storyline runs are
  triggered by the owner as admin, or on a timer (`SIEM_DEMO_LOOP=1` runs the
  storyline every 15 minutes and resets synthetic data between runs).
- Rate limiting on login and on the public routes (per-IP token bucket in
  memory).
- `LINKEDIN.md` rewritten for 2.0 with a post, a project entry, and the honest
  limits section. `DEMO_SCRIPT.md` rewritten as a shot list for a 30-second
  recording plus a 2-minute walkthrough.
- README updated with the 2.0 architecture diagram and screenshots
  placeholders.

This workstream needs the owner's VM access and runs after A through E merge.

## Data flow after 2.0

```
files / syslog / shipper / storyline ──► ingest ──► normalize ──► events
                                                                  │
                                                     rules (pure) ▼
                                                     alerts ──► correlate ──► incidents ──► report.md / report.pdf
                                                                  │                 │
                                                     SSE /api/stream ◄──────────────┘
                                                                  ▼
                                                            dashboard (static/)
```

## Error handling

- The storyline thread and syslog listener log to `error_log` and never crash
  the server. Health reports them as components.
- SSE connections drop cleanly on client disconnect.
- Correlation failures leave alerts untouched and are surfaced in health.
- Report generation on a missing incident returns 404 JSON.

## Testing

- Every workstream adds unit tests under `tests/` in the existing style and
  keeps `./run_tests.sh` green.
- The smoke script gains steps: storyline fast run produces an incident,
  incident report PDF downloads, coverage endpoint lists techniques.

## Out of scope

Real geo lookups, machine learning, multi-node, Sigma YAML parsing (a JSON
rule pack could come later), user management UI beyond the viewer role,
retention jobs.
