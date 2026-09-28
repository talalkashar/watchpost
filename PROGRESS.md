# Watchpost progress log

Hand-off notes so any session can continue the work.

## Starting point (2026-09-16)

The brief asked me to continue an existing SOC/SIEM project on Replit. That project was **not reachable from this machine**: the `cybersecurity` workspace had only notes and resumes, and a search of the home directory found no SIEM code or `.replit` file. So Watchpost was built new, in `labs/siem/`, using only the Python standard library, so it runs unchanged on Replit (`.replit` included).
**If the original Replit project has features worth keeping, merge them in or port this code into it. Nothing here depends on the old project.**

## Milestones completed

| # | Milestone | Evidence |
|---|---|---|
| 0 | Baseline: nothing existed; set up test harness and smoke script | `tests/`, `scripts/smoke.py` |
| 1 | Storage + normalized schema (SQLite, WAL, indexes) | `watchpost/db.py` |
| 2 | Ingestion: JSON/JSONL/CSV/auth.log/Windows, validation, redaction, per-record rejection reasons, batch audit | `test_normalize.py` (16 tests), `IngestTests` |
| 3 | Detection: 5 explainable rules, sliding windows, dedup/extension of open alerts, run records | `test_rules.py` (12 tests), dedup test in `IngestTests` |
| 4 | Analyst workflow: alert detail, evidence, related timeline, notes, status, verdicts, activity log | `EndToEndTests.test_full_analyst_flow` |
| 5 | Search + metrics | `SearchTests` (filters, paging, validation, injection attempts) |
| 6 | Security: PBKDF2, lockout, sessions, CSRF, roles, hashed ingest-only tokens, CSP/security headers, body limits, static path-traversal guard, loopback default bind, generated creds file with mode 0600 | `AuthTests` (9 tests), `test_generated_credentials_file_is_private` |
| 7 | Self-diagnosis: 4 health checks, public/private health endpoints, redacted error log, failure → backlog → recovery | `HealthRecoveryTests` (8 tests) |
| 8 | Continuous improvement: verdict-based precision, heuristic suggestions, scenario evaluation before and after, two-person review for rules *and* security settings, rule history, evaluation history | `test_full_analyst_flow` steps 5–8, `test_manual_rule_proposal_review_rules`, `test_security_setting_change_requires_second_admin` |
| 9 | Synthetic data + simulations: 7 labeled scenarios, loopback-only simulator CLI, 3 sample files | `EvaluationTests`, smoke steps 4–5 |
| 10 | Web UI (dashboard, alerts, events, ingest, rules, health, admin) | Browser verification below |
| 11 | Docs: README, API reference, demo script, LinkedIn text | this folder |

## Verification (latest run: 2026-09-16)

- `./run_tests.sh` → **57 tests OK** (Python 3.14.2), then **SMOKE OK**, all 12 steps. The smoke check starts a real server process, uploads the 3 sample files, runs the simulator CLI with an API token, confirms the simulator refuses a non-loopback URL and the token can't read data, searches, and checks that all 5 rules fired (13 alerts). It then resolves an alert, turns false-positive feedback into a proposal, has a second user approve it, checks health, and confirms no password or token appears in the server log.
- Also passes on Python 3.13. No syntax that requires 3.12 or later (checked with a tokenizer scan).
- **Browser check** (Playwright, real Chromium, against a scratch database):
  - Login screen hides the navigation. Admin sign-in works.
  - Admin → Load demo data: 7 scenarios, detection `ok`.
  - Dashboard: 9 open alerts, 105 events (all synthetic), activity chart, breakdowns.
  - Alerts list sorted with the critical alert first, synthetic tags visible.
  - On the compromise alert, Start investigating → Add note → Resolve (true positive). The database confirmed `resolved | true_positive | admin` and the note text.
  - Rules, Health, Ingest, and Events pages all render. No console errors besides the expected 401 from the pre-login session check.
  - Breaking a rule and running detection showed `failing`, the guidance text, and a red banner. Restoring the rule and running detection again returned everything to `ok`.
- **Bugs found and fixed during verification:**
  - Redaction let a bearer token through ("Authorization: Bearer x" matched the generic key=value pattern first).
  - The failing-health banner never showed, because the UI treated HTTP 503 as a fetch error.
  - Status and enabled pills rendered as nothing.
  - A literal "null" appeared on the dashboard.
  - The nav bar was visible before login (CSS overrode `hidden`).
  - A Windows sample file had invalid timestamps.

## Acceptance criteria status

| Requirement | Status |
|---|---|
| Documented ingest API + sample uploads | ✅ `docs/API.md`, `samples/` |
| Normalized, persistent storage | ✅ |
| Search by time/source/severity/user/IP/type | ✅ (plus host, message text, synthetic flag) |
| Brute force / suspicious auth / repeated failures rules | ✅ 5 rules |
| Alerts with evidence, severity, explanation | ✅ |
| Investigate / notes / status / resolve | ✅ |
| SOC metrics + related-event timeline | ✅ |
| Labeled synthetic data + reproducible simulations | ✅ seeded, `demo:*`, `synthetic=1` |
| Auth, validation, secret handling, access control | ✅ |
| Health checks for ingestion/storage/detection/dependencies with guidance | ✅ |
| Honest degraded/failing states; redacted errors; recovery tested | ✅ |
| TP/FP feedback, rule performance, proposals, history, evaluation results | ✅ |
| Review required for rule and security-setting changes | ✅ two-person rule |
| No ML claims | ✅ stated in UI and docs |
| README, demo script, LinkedIn text, real/synthetic/future separation | ✅ |

## Watchpost 2.0 / D: incident reports (2026-09-28, branch `ws/d-reports`)

Shipped:
- `watchpost/pdfwriter.py`: a hand-written PDF 1.4 writer (Helvetica and Helvetica-Bold with WinAnsi encoding,
  word wrap from the standard AFM widths, headings, rules, a highlighted banner, tables with a repeating header
  and truncated cells, automatic page breaks, "Page n of N" footers, byte-exact xref table). Under 300 lines.
- `watchpost/report.py`: `build(conn, incident_id)` and `build_from_alert(conn, alert_id)` return one report model;
  `to_markdown(model)` and `to_pdf_bytes(model)` render it. Recommended actions come from a static table keyed by
  ATT&CK technique id (sub-techniques fall back to the parent), with generic actions when no technique is mapped.
  Techniques come from the `rules.techniques` column (falling back to `DEFAULT_RULES`), resolved through the
  ATT&CK catalog in `watchpost/attack.py` and grouped by tactic in kill-chain order.
- After A merged: `build(conn, incident_id)` reads the real incident through `incidents.get_incident` (status,
  severity with escalation, span, kill-chain stages, entities, techniques per tactic with the alerts behind each),
  then adds every member alert's evidence, timeline, and notes. Unknown incidents are a 404 `incident not found`.
- Routes `GET /api/alerts/{id}/report.{md,pdf}` and `GET /api/incidents/{id}/report.{md,pdf}` (analyst+), audited.
- UI: "Report (PDF)" and "Report (Markdown)" links on the alert detail view and the incident detail view.
- Tests: `tests/test_pdfwriter.py` (6), `tests/test_report.py` (15, eight on incidents built by the real
  correlation engine), `ReportApiTests` in `tests/test_api.py` (3), plus a tiny PDF reader in `tests/pdfparse.py`
  that follows the xref table and extracts page text. The smoke check downloads alert and incident reports in both
  formats and checks the incident Markdown lists every kill-chain tactic.
- Verified outside the test suite (scratch venv, not a project dependency): qpdf (via pikepdf) reports no syntax
  problems, pypdf opens the files in strict mode, and PDFium (the engine inside Chrome) renders every page.

Not done:
- The HTML print view from the spec ("third option via the dashboard") belongs with the dashboard rework (B).
- Not opened in macOS Preview (no Mac in the cloud session). The file passes qpdf's checks and renders in PDFium.

Decision for the owner: none required.

## Open items and blockers

- **Not yet done by a human:** deploying to the user's Replit account (needs their login) and recording the demo video.
- **Needs the user's decision:** whether to replace or merge the original Replit project.
- Not run: Replit's own environment. The `.replit` file is written for its Python 3.11 module but untested there.

## Next concrete tasks (optional improvements)

1. Push `labs/siem/` to the Replit project, set the two password Secrets, click Run, and walk through DEMO_SCRIPT.md there.
2. Add a user-management endpoint and UI (admin creates and disables accounts). Today, extra accounts need `watchpost.auth.create_user`.
3. Add a retention job (delete events older than N days) behind a reviewed setting.
4. Add a syslog UDP/TCP listener on loopback for live shipping.
5. Add a Sigma-style YAML rule loader for simple field-match rules.

## Watchpost 2.0 / A: correlation engine and MITRE ATT&CK (2026-09-28, branch `ws/a-correlation-attack`)

**Shipped**
- `watchpost/attack.py`: static ATT&CK Enterprise subset (17 techniques, all 14 tactics in kill-chain order), `technique(id)`, `tactics()`, `coverage()`. No network fetch.
- Every rule carries `techniques`; new `rules.techniques` JSON column (added in place on existing databases), written by `seed_rules`, returned by `GET /api/rules` and in alert detail.
- Parsers: nginx/Apache combined (`weblog`, auto-detected) → `web_request`/`web_scan`/`web_error`; firewall CSV (`action` column) and UFW/iptables syslog → `fw_deny`/`fw_allow`; OpenVPN → `vpn_login`; CloudTrail-style JSON → `cloud_api_call`/`cloud_iam_change`/`cloud_data_access`; sudo/su/runas (4648) → `privilege_escalation`; useradd, auditd process (`exe=`) and file (`type=PATH`, 4663) records. New event columns `dest_port`, `bytes`.
- Six new rules with tests and labeled scenarios: `web_scanner`, `firewall_port_sweep`, `impossible_geo_login`, `privilege_escalation_after_login`, `cloud_iam_change_by_new_principal`, `data_exfil_volume`. Evaluation: every rule recall 1.0, no new false positives.
- `watchpost/geo.py`: synthetic geo table (`locate(ip) -> {city, lat, lon, synthetic}` or `None`), documentation + RFC 1918 ranges only.
- `watchpost/correlate.py` + `engine.correlate_alerts`: incidents and `incident_alerts` tables, run after every detection run, idempotent. Correlation failures leave alerts alone, are logged under component `correlation`, and mark detection health `degraded` until the next good run.
- Routes: `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents/{id}/status`, `GET /api/attack/coverage`. UI: active incidents table on the Alerts page, incident detail view (`#incidents/{id}`), ATT&CK chips on rules and alerts.
- Samples: `nginx_access.log`, `firewall.csv`, `cloudtrail.json`, `linux_host.log`. Smoke check uploads them and gained incident and coverage steps.
- Verification: `./run_tests.sh` → 97 tests OK, SMOKE OK (14 steps), run as a non-root user.

**Decisions made (owner may revisit)**
- Linking uses each alert's evidence-event times per entity, not the alert's whole span. With spans, one multi-hour impossible-travel alert chained 9 unrelated demo alerts on host `web01` into one incident.
- A new incident needs ≥ 2 related alerts or 1 critical alert; window 30 min (`correlate.DEFAULT_WINDOW_SECONDS`, not yet a setting).
- `vpn_login` counts as a successful login for `success_after_failures` and `off_hours_privileged_login` too.
- Detection now reads up to 24 h of extra history before each batch (for "new principal" checks); findings made only from that history are ignored, so older behaviour is unchanged.
- Rule tuning suggestions still only propose `threshold`/`ignore_*` changes; the new parameters are tunable via manual proposals.

**Not done / notes**
- `test_storage_unavailable_is_failing_not_a_crash` fails when the suite runs as root (root ignores directory permissions). Pre-existing, identical on `main`; passes as a normal user.
- No incident notes/assignment UI beyond status; reports (D) and dashboard panels (B) consume these routes.

## Watchpost 2.0 / E: live ingestion (2026-09-28, branch `ws/e-live-ingest`)

**Shipped**
- `watchpost/syslog_listener.py`: a UDP and TCP syslog receiver.
  - Parses RFC 3164 and RFC 5424 messages and RFC 6587 TCP framing (octet-counted and newline).
  - Each line goes through the existing auth.log parser first. Anything it doesn't recognize becomes a new `syslog` event type, with severity from PRI.
  - Batches into `engine.ingest` every 2 seconds and bounds the queue at 50,000 frames. Optional `SIEM_SYSLOG_ALLOW` IP/CIDR allow list.
  - Loopback by default. Started from `main.py` when `SIEM_SYSLOG=1`.
  - Reported as the `syslog` health component. A bind failure is failing health plus an error_log entry, never a crash.
- `watchpost/health.py`: `register_check` / `unregister_check`, so optional components can add a health check while they run. The four core checks are unchanged. Workstream C (storyline) can reuse this.
- `scripts/shipper.py`: a stdlib-only tailer that posts to `/api/ingest/upload` with an ingest token.
  - Batches by line count and size, retries with exponential backoff and jitter, and keeps an atomic position file (inode and offset).
  - Follows rename rotation (drains the old file first) and copytruncate.
  - Skips batches the server refuses as invalid instead of stalling. Refuses plain HTTP to non-loopback hosts. The token comes from an env var or a file only.
- `docs/LIVE_INGEST.md`: listener setup, rsyslog forwarding for Debian 12 (install rsyslog first) and Ubuntu, remote options (SSH tunnel or allow list plus ufw), shipper install with a systemd unit, and limits.
- Tests: `tests/test_live_ingest.py` has 29 tests: parsing, framing, a listener on random ports over UDP and TCP, allow list, bind failure, the health API, the shipper against a fake HTTP server, and the shipper CLI against a real server. The smoke check gained step 11 (a syslog frame plus a shipper run against the real server process), and step 12 now checks that `syslog` health is ok.

**Verification:** `./run_tests.sh` gives 86 tests OK and SMOKE OK (13 steps), run as an unprivileged user. As root, the pre-existing `test_storage_unavailable_is_failing_not_a_crash` fails on `main` too, because a read-only directory does not stop root. Nothing in this workstream touches it.

**Not done / limits**
- No TLS syslog (RFC 5425). Syslog is unauthenticated, so use loopback, an SSH tunnel, or an allow list.
- BSD syslog timestamps are treated as UTC (the existing rule). The docs recommend the RFC 5424 rsyslog template.

**Merge with workstream A (2026-09-28)**
- Merged `origin/main` (A: correlation, incidents, ATT&CK, new parsers) into this branch. Conflicts in `normalize.py` (`EVENT_TYPES` keeps both `syslog` and A's new types), `README.md`, and this file were resolved keeping both sides.
- The syslog listener now tries A's nginx/Apache combined parser when the auth.log parser does not recognize a message, so a forwarded access line becomes `web_request`/`web_scan`/`web_error` (host from the syslog header) instead of `syslog`. UFW/iptables firewall and OpenVPN lines already get `fw_deny`/`fw_allow`/`vpn_login` because A added them to the auth.log parser the listener uses.
- The shipper passes `weblog` through to the server; docs and `--file` help list it.
- New tests: nginx and firewall frames parsed to specific types, a UDP+TCP listener test asserting they land as `web_scan` and `fw_deny` (not `syslog`), and a shipper CLI test shipping an nginx access log to a real server with `weblog` and `auto`.
- Verification after the merge: `./run_tests.sh` gives 130 tests OK and SMOKE OK (15 steps), run as an unprivileged user.

**Decisions for the owner**
- Default syslog port is 5514, not 514, so Watchpost never needs root. Change it with `SIEM_SYSLOG_PORT`.
- For the public demo VM (workstream F), the recommended live feed is the VM's own rsyslog forwarding to `127.0.0.1:5514`. It needs no open port.
## Watchpost 2.0 / B: SOC dashboard (2026-09-28, branch `ws/b-soc-dashboard`)

**Shipped**
- `GET /api/stream` (SSE): `watchpost/stream.py` broker with bounded per-client queues (overflow turns into a `resync` frame), 64-connection cap, heartbeat every 15 s, clean unsubscribe on disconnect. The engine publishes `event` after each stored batch and `alert`, `incident` (once A's `incidents` table exists), and partial `health` after each detection run. Publishing is skipped when nobody is connected and can never fail an ingest.
- `GET /api/dashboard` (one aggregate read) and `GET /api/geo`. `GET /api/events` gained an additive `since_id` filter for the polling fallback.
- `watchpost/geo.py`: A merged first, so A's table and `locate()` are kept unchanged (its `impossible_geo_login` rule and tests depend on them). B adds `LABEL` and `is_internal(ip)` (RFC 1918 only); `/api/geo` adds an `internal` flag per address so the map can draw internal sites as the HQ target.
- Merged with A: A's incident detail view in `app.js` is kept (built on the real payload); B adds the Incidents board page, and the dashboard reads A's `/api/incidents` and `/api/attack/coverage`, including A's `covered` flag (enabled rules only).
- `static/charts.js` (sparkline, line, bars, stacked bars, ranked bars, heat matrix: pure data-to-SVG-string functions), `static/map.js` (hand-drawn continent rings, dot-matrix world map, arcs), `static/dashboard.js` (panels, live client, incident board, incidents pages), dark theme in `static/style.css`. All earlier views are still in the left nav; the 1.0 dashboard is now "Metrics".
- Graceful degradation: `/api/incidents`, `/api/attack/coverage`, `/api/storyline/status` returning 404 show "pending" panels; the incident board falls back to alerts by status. Checked in a browser both ways (real 404s, and mocked A/C payloads).
- Tests: `tests/test_dashboard.py` (raw-socket SSE reads of the first frames, ingest → event/health/alert frames, heartbeat and disconnect cleanup, broker overflow and cap, geo table and route, dashboard aggregates, `since_id`, static-asset/CSP checks for the JS). Smoke step 12 checks dashboard, geo, and the stream's first frames.

**Verification.** `./run_tests.sh` ends with SMOKE OK and no failures when run as a non-root user. Browser check with Playwright/Chromium at 1280×800: no page errors on any view; SSE mode shows LIVE, and blocking `/api/stream` switches to POLLING 3s and still delivers new events.

**Not done / notes for the owner**
- `tests/test_workflow.py::test_storage_unavailable_is_failing_not_a_crash` fails when the suite runs as **root** (as in the cloud container), on `main` too: it relies on `chmod` blocking writes, which root ignores. Not changed here. Decide whether to skip it under root or run CI as a normal user.
- The tolerant readers for A's `/api/incidents` and `/api/attack/coverage` accept a list or `{incidents|techniques: [...]}` and several field spellings (`kill_chain`/`stages`/`tactics`, `hits`/`hit_count`/`alerts`). Check them against A's final shapes after merge.
- C's storyline status tile appears only when `/api/storyline/status` exists; it reads `running`, `stage`, `progress`.

## Watchpost 2.0 / F: viewer role, rate limits, deploy kit, LinkedIn kit (2026-09-28, branch `ws/f-demo-kit`)

**Shipped**
- **Read-only `viewer` role, enforced by the server.** `Handler._authorize` refuses any non-GET request from a viewer
  (403 `viewer accounts are read-only`), except logout, whatever role a route declares. A future write route that
  keeps the default role is still closed to viewers. Viewers can read the dashboard, SSE stream, events, alerts,
  incidents, **reports** (now open to every signed-in role; they were analyst-only), ATT&CK coverage, metrics, rules,
  and health details. Admin-only reads (tokens, audit) stay 403. The UI shows report links to viewers and labels the
  account "(read-only)".
- `SIEM_VIEWER_PASSWORD` seeds a `viewer` account on start when set and no `viewer` user exists, so an existing
  database can gain one. It is never generated and never resets an existing viewer's password.
- **Rate limiting** (`watchpost/ratelimit.py`): in-memory per-IP token buckets. Login gets a burst of 10, then
  10/min. Everything else, static files included, gets a burst of 300, then 1200/min. Over the limit: 429 JSON with
  `retry_after` and a `Retry-After` header. Configured with `SIEM_RATE_LIMIT`, `SIEM_LOGIN_RATE_BURST`,
  `SIEM_LOGIN_RATE_PER_MIN`, `SIEM_RATE_BURST`, `SIEM_RATE_PER_MIN`, and `SIEM_TRUST_PROXY` (the last
  `X-Forwarded-For` entry, only from a loopback peer). Memory is bounded (10,000 keys, pruned).
- **`deploy/`** for Debian 12: `watchpost.service` (dedicated `watchpost` user, `SIEM_HOST=127.0.0.1` forced in
  `ExecStart`, StateDirectory `/var/lib/watchpost`, systemd sandboxing), an idempotent `install.sh` (apt deps, system
  user, rsync to `/opt/watchpost`, `/etc/watchpost.env` from a secret-free template written once, enable and
  restart, optional `--caddy DOMAIN` or `--nginx-selfsigned [IP]`, health wait), a `Caddyfile` with a domain
  placeholder, `nginx-selfsigned.conf`, and `deploy/README.md` with the exact steps.
- Rewrote `LINKEDIN.md` (project entry, a 1,220-character post, honest limits) and `DEMO_SCRIPT.md` (30-second shot
  list plus a 2-minute walkthrough built around C's **Run attack storyline** button). Added the 2.0 feature table,
  architecture diagram, configuration rows, and screenshot placeholders to the README. Documented the viewer rules
  and rate limiting in `docs/API.md`.
- Tests: `tests/test_viewer.py` (9) walks **every** registered route. Each GET must answer a viewer 200 (403 for
  admin-only reads). Each POST except login and logout must answer 403 and leave events, notes, tokens, change
  requests, evaluations, rule history, and alert and incident statuses unchanged. It also covers the read-only
  backstop and account seeding. `tests/test_ratelimit.py` (11) covers bucket math with a fake clock, per-key
  isolation, bounded memory, env parsing, login 429 with `Retry-After`, independent buckets, proxy trust (spoofed
  first entries ignored), and disabling. The existing report-access test now expects viewers to get 200. Smoke
  step 17 signs in as the seeded viewer, reads an incident and its PDF, is refused four writes, and sees login
  return 429.
- `tests/test_workflow.py::test_storage_unavailable_is_failing_not_a_crash` used `chmod` to make storage
  unwritable, which root ignores, so it failed in the cloud container (noted by B). It now puts a regular file where
  the database directory should be, which fails for every user. Same assertions, no skip.

**Verification.** `./run_tests.sh` as root in the cloud container: 194 tests OK, then SMOKE OK (18 steps).
`bash -n` passes on `deploy/install.sh`, `start.sh`, and `run_tests.sh`. `systemd-analyze verify` accepts
`watchpost.service`. `install.sh` ran three times in the container (Ubuntu 24.04, no systemd, `systemctl`
stubbed to launch the app as the `watchpost` user with the env file). Each run was idempotent: the env file was kept
at root:watchpost 0640, the app ran as `watchpost`, and adding `SIEM_VIEWER_PASSWORD` and re-running created a
working viewer login. With `--nginx-selfsigned 203.0.113.10` and nginx 1.24: the certificate SAN is that IP, HTTP
redirects to HTTPS, the cookie carries `Secure`, SSE streams through without buffering, and the login bucket
returned 429 with `Retry-After` while spoofed `X-Forwarded-For` values made no difference. With `--caddy`: `caddy
validate` passes on Caddy 2.6.2, the Debian 12 version, and `caddy fmt` reports no changes.

**Not done**
- Not run on the real VM: that needs the owner's access. Run `sudo ./deploy/install.sh --caddy <domain>` or
  `--nginx-selfsigned <public IP>` there, per `deploy/README.md`. Real systemd sandboxing and Let's Encrypt
  issuance are untested.
- The `SIEM_DEMO_LOOP` timer and anything under `/api/storyline` belong to workstream C and are not in this branch.
  `DEMO_SCRIPT.md` assumes C's button and stage tile.
- No video recorded and no new screenshots. README has placeholders for `incident-detail.png`,
  `incident-report-pdf.png`, and `storyline-running.png`.
- nginx listens on `[::]` as well as IPv4. In the container, which has no IPv6, those two lines had to be removed;
  Debian 12 on GCP supports IPv6 sockets. The fix is in the deploy README's troubleshooting section.

**Decisions for the owner**
- Reports are now readable by viewers (the spec lists reports among what viewers see). Reports of synthetic incidents
  contain only synthetic data, but every public visitor can download them. Revert by setting the two report routes
  back to `role="analyst"`.
- Pick the public viewer password (12+ characters) and put it in `/etc/watchpost.env` on the VM, not in the post
  draft in the repo.
- Rate-limit defaults suit a small public demo. Visitors behind one corporate NAT share a bucket. Raise
  `SIEM_RATE_PER_MIN` if that becomes a problem.
