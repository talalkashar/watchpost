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
