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
  Techniques are read from a `rules.techniques` JSON column or `DEFAULT_RULES[...]["techniques"]` when either
  exists, so the reports light up automatically once workstream A lands. The incident path detects the
  `incidents` / `incident_alerts` tables at runtime and returns a clean 404 when they are missing.
- Routes `GET /api/alerts/{id}/report.{md,pdf}` and `GET /api/incidents/{id}/report.{md,pdf}` (analyst+), audited.
- UI: "Report (PDF)" and "Report (Markdown)" links on the alert detail view. `reportLinks("incidents", id)` in
  `static/app.js` is ready for the incident detail view that workstream A/B adds.
- Tests: `tests/test_pdfwriter.py` (6), `tests/test_report.py` (9), `ReportApiTests` in `tests/test_api.py` (3),
  plus a tiny PDF reader in `tests/pdfparse.py` that follows the xref table and extracts page text. Smoke check
  gained a step that downloads both report formats (and an incident report once `/api/incidents` exists).
- Verified outside the test suite (scratch venv, not a project dependency): qpdf (via pikepdf) reports no syntax
  problems, pypdf opens the files in strict mode, and PDFium (the engine inside Chrome) renders every page.

Not done:
- The HTML print view from the spec ("third option via the dashboard") belongs with the dashboard rework (B).
- No incident detail view exists on `main` yet, so the incident report buttons wait for A/B to call `reportLinks`.
- Not opened in macOS Preview (no Mac in the cloud session). The file passes qpdf's checks and renders in PDFium.

Decision for the owner: none required. When A merges, confirm its join table uses `incident_alerts(incident_id,
alert_id)`; the report code also accepts a column named `incident`.

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
