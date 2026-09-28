# Watchpost 2.0 implementation plan

Spec: `docs/superpowers/specs/2026-09-27-watchpost-2-design.md`. Read it first.

Workstreams A through E each run in their own cloud session on their own
branch, in parallel. F runs after they merge. Every session follows the same
rules.

## Rules for every session

1. Branch from `main`: `ws/<letter>-<slug>`. Never push to `main`.
2. Standard library only. `python3 -m py_compile` every changed module.
3. Test first where practical. Add tests under `tests/` in the existing
   style (see `tests/helpers.py`). `./run_tests.sh` must end with `SMOKE OK`
   and zero failures before the PR opens.
4. Additive changes. Do not rename existing routes, tables, or columns. New
   columns go through `db.py` with `ALTER TABLE ... ADD COLUMN` guarded by a
   check, so existing databases upgrade in place.
5. Keep secrets out. No real IPs, no real hostnames, no credentials.
6. Update `docs/API.md` for every new route and `PROGRESS.md` with what
   shipped, what was not done, and any decision the owner should make.
7. Open a PR titled `Watchpost 2.0 / <letter>: <title>` with a summary,
   testing evidence (paste the tail of `./run_tests.sh`), and a screenshot
   or ASCII sketch for UI work.
8. If a shared interface in the spec must change, say so in the PR body
   under "Interface changes" and keep the old behavior working.

## A. Correlation engine and MITRE ATT&CK  (`ws/a-correlation-attack`)

1. `watchpost/attack.py`: static technique catalog, `technique(id)`,
   `tactics()`. Tests: every id used by a rule exists in the catalog.
2. Add `techniques` to each entry in `DEFAULT_RULES`; JSON column on
   `rules`; `seed_rules` writes it; `GET /api/rules` returns it.
3. Parsers and samples: nginx combined, firewall CSV, CloudTrail-like JSON,
   host sudo/process lines in auth.log. Extend `EVENT_TYPES`, severities,
   `normalize_type` synonyms, `detect_format`. Tests per format.
4. Six new rules in `rules.py`, each pure with `validate_params` entries and
   tests in `tests/test_rules.py`. Register in `DEFAULT_RULES`.
5. `watchpost/geo.py`: synthetic geo table and `locate(ip)`; used by
   `impossible_geo_login`. Tests.
6. `watchpost/correlate.py`: `correlate(open_alerts, window_seconds)` pure;
   `incidents` and `incident_alerts` tables; `engine.run_detection` calls it
   after applying findings. Idempotency test: run twice, same incidents.
7. Routes: `/api/incidents`, `/api/incidents/{id}`,
   `/api/incidents/{id}/status`, `/api/attack/coverage`. Tests in
   `tests/test_api.py`. Add incident list to the existing UI alerts view as a
   simple table so the feature is visible before B merges.
8. Extend `samples/README.md`, `docs/API.md`, `PROGRESS.md`.

## B. SOC dashboard  (`ws/b-soc-dashboard`)

1. `GET /api/stream` SSE in `server.py`: thread-safe subscriber list, engine
   publishes after ingest, detection, and health changes. Heartbeat. Test
   with a raw socket client reading the first two frames.
2. `static/charts.js`: bar, line, sparkline, heat matrix as inline SVG. Pure
   functions from data to SVG string. Unit test via a tiny Node-free check:
   a Python test that loads the file and asserts exported function names
   exist (no JS runtime in CI).
3. `watchpost/geo.py` if A has not landed: create the same module and table
   (identical signature `locate(ip) -> {"city","lat","lon","synthetic"}` or
   `None`). Whichever merges first wins; the second rebases.
4. Rebuild `static/index.html`, `style.css`, `app.js` into the dashboard
   layout with the panels in the spec. Keep old views as routes in the left
   nav. Dark theme tokens on `:root`.
5. World map SVG: simplified continent paths in `static/map.js`, pulses via
   CSS animation, positions from `/api/geo?ips=` (new small route that
   calls `geo.locate`).
6. Graceful degradation: when `/api/incidents` or `/api/attack/coverage`
   returns 404, panels show "pending" and the app keeps working.
7. Manual check at 1280x800 with `./start.sh`, load demo data, take a
   screenshot for the PR (use any headless browser available in the cloud
   image; if none, describe the layout in the PR).

## C. Attack storyline mode  (`ws/c-storyline`)

1. `watchpost/storyline.py`: `build(seed, speed)` returns an ordered list of
   `(offset_seconds, event_dict, stage_name)`. Deterministic. Tests.
2. `StorylineRunner` thread: posts batches to loopback ingest with a
   generated ingest token (reuse the pattern in `simulate.py`), runs
   detection after each batch, updates a status dict, honors stop.
3. Routes: `/api/storyline/start|stop|status`, admin only, single runner.
   Tests using speed 1000 so the run finishes in under two seconds.
4. Event vocabulary must match A's new event types. Until A merges, emit
   those types anyway; the normalizer's unknown-type fallback keeps them as
   `other`, and A's merge lights them up. Document this in the PR.
5. UI: a "Run attack storyline" button and stage ticker in the admin view.
6. Smoke step: fast storyline run yields alerts from four or more rules.

## D. Incident reports  (`ws/d-reports`)

1. `watchpost/pdfwriter.py`: minimal PDF 1.4 writer (pages, Helvetica,
   text lines, simple rules, page breaks, xref table). Tests: header,
   page count, text found in stream.
2. `watchpost/report.py`: `build(conn, incident_id)` and
   `build_from_alert(conn, alert_id)` returning one model; `to_markdown`,
   `to_pdf_bytes`. Recommended actions table keyed by technique id, with a
   fallback when techniques are absent.
3. Routes for `.md` and `.pdf` on alerts and incidents. Content-Disposition
   attachment. Analyst and admin only. Tests.
4. Buttons in the alert and incident detail views.

## E. Live ingestion  (`ws/e-live-ingest`)

1. `watchpost/syslog_listener.py`: UDP and TCP servers on threads, RFC 3164
   and 5424 framing, PRI parsing, batching into `engine.ingest`. Started
   from `main.py` when `SIEM_SYSLOG=1`. Health component. Tests on random
   ports.
2. `scripts/shipper.py`: tail files, batch, post with token, backoff,
   position file. Test against a temp file with a fake HTTP server.
3. `docs/LIVE_INGEST.md` with rsyslog and shipper instructions.

## F. Public demo and LinkedIn kit  (after A through E merge)

1. `viewer` role in `auth.py` and route guards; tests for every denied
   action.
2. Rate limiting for login and read routes.
3. `SIEM_DEMO_LOOP=1` timer that runs the storyline every 15 minutes and
   resets synthetic rows between runs.
4. `deploy/` with systemd unit, Caddy or nginx config, `deploy.sh` that is
   idempotent on Debian 12.
5. Rewrite `LINKEDIN.md`, `DEMO_SCRIPT.md`, README 2.0 section.
6. Owner runs `deploy.sh` on the VM (or the local agent does over SSH with
   the owner watching) and records the video.
