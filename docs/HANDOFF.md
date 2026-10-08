# Handoff: Watchpost autonomous loop (Claude Code → Codex, 2026-10-08)

The owner (Talal) gave the agent full responsibility for making Watchpost closer to a real SIEM, one milestone at a
time. `docs/ROADMAP.md` is the state file: take the first unchecked milestone, ship it, tick it with the PR number.
When the list runs out, add a new wave of real-SIEM gaps and keep going.

## Where things stand

- Repo: `labs/siem` (its own git repo, remote `talalkashar/watchpost`). Default branch `main`.
- Live demo: https://watchpost-nxxu.onrender.com (Render service `srv-dast6v60tbcc738v3la0`). Every merge to `main`
  auto-deploys. After a merge, confirm `GET /api/health` returns 200 and reports the new version.
- Merged so far: PRs #11 to #35. Milestones 1 to 20 are ticked.
- **In flight: release 5.0.0** on branch `ws/5.0-release` (version bump, `CHANGELOG.md`, README/PROGRESS/LINKEDIN_3
  refreshed, roadmap item 21 ticked as PR #36). If not yet pushed: run `./run_tests.sh`, push, open the PR,
  merge, confirm the live `/api/health` shows `5.0.0`. If the PR number isn't #36, fix the number in ROADMAP item 21.
- **Blocked: milestone 10 (CI)**. The commit sits on local branch `ws/4.9-ci`; pushing workflow files needs the
  owner to run `gh auth refresh -h github.com -s workflow`. Do not work around it.
- Next: wave 4 is not written yet. Add it to `docs/ROADMAP.md` (ideas: per-rule alert suppression windows with
  expiry and review, detection-as-code tests runnable from the CLI, case notes/timeline export, role-scoped API
  tokens with expiry, dashboard saved views, alert dedup/grouping keys per rule). Check each against the reserved
  list below before adding.

## Per-milestone routine

1. Branch `ws/<n>-<slug>` from `origin/main`.
2. Tests first, then code. Stdlib-only Python, plain-JS UI (build nodes with the `el()` helper, never innerHTML;
   the CSP blocks inline style attributes).
3. `./run_tests.sh` must pass (about 5 to 6 minutes; ~569 tests plus a 26-step smoke check). The smoke step
   "login attempts were not rate limited" can flake on a loaded machine; rerun `python3 scripts/smoke.py` before
   assuming a regression.
4. Headless browser pass: start a server on **port 8090** (8080 is the owner's AI router), e.g.
   `SIEM_DB=/tmp/x.db SIEM_PORT=8090 SIEM_ADMIN_PASSWORD=... SIEM_VIEWER_PASSWORD=... SIEM_RATE_LIMIT=0 python3 main.py`,
   load demo data with `POST /api/demo/load` (admin + `X-CSRF-Token`), and run `scripts/ui_check.js` with
   playwright-core (`NODE_PATH` pointing at a playwright-core install, `CHROME` at a chromium headless shell).
   Stop the server by its PID only, never `pkill -f`.
5. Commit, push, open a PR (`gh pr edit` is broken here; use `gh api -X PATCH repos/talalkashar/watchpost/pulls/<n>`).
6. Fix every automated security-review finding before or right after merge, with a regression test that fails on
   the old code. Past findings: #22→#23 (rate limits), #25→#27 (TOTP lockout race), #29→#30 (Sigma compile size),
   #34→#35 (masking fail-closed).
7. Merge with `gh pr merge <n> --merge`, confirm the Render deploy and the live 200, tick the milestone.

## Hard rules

- Reserved for Juan Carlos Munera (issue #8), never build: encrypted syslog, non-syslog log sources/parsers,
  orchestration/playbooks, hot/warm/cold retention, alert-to-incident correlation (`watchpost/correlate.py` stays
  untouched), threat intel feeds.
- Never post to LinkedIn. `LINKEDIN*.md` are drafts only. The owner's "SOC Analyst" job title is physical security:
  no cyber-SOC claims, keep copy modest. Credit Juan by plain name, no @-mention.
- Revert, never force-push. No `--no-verify`, no `reset --hard`. No secrets or credentials in the repo.
- Synthetic data is labeled synthetic; no ML claims; viewer role stays read-only; every number in the README comes
  from a reproducible run.
- Changes to rules, settings, assets and imported detections go through two-person change review
  (`improve.propose_change` / `review_change`, reviewer ≠ proposer). Keep it that way.
