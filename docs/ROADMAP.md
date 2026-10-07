# Watchpost roadmap

Owner handed day-to-day direction to Claude on 2026-10-07 ("full responsibility"). This file is the loop's state:
each iteration takes the first unchecked milestone, ships it, and ticks it with the PR number.

## Direction

Make Watchpost credible to a detection engineer reading the code, not just impressive in a screenshot:
every feature verifiable, every number reproducible, nothing overclaimed.

## Ground rules

- Stdlib-only Python, plain-JS front end, synthetic-data labeling, no ML claims, viewer stays read-only.
- Reserved for Juan Carlos Munera (issue #8), do not build: encrypted syslog, non-syslog log sources/parsers,
  orchestration/playbooks, hot/warm/cold retention, alert-to-incident correlation (`watchpost/correlate.py`),
  threat intel feeds.
- One milestone per branch `ws/<n>-<slug>` and PR. Tests first. `./run_tests.sh` green plus a headless browser
  pass before merge. Every automated security-review finding is fixed or answered before merge.
- Merge to `main` redeploys the live demo; confirm it serves 200 after deploy. Revert, never force-push.
- `LINKEDIN*.md` are drafts only; never post.

## Milestones

- [x] 1. Ship 3.1: merge PR #11, confirm the live demo serves the new routes. (PR #11, live 2026-10-07)
- [x] 2. Tamper-evident audit log: hash-chained audit entries, `GET /api/audit/verify`, a verified/broken badge in
      the UI, tests that edit a row and detect it.
- [x] 3. ATT&CK coverage view in the app: tactics x techniques, each cell showing the rules that cover it and their
      noise-lab verdict; no technique claimed without a rule and a labeled scenario. (PR #13: 15 validated, 3 mapped)
- [x] 4. Hunting: saved searches over events with a small documented query syntax (field:value, NOT, time range),
      pivot from entity pages, viewer can run but not save. (PR #14)
- [ ] 5. New detections from events the schema already carries, each with a malicious scenario and a benign
      look-alike in the noise lab (candidates: audit/logging disabled T1562, MFA push fatigue T1621, first-seen
      admin source for a user).
- [ ] 6. Scale honesty: load test (100k+ events), indexes and pagination where it hurts, published numbers in the
      README from a reproducible script.
- [ ] 7. Owner-level review gaps: asset inventory edits through two-person review (Juan's PR #9 left this to the
      owner; coordinate on the PR, credit him).
- [ ] 8. UI pass: keyboard triage, mobile width, accessibility labels.
- [ ] 9. Refresh `LINKEDIN_3.md` draft and README numbers from the latest test run.
