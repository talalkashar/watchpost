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
- [x] 5. New detections from events the schema already carries, each with a malicious scenario and a benign
      look-alike in the noise lab (candidates: audit/logging disabled T1562, MFA push fatigue T1621, first-seen
      admin source for a user). (PR #15: logging disabled + admin from new source; MFA skipped, no MFA signal)
- [x] 6. Scale honesty: load test (100k+ events), indexes and pagination where it hurts, published numbers in the
      README from a reproducible script. (PR #16: ingest 2.1k → 5.3k events/s at 100k)
- [x] 7. Owner-level review gaps: asset inventory edits through two-person review (Juan's PR #9 left this to the
      owner; coordinate on the PR, credit him). (PR #17)
- [x] 8. UI pass: keyboard triage, mobile width, accessibility labels. (PR #19)
- [x] 9. Refresh `LINKEDIN_3.md` draft and README numbers from the latest test run. (PR #20, version 4.0.0)

## Next wave (added 2026-10-07: owner: "the siem can be endlessly better and closer to a real siem")

When this list runs low, add more real-SIEM gaps here and keep going. Same ground rules.

- [ ] 10. (blocked: needs owner's `gh auth refresh -s workflow`; commit on local branch ws/4.9-ci) CI: GitHub Actions running `./run_tests.sh` on every PR (Python 3.11 to 3.14), badge in README.
- [x] 11. Rule backtesting: run a proposed rule change against stored history before approval and show the
      alert diff (new / lost alerts) in the review panel, so reviewers approve evidence, not params. (PR #21)
- [x] 12. Case workflow metrics: alert assignment, acknowledge/resolve timestamps, MTTA/MTTR per severity on the
      dashboard, SLA breach badges. Numbers labeled synthetic when the data is. (PR #24)
- [x] 13. Login hardening: TOTP second factor (stdlib HMAC, RFC 6238) for admin/analyst, per-account lockout with
      audit entries, session list with revoke. (PR #25; lockout already existed)
- [x] 14. Explainable entity risk: per-user/host score from alert severities, asset weight, and recency with a
      visible breakdown; no ML, every point traceable to an alert. (PR #26: scoring existed since 3.0; the breakdown now shows asset raises)
- [ ] 15. Detection content portability: export/import rules as versioned JSON, plus a documented field mapping
      from Watchpost's event schema to ECS names.
- [ ] 16. Sigma subset: import a documented subset of Sigma rules (stdlib parser for the YAML subset Sigma uses),
      refuse anything outside it with a clear reason, scenario required before enable.
