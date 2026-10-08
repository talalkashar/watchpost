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

- [x] 10. CI: GitHub Actions running `./run_tests.sh` on every PR (Python 3.11 to 3.14), badge in README. (PR #49)
- [x] 11. Rule backtesting: run a proposed rule change against stored history before approval and show the
      alert diff (new / lost alerts) in the review panel, so reviewers approve evidence, not params. (PR #21)
- [x] 12. Case workflow metrics: alert assignment, acknowledge/resolve timestamps, MTTA/MTTR per severity on the
      dashboard, SLA breach badges. Numbers labeled synthetic when the data is. (PR #24)
- [x] 13. Login hardening: TOTP second factor (stdlib HMAC, RFC 6238) for admin/analyst, per-account lockout with
      audit entries, session list with revoke. (PR #25; lockout already existed)
- [x] 14. Explainable entity risk: per-user/host score from alert severities, asset weight, and recency with a
      visible breakdown; no ML, every point traceable to an alert. (PR #26: scoring existed since 3.0; the breakdown now shows asset raises)
- [x] 15. Detection content portability: export/import rules as versioned JSON, plus a documented field mapping
      from Watchpost's event schema to ECS names.  (PR #28: tuning only, imports become reviewed proposals)
- [x] 16. Sigma subset: import a documented subset of Sigma rules (stdlib parser for the YAML subset Sigma uses),
      refuse anything outside it with a clear reason, scenario required before enable. (PR #29)

## Wave 3 (added 2026-10-08, same ground rules; none of these are Juan's reserved items)

- [x] 17. Log source health: per-source last-seen and expected cadence, a "source went silent" detection with a
      labeled scenario and look-alike (maintenance window), and a source-health panel. Not a new parser. (PR #31)
- [x] 18. Hunt aggregations: `| stats count by <field>`, `| top <field>`, `| timechart span=1h` over the existing
      query language, with whitelisted fields, bound parameters, and row caps. (PR #32)
- [x] 19. Scheduled searches as detections: promote a saved hunt to a threshold rule through the change-request
      workflow (backtest, two-person review, scenario before enable, like Sigma rules). (PR #33)
- [x] 20. Viewer data masking: usernames and internal IPs masked for the viewer role in API responses and exports,
      consistent across endpoints, with tests that walk every viewer GET route. (PR #34; off by default)
- [x] 21. Release 5.0 (PR titles already used 4.1-4.9): version bump, CHANGELOG from merged PRs, README numbers refreshed from a test run,
      `LINKEDIN_3.md` draft refreshed (draft only, never posted). (PR #36)

## Wave 4 (added 2026-10-08, same ground rules; none of these are Juan's reserved items)

- [x] 22. Per-rule alert suppression windows: time-bounded windows with a reason and expiry, created through
      two-person review, visible with active/upcoming/expired state, and applied without hiding audit history.
      (PR #37)
- [x] 23. Detection-as-code checks: a stdlib CLI that validates exported Watchpost rules and runs their labeled
      malicious and benign samples, with machine-readable output and a failing exit status for CI or pre-merge use.
      (PR #39)
- [x] 24. Case notes and timeline export: one chronological incident case record combining alert transitions,
      assignments, analyst notes, and evidence, downloadable as JSON and Markdown with viewer masking preserved.
      (PR #41)
- [x] 25. Role-scoped API tokens with expiry: hashed bearer tokens limited to explicit API capabilities, optional
      expiry, revocation and last-used metadata; viewer-equivalent tokens remain read-only. (PR #43)
- [x] 26. Saved dashboard views: analysts can save and share dashboard filter/layout presets, viewers can apply
      them read-only, and changes are audited with ownership and visibility enforced server-side. (PR #45)
- [x] 27. Per-rule alert grouping keys: reviewed grouping configuration with a preview of deduplication effects,
      stable evidence attachment, and clear documentation of how grouping differs from incident correlation.
      (PR #47)
