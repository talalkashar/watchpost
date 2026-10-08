# Changelog

All bundled data is synthetic. PR numbers refer to https://github.com/talalkashar/watchpost.

## 5.0.0 (2026-10-08)

PRs #21 to #35. The PR titles used 4.1 to 4.9 for these rounds; none of them was released under its own version.

### Detection content

- Rule backtesting in review: a proposed rule change is replayed over stored events (default 7 days, up to 100k events) and reported as kept / new / lost findings; losing a finding tied to an open alert needs `acknowledge_detection_loss`. Preview at `GET /api/rules/{id}/backtest`. (#21)
- Rule export and import as versioned JSON (tuning only, not detection logic); each imported change becomes a reviewed `rule_update` proposal. (#28)
- Sigma subset import: a stdlib parser and matcher for a subset of Sigma, added disabled through two-person review, and enabled only after a labeled sample passes. (#29)
- Log source health: per (source, host) cadence with learning / healthy / late / silent states, `GET /api/sources/health`, reviewed maintenance windows, and a new built-in rule, `log_source_silent` (T1562.006). (#31)
- Saved searches as detections: a filter-only hunt query promoted to a `search_<slug>` threshold rule, with the same review and labeled-sample gates as Sigma rules. Grouping by `user` is case-insensitive, matching the `user:` filter (fixed during review). (#33)

### Triage

- Triage metrics: `alerts.acknowledged_at` (schema 7), MTTA and MTTR per severity (mean, median, p90), SLA breach counts, and alert assignment (`POST /api/alerts/{id}/assign`). `GET /api/metrics/triage`. (#24)
- Entity risk breakdown shows each alert's base severity and the asset weight that raised it. (#26)

### Security

- TOTP second factor (RFC 6238, stdlib only), opt-in for analysts and admins, and session listing and revocation (schema 8). (#25)
- Viewer data masking, off by default: usernames and internal IPs are replaced with keyed pseudonyms in viewer responses, exports and the stream. (#34)
- Fix (found by automated security review of #21): rule proposals and rule-change approvals each ran a full backtest without a rate limit; they now draw on a per-account backtest quota. (#22)
- Fix (found by automated security review of #22): the shared quota had loosened the preview limit; previews are back to a burst of 6, and proposals and approvals use a separate bucket. (#23)
- Fix (found by automated security review of #25): parallel TOTP guesses could race past the lockout threshold; each attempt now checks and counts in one transaction. Wrong codes on `/api/auth/mfa/disable` now count toward the same lockout budget. (#27)
- Fix (found by automated security review of #29): a Sigma condition that repeated selections could compile a 63 KB rule to 8.2 MB; compiled detections are now capped at 2,000 values and 128 KB. (#30)
- Fix (found by automated security review of #34): masking now fails closed. Error messages, rule-export JSON and live streams opened before masking was turned on are masked for viewers, and past 10,000 distinct usernames a viewer gets a 503 instead of raw names. (#35)

### Hunting

- Hunt aggregations: one `| stats`, `| top` or `| timechart` stage after the filter, on whitelisted fields, with group and bucket caps. (#32)

### Platform

- ECS field mapping for export: `GET /api/events/{id}/ecs`. (#28)
- `__version__` is 5.0.0, so `/api/health` reports 5.0.0.
- `./run_tests.sh`: 569 tests and the 26-step smoke check pass.

## 4.0.0

Released with PR #20, which bumped `__version__` from 0.1.0 to 4.0.0 (the version had not moved through 2.0 to 3.1) and refreshed the README and API docs. Earlier changes, PR #20 and before, are described in the README's "What's new" sections and in the git history.
