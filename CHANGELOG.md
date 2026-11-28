# Changelog

All bundled data is synthetic. PR numbers refer to https://github.com/talalkashar/watchpost.

## Unreleased

### Added

- Run `./start.sh --demo` for an offline SSH investigation, or choose the Windows or firewall fixture. Source installs now provide `watchpost-demo` and `watchpost-serve`.

- Firewalls over syslog, part of the second item of #8. Syslog lines from pfSense/OPNsense (`filterlog`), FortiGate, Cisco ASA/FTD and Palo Alto (`TRAFFIC`) become `fw_deny` and `fw_allow` events with source, destination and port, and firewall admin and VPN logins become `auth_failure` and `auth_success`. Lines in other formats stay generic `syslog` events. The parsers follow the published log formats and are tested on synthetic lines, not on the devices. New sample: `samples/firewall_syslog.log`.

- Syslog can receive TLS 1.2+ streams with optional client certificates. See [Live ingestion](docs/LIVE_INGEST.md#syslog-over-tls).

- The [investigation graph](docs/screenshots/07-investigation-graph.jpg) connects alerts, incidents, and evidence entities. Open **Graph** to filter by type or severity and follow a node to its case or entity page. The authenticated snapshot is available at `GET /api/graph`.

- A forwarder for the Windows Event Collector service, the other half of agentless Windows collection in #8. `scripts/wec_forwarder.ps1` runs on a server that already collects forwarded events, which is the usual setup in a Windows domain, and posts its *ForwardedEvents* log to the ingest API. It keeps its position, retries without moving it, and reads the token from the environment or a file. **Experimental:** its logic is tested with PowerShell 7 on Linux against a stand-in for the event log; it has not been run on Windows. See [docs/LIVE_INGEST.md](docs/LIVE_INGEST.md#5-forwarder-for-a-windows-event-collector).

- Threat intelligence feeds, the sixth item of #8 (`watchpost/threat_intel.py`). Lists of hostile addresses and networks are imported by an admin or fetched from open feeds turned on by name in `SIEM_THREAT_FEEDS`: Spamhaus DROP, Emerging Threats, CINS Army, blocklist.de, IPsum, abuse.ch Feodo, Tor exits, and AlienVault OTX with the operator's own API key. Events are tagged on arrival and again when a feed changes (`threat` field, hunt `threat:*`), and an alert whose evidence is tagged is raised one severity level. Entries naming internal or over-broad networks are refused. No feed data is bundled and nothing is fetched unless configured; each feed is fetched at most once an hour. The OTX reader is tested against a stand-in, not against OTX. See the reference, [Threat intelligence](docs/REFERENCE.md#threat-intelligence).

- Stronger correlation, the fifth item of #8. Five correlation rules (`correlate.PATTERNS`) recognize multi-stage shapes across alerts: a scan then an attack from one source, a password attack then a suspicious login, a suspicious login then privilege escalation or data leaving, and logging impaired around other activity. They are written over ATT&CK tactics, allow up to 24 hours between stages, and require the same source address or account, never just the same host. Alerts that complete a rule are joined into one incident, which lists the rule and is raised to at least its severity. One behaviour change: an incident that completes a rule can now be more severe than before (a password attack followed by a suspicious login from the same source is critical). The demo dataset's incidents keep their membership; two of them now name a rule.

- Tiered retention, the fourth item of #8 (hot, warm and cold storage). Off by default. With `SIEM_RETENTION_HOT_DAYS` set, events older than that leave the database for one verified gzip file per arrival day (warm, still searchable a day at a time); `SIEM_RETENTION_WARM_DAYS` moves files to a cold directory, and `SIEM_RETENTION_TOTAL_DAYS` deletes them. Rows are deleted only after their file has been written, read back and recorded; alert evidence is never deleted; the hot period never drops below what the enabled rules read. File hashes go into a manifest and the audit log. See the reference, [Tiered retention](docs/REFERENCE.md#tiered-retention-hot-warm-cold).

- Response playbooks, the third item of #8 (orchestration). Every alert gets an ordered list of steps for its kind of alert (`watchpost/playbooks.py`, seven built-in playbooks). Context is gathered automatically, analysts check off the manual steps on the alert page, and response actions (block an address, disable an account, isolate a host) are sent as signed requests to a webhook the operator configures with `SIEM_PLAYBOOK_WEBHOOK_URL`. Watchpost carries out no action itself: nothing is sent without a webhook, synthetic alerts are never sent, a target must come from the alert's evidence, and every request needs an analyst and a reason and is audited. New reviewed setting `playbook_automation`. See the reference, [Response playbooks](docs/REFERENCE.md#response-playbooks).

- Agentless Windows collection, part of the second item of #8. `scripts/wef_collector.py` (standard library only) is a Windows Event Forwarding collector: Windows hosts push their event logs to it over HTTPS with their built-in forwarder, authenticated by certificates in both directions, and it posts them to the ingest API. It keeps a bookmark per host, acknowledges a batch only once Watchpost has stored it, and labels every record with the authenticated sender. **Experimental:** it follows Microsoft's protocol documents and is tested against a simulated sender; it has not been run against a Windows host. See [docs/LIVE_INGEST.md](docs/LIVE_INGEST.md#4-windows-event-forwarding-collector).

- CloudTrail collection with a read-only account, part of the second item of #8. `scripts/cloudtrail_collector.py` (standard library only) reads CloudTrail `LookupEvents` across regions and, through one assumed read-only role per account, across accounts, and posts the events to the ingest API. It needs only `cloudtrail:LookupEvents`, which `SecurityAudit` and `ReadOnlyAccess` include. Request signing matches AWS's published Signature Version 4 examples; the collector is tested against a local stand-in for the AWS APIs, not against an AWS account.

### Fixed

- Dual-stack syslog listeners accept IPv4 senders covered by IPv4 or mapped IPv6 allow-list entries and store the fallback host as dotted IPv4.

- A promoted saved search groups `user` with the ASCII fold the `user:` filter uses. `Alice`, `alice`, and `ALICE` stay one key. `ÉRIN` and `érin` stay two keys and no longer trip a threshold together. The finding key is the folded spelling. A host group stays the stored spelling, so `WEB01` and `web01` stay two groups.

- Viewer masking folds usernames on ASCII letters only. `Alice` and `alice` stay one pseudonym. `ÉRIN` and `érin` stay two, and a viewer named `érin` no longer sees `ÉRIN` in clear. The 10,000-name cap still counts those as two and still fails closed. Public addresses stay visible and internal addresses stay masked.

- With `SIEM_TRUST_PROXY=1`, the rate-limit client IP is the last entry of exactly one `X-Forwarded-For` header on a loopback connection. A second header is not used, so a client-supplied line cannot choose the key. A value that is not an address stays the peer address. One header `192.0.2.1, 203.0.113.7` still uses `203.0.113.7`.

- Asset host matching folds ASCII letters only, the same fold as entity hosts. An asset named `Érin-host` no longer matches events on `érin-host`, so one host does not take the other's criticality. `WEB01` still matches `web01`. Addresses stay the form already stored.

- Alert related timeline also matches the evidence host, case-insensitively for ASCII. An event on `web01` in the window is included when the evidence host is `WEB01`, even with a different user and source IP. `Érin-host` and `érin-host` stay apart. Source IP matches stay exact.

- Event search and hunt match `outcome` case-insensitively (ASCII). `outcome:failure` and `GET /api/events?outcome=Failure` return a row stored as `failure`. A prefix already folded ASCII. Grouping by outcome stays exact. The lookup uses `idx_events_outcome_nocase`.

- Event search and hunt match `source` case-insensitively (ASCII). `source:Demo` and `GET /api/events?source=demo` return a row stored as `demo`. A prefix already folded ASCII. Grouping by source stays exact. The lookup uses `idx_events_source_nocase`.

- A missing static file (404) and a non-GET on a static path (405) send `Cache-Control: no-store`. A static file that exists stays `no-cache`.

- Hunt and event search bind a complete IP in the form ingest stores, so `src_ip:2001:DB8::1` and `GET /api/events?ip=2001:DB8::1` match a row stored as `2001:db8::1`. A trailing `*` stays a text prefix. Anything that is neither a prefix nor one address is 400.

- Alert related timeline matches `user` case-insensitively (ASCII, like event search). Evidence stored as `Alice` includes events stored as `alice`. Source IP matches stay exact.

- Event search and hunt match `host` case-insensitively (ASCII, like the asset inventory). `WEB01` and `web01` are one host in `host=` and `host:`. Grouping by host stays exact. The lookup uses `idx_events_host_nocase`.

- Hunt `timechart` returns `note` when there are no rows or every bucket count is 0, naming the query and the span. The rows stay as they are. A chart with a count above 0 omits `note`.

- Hunt `stats`, `top`, and `timechart` group `user` case-insensitively, and `dc(user)` counts those spellings once. The group label is the lowercase account. Other fields still compare exactly.

- Alert and incident Markdown and PDF reports list each ATT&CK technique with its evidence level. Mapped means a rule names the technique and is not proof; only validated is a labeled scenario.

- Incident case Markdown lists each ATT&CK technique with its evidence level. Mapped means a rule names the technique and is not proof; only validated is a labeled scenario.

- Coverage detail: each mapped-only technique states why it is not validated. With the default rules, T1190 is probed but never exploited, T1595.001 sweeps one host rather than IP blocks, and T1048 is cloud storage reads with no exfiltration channel.

- Dashboard ATT&CK matrix: every catalog technique is drawn, empty tactics stay on the kill chain, and cells are colored by evidence level. A mapped technique is no longer painted as a gap, and Initial Access is no longer clipped at four rows.

- Sigma import: unquoted values with a leading zero, such as the keyboard layout ID `00000429`, stay text instead of becoming the number 429, so `contains` matches the full identifier. Found by comparing the parser with PyYAML on all 3,164 SigmaHQ rules; every rule now parses identically. (#67)

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
