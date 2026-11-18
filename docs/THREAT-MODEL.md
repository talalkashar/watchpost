# Threat model

What Watchpost protects, from whom, and what it does not cover. It is a portfolio and learning project, so the limits are listed as plainly as the controls. Controls named here are described in [REFERENCE.md](REFERENCE.md).

## Assets

- **Stored events and alerts.** The record an analyst relies on. Integrity matters more than secrecy here.
- **Analyst decisions.** Incident status, notes, rule changes and tuning exceptions.
- **Accounts and credentials.** Password hashes (PBKDF2-SHA256), TOTP secrets stored as-is, session token hashes, and API token hashes. The session cookie and the API token secret are not stored.
- **The audit log.** The evidence of who did what, in the same database file.
- **Exported copies.** Reports, case files, and rule-tuning JSON. Once downloaded they are outside this process.

## Trust boundaries

| Boundary | Trust |
|---|---|
| Browser to server | Untrusted until a session or API token is verified. A cookie session's POST must send `X-CSRF-Token` on routes that require it. Bearer tokens skip that check. `POST /api/auth/login`, `POST /api/auth/mfa`, `GET /api/health` (statuses only), and static files need no session. |
| Log sources to the ingest API | A session needs the analyst role or higher, plus the CSRF token. A bearer token needs capability `ingest` and the analyst role. A viewer session or a read-only token cannot ingest. New tokens default to role analyst and `["ingest"]`. Event content is always untrusted, and the caller sets `synthetic`. |
| Syslog listener (UDP/TCP) | **Unauthenticated by design of the protocol.** Off unless `SIEM_SYSLOG=1`. Binds to `127.0.0.1:5514` by default. An empty allowlist accepts any peer that can reach the socket. An invalid allowlist does not listen. |
| Server to SQLite | The process and its data directory are trusted. Anyone with file access to the database is out of scope. WAL mode is not a control against that reader. |

## Attackers considered

1. **Unauthenticated network user** probing the login, API and static routes.
2. **Authenticated low-privilege user** (viewer, analyst, or a bearer token) trying to exceed their role or the token's capabilities.
3. **Malicious log content** crafted to break parsers, the UI or the query layer. A principal who can ingest can also mark the batch synthetic.
4. **A compromised analyst account** trying to hide actions or push rule changes through alone.

## Threats and what answers them

| Threat | Control |
|---|---|
| Password guessing | PBKDF2-SHA256 (default 310,000 iterations; passwords are 12–256 characters). Unknown user, a password of the wrong shape, and a disabled account all return the same 401. Per-account lockout defaults to 5 failures and 15 minutes and answers 429. A disabled account is not counted toward lockout. `POST /api/auth/login` and `POST /api/auth/mfa` share a per-IP limit (default burst 10, 10 per minute, 429 with `Retry-After`). `SIEM_RATE_LIMIT=0` turns the limiters off. |
| Stolen password | Optional TOTP (RFC 6238) for analyst and admin. A viewer cannot enroll. The pending token is stored as a hash, lasts 5 minutes, and the first success consumes it. A wrong code shares the account lockout and is counted before the code is checked. There are no recovery codes: another admin resets it, and cannot reset their own. |
| Session theft or fixation | Login issues a new server-side session. The session token is stored only as a hash. The cookie is `HttpOnly` and `SameSite=Strict`; `Secure` only when `SIEM_SECURE_COOKIES=1`. Default lifetime is 8 hours (`SIEM_SESSION_TTL`). A disabled user's session is rejected. Sessions can be revoked. |
| Cross-site request forgery | A cookie session's POST must send `X-CSRF-Token` where the route requires it. Bearer tokens skip that check. Login and MFA do not require it. A viewer may POST only logout, and that POST still requires the token. |
| Role escalation | The server checks the role. Viewer accounts are read-only except logout. API tokens are viewer or analyst, never admin. A token call needs capability `read` (GET), `ingest`, or `triage`; any other POST is 403. A viewer token is exactly `["read"]`. |
| Injection through hunting queries | One-line query language compiled from a field whitelist with bound values, never string-built SQL. |
| Oversized or malformed input | Upload and batch limits (`SIEM_MAX_UPLOAD_BYTES` default 5 MiB, `SIEM_MAX_BATCH_EVENTS` default 20,000) and validation in `normalize.py`. A rejected record is not stored as an event. The batch stores the count and up to 100 `{index, reason}` entries. An unparseable timestamp reason quotes 40 characters of that field. |
| Hiding a batch as demo data | The ingester chooses `synthetic` (`0`, `1`, `true`, or `false`). Demo load, simulate, and storyline force it on. Detection still runs. An alert is labeled synthetic only when every evidence event is. The label does not drop the alert. |
| Unreviewed rule change | Rule changes, suppressions, security settings, maintenance windows, Sigma imports, and promoted saved searches need a different admin. An asset write applies at once when nothing is gated. A delete always needs a second admin, as does lowering criticality, dropping a tag or address, renaming, or claiming an address another asset already has. Where the proposal stores evidence, approval must carry that evidence's digest. Settings and maintenance windows have none, so they do not. A rules-file import and a Sigma import apply nothing; Sigma approval and a promoted saved search insert the rule disabled. Skipping confirmed-malicious activity is refused. |
| Quiet tampering with history | Audit entries form a hash chain: HMAC-SHA256 when `SIEM_AUDIT_KEY` is set, otherwise plain SHA-256. A key that does not match the chain refuses startup and refuses to extend it. `GET /api/audit/verify` is admin. |
| Data exposure to viewers | Off until a reviewed setting turns `viewer_masking` on (default 0). Then a viewer sees keyed pseudonyms for usernames and internal IPs. Analyst and admin responses are not masked. Public IPs and host names stay visible, and the viewer's own name is not hidden. Past 10,000 distinct usernames the viewer gets 503. Viewer downloads are masked (rendered from a masked model, or masked as JSON or text). A binary download with no model is 403. If masking fails, a stream ends rather than send the frame unmasked. This is presentation-layer masking, not anonymization. |
| Secrets in logs | The `watchpost` logger redacts bearer and basic credentials, key=value secret names, `wp_` tokens, and JSON secret keys. `message` and `raw` are redacted and then cut. Other text fields are control-stripped and length-capped, not secret-redacted. Generated bootstrap passwords are written to `initial_credentials.txt` (mode 0600), not the log. A smoke check asserts the bootstrap passwords, the API token, and the audit key from that run are absent from the server log. The match is by pattern. |

## Exports

Downloads require a signed-in reader (viewer and above). A bearer token also needs `read`, so an ingest-only token cannot download them. Nothing recalls a file after it is saved. An analyst or admin download is the stored data; masking, when on, covers only the viewer.

- **Reports.** `GET /api/alerts/<id>/report.{md,pdf}` and `GET /api/incidents/<id>/report.{md,pdf}` are audited as `report_downloaded`.
- **Case files.** `GET /api/incidents/<id>/case.{json,md}` is audited as `case_exported`. It is assembled from existing records, not a second database, and it is not a legal hold. Evidence follows the incident's 1,000-event cap. Notes, activity, and status changes are the newest 100.
- **Rule tuning.** `GET /api/rules/export` is `params`, `enabled`, and `grouping` for rules this code already has. Detection logic is not in the file. `POST /api/rules/import` (analyst, at most 256 KB and 200 rules) applies nothing: differing rules become `rule_update` proposals, still backtested and still needing a different admin. An unknown rule is refused. `dry_run=1` proposes nothing. `POST /api/rules/sigma` (analyst, at most 256 KB) is the same shape; approval inserts the rule disabled.
- **Read-side mappings.** `GET /api/events/<id>/ecs` and `GET /api/attack/navigator.json` reshape stored data on the way out, under the same login. Navigator scores are alert counts. The layer says a validated technique was detected on the project's labeled synthetic data, not that the score is real-world coverage.

## Known gaps and non-goals

- **The audit chain is only tamper-evident.** Without `SIEM_AUDIT_KEY` it uses plain SHA-256, so someone who can rewrite the database can recompute the whole chain. With the key set, they would also need the key, and a different key is refused rather than used. Neither stops deleting the newest entries: what remains is still a valid shorter chain. Clearing every hash and restarting looks like a 3.x upgrade (`partial`, not `ok`). Neither stops a root user from deleting the database.
- **Syslog has no authentication or encryption.** It is off unless `SIEM_SYSLOG=1`. An empty allowlist means any peer that can reach the socket. Exposing it beyond loopback without an allowlist and a firewall lets anyone inject events. Frames longer than 16 KiB are truncated before parse, and that cut happens before redaction. Frames past the 50,000 queue are dropped and counted, not stored. Encrypted syslog is not built.
- **Plain HTTP by default.** The process listens on `127.0.0.1:8080` unless `SIEM_HOST` or `SIEM_PORT` says otherwise. `SIEM_SECURE_COOKIES` defaults to `0`. Binding beyond loopback logs a warning to set that flag behind HTTPS.
- **Rate limits are in memory.** They reset on restart and are per process. `SIEM_RATE_LIMIT=0` disables them. The client address is the TCP peer unless `SIEM_TRUST_PROXY=1` and that peer is loopback, in which case it is the last entry of exactly one `X-Forwarded-For`. The login limiter and the general request limiter are separate.
- **Viewer masking is off by default.** The pseudonym key comes from `SIEM_AUDIT_KEY` when that is set, otherwise from a random secret in the database, so a reader of that file can reverse the pseudonyms. The viewer's own name is not hidden.
- **Single process, SQLite.** No high availability, no horizontal scale, no per-tenant isolation. Password hashes, token hashes, the audit chain, TOTP secrets, and (with no audit key) the masking key are all in that one file.
- **TOTP uses HMAC-SHA1 as the RFC specifies, and the secret is stored as-is.** That matches common authenticator apps. It is not a hardware-backed factor, and anyone who can read the database can generate codes.
- **Not covered:** a compromised host running Watchpost, denial of service from a well-resourced attacker, supply-chain attacks on the Python runtime, and physical access.

## Reporting

Found something that contradicts this document? See [SECURITY.md](../SECURITY.md).
