# Threat model

What Watchpost protects, from whom, and what it does not cover. It is a portfolio and learning project, so the limits are listed as plainly as the controls. Controls named here are described in [REFERENCE.md](REFERENCE.md).

## Assets

- **Stored events and alerts.** The record an analyst relies on. Integrity matters more than secrecy here.
- **Analyst decisions.** Incident status, notes, rule changes and tuning exceptions.
- **Accounts and credentials.** Passwords, TOTP secrets, sessions, ingest tokens.
- **The audit log.** The evidence of who did what.

## Trust boundaries

| Boundary | Trust |
|---|---|
| Browser to server | Untrusted until a session (or API token) is verified. State-changing requests also need a CSRF token. |
| Log sources to the ingest API | Authenticated by session or ingest token. Event content is always untrusted. |
| Syslog listener (UDP/TCP) | **Unauthenticated by design of the protocol.** Binds to loopback by default; an allowlist narrows who may send. |
| Server to SQLite | The process and its data directory are trusted. Anyone with file access to the database is out of scope. |

## Attackers considered

1. **Unauthenticated network user** probing the login, API and static routes.
2. **Authenticated low-privilege user** (viewer or analyst) trying to exceed their role.
3. **Malicious log content** crafted to break parsers, the UI or the query layer.
4. **A compromised analyst account** trying to hide actions or push rule changes through alone.

## Threats and what answers them

| Threat | Control |
|---|---|
| Password guessing | PBKDF2-SHA256 hashing, account lockout, per-IP login rate limiting (429 with `Retry-After`). |
| Stolen password | Optional TOTP two-factor (RFC 6238). |
| Session theft or fixation | Server-side sessions that store only token hashes, with a fixed lifetime. `SIEM_SECURE_COOKIES=1` behind HTTPS. |
| Cross-site request forgery | CSRF token on state-changing routes. |
| Role escalation | Roles are checked by the server, and the read-only viewer role is enforced on every route. |
| Injection through hunting queries | One-line query language compiled from a field whitelist with bound values, never string-built SQL. |
| Oversized or malformed input | Upload and batch limits (`SIEM_MAX_UPLOAD_BYTES`, `SIEM_MAX_BATCH_EVENTS`), validation in `normalize.py`, rejected frames counted but not stored. |
| Unreviewed rule change | Changes come from analyst feedback, are backtested first, and need a second person's approval. The approval must carry the digest of the exact evidence it covers. |
| Quiet tampering with history | Audit entries form a hash chain; `GET /api/audit/verify` walks it. |
| Data exposure to viewers | Usernames and internal IP addresses become keyed pseudonyms in viewer responses. This is presentation-layer masking for a low-trust role, not anonymization. |
| Secrets in logs | A smoke check confirms the server log contains no secrets. |

## Known gaps and non-goals

- **The audit chain is only tamper-evident.** Without `SIEM_AUDIT_KEY` it uses plain SHA-256, so someone who can rewrite the database can recompute the whole chain. With the key set, they would also need the key. Neither stops a root user from deleting the database.
- **Syslog has no authentication or encryption.** Frames from any permitted address are accepted. Exposing it beyond loopback without the allowlist and a firewall lets anyone inject events. Encrypted syslog is not built.
- **Plain HTTP by default.** `SIEM_SECURE_COOKIES` defaults to `0`; the deploy kit runs behind a reverse proxy on loopback.
- **Rate limits are in memory.** They reset on restart and are per process.
- **Single process, SQLite.** No high availability, no horizontal scale, no per-tenant isolation.
- **TOTP uses HMAC-SHA1 as the RFC specifies.** That matches common authenticator apps; it is not a hardware-backed factor.
- **Not covered:** a compromised host running Watchpost, denial of service from a well-resourced attacker, supply-chain attacks on the Python runtime, and physical access.

## Reporting

Found something that contradicts this document? See [SECURITY.md](../SECURITY.md).
