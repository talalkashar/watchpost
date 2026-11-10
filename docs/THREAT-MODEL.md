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
| Syslog over TLS (optional) | With a client CA, a sender proves a certificate from that CA before any frame is read. Without one, the stream is encrypted but any sender is accepted. Frame content is always untrusted. |
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
| Syslog read or injected on the network | Syslog over TLS (RFC 5425, TLS 1.2+). With a client CA, frames are read only from senders that hold a certificate it signed. TLS settings that cannot be loaded stop the listener; it never falls back to plaintext. |
| Oversized or malformed input | Upload and batch limits (`SIEM_MAX_UPLOAD_BYTES`, `SIEM_MAX_BATCH_EVENTS`), validation in `normalize.py`, rejected frames counted but not stored. |
| Unreviewed rule change | Changes come from analyst feedback, are backtested first, and need a second person's approval. The approval must carry the digest of the exact evidence it covers. |
| Quiet tampering with history | Audit entries form a hash chain; `GET /api/audit/verify` walks it. |
| Data exposure to viewers | Usernames and internal IP addresses become keyed pseudonyms in viewer responses. This is presentation-layer masking for a low-trust role, not anonymization. |
| Events lost or altered by retention | Retention is off by default. A day's events are deleted only after their archive file has been written, read back and recorded, and never when they are evidence of an alert. Each file's SHA-256 is in the manifest and in the hash-chained audit log, and can be re-verified at any time. |
| A response action aimed at the wrong thing | Watchpost carries out no response action. A request goes to a webhook the operator configures, needs an analyst and a reason, can only name a value from the alert's own evidence, is never sent for a synthetic alert, and is audited. |
| A forged or misdirected webhook message | Bodies are signed with HMAC-SHA256 when `SIEM_PLAYBOOK_WEBHOOK_SECRET` is set. The URL must be HTTPS (or this machine), comes only from the environment, and redirects are not followed. Bodies hold an alert's summary, never its events. |
| Secrets in logs | A smoke check confirms the server log contains no secrets. |

## Known gaps and non-goals

- **The audit chain is only tamper-evident.** Without `SIEM_AUDIT_KEY` it uses plain SHA-256, so someone who can rewrite the database can recompute the whole chain. With the key set, they would also need the key. Neither stops a root user from deleting the database.
- **Plain syslog has no authentication or encryption.** UDP and TCP frames from any permitted address are accepted. Exposing them beyond loopback without the allowlist and a firewall lets anyone inject events.
- **Syslog over TLS has limits.** Every certificate the client CA has signed is admitted, and there is no revocation check. A certificate authenticates the connection, not the content: an admitted sender can still claim any host name inside its messages. UDP stays plaintext. Without a client CA, TLS only encrypts.
- **Plain HTTP by default.** `SIEM_SECURE_COOKIES` defaults to `0`; the deploy kit runs behind a reverse proxy on loopback.
- **Rate limits are in memory.** They reset on restart and are per process.
- **Single process, SQLite.** No high availability, no horizontal scale, no per-tenant isolation.
- **TOTP uses HMAC-SHA1 as the RFC specifies.** That matches common authenticator apps; it is not a hardware-backed factor.
- **Not covered:** a compromised host running Watchpost, denial of service from a well-resourced attacker, supply-chain attacks on the Python runtime, and physical access.

## Reporting

Found something that contradicts this document? See [SECURITY.md](../SECURITY.md).
