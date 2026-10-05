# LinkedIn kit: Watchpost 2.0

Demo: https://watchpost-nxxu.onrender.com (read-only login `viewer` / `watchpost-viewer-demo`, set in `render.yaml`).
One placeholder left: `<VIDEO>`, the 30-second recording from `DEMO_SCRIPT.md`. The repository is https://github.com/talalkashar/watchpost.

---

## 1. Project section entry

**Title:** Watchpost: a SIEM with incident correlation and MITRE ATT&CK mapping, built from scratch in Python

**Dates / association:** Personal project

**Link:** https://github.com/talalkashar/watchpost (demo: `https://watchpost-nxxu.onrender.com`, read-only login `viewer`)

**Description:**

Watchpost is a Security Information and Event Management (SIEM) system I built from scratch to learn how a
detection pipeline works from the raw log line to the incident report.

- **Ingest:** Linux auth.log, Windows Security events, nginx/Apache access logs, firewall and VPN logs, and
  CloudTrail-style cloud audit records. Logs arrive through a token-authenticated API, file upload, a live syslog
  listener (UDP/TCP, RFC 3164/5424), or a file-tailing shipper. Everything is normalized into one schema in SQLite.
- **Detect:** eleven explainable rules (brute force, password spray, web scanning, port sweeps, impossible travel,
  privilege escalation after a suspicious login, IAM changes by new principals, data exfiltration volume, and more).
  Each one maps to MITRE ATT&CK techniques.
- **Correlate:** related alerts are chained into incidents by shared IP, account, or host, with a kill-chain stage
  list. Severity escalates when an incident spans three or more ATT&CK tactics.
- **Respond:** a dark SOC dashboard with a live Server-Sent Events stream, an attacker map, ATT&CK coverage, and an
  incident board. Analysts triage, annotate, and resolve alerts, then download a one-click incident report in
  Markdown or a hand-written PDF.
- **Secure by default:** PBKDF2 hashing, lockout, per-IP rate limiting, admin/analyst/read-only viewer roles, CSRF
  tokens, a strict CSP, hashed ingest-only API tokens, secret redaction, and two-person review for rule changes. It
  runs as a hardened systemd service behind HTTPS.

Python standard library only: no frameworks, no packages. Covered by about 200 automated tests plus an end-to-end
smoke check.

**Skills:** Python · SIEM · Detection engineering · MITRE ATT&CK · Incident response · Log analysis · Secure web
application design · Linux / systemd · SQLite · Automated testing

---

## 2. Post (under 1,300 characters)

> I built a SIEM from scratch to understand what happens between "a log line arrives" and "an analyst closes the
> incident."
>
> In the 30-second clip, a synthetic intrusion plays out live: web recon, a password spray, a VPN foothold, sudo to
> root, a new cloud access key, and a data exfiltration burst. Watchpost detects each stage and chains the alerts
> into one incident tagged with MITRE ATT&CK techniques. One click produces the incident report as a PDF.
>
> What's under the hood:
> • 11 explainable detection rules, each mapped to ATT&CK
> • Correlation into incidents, with severity escalated when an attack spans 3+ tactics
> • Live SOC dashboard over Server-Sent Events
> • Syslog listener and a log shipper for real Linux hosts
> • Roles, CSRF, rate limiting, and two-person review for rule changes
> • Python standard library only, about 200 tests
>
> Being upfront: the attack data is synthetic, there's no machine learning, and it's a single-node portfolio
> project, not a product.
>
> Try the read-only demo: https://watchpost-nxxu.onrender.com (user: viewer / watchpost-viewer-demo)
> Code: github.com/talalkashar/watchpost
>
> Feedback from SOC analysts and detection engineers is very welcome.
>
> #cybersecurity #SOC #SIEM #detectionengineering #MITREATTACK #blueteam

Length check: 1,220 characters as written, about 1,245 with a typical URL and password filled in. Re-count after
you fill them. LinkedIn cuts at "see more" after roughly 210 characters, so the first two lines are the hook.

---

## 3. Honest limits (say these if asked; the post already says the first three)

- **Synthetic data.** The attack storyline, demo scenarios, and sample files are invented. External IPs come from the
  reserved documentation ranges (RFC 5737), and every synthetic event is stored with `synthetic=1` and labeled in the
  UI and in reports. The map positions come from a labeled synthetic table, not a geo lookup.
- **No machine learning.** Detection is threshold rules. Rule tuning is fixed heuristics over analyst verdicts, and a
  second person must approve every change. Precision and recall numbers measure my own labeled scenarios, not
  real-world traffic.
- **Single node.** One Python process and SQLite, sized for thousands to low millions of events. There is no
  clustering, retention, or high availability. Rate limits and SSE subscribers live in memory.
- **Portfolio project.** Built to learn and to show how the pieces fit, not hardened or supported for production
  use. The live syslog listener is unauthenticated and bound to loopback by default. The public demo is read-only.
- **Scope.** The rules are fixed thresholds over authentication, web, firewall/VPN, cloud audit, and host events.
  There is no Sigma import, threat-intel enrichment, or case management beyond incidents.
