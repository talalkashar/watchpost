# LinkedIn project entry

**Title:** Watchpost: a working mini-SIEM built from scratch (Python)

**Short description (project section):**

I built a small Security Information and Event Management (SIEM) system to learn how detection pipelines work end to end. It ingests authentication logs (Linux auth.log, Windows Security events, JSON, CSV) through an authenticated API or a file upload, normalizes them into one schema, and stores them in SQLite. It runs five explainable detection rules: brute force, password spraying, repeated account failures, a successful login after failures, and off-hours privileged logins. Each alert carries its evidence events, a plain-English explanation, and a related-activity timeline. Analysts can investigate, add notes, and resolve alerts with a true-positive or false-positive verdict.

Those verdicts feed per-rule precision tracking. From them, Watchpost proposes rule tuning, such as excluding an authorized scanner. Each proposal is scored against labeled test scenarios, and a second person must approve it before it takes effect. The app also monitors itself: health checks for storage, ingestion, detection, and dependencies surface failures with recovery steps, and events are never lost while detection is broken.

Security basics are built in: salted PBKDF2 password hashing, account lockout, role-based access, CSRF protection, a strict Content-Security-Policy, hashed ingest-only API tokens, input validation, parameterized SQL, and redaction of secrets from stored logs and error records.

Python standard library only. 57 automated tests plus an end-to-end smoke check.

**Being upfront:** all demo data is synthetic, generated with reserved documentation IP ranges. The detection accuracy numbers come from my own labeled scenarios, not real-world traffic. The tuning suggestions are rule-based heuristics, not machine learning. It's a single-node learning project, not a production SIEM.

**Skills:** Python · SIEM / log analysis · detection engineering · SOC analyst workflow · secure web application design · SQLite · automated testing

---

**Optional post text:**

> I wanted to understand what actually happens between "a log line arrives" and "an analyst closes an alert," so I built a small SIEM from scratch.
>
> Watchpost ingests SSH and Windows authentication logs, detects brute force, password spraying, and logins that succeed after repeated failures, and walks an analyst through investigation and resolution.
>
> Two parts I learned the most from:
> 1. **Feedback without magic.** When analysts mark alerts as false positives (in my demo, an authorized vulnerability scanner), the system proposes a specific tuning change and shows its effect on labeled test scenarios. A second person has to approve it before it takes effect.
> 2. **Failing honestly.** If a rule breaks, the app keeps ingesting and storing events, reports "detection failing" with recovery steps, and processes the backlog once it's fixed.
>
> All the data is synthetic, and it's a learning project, not a product. Demo video and code below. Feedback from SOC folks welcome!
