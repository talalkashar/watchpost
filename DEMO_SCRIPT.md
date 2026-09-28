# Watchpost demo script (about 5 minutes)

Setup: a fresh database, with the app started via `./start.sh`. Open two browser profiles: one signed in as **admin**, one as **analyst**. Every step below was run and verified; see PROGRESS.md.

Say up front: *"Everything you'll see is synthetic data I generated. The IPs come from reserved documentation ranges."*

## 1. Empty state and health (30 s)
- Sign in as **admin**. The dashboard says "No events yet".
- Open **Health**: four checks (storage, ingestion, detection, dependencies), all `ok`, each with timing.
- *"The app checks itself. There's a public health endpoint for uptime monitors that returns HTTP 503 on failure."*

## 2. Load data and let the rules fire (45 s)
- **Admin → Load synthetic demo data**. The results table lists seven scenarios, and each one's detection run shows `ok`.
- **Dashboard**: 9 open alerts, a failed-login spike in the activity chart, `203.0.113.45` at the top of failed-login sources.
- *"The labeled scenarios are brute force, password spraying, a compromised account, an off-hours root login, and a noisy but authorized internal scanner that I included on purpose as a false-positive source."*

## 3. Investigate the critical alert (90 s), as **analyst**
- **Alerts**: the list is sorted by severity. Open **"Possible compromise of dave: login after 7 failures"**.
- Point out the **"Why this fired"** explanation, the rule description, the 8 evidence events, and the **related timeline**.
- Click **Start investigating**, then add a note ("Reset dave's password; reviewing VPN logs").
- Click **Resolve…** → *True positive* → Resolve. The activity log records every step with who and when.

## 4. Search (30 s)
- **Events**: set Source `demo:*`, IP `198.51.100.23` → 12 failures across 12 accounts (the spray).
- Click a row to show the original record, then say: *"Secrets like `password=` are redacted before they're stored."*

## 5. Feedback → reviewed rule change (90 s)
- As **analyst**, resolve the three `brute_force_ip` alerts: the two for `10.0.50.5` as *False positive* (it's the authorized scanner), the one for `203.0.113.45` as *True positive*.
- **Rules**: `brute_force_ip` now shows precision 33 %. Click **Suggest improvements from feedback**.
- A pending change request appears: `ignore_ips: ["10.0.50.5"]`, with scenario impact **FP 2→0, TP unchanged**.
- *"This is a heuristic, not machine learning. Nothing changes until someone else approves it."* Show that the analyst has no approve button.
- As **admin**, click **Approve** and add a note. The rule goes to v2, and **History** shows who proposed and who approved it.
- **Ingest → Replay** `noisy_scanner`: 0 new brute-force alerts. Replay `brute_force`: a new alert still opens.

## 6. Failure and recovery (45 s) *(optional; do it in a scratch DB)*
- Break a rule in the database, e.g. `sqlite3 data/watchpost.db "update rules set params='{\"threshold\":0}' where id='brute_force_ip'"`, then **Replay** `brute_force`.
- The response says detection **failed** but 40 events were stored. A red banner appears, and **Health** shows `detection: failing` with "What to do" guidance and the redacted error.
- Restore the parameters, click **Run detection (full scan)**, and everything returns to `ok`. The alerts are created from the stored backlog.
- *"It doesn't hide failures, and it doesn't lose data while it's broken."*

## 7. Close (15 s)
- Mention: standard library only, 57 automated tests, and an end-to-end smoke script.
- Limitations: single-node SQLite, synthetic evaluation data, authentication-focused rules.
