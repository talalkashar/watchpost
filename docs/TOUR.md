# Five-minute tour of the public demo

For a security engineer who opened the live console from LinkedIn. Five minutes, one read-only account, synthetic data. Every claim below is what the console and the detection code do.

Open [https://watchpost-nxxu.onrender.com](https://watchpost-nxxu.onrender.com). Sign in as `viewer` / `watchpost-viewer-demo`. The free-tier host can take about a minute on a cold start. The sign-in page says **All data is synthetic.** That is the whole dataset: labeled office traffic and attack scenarios, not a customer tenant.

After sign-in the rail reads **viewer · read-only**. **Account** and **Admin** are not in the nav. Below 760px wide, open **Menu** to see the views.

If the rail also shows **Masked view**, the setting `viewer_masking` is on. Usernames and internal addresses are then stable pseudonyms (`user-…`, `internal-…`) on every response, including reports. Public addresses stay visible, including the RFC 5737 ranges the scenarios use (`203.0.113.0/24` and the other documentation nets). A pseudonym in a filter or a hunt still resolves on the server. This is presentation masking for a low-trust role, not anonymization. The shipped default is off, so a demo that has not approved that setting shows the raw synthetic names (`alice`, `admin`, `erin`) and the internal addresses as stored. Either way, the rest of this tour is the same clicks.

The status strip stays up on every view: events per minute, open alerts, critical, incidents, events stored, and the health checks (storage, ingestion, detection, dependencies, labeled store / ingest / detect / deps). **LIVE** means `GET /api/stream` (server-sent events) is connected. If the stream fails, the console polls and the badge is not LIVE. A banner appears only when health is not ok, and it links to Health.

Start the clock on the dashboard. Counts move as the demo is replayed; read the labels, not a number from this page.

## 0:00 Dashboard

You land on `#dashboard`. The bar says **Dashboard**. The dropdown is saved dashboard views: a name, a severity filter, and which panels are on. **Default view** is the full board. **Apply** loads the one you pick. **Save a view** is analyst-only and is absent here. A saved layout that hides the matrix shows a coverage chip that links to Coverage.

Read three panels. That is the product.

**Attack map.** The card opens as a 3D globe; **2D** switches to the flat map, which is also the view when the browser asks for reduced motion or has no WebGL 2. **Overhead** looks straight down on HQ, and **Pause orbit** stops the rotation. Arcs run from fictional cities to HQ. Cities exist only for RFC 5737 and RFC 1918 ranges (for example `203.0.113.0/25` is Ironvale, `10.0.0.0/8` is Riverton HQ). Anything else is counted as **no geo entry** and is never placed. Internal sources are not drawn as attacker arcs. The side list is **Busiest arcs**. Select a city there for its event count, source IP count, and highest severity. This proves the map is a fixed demo table, not a geo feed and not threat intelligence.

**Live event stream.** Rows are recent events, dripped as they arrive. **Pause** stops the drip. Severity, type, and the message are the normalized event, not the raw line. This proves ingest reaches the screen without a reload.

**MITRE ATT&CK coverage.** Each cell is a technique in the catalog. The legend is the grading rule: **Validated** means an enabled rule caught a labeled attack for that technique (heat is how many alerts hit it). **Mapped only** means a rule names the technique and no labeled scenario proves it. **Disabled** means only a disabled rule maps there. **Gap** means no rule maps there. Only validated counts as covered. **Export Navigator layer** downloads the same grades as a MITRE ATT&CK Navigator JSON file.

Then glance at the rest, in order: **Alerts over time** (stacked severity plus event volume), **Top attacker IPs** (by evidence events; a public address is still the real address), **Incident board** (Open / Investigating / Resolved, five cards per column, **all incidents →**), **Top rules**, **Health** (each check, the stream mode, and dots for recent detection runs), **Riskiest entities** (alert weight, decayed by age).

If the store were empty, the panels would be hidden and one card would say there are no events. This account cannot load demo data.

## 0:40 Incidents

Click **Incidents**, or a card on the board. Columns are Open, Investigating, and Resolved, highest severity first, then newest, up to fifty cards a column. A card title is the kill-chain path plus up to three entities (source IP, account, host). `j` / `k` move the selection, Enter opens it. Press `?` for the shortcut list. This account has no action keys.

A technique tag on the card is the earliest kill-chain technique (tactic order, then technique id). Up to four tactic names follow it.

Open one card (`#incidents/<id>`).

- The kill chain lists every tactic. Filled stages fired in this incident. Dim stages were not observed. Technique ids sit under the stage that produced them.
- **escalated: 3+ tactics** appears when the alerts span three or more tactics. Severity is the highest alert severity, raised one level in that case.
- The sentence under Details is the correlation rule: alerts that share a source IP, account, or host within 30 minutes are one incident. A new incident is opened for two related alerts, or for one critical alert. A single alert below critical stays an alert.
- **Alert timeline** is the alerts in order. Click a row.
- **Evidence** is the events behind those alerts. User, source IP, and host are links.
- **Assets involved** are inventoried systems this incident reached. An alert that touches a high or critical asset, or a system tagged as processing sensitive data, can show a severity above the rule's base severity. The note says so.
- **MITRE ATT&CK** repeats the techniques, grouped by tactic.

**Report (PDF)** and **Report (Markdown)** download a case report. **Case timeline (JSON)** and **Case timeline (Markdown)** download the timeline. Names in the file match the screen: when Masked view is on, the PDF is rendered from the masked model rather than shipped as raw bytes. **Start investigating** and **Resolve** are not shown.

This view proves correlation: shared entities inside a fixed window, a visible kill chain, and a downloadable case. It is not a score.

## 1:20 One alert

Click **Alerts**, or the timeline row you just opened. A first visit is filtered to **Showing open critical and high** (`status=open` and `severity=critical,high`). Change the two selects and press **Filter**, or **Reset** for every alert. The choice is remembered in this browser tab.

**Active incidents** restates the same 30-minute rule and the three-tactic raise. The table under the filter is the queue: severity, title, rule id, status, verdict if one was recorded, an SLA pill when an open alert is past its ack or resolve target, event count, last seen.

Open one row (`#alerts/<id>`).

- **Why this fired** is the rule's own explanation, then the rule name, version, and description.
- **MITRE ATT&CK** is the technique list on that rule.
- **Assets** and, when the stored severity is above the rule severity, the base severity and the reason.
- **Evidence** is the events that matched. Click a user, a source IP, or a host.
- **Related timeline** is every stored event for those IPs or accounts from 30 minutes before the alert to 30 minutes after. Highlighted rows are the evidence. The other rows are context the rule did not count.
- **Details** has the group key (how this rule deduplicates alerts; that key is not how incidents are built), assignee, acknowledgement time, and verdict.
- **Notes** and **Activity** are readable. There is no note box and no resolve button.

**Report (PDF)** and **Report (Markdown)** work the same way as on an incident. Esc returns to the queue.

This view proves a detection is a named rule plus the events that satisfied it, with the surrounding half hour still on the page.

## 2:05 Entity, then Hunt

From the evidence table, click a source IP or an account. The page is `#entity/src_ip/…`, `#entity/user/…`, or `#entity/host/…`.

The score is the sum of severity weights on alerts whose evidence includes this entity: critical 40, high 20, medium 10, low 5, info 1. Each weight is halved every 24 hours of age. Age is measured from the newest event in the database, not from the wall clock, so replayed demo timestamps do not decay to zero. Alerts closed as false positive or benign add nothing. **Why this score** lists every contribution, including a severity that was raised by asset weight. The weights on that table are the score. **Alerts by day** counts each alert on the UTC day of its newest stored event for this entity, up to the newest 31 days.

Click **Hunt this … (last 7 days)**. That opens Hunt with the field, the value, and `last:7d` in the hash, which is a shareable link. If the value on screen was a pseudonym, the query still finds the underlying account or internal address.

You are now on **Hunt**. The box is a one-line filter. Terms are ANDed. There is no OR. The server parses the query and the page shows **Parsed as** pills; the browser does not interpret the language. Fields are `user`, `host`, `source`, `outcome`, `src_ip`, `dest_ip`, `ip` (source or destination), `batch_id`, `event_type`, `severity`, `dest_port`, `synthetic`, `message`, plus `last`, `since`, and `until`. One `|` stage may follow: `stats`, `top`, or `timechart`. Click a value in an aggregate to add it to the filter.

Run the **Brute force** example. The query is `event_type:auth_failure user:admin src_ip:203.0.113.45 synthetic:1 last:7d`. The three example links use the raw demo names. With Masked view off, the account column shows those names. With it on, the same link still runs and the account column shows the pseudonym; `203.0.113.45` stays, because it is not an internal address. The other two examples are the impossible-travel scenario (`source:demo:impossible_travel`, user `erin`) and the large cloud read (`event_type:cloud_data_access`, user `svc-deploy-tmp`, message contains `customer-exports`). Demo events are dated on the most recent weekday strictly before today (UTC), so `last:7d` still covers them. Click a result row for the event: normalized fields, whether it is synthetic, linked alerts, and the original record with secrets redacted.

**Save search** and **Promote to detection** are absent. Saved searches that already exist are listed and can be re-run.

This pair of views proves entity risk is a published formula with the arithmetic on the page, and hunt is a bound query over the same events, not a second datastore.

## 3:05 Rules & review

Click **Rules & review**.

Read **How rules change** before any rule card. A rule change, a tuning exception, a suppression window, a Sigma import, a promoted search, and an asset edit that could lower severity all become a change request. A different admin has to approve it. The request is tested against labeled scenarios, and a rule-parameter change is also backtested on stored events. Two false positives with a shared cause can produce a suggested exclusion or threshold change. **Suggest improvements** and **Run evaluation** are not on this account.

**Export rules (JSON)** downloads parameters and enabled flags. Detection logic stays in code, so an import can only retune rules this instance already has, and an import applies nothing until review. **Import** is absent. A Sigma rule, a documented subset, is the one path that adds logic: it is imported disabled and can be enabled only after its labeled sample passes.

**Change requests** shows pending and recent proposals with before/after scenario impact. You cannot approve. **Tuning exceptions** skip one rule for one group key until expiry. One rule is different: `data_exfil_volume` is not skipped. An approved exception turns on a baseline for that principal. **Rule suppression windows** pause one whole rule for a bounded period; approval has to acknowledge the labeled detections that will be missed.

Each built-in rule is a card: plain-language description, ATT&CK techniques, alert-grouping fields (deduplication only), parameters, analyst feedback (true positive, false positive, benign, precision), and the latest scenario evaluation (detected, missed, false positives, recall, precision). The pill on the card is the noise-lab verdict. **History** opens the parameter history. **Propose change** is absent.

The fifteen built-in rules are `brute_force_ip`, `password_spray`, `account_repeated_failures`, `success_after_failures`, `off_hours_privileged_login`, `web_scanner`, `firewall_port_sweep`, `impossible_geo_login`, `privilege_escalation_after_login`, `cloud_iam_change_by_new_principal`, `data_exfil_volume`, `unsanctioned_cloud_service`, `cloud_logging_disabled`, `admin_action_from_new_source`, and `log_source_silent`.

This view proves detections are pure functions with visible parameters, and that tuning is a reviewed change with a backtest, not an edit in production.

## 3:35 Noise lab

Click **Noise lab**. The strip at the top is pass only when every labeled attack was detected and no benign scenario fired. Otherwise it is fail, with the miss list and the benign scenarios that fired.

Each rule card is that rule run alone against its attacks and its benign look-alikes, using current parameters and approved exceptions. **Quiet** means it catches its attack and stays silent on its look-alikes. **Noisy** means it catches the attack and also fires on benign activity. **Blind** means it misses a labeled attack. **Disabled** means it is not running. **Untested** means no look-alike has been written, or the rule is an imported Sigma rule or a promoted search (those are proved by their own labeled sample, not by this lab).

Read the note on `data_exfil_volume`: its thresholds are flat, so the nightly-backup look-alike fires here until a tuning exception for that principal is approved. After that, the burst has to beat the principal's own recent history.

This view proves the project publishes where the rules are noisy. It does not hide the false positives inside a precision chart.

## 4:00 Coverage

Click **Coverage**. The summary line is the same four grades as the dashboard matrix, with a sentence for each. **Export Navigator layer** is the same JSON as on the dashboard.

Click one green cell and one that is not validated. The detail names the proving scenarios, or says there are none. A mapped technique adds one sentence on why the labeled traffic does not prove it (a scan that probes and never exploits is mapped to exploitation, not validated). Each rule row links back to that rule's card and shows the noise-lab verdict, which benign scenarios fired, and how many live alerts hit.

**Gaps: not validated** lists everything that is mapped only, disabled, or a gap. Validated is the only grade that counts as covered.

This view proves ATT&CK coverage is an evidence grade against labeled scenarios, not a list of technique ids pasted onto rules.

## 4:25 Health

Click **Health**. **Overall** is the worst check. The four that are always present:

| Check | Failing | Degraded |
|---|---|---|
| storage | The event store cannot be read or written | Less than 100 MB free |
| ingestion | The ingest check crashed | Recent batches were rejected or failed |
| detection | The last detection run failed | Rules are off, a run is stuck, or batches were skipped |
| dependencies | Python, SQLite, or a writable database directory is missing | Console files are missing |

Syslog or storyline appear when that component registered a check. Each row has the status, a message, latency, **What to do** when the check is unhappy, and a **means** sentence that is shown even while the check is ok. Open **details** for the raw fields. `GET /api/health` is unauthenticated and returns statuses only (HTTP 503 when failing). This page is the authenticated detail.

**Log source health** groups events by source and host and judges them on arrival time, not on the timestamp inside the event. **Learning** means the cadence is not known yet. **Late** and **Silent** are quiet longer than a multiple of that cadence. On a late or silent row, **Hunt its events** opens a seven-day hunt for that source. Silence inside an approved maintenance window does not alert. **Run detection** is not on this account.

**Recent errors** are redacted. **Recent detection runs** show trigger, status, events scanned, alerts created, updated, and suppressed.

This view proves the console reports its own pipeline, including a failed detection run, instead of only the attacks.

## 4:40 Events, Metrics, Ingest

Three short stops. They are reads.

**Events** (`#events`). Set **Data** to **Synthetic only** and press **Search**. That is `synthetic=1` on the normalized store. **Real only** is the other half of the same flag. Filters are source (demo events use `demo:<scenario>`), user, IP, event type, minimum severity, message substring, and a UTC range. Click a row for the same event dialog as Hunt. Paging is 100 events. This proves the detection store is the normalized event, and synthetic is a column you can filter, not a watermark in a screenshot.

**Metrics** (`#overview`). The top row is the queue: awaiting investigation, investigating, resolved, mean time to resolve, and a count of synthetic events. Below that is the last 24 hours of event time (ending at the newest event, not at the wall clock), open alerts by severity, alerts by rule, failure sources, targeted accounts, analyst verdicts, and event types. **SOC metrics** adds time to resolve by severity, false-positive rate by rule from analyst verdicts, and open-alert aging. **Triage metrics** is mean, median, and p90 for time to acknowledge and time to resolve, plus SLA breaches. **Unavailable metrics** lists the figures the API will not invent, each with a reason. This proves the numbers are defined, and the missing ones are named.

**Ingest** (`#ingest`). **Upload a log file** accepts `.log`, `.txt`, `.json`, `.jsonl`, and `.csv`, up to 5 MB, and can mark the batch synthetic. **Replay an attack simulation** lists every scenario, whether it is malicious or benign, and the rules it is expected to fire (or none). Both submit buttons are disabled for this account. **Recent batches** is the audit of what was accepted, rejected, and whether detection on that batch succeeded. The curl sample on the page is the local API, not an invitation to post at the public host.

## What you cannot do from this login

You can GET the views above, download reports, the Navigator layer, and the rules JSON, and sign out. Every other write returns 403. That includes ingest, replay, demo reload, alert status, notes, rule proposals, approvals, and tokens. The audit log is an admin read, so this account cannot open it. By default, five failed sign-ins lock the account for 15 minutes. Both numbers are security settings and change only through a reviewed proposal.

Keyboard, if you want it: `j` / `k` and Enter on Alerts and Incidents, Esc back to the list, `/` focuses the search box or opens Hunt, `?` shows the list.
