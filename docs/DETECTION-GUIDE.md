# Writing and testing detections

A Watchpost detection is a pure function. It takes a list of events and a params dict. It returns findings. It does not learn, and it does not talk to the database.

`watchpost/engine.py` loads enabled rules and calls `rules.rule_function(rule_id)` after each stored batch, and again on `POST /api/detection/run`. Built-in rules live in `watchpost/rules.py`. Sigma rules use `watchpost/sigma.py`. Promoted saved searches use `watchpost/search_rules.py`.

This page is how to write and test the first two. The field reference is [REFERENCE.md](REFERENCE.md). The HTTP routes are [API.md](API.md).

## What the function sees

Each event is a dict. The engine loads `id`, `ts`, `event_type`, `user`, `src_ip`, `host`, `dest_ip`, `dest_port`, `bytes`, `message`, `synthetic`, `source`, and `ingested_at` (`engine.RULE_EVENT_FIELDS`). Rule code matches on the eight fields from `event_type` to `message`. `id` and `ts` are evidence and ordering. Timestamps are ISO-8601.

`event_type` is one of the names in `normalize.EVENT_TYPES`:

`auth_failure`, `auth_success`, `account_lockout`, `user_created`, `privilege_use`, `privilege_escalation`, `process_start`, `network_connection`, `file_access`, `web_request`, `web_scan`, `web_error`, `fw_deny`, `fw_allow`, `vpn_login`, `cloud_api_call`, `cloud_iam_change`, `cloud_data_access`, `syslog`, `other`.

A finding is a dict with these keys:

| Key | Meaning |
|---|---|
| `group_key` | The string later alerts are deduplicated on |
| `event_ids` | Evidence event ids, in time order |
| `first_seen`, `last_seen` | ISO timestamps of the first and last evidence event |
| `title`, `explanation` | What fired, in plain text, including the threshold that was met |

`log_source_silent` is the exception. It does not scan the event list. It reads each source's arrival times and the clock. See [REFERENCE.md](REFERENCE.md).

## Built-in rules

There are fifteen built-in rules. Fourteen functions are in `watchpost/rules.py`. `log_source_silent` is in `watchpost/sources.py`. Both are registered in `rules.RULE_FUNCTIONS`.

`engine.seed_rules` inserts any built-in id that is missing, enabled, with the default params. An id that already exists keeps its stored params. Technique tags are copied from code on startup.

| Rule id | Fires when | Labeled attack | Benign look-alike |
|---|---|---|---|
| `brute_force_ip` | One IP has `threshold` `auth_failure` events inside `window_seconds` | `brute_force` | `noisy_scanner`, `noisy_scanner_repeat` |
| `password_spray` | One IP fails as `distinct_users` accounts inside the window | `password_spray` | `password_expiry_nat` |
| `account_repeated_failures` | One account fails `threshold` times from any IPs | `brute_force` | `stale_password_device` |
| `success_after_failures` | A success follows `failures` failures for that account | `compromise` | `password_typo` |
| `off_hours_privileged_login` | A `privileged_users` account logs in outside business hours (UTC) | `off_hours_admin` | `oncall_admin` |
| `web_scanner` | One IP sends `threshold` `web_scan` events inside the window | `web_scan` | `uptime_monitor` |
| `firewall_port_sweep` | One IP is denied on `distinct_ports` ports | `port_sweep` | `authorized_port_scan` |
| `impossible_geo_login` | Two successes for one account are too far apart, too fast | `impossible_travel` | `vpn_traveler` |
| `privilege_escalation_after_login` | Privilege use soon after a login that followed failures | `privilege_escalation` | `typo_then_sudo` |
| `cloud_iam_change_by_new_principal` | A principal changes IAM with no cloud activity of its own in `history_seconds` | `cloud_new_principal` | `ci_key_rotation` |
| `data_exfil_volume` | One principal moves `bytes_threshold` bytes or `access_threshold` cloud reads | `exfiltration` | `nightly_backup` |
| `unsanctioned_cloud_service` | An account uses a cloud service not in `sanctioned_services` | `shadow_it` | `sanctioned_saas` |
| `cloud_logging_disabled` | A cloud message names an action in `logging_actions` | `logging_disabled` | `trail_maintenance` |
| `admin_action_from_new_source` | A privileged action comes from an IP that account has not used | `admin_new_source` | `admin_known_source` |
| `log_source_silent` | A learned source stops sending | `log_source_stops` | `office_badge_reader` |

The scenario names are keys of `simulate.SCENARIOS`. `expected` maps a rule id to the `group_key` the attack must produce. `lookalike_of` names the rule a benign scenario is written to test. That column is not a promise that the default params stay quiet. The shipped `brute_force_ip` params detect `brute_force` and also fire on `noisy_scanner` and `noisy_scanner_repeat`.

Defaults and legal ranges live in `DEFAULT_RULES` and `PARAM_SCHEMA`. `rules.validate_params(rule_id, partial)` fills missing keys from the defaults and rejects unknown keys, bools used as ints, and values outside the range. `threshold` is an int from 2 to 10000. `window_seconds` is an int from 10 to 604800. `ignore_ips` is a list of 0 to 500 addresses.

List matching is `rules.list_entry` and `rules.covers`:

- `ignore_users` and `privileged_users` fold ASCII letters only. `Alice` and `alice` are one account. `ÉRIN` and `érin` stay two.
- `ignore_ips` matches the stored address form. `2001:DB8::1` and `2001:db8::1` are one address. A prefix does not match.
- `sanctioned_services` and `logging_actions` fold the whole string. A sanctioned name also covers its subdomains.

Account group keys use the same ASCII fold. An IP group key stays the stored address.

Most built-in rules count with a sliding window (`rules._clusters`). Events that qualify and sit closer than `window_seconds` become one finding. Events outside every qualifying window do not count.

### Call a built-in rule

This is the same shape as `tests/test_rules.py`. Nine failures in one second stay quiet. Ten fire. Ten failures a minute apart never put ten events inside the 300 second window, so they stay quiet.

```python
from datetime import datetime, timedelta, timezone
from watchpost import rules
from watchpost.db import iso

base = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)

def fail(sec, user="admin", ip="203.0.113.1"):
    return {"ts": iso(base + timedelta(seconds=sec)),
            "event_type": "auth_failure", "user": user, "src_ip": ip}

def make(events):
    return [{"id": i, **event} for i, event in enumerate(events, start=1)]

params = rules.validate_params("brute_force_ip", {})
quiet = rules.brute_force_ip(make([fail(i) for i in range(9)]), params)
hit = rules.brute_force_ip(make([fail(i) for i in range(10)]), params)
spread = rules.brute_force_ip(make([fail(i * 60) for i in range(10)]), params)
```

`quiet` and `spread` are `[]`. `hit` is one finding. `group_key` is `203.0.113.1`. `event_ids` has ten ids. `title` is `Brute force from 203.0.113.1: 10 failed logins`.

`{}` means the shipped defaults: `threshold` 10, `window_seconds` 300, empty ignore lists.

### Tune a built-in rule

Change params through review. Do not edit the function to quiet one IP.

`POST /api/rules/{id}/proposals` (analyst) takes `{params, enabled, reason}`. `params` may be a partial object. The server merges it with the current params, runs the labeled scenarios, and backtests stored events. A different admin approves with `POST /api/changes/{id}/review`. The body needs `decision`, `note`, and the `evidence_digest` of the evidence they were shown. If the change drops a labeled detection, it also needs `acknowledge_detection_loss: true`. Self-review is refused.

An approved tuning exception (`POST /api/rules/{id}/suppressions`) skips that `(rule_id, group_key)` on later runs. `data_exfil_volume` does not skip. An exception for that rule turns on a baseline for that principal instead.

### Add a built-in rule

A new built-in rule is a code change. Import and export move tuning only. They cannot add a function.

1. Write `(events, params) -> list of findings` next to the other functions. Use `_filtered`, `_clusters`, and `_finding` when the rule is a threshold. Sort is already done inside `_filtered`.
2. Add a `DEFAULT_RULES` entry: `id`, `name`, `description`, `techniques`, `severity`, `params`. Technique ids must be in the catalog in `watchpost/attack.py`.
3. Put every new param key in `PARAM_SCHEMA`.
4. Register the function in `RULE_FUNCTIONS`. `rule_function` returns `None` for an unknown id, and detection then fails that run.
5. If `params` has `history_seconds`, add the event types the function reads to `HISTORY_EVENT_TYPES`. The engine loads only those types from the history span. A missing entry makes the rule blind to its own history.
6. Add a malicious scenario in `simulate.SCENARIOS` with `expected` set to the group key you want. Add a benign look-alike with `lookalike_of` set to the new id.
7. Restart. `seed_rules` inserts the new id if it is absent.

Then test the function on a handful of events, and test it against the scenarios. Both are below.

## Test a built-in rule

### On a list of events

Call the function. Assert the boundary: one under the threshold, the threshold itself, and the same count spread past the window. That is what `tests/test_rules.py` does.

```bash
python3 -m unittest tests.test_rules.BruteForceTests
```

### Against the labeled scenarios

`improve.evaluate` builds every scenario in isolation and runs the rule functions. Seed `7` is the default.

```python
from watchpost import rules
from watchpost.improve import evaluate

report = evaluate(
    {"brute_force_ip": rules.validate_params("brute_force_ip", {})},
    seed=7,
)
row = report["rules"]["brute_force_ip"]
```

With the shipped params, `detected` is `["brute_force"]`, `missed` is `[]`, and `lookalikes_fired` is `["noisy_scanner", "noisy_scanner_repeat"]`. Recall is 1.0. Precision is 0.333. The scanner is labeled benign and still trips the default threshold. That is a real result, not a broken test.

The same call with `ignore_ips: ["10.0.50.5"]` still detects `brute_force` and fires on neither scanner scenario. That address is the authorized scanner in `simulate.py`.

On a running instance, `GET /api/noise-lab` is this evaluation for the enabled rules. `POST /api/evaluations` stores one run. `POST /api/demo/simulate` with `{"scenario": "brute_force"}` replays one scenario into the database so the next detection run can raise the alert.

### Detection-as-code on an export

`watchpost/detection_tests.py` checks an exported rules document and runs each enabled built-in rule on its malicious scenarios and its look-alikes. Disabled rules are validated and reported as `skipped`. The document must include every param key. A partial params object is rejected. Sigma and `search_` ids are rejected with `has no bundled detection-as-code samples`. Their samples live in the database, not in the version 1 export.

```bash
python3 scripts/test_detections.py watchpost-rules.json
```

The script prints JSON only. Exit 0 means every tested rule passed. Exit 1 means at least one failed. Exit 2 means the file was not a valid export. Pass `-` to read stdin. `--seed` defaults to 7.

A one-rule document:

```json
{
  "format": "watchpost-rules",
  "format_version": 1,
  "rules": [
    {
      "id": "brute_force_ip",
      "enabled": true,
      "params": {
        "threshold": 10,
        "window_seconds": 300,
        "ignore_ips": [],
        "ignore_users": []
      }
    }
  ]
}
```

`detection_tests.check` on that document returns `ok: false`. The malicious scenario `brute_force` passes. The benign scenarios `noisy_scanner` and `noisy_scanner_repeat` fail. Put `"10.0.50.5"` in `ignore_ips` and the same check returns `ok: true`, with both sides passed.

A document that sets `"enabled": false` returns `ok: true`, `tested: 0`, and `status: "skipped"`. Skipped is not a failure.

A full export of the shipped defaults exits 1 for the same reason as the one-rule document. Rules that still fire on a known look-alike are listed by name. Tune them, or read the failures as evidence. Do not treat exit 1 on an untouched export as a crash.

```bash
python3 -m unittest tests.test_detection_cli
```

## Sigma rules

Sigma is the way to add detection logic without editing Python. `watchpost/sigma.py` compiles a small subset of a Sigma rule into a JSON tree and walks that tree over each event. It does not `eval` the YAML. It does not build a regular expression from the rule. Wildcards use a linear-time glob.

Anything outside the subset is refused with a reason. Nothing is approximated.

### What you can write

Required: `title` (1 to 200 characters) and `detection` with one `condition` string and 1 to 50 named selections.

`level` is `informational`, `low`, `medium`, `high`, or `critical`. The default is `medium`. `informational` and `low` both store severity `low`.

A tag `attack.tXXXX` or `attack.tXXXX.XXX` becomes an ATT&CK technique when that id is in the catalog. Other tags are kept out of coverage and returned as warnings. `logsource` is stored and ignored at match time. The rule runs on every event. Other known keys (`author`, `references`, `falsepositives`, and the rest of `INFO_KEYS`) are ignored. Unknown keys are ignored and named in `warnings`.

A selection is a map of `field` or `field|modifier` to a value or a list. A list is OR. Fields in one map are AND. A list of maps is OR of those maps. A bare string or list of strings is a keyword: a case-insensitive substring of `message`.

Values match case-insensitively. `*` and `?` are wildcards. `\*`, `\?`, and `\\` are literals. `null` matches an empty field. A number is compared as text, so `dest_port: 22` matches the text `22`.

Modifiers: `contains`, `startswith`, `endswith`, `cidr`, `all`, `windash`, `base64`, and `base64offset`. Use at most one of the first four, plus `all`. `all` means every value must match. `windash` also tries each leading `-` as `/` and the dash look-alikes, at most three dashes per value. `base64` and `base64offset` encode the value before matching and must come before `contains`, `startswith`, or `endswith` (`CommandLine|base64offset|contains` order). `cidr` does not combine with them.

Conditions: a selection name, `and`, `or`, `not`, parentheses, `1 of them`, `all of them`, `1 of sel*`, `all of sel*`. Names that start with `_` are left out of `them`.

Refused, with the reason in the error:

- Unknown fields. `EventID`, `Image`, and `CommandLine` have no Watchpost column.
- `re`, `wide` / `utf16` / `utf16le` / `utf16be`, `expand`, `lt` / `lte` / `gt` / `gte`, `exists`.
- `| count()` and any other `|` aggregation, `near`, and `timeframe`.
- `N of` other than `1` and `all`.
- Anchors, aliases, tags (`!`), tabs, duplicate keys, and the rest of the YAML list in the module docstring.

Field names that do map:

| In the YAML | Watchpost field |
|---|---|
| `event_type`, and ECS `event.action` | `event_type` |
| `user`, `User`, `TargetUserName`, ECS `user.name` | `user` |
| `src_ip`, `SourceIp`, `IpAddress`, ECS `source.ip` | `src_ip` |
| `host`, `Computer`, `ComputerName`, `hostname`, ECS `host.name` | `host` |
| `dest_ip`, `DestinationIp`, `dst_ip`, ECS `destination.ip` | `dest_ip` |
| `dest_port`, `DestinationPort`, `dst_port`, ECS `destination.port` | `dest_port` |
| `bytes` | `bytes` |
| `message` | `message` |

Caps: 64 KB and 2,000 lines of YAML. 100 values on one field. A condition of at most 1,000 characters. After the condition is expanded, at most 2,000 values and 128 KB. Naming one selection many times copies it, so a short rule can still hit the cap.

The rule id is `sigma_` plus the title in lowercase, with non-letters turned into underscores, trimmed to 48 characters of that base. `Failed Admin Login From External Source` becomes `sigma_failed_admin_login_from_external_source`.

### The worked example

`docs/sigma-examples/failed_logins_from_external_source.yml` is a failed login for `root`, `admin`, or `administrator` from an address outside the private ranges. The detection block is:

```yaml
detection:
  selection:
    event.action: auth_failure
    user.name:
      - root
      - admin
      - administrator
  internal:
    SourceIp|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
  condition: selection and not internal
```

Compile it and match three events:

```python
from pathlib import Path
from watchpost import sigma

source = Path("docs/sigma-examples/failed_logins_from_external_source.yml").read_text()
compiled = sigma.compile_rule(source)

attack = {"event_type": "auth_failure", "user": "root", "src_ip": "203.0.113.5"}
inside = {"event_type": "auth_failure", "user": "root", "src_ip": "10.1.2.3"}
success = {"event_type": "auth_success", "user": "root", "src_ip": "203.0.113.5"}

sigma.matches(compiled["params"], attack)    # True
sigma.matches(compiled["params"], inside)    # False
sigma.matches(compiled["params"], success)   # False
```

`compiled["rule_id"]` is `sigma_failed_admin_login_from_external_source`. Severity is `high`. The only technique is `T1110.001`. `conditions` is one line:

```text
((event_type = 'auth_failure' AND user = any of ['root', 'admin', 'administrator']) AND NOT src_ip in any of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'])
```

`warnings` names `attack.credential_access` as unmapped, and says `logsource` does not filter. `user: ADMIN` matches. Matching folds case. A missing `src_ip` does not match the `cidr` list, so `not internal` is true. A failed `root` login that has a host and no address still matches. The finding key is then the host.

A field Watchpost does not store fails closed:

```python
sigma.compile_rule(
    "title: Bad\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel\n"
)
# SigmaError: field 'EventID' does not map to a Watchpost event field ...
```

An aggregation fails closed the same way: `condition: aggregations ('| count() by ...') are not supported`.

### Example packs

`docs/sigma-examples/` holds the worked example and the other top-level rules. Each subfolder is a pack of rules for one surface: `azure`, `cloud`, `email`, `kubernetes`, `linux`, `linux-persistence`, `macos`, `network`, `ransomware`, `saas`, `web`, `windows`, `windows-lateral`. `tests/test_sigma_pack_<pack>.py` compiles that pack and checks matching and non-matching events.

Because `logsource` does not filter, a pack rule that only names a path or a keyword runs against web requests, firewall lines, and everything else. The `linux-persistence` rules exclude web, firewall, network, and VPN event types with a `network_or_web` selection, so a scanner probing `/etc/crontab` does not trip them. They do not list host types instead: auditd `EXECVE` records and shell command logs normalize to `other`, and an allowlist would miss them. Rules that would fire on routine traffic carry a `filter_*` selection with placeholder values, such as known mail relays or trusted principals. Replace those placeholders with your own values before you enable the rule. The `falsepositives` field on each rule names the knob.

### Findings

There is no threshold. Every matching event is evidence. `sigma.run(events, params)` groups by source IP. An event with no source IP groups by host, then by user, then by `"unknown"`. A host or user key folds ASCII letters only when that field is the key. `WEB01` and `web01` are one host `web01`. An address is not folded. `2001:DB8::1` and `2001:db8::1` are two keys.

Inside one group, events more than `GROUP_GAP_SECONDS` (3600) apart start a new finding.

```python
events = [
    {"id": 1, "ts": "2026-09-15T12:00:00+00:00", "event_type": "auth_failure",
     "user": "root", "src_ip": "203.0.113.5"},
    {"id": 2, "ts": "2026-09-15T12:10:00+00:00", "event_type": "auth_failure",
     "user": "Admin", "src_ip": "203.0.113.5"},
    {"id": 3, "ts": "2026-09-15T14:00:01+00:00", "event_type": "auth_failure",
     "user": "root", "src_ip": "203.0.113.5"},
    {"id": 4, "ts": "2026-09-15T12:05:00+00:00", "event_type": "auth_failure",
     "user": "root", "host": "WEB01"},
]
findings = sigma.run(events, compiled["params"])
```

That returns three findings: ids `[1, 2]` and `[3]` under `203.0.113.5`, and id `[4]` under `web01`. Event 3 is more than an hour after event 2, so it does not join the first finding.

`params` is `{"format", "title", "detection"}`. It is not tunable. Sigma rules stored before `format` existed are recompiled from their approved YAML when the schema initializes. One whose source no longer compiles is disabled with the reason in its history. To change the logic, import the YAML again under a new title.

### The labeled sample

A Sigma rule has no built-in scenario. You supply one. Both lists are required. Each has 1 to 50 events. Field names are the Watchpost names plus `ts`. ECS names in the sample are rejected. `dest_port` and `bytes` are ints. Other values are strings.

The sample passes when every malicious event matches and no benign event matches. It is judged event by event, not as a count.

```python
sample = sigma.validate_sample({
    "malicious": [attack],
    "benign": [inside, success],
})
sigma.sample_result(compiled["params"], sample)["passes"]  # True
```

A passing sample shows that these events match. It does not show that the rule catches the technique in live traffic.

### Import, review, enable

`POST /api/rules/sigma` (analyst) takes `{source, sample, reason}`. `source` is the YAML text.

`?dry_run=1` compiles the rule and creates nothing. The body has `compiled` (rule id, conditions, warnings, sha256, params), `sample`, and `backtest`. The preview is the last 7 days of stored events, through the same scan the engine uses. A bad rule is `{ok: false, refused: "<reason>"}`.

Without `dry_run` the server opens a `sigma_add` change request. A different admin approves it with the evidence digest. Approval inserts the rule **disabled**, and stores the YAML, its sha256, and the sample on `sigma_rules`.

Replace the sample later with `POST /api/rules/<id>/sigma-sample`. That is a `sigma_sample` change request. It bumps the rule version.

Enable with an ordinary `rule_update` that sets `enabled: true`. Proposal and approval both refuse unless the stored sample passes. In the noise lab the sample is the scenario `sigma_sample:<rule id>`. Techniques are **mapped** while the rule is enabled and the sample fails, and **validated** only while the sample passes.

```bash
python3 -m unittest tests.test_sigma.CompileTests tests.test_sigma.SigmaGroupKeyTests
```

`tests.test_sigma.ImportWorkflowTests` covers dry run, two-person approval, the enable gate, and an alert on ingested events.

## When you need a count

Sigma in Watchpost has no `count()`. A threshold over a hunt filter is a promoted saved search, not a Sigma rule.

`POST /api/hunt/saved/<id>/promote` copies the saved search's filter into a `search_<slug>` rule. The filter cannot contain `|`, `last:`, `since:`, or `until:`. The window does the counting. `group_by` is one of `src_ip`, `user`, `host`, `dest_ip`, `source`, `event_type`, `dest_port`. The rule fires when one group value has `threshold` matches inside a sliding `window_minutes`.

The sample is the same two lists. It is judged as a run: the malicious events must raise at least one finding, and the benign events must raise none. `threshold` and `window_seconds` stay tunable. The query does not. A new query is a new rule.

Details are in [REFERENCE.md](REFERENCE.md) under "Saved searches as detections".

## What a detection run does with the finding

`engine.run_detection` loads enabled rules and calls `validate_params` on each. It reads events in the batch window, widened by the longest `window_seconds` (at least 3600 seconds). Rules with `history_seconds` also get that much earlier history, limited to the event types in `HISTORY_EVENT_TYPES`. Findings whose `last_seen` falls inside the history span are dropped. They are context, not new alerts.

`grouping.apply` then runs. An empty grouping list leaves the rule's `group_key`. A reviewed grouping list rebuilds the key from evidence fields. User and host parts fold ASCII letters. Addresses stay as stored.

An active tuning exception drops findings for that rule and group key. `data_exfil_volume` keeps the finding and applies the baseline instead. A rule-wide suppression window drops every finding for that rule until the window ends.

An unresolved alert with the same rule id and group key is extended when its `last_seen` is within `window_seconds` before the finding's `first_seen`. A rule with no `window_seconds`, including every Sigma rule, uses 3600 seconds there. Otherwise a new open alert is created. Evidence that is already attached to an alert for that rule and key is left as it is.

The run is stored in `detection_runs`. A failed run leaves the events stored. `POST /api/detection/run` processes the backlog.

Before you propose a param change, `GET /api/rules/{id}/backtest?params=<JSON object>&days=<1-30>` replays today's params and the draft on stored events (default 7 days) and reports findings as kept, new, or lost. It changes nothing. Analysts call it. A viewer sees the same comparison inside the change request after the proposal exists.
