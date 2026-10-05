# Watchpost 3.0: built from the LinkedIn feedback

Date: 2026-10-04. Branch: `ws/3.0-feedback`. Owner approved the scope in chat and asked for autonomous execution.

## Goal

Answer the public feedback on the 2.0 post with shipped features, so the follow-up post can say
"you asked, here is what changed" and credit the people who asked.

## Constraints

- Stdlib-only Python. No new dependencies, no build step for the front end.
- Synthetic-data labeling stays everywhere it is today. No ML claims. It is a portfolio project.
- Viewer role stays read-only. New GET routes default to `viewer`; anything that changes state needs
  `analyst` or `admin` and goes through the existing change-review flow where one exists.
- All existing tests stay green (`./run_tests.sh`: 199 tests + smoke). New behavior gets tests first.
- No commits, no pushes. Work stays uncommitted on `ws/3.0-feedback` for the owner to review.
- Do not touch `LINKEDIN.md` or the existing uncommitted edits in `README.md` beyond adding new sections.

## Out of scope (reserved for Juan Carlos Munera, issue #8)

Encrypted syslog, non-syslog log sources/parsers, orchestration/response playbooks, hot/warm/cold
retention, alert-to-incident correlation (`watchpost/correlate.py` stays untouched), threat intel feeds.

## Workstream 1: detection quality

Feedback: Charles Vosburgh (test with benign look-alikes, find where rules get noisy), Abderrazak
Benarous (rules are plain thresholds; how is exfil told apart from normal outbound), Issouf Dayo
(false positives, shadow IT).

1. **Noise lab.** Add benign look-alike scenarios to `simulate.SCENARIOS` (`malicious: False`,
   `expected: {}`, plus `lookalike_of: <rule_id>`), at least one per rule where a realistic one exists:
   nightly backup moving several GB, a user mistyping a password then logging in, on-call admin at 03:00,
   an office NAT where many users fail after a password-expiry day, an uptime monitor walking many paths,
   a traveling employee on VPN, a CI role that legitimately creates a key, and so on.
   `improve.evaluate` already computes tp/fn/fp per rule; extend its result so each rule lists which
   benign scenarios it was tested against and which tripped it. New `GET /api/noise-lab` (viewer) and a
   "Noise lab" nav view: one row per rule with recall, precision, look-alikes tested, look-alikes that
   fired, and a plain verdict. Rules that stay noisy are shown as noisy. That honesty is the feature.
2. **Baseline-aware exfil.** `data_exfil_volume` gains a `baseline_multiplier` param: a principal with
   comparable volume in its own history (inside the rule's history window) does not alert; the
   explanation states the baseline and the ratio. The nightly-backup look-alike must stop firing and the
   exfiltration scenario must still fire. Apply the same idea to other rules only where the noise lab
   shows noise and a principled fix exists. Do not tune a rule into silence to make the scoreboard green.
3. **Tuning exceptions (suppressions).** A reviewed, expiring allowlist: rule id + group key + reason +
   expiry. Proposed by an analyst, approved by an admin through the existing `change_requests` flow,
   audited. The engine skips matching findings and counts them as suppressed in the detection run. The
   authorized internal scanner (10.0.50.5) is the worked example. Shown in "Rules & review".
4. **Shadow IT rule.** One new rule that flags use of a cloud service that is not on a sanctioned list
   (rule param), from events the existing JSON ingest and schema can already carry. Mapped to an honest
   ATT&CK technique, with a malicious scenario and a benign look-alike. Add it to the attack storyline
   only if it fits without breaking `tests/test_storyline.py`.

## Workstream 2: investigation

Owner asked for extra SIEM features beyond the comments.

5. **Entity risk and entity page.** New `watchpost/entities.py`. An entity is a user, source IP, or host.
   Risk score = sum over the entity's alerts of a severity weight, decayed by age, excluding alerts
   closed as false positive or benign. The score must be explainable: the API returns the contributing
   alerts and their weights. `GET /api/entities` (top N by risk) and `GET /api/entities/<kind>/<value>`
   (score breakdown, alerts, incidents, recent events, first/last seen). Dashboard panel "Riskiest
   entities"; users/IPs/hosts in alert and incident views link to the entity page.
6. **SOC metrics.** Extend `/api/metrics` and the Metrics view with numbers that are meaningful on this
   data: time to resolve by severity, false-positive rate by rule, open-alert aging. Leave out any metric
   that replayed synthetic timestamps would make misleading, and say so in the README.

## Workstream 3: docs and verification

- README: "What's new in 3.0" section and an updated real/synthetic/future table. Credit commenters.
- New `LINKEDIN_3.md` (do not edit `LINKEDIN.md`): a modest follow-up post draft. No claims of
  cyber-SOC job experience, no inflated numbers; every number must come from the test run or the noise lab.
- `scripts/smoke.py` gains steps for the new routes. Full `./run_tests.sh` green.
