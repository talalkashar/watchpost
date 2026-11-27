"""Validate exported rules and run their bundled malicious and benign samples."""

from . import improve, portability, rules, simulate


class ValidationError(ValueError):
    """The supplied export cannot be tested safely."""


def _has_bundled_samples(rule_id):
    """True when this built-in has at least one malicious label and one look-alike."""
    malicious = benign = False
    for spec in simulate.SCENARIOS.values():
        expected = spec.get("expected") or {}
        if isinstance(expected, dict) and rule_id in expected:
            malicious = True
        if spec.get("lookalike_of") == rule_id:
            benign = True
        if malicious and benign:
            return True
    return False


def _validated_rules(document):
    if isinstance(document, dict) and any(not isinstance(key, str) for key in document):
        raise ValidationError("the import has a non-string key")
    try:
        entries = portability._check_document(document)
    except improve.ChangeError as exc:
        raise ValidationError(str(exc)) from exc
    if not entries:
        raise ValidationError("rules must contain at least one rule")

    checked, seen = [], set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValidationError(f"rule entry {index} must be an object")
        if any(not isinstance(key, str) for key in entry):
            raise ValidationError(f"rule entry {index} has a non-string key")
        unknown = set(entry) - portability.RULE_KEYS
        if unknown:
            raise ValidationError(f"rule entry {index} has unknown key(s): {', '.join(sorted(unknown))}")
        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(f"rule entry {index} must have a non-empty string id")
        if rule_id in seen:
            raise ValidationError(f"duplicate rule {rule_id!r}")
        if rule_id not in rules.RULE_FUNCTIONS or not _has_bundled_samples(rule_id):
            raise ValidationError(f"rule {rule_id!r} has no bundled detection-as-code samples")
        enabled = entry.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError(f"rule {rule_id!r} enabled must be a boolean")
        if "params" not in entry:
            raise ValidationError(f"rule {rule_id!r} must include params")
        raw_params = entry["params"]
        if isinstance(raw_params, dict) and any(not isinstance(key, str) for key in raw_params):
            raise ValidationError(f"rule {rule_id!r} params has a non-string key")
        try:
            params = rules.validate_params(rule_id, raw_params)
        except rules.RuleConfigError as exc:
            raise ValidationError(f"rule {rule_id!r}: {exc}") from exc
        missing = set(params) - set(entry["params"])
        if missing:
            raise ValidationError(f"rule {rule_id!r} params missing key(s): {', '.join(sorted(missing))}")
        checked.append({"id": rule_id, "enabled": enabled, "params": params})
        seen.add(rule_id)
    return checked


def check(document, seed=7):
    """Return a JSON-serializable test report; malformed content raises ValidationError."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValidationError("seed must be an integer")
    entries = _validated_rules(document)
    enabled = {entry["id"]: entry["params"] for entry in entries if entry["enabled"]}
    evaluation = improve.evaluate(enabled, seed=seed) if enabled else {"rules": {}}
    report = []
    for entry in entries:
        rule_id = entry["id"]
        if not entry["enabled"]:
            report.append({"id": rule_id, "status": "skipped", "reason": "disabled"})
            continue
        result = evaluation["rules"][rule_id]
        detected, missed = set(result["detected"]), set(result["missed"])
        fired, tested_benign = set(result["lookalikes_fired"]), set(result["lookalikes"])
        malicious = sorted(name for name, spec in simulate.SCENARIOS.items() if rule_id in spec["expected"])
        benign = sorted(name for name, spec in simulate.SCENARIOS.items() if spec.get("lookalike_of") == rule_id)
        malicious_passed = sorted(name for name in malicious if name in detected and name not in missed)
        malicious_failed = sorted(set(malicious) - set(malicious_passed))
        benign_passed = sorted(name for name in benign if name in tested_benign and name not in fired)
        benign_failed = sorted(set(benign) - set(benign_passed))
        status = "failed" if malicious_failed or benign_failed else "passed"
        report.append({
            "id": rule_id,
            "status": status,
            "malicious": {"passed": malicious_passed, "failed": malicious_failed},
            "benign": {"passed": benign_passed, "failed": benign_failed},
        })
    counts = {status: sum(item["status"] == status for item in report)
              for status in ("passed", "failed", "skipped")}
    summary = {"tested": counts["passed"] + counts["failed"], **counts}
    return {"ok": counts["failed"] == 0, "seed": seed, "summary": summary, "rules": report}
