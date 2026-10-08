"""Validate exported rules and run their bundled malicious and benign samples."""

from . import improve, portability, rules, simulate


class ValidationError(ValueError):
    """The supplied export cannot be tested safely."""


def _validated_rules(document):
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
        unknown = set(entry) - portability.RULE_KEYS
        if unknown:
            raise ValidationError(f"rule entry {index} has unknown key(s): {', '.join(sorted(unknown))}")
        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(f"rule entry {index} must have a non-empty string id")
        if rule_id in seen:
            raise ValidationError(f"duplicate rule {rule_id!r}")
        if rule_id not in rules.RULE_FUNCTIONS:
            raise ValidationError(f"rule {rule_id!r} has no bundled detection-as-code samples")
        enabled = entry.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError(f"rule {rule_id!r} enabled must be a boolean")
        if "params" not in entry:
            raise ValidationError(f"rule {rule_id!r} must include params")
        try:
            params = rules.validate_params(rule_id, entry["params"])
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
        malicious = sorted(name for name, spec in simulate.SCENARIOS.items() if rule_id in spec["expected"])
        benign = sorted(name for name, spec in simulate.SCENARIOS.items() if spec.get("lookalike_of") == rule_id)
        malicious_failed = sorted(set(malicious) & set(result["missed"]))
        benign_failed = sorted(set(benign) & set(result["lookalikes_fired"]))
        status = "failed" if malicious_failed or benign_failed else "passed"
        report.append({
            "id": rule_id,
            "status": status,
            "malicious": {"passed": sorted(set(malicious) - set(malicious_failed)), "failed": malicious_failed},
            "benign": {"passed": sorted(set(benign) - set(benign_failed)), "failed": benign_failed},
        })
    counts = {status: sum(item["status"] == status for item in report)
              for status in ("passed", "failed", "skipped")}
    summary = {"tested": counts["passed"] + counts["failed"], **counts}
    return {"ok": counts["failed"] == 0, "seed": seed, "summary": summary, "rules": report}
