"""
Lightweight schema validator for Elastic-style TOML detection rules.

Mirrors (a small slice of) what elastic/detection-rules enforces: required
fields are present, the rule_id is a UUID, severity/type/language are from the
allowed set, and an ATT&CK threat mapping exists. Run as a script; exits
non-zero if any rule is invalid, so it can gate CI.
"""
from __future__ import annotations

import glob
import os
import sys
import uuid

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}
ALLOWED_TYPE = {"query", "eql", "threshold", "machine_learning", "new_terms"}
ALLOWED_LANGUAGE = {"kuery", "lucene", "eql"}
REQUIRED_RULE_FIELDS = [
    "rule_id", "name", "description", "severity", "risk_score",
    "type", "language", "query",
]


def validate_file(path: str) -> list[str]:
    errors: list[str] = []
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    rule = data.get("rule")
    if not rule:
        return [f"{path}: missing [rule] table"]

    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            errors.append(f"{path}: missing required field rule.{field}")

    if "rule_id" in rule:
        try:
            uuid.UUID(str(rule["rule_id"]))
        except ValueError:
            errors.append(f"{path}: rule_id is not a valid UUID")

    if rule.get("severity") not in ALLOWED_SEVERITY and "severity" in rule:
        errors.append(f"{path}: severity {rule.get('severity')!r} not in {sorted(ALLOWED_SEVERITY)}")
    if rule.get("type") not in ALLOWED_TYPE and "type" in rule:
        errors.append(f"{path}: type {rule.get('type')!r} not in {sorted(ALLOWED_TYPE)}")
    if rule.get("language") not in ALLOWED_LANGUAGE and "language" in rule:
        errors.append(f"{path}: language {rule.get('language')!r} not in {sorted(ALLOWED_LANGUAGE)}")

    rs = rule.get("risk_score")
    if isinstance(rs, int) and not (0 <= rs <= 100):
        errors.append(f"{path}: risk_score {rs} out of range 0-100")

    threat = rule.get("threat")
    if not threat:
        errors.append(f"{path}: missing ATT&CK threat mapping (rule.threat)")

    return errors


def main() -> int:
    rules = sorted(glob.glob(os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules_toml", "*.toml")))
    all_errors: list[str] = []
    for path in rules:
        errs = validate_file(path)
        if errs:
            all_errors.extend(errs)
        else:
            print(f"OK   {os.path.basename(path)}")
    if all_errors:
        print("\nVALIDATION FAILED:")
        for e in all_errors:
            print(f"  - {e}")
        return 1
    print(f"\nAll {len(rules)} TOML rules valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
